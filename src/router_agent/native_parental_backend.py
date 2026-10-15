"""Finite parental backend with HMAC-bound, private recovery contexts.

Only the six reviewed policy strings are persisted; passwords and client
inventories never enter recovery files. Caller owns the root state lock.
"""
import asyncio
from contextlib import contextmanager
import hashlib
import hmac
import json
from pathlib import Path
import re

from .catalog import canonical
from .errors import RouterError
from .snapshots import private_dir, private_read, atomic_write

OPERATIONS=frozenset({'parental.enable','parental.block_all','parental.rule'})
_ALIAS=re.compile(r'client-[0-9a-f]{16}\Z')
_HASH=re.compile(r'[0-9a-f]{64}\Z')


def validate_parental_intent(operation,intent):
    if not isinstance(intent,dict):raise RouterError('invalid_parental_intent','Invalid named parental intent.')
    if operation=='parental.enable':
        valid=set(intent)=={'enabled'} and type(intent['enabled']) is bool
    elif operation=='parental.block_all':
        valid=set(intent)=={'blocked'} and type(intent['blocked']) is bool
    elif operation=='parental.rule':
        valid=set(intent)<= {'client_alias','rule_type','schedule'} and {'client_alias','rule_type'}<=set(intent)
        valid=valid and isinstance(intent['client_alias'],str) and _ALIAS.fullmatch(intent['client_alias']) is not None and intent['rule_type'] in {'disable','time','block','remove'}
        if valid and 'schedule' in intent:
            if intent['rule_type']=='remove':valid=False
            else:
                from .parental_policy import validate_schedule
                validate_schedule(intent['schedule'])
    else:valid=False
    if not valid:raise RouterError('invalid_parental_intent','Invalid named parental intent.')


def _review(snapshot,operation,intent):
    from .parental_policy import public_policy
    public=public_policy(snapshot)
    if operation in {'parental.enable','parental.block_all'}:
        return {key:public[key] for key in ('enabled','block_all','rule_count','rules_write_recoverable')}
    alias=intent.get('client_alias')
    if alias is None:
        # Reverse review shows only opaque fingerprints for the exact original.
        return {'rule_count':public['rule_count'],'policy_fingerprint':public['policy_fingerprint'],'rules_write_recoverable':public['rules_write_recoverable']}
    return next((rule for rule in public['rules'] if rule['alias']==alias),None)


class NativeParentalBackend:
    live=True
    authorization_at_send=True
    live_operations=OPERATIONS
    def __init__(self,config,password,*,fingerprint_key,state_dir,reader=None,writers=None):
        if not isinstance(fingerprint_key,bytes) or len(fingerprint_key)<32:raise RouterError('identity_key_required','A private policy binding key is required.')
        self.config,self._password,self._key=config,password,fingerprint_key
        self.directory=private_dir(Path(state_dir)/'parental-recovery')
        self._reader=reader
        self._writers=writers or {}
        self._active=False
        self._clear()

    def _clear(self):
        self._snapshot=self._identity=self._inventory=self._pending=self._context=None

    @contextmanager
    def transaction(self):
        if self._active:raise RouterError('transaction_busy','A native policy transaction is already active.')
        self._active=True;self._clear()
        try:yield
        finally:self._clear();self._active=False

    def _require(self):
        if not self._active:raise RouterError('transaction_required','Native policy operations require an engine transaction.')

    def _read_policy(self,include_clients=False):
        from .native_parental_control import read_parental_policy
        from .parental_policy import read_policy_snapshot
        self._require()
        result=asyncio.run((self._reader or read_parental_policy)(self.config,self._password,fingerprint_key=self._key,include_clients=include_clients))
        if result.get('warnings'):raise RouterError('native_cleanup_unconfirmed','Native policy read cleanup is unconfirmed.')
        identity=result.get('identity')
        if not isinstance(identity,dict) or set(identity)!={'model','firmware','device_fingerprint'}:raise RouterError('native_state_unknown','Exact native identity and policy are required.')
        from .native_parental_control import validate_parental_applicability
        validate_parental_applicability(identity)
        self._identity=dict(identity)
        self._snapshot=read_policy_snapshot(result['policy'].raw,self._key)
        self._inventory=result.get('client_inventory')

    def device_identity(self):
        self._require()
        if self._snapshot is None:self._read_policy()
        return {'device':self._identity['device_fingerprint'],'firmware':self._identity['firmware']}

    def read(self,operation,fields):
        self._require()
        if operation not in OPERATIONS or list(fields)!=['policy_fingerprint'] or self._snapshot is None:raise RouterError('unsupported_operation','Only named parental policy operations are supported.')
        return {'policy_fingerprint':self._snapshot.fingerprint}

    def _description(self,operation,intent,before,after):
        action=intent['action']
        effects=['firewall_restart']
        if operation=='parental.block_all':effects.append('all_client_internet_blocking_setting')
        if operation=='parental.rule':effects.append('schedule_semantics_and_timezone_unverified')
        return {'before':{'policy_fingerprint':before.fingerprint},'after':{'policy_fingerprint':after.fingerprint},
                'review':{'before':_review(before,operation,intent),'after':_review(after,operation,intent),'preservation':'restore exact plan-bound original order and policy' if intent['action']=='restore_rules' else 'exact plan-bound full policy'},
                'intent':intent,'side_effects':effects}

    def prepare_plan(self,operation,intent):
        from .parental_policy import prepare_enable,prepare_block_all,prepare_rule
        self._require();validate_parental_intent(operation,intent)
        self._read_policy(include_clients=operation=='parental.rule')
        if operation=='parental.enable':prepared=asyncio.run(prepare_enable(self._snapshot,intent['enabled']))
        elif operation=='parental.block_all':prepared=asyncio.run(prepare_block_all(self._snapshot,intent['blocked']))
        else:prepared=asyncio.run(prepare_rule(self._snapshot,intent['client_alias'],intent['rule_type'],client_inventory=self._inventory,schedule=intent.get('schedule')))
        public_intent={'action':{'parental.enable':'enable','parental.block_all':'block_all','parental.rule':'rule'}[operation],**intent}
        self._pending={'operation':operation,'before':prepared.before.raw,'after':prepared.after.raw,'intent':public_intent}
        return self._description(operation,public_intent,prepared.before,prepared.after)

    def seal_plan(self,data):
        from .parental_policy import read_policy_snapshot
        if self._pending is None or data['operation']!=self._pending['operation']:raise RouterError('invalid_policy_context','Policy context is unavailable.')
        before=read_policy_snapshot(self._pending['before'],self._key);after=read_policy_snapshot(self._pending['after'],self._key)
        expected=self._description(data['operation'],self._pending['intent'],before,after)
        if any(data[k]!=v for k,v in expected.items()):raise RouterError('invalid_policy_context','Public review does not match its private policy context.')
        self._pending={'public':json.loads(canonical(data)),'before':before.raw,'after':after.raw}
        return hmac.new(self._key,b'parental-context:'+canonical(self._pending).encode(),hashlib.sha256).hexdigest()

    def bind_plan(self,plan):
        data=plan.data
        if self._pending is None or hmac.new(self._key,b'parental-context:'+canonical(self._pending).encode(),hashlib.sha256).hexdigest()!=data['context_binding']:raise RouterError('invalid_policy_context','Policy context binding is invalid.')
        atomic_write(self.directory/(plan.id+'.json'),canonical({'plan_hash':plan.id,'context':self._pending}).encode())

    def attach_plan(self,plan):
        from .parental_policy import read_policy_snapshot
        self._require()
        data=plan.data
        if _HASH.fullmatch(plan.id) is None:raise RouterError('invalid_policy_context','Policy context identifier is invalid.')
        try:record=json.loads(private_read(self.directory/(plan.id+'.json')))
        except (RouterError,ValueError,TypeError):raise RouterError('invalid_policy_context','Bound private policy recovery context is missing or invalid.') from None
        context=record.get('context') if isinstance(record,dict) else None
        if not isinstance(record,dict) or set(record)!={'plan_hash','context'} or record['plan_hash']!=plan.id or not isinstance(context,dict) or set(context)!={'public','before','after'}:raise RouterError('invalid_policy_context','Policy recovery context does not match the plan.')
        expected={k:v for k,v in data.items() if k not in {'hash','context_binding'}}
        if context['public']!=expected or hmac.new(self._key,b'parental-context:'+canonical(context).encode(),hashlib.sha256).hexdigest()!=data['context_binding']:raise RouterError('invalid_policy_context','Public review or private context binding changed.')
        before=read_policy_snapshot(context['before'],self._key);after=read_policy_snapshot(context['after'],self._key)
        description=self._description(data['operation'],data['intent'],before,after)
        if any(data[k]!=v for k,v in description.items()):raise RouterError('invalid_policy_context','Private policy snapshots do not match approved fingerprints or review.')
        self._context=context

    def write(self,operation,values,*,authorization_check=None):
        from .native_parental_control import set_parental_global,set_parental_block_all,set_parental_rule,restore_parental_rules
        from .parental_policy import read_policy_snapshot
        self._require()
        if self._context is None or self._snapshot is None or operation not in OPERATIONS:raise RouterError('invalid_policy_context','A bound fresh policy context is required.')
        public=self._context['public'];intent=public['intent']
        if values!=public['after']:raise RouterError('invalid_policy_context','Requested policy differs from the approved context.')
        common={'expected_identity':self._identity,'expected_policy_fingerprint':public['before']['policy_fingerprint'],'expected_after_policy_fingerprint':public['after']['policy_fingerprint'],'fingerprint_key':self._key,'authorization_check':authorization_check}
        if intent['action']=='restore_rules':
            fn=self._writers.get('restore',restore_parental_rules)
            result=asyncio.run(fn(self.config,self._password,restore_snapshot=read_policy_snapshot(self._context['after'],self._key),**common))
        elif operation=='parental.enable':
            result=asyncio.run(self._writers.get('enable',set_parental_global)(self.config,self._password,enabled=intent['enabled'],**common))
        elif operation=='parental.block_all':
            result=asyncio.run(self._writers.get('block_all',set_parental_block_all)(self.config,self._password,blocked=intent['blocked'],**common))
        else:
            result=asyncio.run(self._writers.get('rule',set_parental_rule)(self.config,self._password,client_alias=intent['client_alias'],rule_type=intent['rule_type'],schedule=intent.get('schedule'),**common))
        if not isinstance(result,dict) or result.get('warnings'):raise RouterError('apply_uncertain','Policy outcome or cleanup is uncertain; verify independently without replay.')

    def prepare_reverse(self,plan):
        from .parental_policy import read_policy_snapshot,prepare_enable,prepare_block_all,prepare_restore
        self._require()
        if self._context is None or self._snapshot is None:raise RouterError('invalid_policy_context','A bound policy context is required for recovery.')
        original=read_policy_snapshot(self._context['before'],self._key)
        operation=plan.data['operation']
        if operation=='parental.enable':prepared=asyncio.run(prepare_enable(self._snapshot,original.enabled));intent={'action':'enable','enabled':original.enabled,'source_plan':plan.id}
        elif operation=='parental.block_all':prepared=asyncio.run(prepare_block_all(self._snapshot,original.block_all));intent={'action':'block_all','blocked':original.block_all,'source_plan':plan.id}
        else:prepared=asyncio.run(prepare_restore(self._snapshot,original));intent={'action':'restore_rules','source_plan':plan.id,'client_alias':plan.data['intent']['client_alias']}
        self._pending={'operation':operation,'before':prepared.before.raw,'after':prepared.after.raw,'intent':intent}
        return self._description(operation,intent,prepared.before,prepared.after)
