"""Validated, packaged source-evidence ledger. Loading performs no router discovery."""
from collections import Counter
from datetime import date
import hashlib
from importlib.resources import files
import json
from pathlib import Path
import re
from .errors import RouterError

KINDS = frozenset({'read','state','dynamic_read'})
SOURCE_SUPPORT = frozenset({'dedicated_mapping','conditional_mapping','mapped_alias','derived_output','enum_only','handler','registered_handler'})
CLI_STATUS = frozenset({'implemented_selected','implemented','in_progress','unimplemented','not_applicable'})
LIVE_STATUS = frozenset({'recorded_response','unverified','not_applicable'})
ID = re.compile(r'[a-zA-Z][a-zA-Z0-9_.-]{0,127}\Z')
REQUIRED = {'id','family','kind','upstream_symbol','source_support','source_mapping','cli_status','live_status','source_refs','contract_summary','blocks','next_action','priority'}


def _invalid():
    return RouterError('invalid_native_audit','Packaged native audit metadata is invalid.')


def _text(value, maximum=4096):
    return isinstance(value,str) and bool(value) and len(value)<=maximum and not any(ord(c)<32 and c not in '\n\t' for c in value)


class NativeAudit:
    def __init__(self,data):
        try:
            if not isinstance(data,dict) or type(data.get('schema_version')) is not int or data['schema_version'] != 1:
                raise ValueError
            if not _text(data.get('audited_at'),64):raise ValueError
            date.fromisoformat(data['audited_at'][:10])
            upstream=data['upstream']
            if not isinstance(upstream,dict) or any(not _text(upstream.get(k)) for k in ('package','version','tag_url')):
                raise ValueError
            if upstream['package'] != 'asusrouter' or upstream['version'] != '1.21.3':raise ValueError
            boundary=data['evidence_boundary']
            if not isinstance(boundary,dict) or boundary.get('audit_network_calls') is not False or any(not _text(boundary.get(k)) for k in ('live_evidence_document','live_evidence_meaning','source_support_meaning')):
                raise ValueError
            target=boundary['live_evidence_target']
            if not isinstance(target,dict) or any(not _text(target.get(k),256) for k in ('model','firmware','date')):raise ValueError
            date.fromisoformat(target['date'][:10])
            inventory=data['inventory']
            if not isinstance(inventory,dict):raise ValueError
            for field in ('asus_data','asus_state','dynamic_reads'):
                names=inventory[field]
                if not isinstance(names,list) or any(not _text(n,128) for n in names) or len(names)!=len(set(names)):raise ValueError
            if type(inventory.get('catalog_page_count')) is not int or inventory['catalog_page_count']<0 or not _text(inventory.get('action_denominator')):raise ValueError
            if not isinstance(data.get('definitions'),dict) or not isinstance(data.get('extra_boundaries'),list) or not isinstance(data.get('webui_configuration_gaps'),list):raise ValueError
            entries=data['capabilities']
            if not isinstance(entries,list) or not entries:raise ValueError
            seen=set()
            for entry in entries:
                if not isinstance(entry,dict) or not REQUIRED<=entry.keys():raise ValueError
                if not isinstance(entry['id'],str) or ID.fullmatch(entry['id']) is None or entry['id'] in seen:raise ValueError
                seen.add(entry['id'])
                if entry['kind'] not in KINDS or entry['source_support'] not in SOURCE_SUPPORT or entry['cli_status'] not in CLI_STATUS or entry['live_status'] not in LIVE_STATUS:raise ValueError
                if any(not _text(entry[k]) for k in ('family','upstream_symbol','contract_summary','next_action')):raise ValueError
                if entry['priority'] is not None and (type(entry['priority']) is not int or entry['priority']<0):raise ValueError
                if entry['source_mapping'] is not None and not isinstance(entry['source_mapping'],(str,dict,list)):raise ValueError
                refs=entry['source_refs']
                if not isinstance(refs,list) or not refs:raise ValueError
                for ref in refs:
                    if not isinstance(ref,dict) or not _text(ref.get('path')) or type(ref.get('line_start')) is not int or type(ref.get('line_end')) is not int or not 1<=ref['line_start']<=ref['line_end']:raise ValueError
                blocks=entry['blocks']
                if not isinstance(blocks,list):raise ValueError
                for block in blocks:
                    if not isinstance(block,dict) or not isinstance(block.get('code'),str) or ID.fullmatch(block['code']) is None or not _text(block.get('detail')):raise ValueError
            self._payload=json.dumps(data,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False)
            self.hash=hashlib.sha256(self._payload.encode()).hexdigest()
        except (KeyError,TypeError,ValueError,OverflowError) as exc:
            raise _invalid() from exc

    def manifest(self):
        return json.loads(self._payload)

    def page(self,capability_id=None,*,offset=0,limit=5):
        if type(offset) is not int or offset<0 or type(limit) is not int or not 1<=limit<=20:
            raise RouterError('invalid_arguments','Capability limit must be 1..20 and offset nonnegative.',2)
        metadata=self.manifest()
        entries=sorted(metadata['capabilities'],key=lambda entry:entry['id'])
        if capability_id is not None:
            entries=[entry for entry in entries if entry['id']==capability_id]
            if not entries:raise RouterError('unknown_capability','Unknown native capability ID.')
        selected=entries[offset:offset+limit]
        rows=[{**{key:entry[key] for key in ('id','family','kind','source_support','cli_status','live_status','next_action')},'blocks':[block['code'] for block in entry['blocks']]} for entry in selected]
        all_entries=metadata['capabilities']
        counts={'entries':len(all_entries),'kinds':dict(sorted(Counter(e['kind'] for e in all_entries).items())),'cli_status':dict(sorted(Counter(e['cli_status'] for e in all_entries).items())),'live_status':dict(sorted(Counter(e['live_status'] for e in all_entries).items()))}
        boundary=metadata['evidence_boundary']
        return {'schema_version':1,'source':'offline_native_audit','observed_at':None,'freshness':'not_collected','data':{'audit_hash':self.hash,'upstream_version':metadata['upstream']['version'],'audited_at':metadata['audited_at'],'target':{key:boundary['live_evidence_target'][key] for key in ('model','firmware','date')},'evidence_limits':[boundary['source_support_meaning'],boundary['live_evidence_meaning']],'counts':counts,'capabilities':rows,'pagination':{'offset':offset,'limit':limit,'total':len(entries),'next_offset':offset+len(rows) if offset+len(rows)<len(entries) else None}},'capability_gaps':['Inventory and source support do not establish working feature parity.']}


def load_native_audit(path=None):
    source=files('router_agent').joinpath('data/native_audit.json') if path is None else Path(path)
    try:
        return NativeAudit(json.loads(source.read_text(encoding='utf-8')))
    except (OSError,ValueError,TypeError) as exc:
        raise _invalid() from exc
