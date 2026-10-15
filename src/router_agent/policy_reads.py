"""Selected native policy settings, never effective enforcement/exposure claims.

Source: pristine asusrouter 1.21.3 parental_control.py + endpoint/hook.py.
Native rule processors are unchanged. Names are not requested for parental
rules; aligned empty name placeholders exist only for native parser plumbing.
"""
import hashlib
import hmac
import ipaddress
import re
from typing import Any
from .errors import RouterError

PARENTAL_KEYS = ('MULTIFILTER_ALL','MULTIFILTER_BLOCK_ALL','MULTIFILTER_MAC','MULTIFILTER_MACFILTER_DAYTIME_V2','MULTIFILTER_ENABLE')
FORWARDING_KEYS = ('vts_enable_x','vts_rulelist')
PARENTAL_HOOK = ''.join(f'nvram_get({key});' for key in PARENTAL_KEYS)
FORWARDING_HOOK = ''.join(f'nvram_get({key});' for key in FORWARDING_KEYS)
_MAX_RULES = 64
_MAX_LIST = 32768
_MAC = re.compile(r'(?:[A-Fa-f0-9]{2}:){5}[A-Fa-f0-9]{2}\Z')
_PORT = re.compile(r'[0-9]{1,5}(?:(?:-|:)[0-9]{1,5})?\Z')


def _bad():
    return RouterError('malformed_response','Native selected policy settings or rules are malformed.')


def _key(key):
    if not isinstance(key,bytes) or len(key)<32:
        raise RouterError('identity_key_required','A private identity key of at least 32 bytes is required.')


def _alias(key,domain,value,prefix):
    return prefix+hmac.new(key,domain+value.encode(),hashlib.sha256).hexdigest()[:16]


def _flag(value):
    if value is None or value in ('','-999',-999):return None
    if type(value) not in (str,int) or value not in (0,1,'0','1'):raise _bad()
    return bool(int(value))


def _string(value,maximum=_MAX_LIST):
    if not isinstance(value,str) or len(value)>maximum or any(ord(c)<32 for c in value):raise _bad()
    return value


def normalize_parental(raw:Any,fingerprint_key:bytes):
    from asusrouter.modules.endpoint.hook import process_parental_control
    _key(fingerprint_key)
    if not isinstance(raw,dict) or not any(key in raw for key in PARENTAL_KEYS):raise _bad()
    enabled,block_all=_flag(raw.get('MULTIFILTER_ALL')),_flag(raw.get('MULTIFILTER_BLOCK_ALL'))
    native={'MULTIFILTER_ALL':-999 if enabled is None else int(enabled),'MULTIFILTER_BLOCK_ALL':-999 if block_all is None else int(block_all)}
    list_keys=('MULTIFILTER_MAC','MULTIFILTER_MACFILTER_DAYTIME_V2','MULTIFILTER_ENABLE')
    present=[key in raw for key in list_keys]
    rules=None
    gaps=['settings_do_not_prove_parental_enforcement','schedule_fingerprint_is_not_schedule_validation','source_observation_time_unavailable']
    if not any(present):
        gaps.append('rule_inventory_not_returned')
    elif not all(present):
        raise _bad()
    else:
        lists=[_string(raw[key]) for key in list_keys]
        if lists[0]=='' and lists[2]=='':
            # Native read_pc_rules returns no rules when MAC == TYPE; an
            # unused stored timemap is not a rule and is never disclosed.
            rules=[]
            if lists[1]:gaps.append('unused_schedule_data_present')
        else:
            split=[value.split('&#62') for value in lists]
            lengths={len(value) for value in split}
            if len(lengths)!=1 or len(split[0])>_MAX_RULES:raise _bad()
            macs,timemaps,types=split
            if len({mac.upper() for mac in macs})!=len(macs) or any(not _MAC.fullmatch(mac) for mac in macs):raise _bad()
            if any(len(value)>512 for value in timemaps) or any(value not in ('0','1','2','-999','') for value in types):raise _bad()
            native.update(zip(list_keys,lists))
            # These names are placeholders, not observed router configuration.
            native['MULTIFILTER_DEVICENAME']='&#62'.join('' for _ in macs)
            try:
                parsed=process_parental_control(native)['rules']
            except Exception:raise _bad() from None
            if len(parsed)!=len(macs):raise _bad()
            rules=[]
            for mac in macs:
                rule=parsed[mac]
                kind={0:'disabled',1:'time',2:'block',-999:'unknown'}.get(int(rule.type))
                if kind is None:raise _bad()
                schedule=rule.timemap or ''
                rules.append({'alias':_alias(fingerprint_key,b'client:',mac.upper(),'client-'),'rule_type':kind,'schedule_present':bool(schedule),'schedule_fingerprint':_alias(fingerprint_key,b'parental-schedule:',schedule,'schedule-') if schedule else None})
            rules.sort(key=lambda rule:rule['alias'])
    if enabled is None or block_all is None:gaps.append('selected_flags_missing_or_unknown')
    if rules and any(rule['rule_type']=='unknown' for rule in rules):gaps.append('rule_type_unknown')
    return {'scope':'selected_parental_settings_only','enabled':enabled,'block_all':block_all,'rules':rules,'rule_count':None if rules is None else len(rules),'gaps':gaps}


def _port_count(value):
    if not value:return None
    if len(value)>256:raise _bad()
    parts=value.split(',')
    if len(parts)>16:return None
    intervals=[]
    for part in parts:
        if not _PORT.fullmatch(part):return None
        numbers=re.split('[-:]',part)
        start,end=int(numbers[0]),int(numbers[-1])
        if not 1<=start<=end<=65535:return None
        intervals.append((start,end))
    merged=[]
    for start,end in sorted(intervals):
        if merged and start<=merged[-1][1]+1:merged[-1]=(merged[-1][0],max(end,merged[-1][1]))
        else:merged.append((start,end))
    return sum(end-start+1 for start,end in merged)


def normalize_forwarding(raw:Any,fingerprint_key:bytes):
    from asusrouter.modules.endpoint.hook import process_port_forwarding
    _key(fingerprint_key)
    if not isinstance(raw,dict) or not any(key in raw for key in FORWARDING_KEYS):raise _bad()
    enabled=_flag(raw.get('vts_enable_x'))
    native={'vts_enable_x':-999 if enabled is None else int(enabled)}
    rules=None
    gaps=['forwarding_setting_does_not_establish_exposure_absence','other_exposure_paths_not_collected','source_observation_time_unavailable']
    if 'vts_rulelist' not in raw:
        gaps.append('rule_inventory_not_returned')
    else:
        text=_string(raw['vts_rulelist'])
        wire_rules=[rule for rule in text.split('&#60') if rule]
        if len(wire_rules)>_MAX_RULES:raise _bad()
        for rule in wire_rules:
            fields=rule.split('&#62')
            if len(fields)!=6 or any(len(value)>512 for value in fields):raise _bad()
        native['vts_rulelist']=text
        try:parsed=process_port_forwarding(native).get('rules',[])
        except Exception:raise _bad() from None
        if len(parsed)!=len(wire_rules):raise _bad()
        rules=[]
        for rule in parsed:
            try:address=str(ipaddress.ip_address(rule.ip_address))
            except (ValueError,TypeError):raise _bad() from None
            protocol={'TCP':'tcp','UDP':'udp','BOTH':'both','OTHER':'other'}.get(rule.protocol,'unknown')
            external=_port_count(rule.port_external) if protocol in {'tcp','udp','both'} else None
            internal=_port_count(rule.port) if protocol in {'tcp','udp','both'} else None
            if protocol=='unknown' or external is None:gaps.append('port_or_protocol_semantics_unknown')
            rules.append({'target_alias':_alias(fingerprint_key,b'forwarding-address:',address,'target-'),'protocol':protocol,'external_port_count':external,'internal_port_count':internal,'configured_source_filter_present':bool(rule.ip_external)})
        # Stable canonical ordering; aliases do not establish a client association.
        rules.sort(key=lambda rule:(rule['target_alias'],rule['protocol'],rule['external_port_count'] or -1,rule['internal_port_count'] or -1,rule['configured_source_filter_present']))
    if enabled is None:gaps.append('selected_flags_missing_or_unknown')
    return {'scope':'selected_forwarding_settings_only','enabled':enabled,'rules':rules,'rule_count':None if rules is None else len(rules),'gaps':sorted(set(gaps))}
