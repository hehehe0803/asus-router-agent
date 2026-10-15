"""Selected counts/load from pristine asusrouter 1.21.3 SYSINFO.

Public contract: async_api_load(Endpoint.SYSINFO, request='') sends one POST
/ajax_sysinfo.asp with no body/query. Guard the exact origin/path/body, forbid
redirects, and validate this text before upstream parsing/retry. No broad data
collection or LED restoration. Stock firmware applicability remains unverified.
"""
from contextvars import ContextVar
import json
import logging
import math
import re
from typing import Any
from .errors import RouterError

SYSINFO_PATH = '/ajax_sysinfo.asp'
_MAX_BYTES = 65536
_MAX_FIELDS = 128
_SUPPRESS_READER = ContextVar('sysinfo_suppress_reader_log', default=False)
_INTEGER = re.compile(r'[0-9]{1,10}\Z')
_NUMBER = re.compile(r'[0-9]{1,10}(?:\.[0-9]{1,10})?\Z')
_UNKNOWN = {'', '-1', 'unknown', 'N/A', 'n/a'}


class _ReaderFilter(logging.Filter):
    def filter(self, record):
        return not _SUPPRESS_READER.get()


def _bad():
    return RouterError('malformed_response', 'Native SYSINFO selected counts/load are missing or malformed.')


def _auth(raw):
    if not isinstance(raw, dict) or 'error_status' not in raw:
        return
    code = raw['error_status']
    if type(code) not in (int, str) or isinstance(code,str) and not re.fullmatch(r'[0-9]{1,3}',code):
        raise _bad()
    code = int(code)
    if code in {2,3,7,9,10,11}:
        raise RouterError(f'auth_{code}', 'Router authentication stopped; local intervention is required.')
    if code not in {0,200}:
        raise RouterError('native_status_failed', 'The router returned an unsuccessful native status.')


def read_sysinfo_text(text: str) -> dict[str, Any]:
    """Read exact native assignment text without a custom firmware parser."""
    from asusrouter.modules.endpoint.sysinfo import read
    if (not isinstance(text,str) or not text.strip() or len(text.encode('utf-8'))>_MAX_BYTES
            or re.search(r'<\s*(?:!doctype|/?(?:html|head|body|form|script)\b)',text,re.I)):
        raise _bad()
    # Authentication failures can be JSON even though SYSINFO uses assignments.
    try:
        possible_error=json.loads(text)
    except (ValueError,TypeError):
        possible_error=None
    _auth(possible_error)
    logger=logging.getLogger('asusrouter.tools.readers')
    if not any(isinstance(f,_ReaderFilter) for f in logger.filters):
        logger.addFilter(_ReaderFilter())
    token=_SUPPRESS_READER.set(True)
    try:
        raw=read(text)
    except Exception:
        raise _bad() from None
    finally:
        _SUPPRESS_READER.reset(token)
    _auth(raw)
    validate_sysinfo_shape(raw)
    return raw


def _selected_number(value, *, load=False):
    if value is None or isinstance(value,str) and value in _UNKNOWN:
        return None
    if type(value) not in (int,float,str) or type(value) is float and not load:
        raise _bad()
    if isinstance(value,str) and not (_NUMBER if load else _INTEGER).fullmatch(value):
        raise _bad()
    number=float(value) if load else int(value)
    if not math.isfinite(number) or not 0<=number<=(1_000_000 if load else 2**31-1):
        raise _bad()
    return number


def validate_sysinfo_shape(raw: Any) -> dict[str,list]:
    if not isinstance(raw,dict) or len(raw)>_MAX_FIELDS:
        raise _bad()
    _auth(raw)
    selected={}
    for key,size,load in [('conn_stats_arr',2,False),('cpu_stats_arr',3,True),*[(f'wlc_{i}_arr',3,False) for i in range(4)]]:
        if key not in raw:
            continue
        value=raw[key]
        if value is None or value == []:
            selected[key]=[None]*size
            continue
        if not isinstance(value,list) or len(value)!=size:
            raise _bad()
        selected[key]=[_selected_number(v,load=load) for v in value]
    if not selected:
        raise _bad()
    return selected


def normalize_sysinfo(raw: Any) -> dict[str,Any]:
    """Pass only bounded arrays into unchanged native processing; omit detail."""
    from asusrouter.modules.data import AsusData
    from asusrouter.modules.endpoint.sysinfo import process
    from asusrouter.modules.wlan import WLAN_TYPE
    selected=validate_sysinfo_shape(raw)
    radio_indices=[i for i in range(4) if f'wlc_{i}_arr' in selected]
    # Upstream walks contiguous radio indices; missing earlier slots are null,
    # and only slots actually returned by the source are exposed afterward.
    if radio_indices:
        for i in range(max(radio_indices)+1):
            selected.setdefault(f'wlc_{i}_arr',[None,None,None])
    try:
        native=process(selected)[AsusData.SYSINFO]
    except Exception:
        raise _bad() from None
    connections=native['connections']
    load=native['load_avg']
    output={'scope':'selected_counts_and_load_only','connections':{'total':connections.get('total'),'active':connections.get('active')},'load_avg':{'one_minute':load.get(1),'five_minutes':load.get(5),'fifteen_minutes':load.get(15)},'wlan':[],'gaps':['stock_firmware_applicability_unverified','counts_and_load_are_not_network_health','source_observation_time_unavailable']}
    for index in radio_indices:
        counts=native['wlan'][WLAN_TYPE[index]]
        output['wlan'].append({'radio_index':index,**counts})
    values=[*output['connections'].values(),*output['load_avg'].values(),*[row[key] for row in output['wlan'] for key in ('client_associated','client_authorized','client_authenticated')]]
    if not radio_indices or any(value is None for value in values):
        output['gaps'].append('selected_values_missing_or_unknown')
    return output
