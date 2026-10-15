"""Selected DSL hook; applicability is Endpoint.DSL availability (identity.py)."""
import re
from .errors import RouterError
from .health_reads import _auth

DSL_PATH = '/ajax_AdslStatus.asp'
DSL_HOOK = 'nvram_get(dsllog_dataratedown);nvram_get(dsllog_datarateup);'


def normalize_dsl(raw):
    from asusrouter.modules.endpoint.hook import process_dsl
    if not isinstance(raw, dict) or len(raw) > 128:
        raise RouterError('malformed_response', 'Selected DSL rates are malformed.')
    _auth(raw)
    rates = {}
    gaps = ['native_missing_rate_defaults_to_zero', 'rate_is_not_dsl_health', 'source_observation_time_unavailable', 'endpoint_availability_is_not_dsl_hardware_proof']
    for direction, key in [('down', 'dsllog_dataratedown'), ('up', 'dsllog_datarateup')]:
        value = raw.get(key)
        number = unit = None
        if value not in (None, ''):
            if not isinstance(value, str) or len(value) > 64:
                raise RouterError('malformed_response', 'Selected DSL rates are malformed.')
            match = re.fullmatch(r'([0-9]{1,12})(?: ([A-Za-z/]{1,16}))?', value)
            if not match:
                raise RouterError('malformed_response', 'Selected DSL rates are malformed.')
            unit = match[2] if match[2] in {'kbps', 'Mbps', 'Kbps', 'bps', 'Kbit/s', 'Mbit/s'} else None
            number = process_dsl({key: value})['datarate'][direction]
        if number is None:
            gaps.append('rate_missing_or_null')
        if unit is None:
            gaps.append('rate_unit_unknown')
        rates[direction] = {'value': number, 'unit': unit}
    return {'rates': rates, 'gaps': sorted(set(gaps))}


def validate_dsl_probe(text):
    """Availability signal with auth/malformed checks; no hardware inference."""
    import json
    from asusrouter.tools.readers import read_js_variables
    from .health_reads import _text
    _text(text)
    try:
        parsed = json.loads(text)
    except ValueError:
        parsed = read_js_variables(text)
    _auth(parsed)
    if not isinstance(parsed, dict) or not (set(parsed) - {'error_status'}) or len(parsed) > 128:
        raise RouterError('capability_unknown', 'The native DSL availability response was empty or malformed.')
