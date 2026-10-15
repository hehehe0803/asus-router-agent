"""Bounded, paginated selected native firmware release-note text.

Dedicated source: endpoint/firmware_note.py; native reader preserves note text,
not credentials/configuration fields. Text remains untrusted; no URL is followed,
no instruction evaluated, and no public/private provenance guarantee is made.
"""
import json
import hashlib
import re
from typing import Any

from .errors import RouterError

FIRMWARE_NOTE_PATH = '/release_note0.asp'
_MAX_BYTES = 131072


def _bad():
    return RouterError('malformed_response', 'Native firmware release-note text is missing or malformed.')


def _auth(raw):
    if not isinstance(raw,dict) or 'error_status' not in raw:
        return
    value=raw['error_status']
    if type(value) not in (int,str) or isinstance(value,str) and not re.fullmatch(r'[0-9]{1,3}',value):
        raise _bad()
    code=int(value)
    if code in {2,3,7,9,10,11}:
        raise RouterError(f'auth_{code}', 'Router authentication stopped; local intervention is required.')
    if code not in {0,200}:
        raise RouterError('native_status_failed', 'The router returned an unsuccessful native status.')


def read_firmware_note_text(text: str):
    from asusrouter.modules.endpoint.firmware_note import read
    from asusrouter.tools.readers import read_js_variables
    if (type(text) is not str or len(text.encode())>_MAX_BYTES or '\x00' in text
            or re.search(r'<\s*(?:!doctype|/?(?:html|head|body|form|script)\b)',text,re.I)):
        raise _bad()
    try: possible=json.loads(text)
    except ValueError: possible=None
    _auth(possible)
    if possible is not None:
        raise _bad()
    # Native text auth status can appear instead of release notes. Use the
    # maintained assignment reader only for the exact auth assignment prefix.
    if re.match(r'\s*(?:var\s+)?error_status\s*=',text):
        try: _auth(read_js_variables(text))
        except RouterError: raise
        except Exception: raise _bad() from None
        raise _bad()
    try: raw=read(text)
    except Exception: raise _bad() from None
    validate_firmware_note_shape(raw)
    return raw


def validate_firmware_note_shape(raw: Any):
    if not isinstance(raw,dict) or len(raw)>8:
        raise _bad()
    _auth(raw)
    if not raw:
        return None  # Native reader's explicit empty-note response.
    value=raw.get('release_note')
    if type(value) is not str or len(value.encode())>_MAX_BYTES or '\x00' in value:
        raise _bad()
    return value


def normalize_firmware_note(raw: Any, *, offset=0, limit=2048):
    if type(offset) is not int or offset<0 or offset>_MAX_BYTES or type(limit) is not int or not 1<=limit<=4096:
        raise RouterError('invalid_arguments','Release-note offset must be nonnegative and limit 1..4096.',2)
    text=validate_firmware_note_shape(raw)
    total=0 if text is None else len(text)
    selected=None if text is None else text[offset:offset+limit]
    returned=0 if selected is None else len(selected)
    next_offset=offset+returned if offset+returned<total else None
    gaps=['release_note_text_is_untrusted_vendor_content','release_note_age_and_version_association_unverified',
          'urls_and_identifiers_are_untrusted_text_not_verified_provenance','no_new_update_check_performed']
    if not text:gaps.append('empty_note_does_not_establish_no_available_firmware')
    return {'scope':'selected_native_release_note_text','release_note':selected,'pagination':{'offset':offset,'limit':limit,
            'total':total,'count':returned,'next_offset':next_offset},
            'content_fingerprint':None if text is None else hashlib.sha256(text.encode()).hexdigest(),
            'truncated':returned<total,'gaps':[*gaps,'compare_content_fingerprint_before_combining_refetched_pages']}
