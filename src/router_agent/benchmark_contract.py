"""Explicit dated fixture replay, never a current CLI response parity claim."""
from contextlib import contextmanager
from contextvars import ContextVar
import hashlib
import json
from pathlib import Path

ARCHIVAL = ContextVar('benchmark_pre_fetched_at_contract', default=False)
FETCHED_AT = '2026-10-13T00:00:00+00:00'


def fixture_contract(value):
    if not ARCHIVAL.get():
        return value
    if isinstance(value, dict):
        return {key: fixture_contract(item) for key, item in value.items() if key != 'fetched_at'}
    if isinstance(value, list):
        return [fixture_contract(item) for item in value]
    return value


@contextmanager
def archive_contract(enabled):
    token = ARCHIVAL.set(enabled)
    try:
        yield
    finally:
        ARCHIVAL.reset(token)


def validate_registered(raw):
    manifest = json.loads((Path(__file__).resolve().parents[2] / 'benchmarks/archive-contract.json').read_text())
    if hashlib.sha256(raw).hexdigest() not in {record['corpus_sha256'] for record in manifest['archives']}:
        raise ValueError('Archive differs from frozen registered corpus')


def archival_notice():
    return 'Archival pre-fetched_at fixture/envelope contract and archived help; all dated facts are checked. No current CLI response parity or current help-cost claim.'


def validate_historical_transcript(raw):
    """Admit only pinned, superseded transcripts; never infer present CLI parity."""
    manifest = json.loads((Path(__file__).resolve().parents[2] / 'benchmarks/history-2026-10-22.json').read_text())
    if hashlib.sha256(raw).hexdigest() not in {record['corpus_sha256'] for record in manifest['archives']}:
        raise ValueError('Archive differs from frozen registered corpus')
