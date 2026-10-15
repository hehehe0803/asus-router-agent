import hashlib
import json
import os
from pathlib import Path

import pytest

from router_agent.backup_custody import inspect_custody, load_private_manifest, MAX_FILE


@pytest.fixture
def artifact(tmp_path):
    tmp_path.chmod(0o700)
    path=tmp_path/'PRIVATE-SENTINEL.cfg';path.write_bytes(b'PRIVATE-SENTINEL');path.chmod(0o600)
    return path


def manifest(path, **kwargs):return {'original':{'path':str(path),**kwargs}}


def test_stable_digest_private(artifact):
    digest=hashlib.sha256(artifact.read_bytes()).hexdigest()
    report=inspect_custody(manifest(artifact,expected_sha256=digest))
    assert report['outcome']=='passed'
    assert report['roles'][0]['expected_digest_matches'] is True
    assert report['production_admission_verified'] is False
    assert 'PRIVATE-SENTINEL' not in json.dumps(report) and digest not in json.dumps(report)


def test_unknown_and_mismatched_digest(artifact):
    assert inspect_custody(manifest(artifact))['roles'][0]['expected_digest_matches'] is None
    assert inspect_custody(manifest(artifact,expected_sha256='0'*64))['outcome']=='failed'


def test_pair_equality(artifact):
    second=artifact.parent/'other';second.write_bytes(artifact.read_bytes());second.chmod(0o600)
    assert inspect_custody({'original':{'path':str(artifact)},'roundtrip':{'path':str(second)}})['original_roundtrip_equal'] is True


@pytest.mark.parametrize('fault',['missing','leaf_symlink','ancestor_symlink','fifo','hardlink','directory_mode','file_mode','empty','oversize','nul'])
def test_unsafe(artifact,fault):
    path=artifact
    if fault=='missing':path=artifact.parent/'missing'
    if fault=='leaf_symlink':
        path=artifact.parent/'symlink';path.symlink_to(artifact)
    if fault=='ancestor_symlink':
        link=artifact.parent/'ancestor';link.symlink_to(artifact.parent,target_is_directory=True);path=link/artifact.name
    if fault=='fifo':
        artifact.unlink();os.mkfifo(artifact,0o600)
    if fault=='hardlink':os.link(artifact,artifact.parent/'hard')
    if fault=='directory_mode':artifact.parent.chmod(0o755)
    if fault=='file_mode':artifact.chmod(0o640)
    if fault=='empty':artifact.write_bytes(b'')
    if fault=='oversize':
        with artifact.open('wb') as f:f.truncate(MAX_FILE+1)
    if fault=='nul':path=str(artifact)+'\x00'
    result=inspect_custody(manifest(path))
    assert result['outcome']=='failed'
    assert 'PRIVATE-SENTINEL' not in json.dumps(result)


@pytest.mark.parametrize('fault',['mutate','truncate','replace','reader_failure','clock_nan','clock_back','deadline'])
def test_read_races(artifact,fault):
    invoked=[False];ticks=[0]
    def read(fd,n):
        chunk=os.read(fd,n)
        if not invoked[0]:
            invoked[0]=True
            if fault=='mutate':artifact.write_bytes(b'X'*len(chunk))
            if fault=='truncate':artifact.write_bytes(b'X')
            if fault=='replace':
                replacement=artifact.parent/'replacement';replacement.write_bytes(b'x');replacement.chmod(0o600);replacement.replace(artifact)
            if fault=='reader_failure':raise RuntimeError('PRIVATE-SENTINEL')
        return chunk
    def clock():
        ticks[0]+=1
        if ticks[0]>1:
            if fault=='clock_nan':return float('nan')
            if fault=='clock_back':return -1
            if fault=='deadline':return 31
        return 0
    result=inspect_custody(manifest(artifact),read_chunk=read,clock=clock)
    assert result['outcome']=='failed'
    assert 'PRIVATE-SENTINEL' not in json.dumps(result)


def test_wrong_owner(artifact,monkeypatch):
    import router_agent.backup_custody as module
    original=os.getuid()
    monkeypatch.setattr(module.os,'getuid',lambda:original+1)
    assert inspect_custody(manifest(artifact))['outcome']=='failed'


@pytest.mark.parametrize('value',[{},[],{'secret':{}},{'original':{}},{'original':{'path':'/x','expected_sha256':'PRIVATE-SENTINEL'}}, {'original':{'path':'/x','extra':'PRIVATE-SENTINEL'}}])
def test_invalid_manifest(value):
    result=inspect_custody(value)
    assert result['outcome']=='failed' and 'PRIVATE-SENTINEL' not in json.dumps(result)


def test_private_manifest(artifact):
    path=artifact.parent/'manifest';path.write_text(json.dumps(manifest(artifact)));path.chmod(0o600)
    assert load_private_manifest(path)==manifest(artifact)
    path.chmod(0o644)
    with pytest.raises(ValueError):load_private_manifest(path)
