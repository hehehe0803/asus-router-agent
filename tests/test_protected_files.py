"""Synthetic local files only; no router, private-state or Secret Service access."""
from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import stat

import pytest

from router_agent.errors import RouterError
import router_agent.protected_files as module
from router_agent.protected_files import MAX_FILE, ProtectedFileStore


@pytest.fixture
def files(tmp_path):
    tmp_path.chmod(0o700)
    source_dir = tmp_path / 'source'
    directory = tmp_path / 'store'
    destination_dir = tmp_path / 'destination'
    for path in (source_dir, directory, destination_dir):
        path.mkdir(mode=0o700)
    source = source_dir / 'PRIVATE-SENTINEL.cfg'
    source.write_bytes(b'PRIVATE-SENTINEL\r\n\x00\xff')
    source.chmod(0o600)
    store = ProtectedFileStore(directory, binding_key=b'k' * 32)
    return store, source, directory, destination_dir


def ingest(files):
    store, source, directory, destination_dir = files
    return store.ingest(source, kind='opaque_configuration')


def assert_sanitized(exc):
    assert 'PRIVATE-SENTINEL' not in str(exc.value)
    assert '/tmp/' not in str(exc.value)


def test_exact_bytes_opaque_refs_public_description_and_delete(files):
    store, source, directory, destination_dir = files
    original = source.read_bytes()
    first, second = ingest(files), ingest(files)
    assert first.ref != second.ref and len(first.ref) == 32
    assert first.original_sha256 == hashlib.sha256(original).hexdigest()
    assert first.original_bytes == len(original)
    assert store.read_bound(first) == original
    public = json.dumps(store.describe(first.ref))
    for secret in ('PRIVATE-SENTINEL', str(source), first.original_sha256, first.binding):
        assert secret not in public and secret not in repr(first) and secret not in repr(store)
    assert store.describe(first.ref) == {'ref': first.ref, 'kind': first.kind, 'available': True}
    assert stat.S_IMODE((directory / (first.ref + '.artifact')).stat().st_mode) == 0o600
    unrelated = directory / 'notes'
    unrelated.write_bytes(b'keep')
    store.delete(first.ref)
    store.delete(first.ref)
    assert store.describe(first.ref)['available'] is False
    assert store.read_bound(second) == original
    assert unrelated.read_bytes() == b'keep' and source.read_bytes() == original


@pytest.mark.parametrize('fault', ['empty', 'oversize', 'symlink', 'hardlink', 'fifo',
                                  'directory', 'file_mode', 'parent_mode', 'ancestor_symlink'])
def test_reject_source_objects_and_preserve_source(files, fault):
    store, source, directory, destination_dir = files
    candidate = source
    if fault == 'empty': source.write_bytes(b'')
    elif fault == 'oversize':
        with source.open('wb') as stream: stream.truncate(MAX_FILE + 1)
    elif fault == 'symlink':
        candidate = source.parent / 'link'
        candidate.symlink_to(source)
    elif fault == 'hardlink': os.link(source, source.parent / 'hard')
    elif fault == 'fifo':
        candidate = source.parent / 'fifo'
        os.mkfifo(candidate, 0o600)
    elif fault == 'directory': candidate = source.parent
    elif fault == 'file_mode': source.chmod(0o640)
    elif fault == 'parent_mode': source.parent.chmod(0o755)
    elif fault == 'ancestor_symlink':
        link = source.parent.parent / 'link'
        link.symlink_to(source.parent, target_is_directory=True)
        candidate = link / source.name
    with pytest.raises(RouterError) as exc:
        store.ingest(candidate, kind='opaque_configuration')
    assert_sanitized(exc)
    assert list(directory.iterdir()) == []
    assert source.exists()


@pytest.mark.parametrize('size', [1, MAX_FILE])
def test_size_boundary(files, size):
    store, source, directory, destination_dir = files
    source.write_bytes(b'x' * size)
    bound = ingest(files)
    assert bound.original_bytes == size and store.read_bound(bound) == b'x' * size


@pytest.mark.parametrize('fault', ['mutate', 'truncate', 'replace', 'ancestor_replace', 'read_error'])
def test_read_races_do_not_publish(files, monkeypatch, fault):
    store, source, directory, destination_dir = files
    read, called = os.read, [False]
    def racing_read(fd, count):
        chunk = read(fd, count)
        if not called[0]:
            called[0] = True
            if fault == 'mutate': source.write_bytes(b'x' * source.stat().st_size)
            elif fault == 'truncate': source.write_bytes(b'x')
            elif fault == 'replace':
                replacement = source.parent / 'replacement'
                replacement.write_bytes(b'x' * len(chunk)); replacement.chmod(0o600)
                replacement.replace(source)
            elif fault == 'ancestor_replace':
                source.parent.rename(source.parent.with_name('moved'))
                source.parent.mkdir(mode=0o700)
            else: raise RuntimeError('PRIVATE-SENTINEL')
        return chunk
    monkeypatch.setattr(module.os, 'read', racing_read)
    with pytest.raises(RouterError) as exc: ingest(files)
    assert_sanitized(exc)
    assert list(directory.iterdir()) == []


@pytest.mark.parametrize('fault', ['body', 'metadata', 'replace', 'hardlink', 'symlink', 'mode'])
def test_read_bound_rejects_tamper(files, fault):
    store, source, directory, destination_dir = files
    bound = ingest(files)
    path = directory / (bound.ref + '.artifact')
    if fault == 'body':
        record = path.read_bytes(); path.write_bytes(record[:-1] + bytes([record[-1] ^ 1]))
    elif fault == 'metadata':
        header, payload = path.read_bytes().split(b'\n', 1)
        metadata = json.loads(header); metadata['kind'] = 'changed'
        path.write_bytes(module._canonical(metadata) + b'\n' + payload)
    elif fault == 'replace':
        other = directory / 'replacement'
        other.write_bytes(b'x' * path.stat().st_size); other.chmod(0o600); other.replace(path)
    elif fault == 'hardlink': os.link(path, directory / 'hard')
    elif fault == 'symlink': path.unlink(); path.symlink_to(source)
    else: path.chmod(0o640)
    with pytest.raises(RouterError) as exc: store.read_bound(bound)
    assert_sanitized(exc)
    assert source.read_bytes().startswith(b'PRIVATE-SENTINEL')


@pytest.mark.parametrize('field,value', [('ref', '../escape'), ('binding', 'a' * 64),
                                        ('original_sha256', 'a' * 64),
                                        ('original_bytes', True), ('kind', 'vpn')])
def test_wrong_binding_fields(files, field, value):
    bound = ingest(files)
    with pytest.raises(RouterError): files[0].read_bound(replace(bound, **{field: value}))


def test_wrong_key_and_cross_reference(files):
    store, source, directory, destination_dir = files
    first, second = ingest(files), ingest(files)
    other = ProtectedFileStore(directory, binding_key=b'z' * 32)
    with pytest.raises(RouterError): other.read_bound(first)
    with pytest.raises(RouterError): store.read_bound(replace(first, ref=second.ref))


def test_export_exact_no_overwrite_and_source_preserved(files):
    store, source, directory, destination_dir = files
    bound, original = ingest(files), source.read_bytes()
    destination = destination_dir / 'saved.cfg'
    assert store.export_bound(bound, destination) == {'ref': bound.ref, 'exported': True}
    assert destination.read_bytes() == original
    assert stat.S_IMODE(destination.stat().st_mode) == 0o600
    destination.write_bytes(b'keep')
    with pytest.raises(RouterError): store.export_bound(bound, destination)
    assert destination.read_bytes() == b'keep' and source.read_bytes() == original


@pytest.mark.parametrize('fault', ['git_directory', 'git_file', 'bare_git', 'symlink', 'hardlink', 'fifo',
                                  'parent_mode', 'ancestor_symlink', 'relative', 'dotdot'])
def test_export_unsafe_destination(files, fault):
    store, source, directory, destination_dir = files
    bound = ingest(files)
    destination = destination_dir / 'saved.cfg'
    if fault == 'git_directory': (destination_dir / '.git').mkdir()
    elif fault == 'git_file': (destination_dir / '.git').write_text('gitdir: elsewhere')
    elif fault == 'bare_git':
        (destination_dir / 'HEAD').write_text('ref: refs/heads/main')
        (destination_dir / 'objects').mkdir(); (destination_dir / 'refs').mkdir()
    elif fault == 'symlink': destination.symlink_to(source)
    elif fault == 'hardlink': os.link(source, destination)
    elif fault == 'fifo': os.mkfifo(destination, 0o600)
    elif fault == 'parent_mode': destination_dir.chmod(0o755)
    elif fault == 'ancestor_symlink':
        link = destination_dir.parent / 'link'
        link.symlink_to(destination_dir, target_is_directory=True); destination = link / 'saved.cfg'
    elif fault == 'relative': destination = Path('saved.cfg')
    else: destination = destination_dir / '..' / 'saved.cfg'
    with pytest.raises(RouterError) as exc: store.export_bound(bound, destination)
    assert_sanitized(exc)
    assert source.read_bytes().startswith(b'PRIVATE-SENTINEL')


@pytest.mark.parametrize('stage', ['write', 'fsync', 'readback'])
def test_failed_export_cleans_only_created_file(files, monkeypatch, stage):
    store, source, directory, destination_dir = files
    bound = ingest(files)
    destination = destination_dir / 'saved.cfg'
    unrelated = destination_dir / 'keep'; unrelated.write_bytes(b'keep')
    if stage == 'write':
        def fail(*args): raise OSError('PRIVATE-SENTINEL')
        monkeypatch.setattr(module.os, 'write', fail)
    elif stage == 'fsync':
        def fail(*args): raise OSError('PRIVATE-SENTINEL')
        monkeypatch.setattr(module.os, 'fsync', fail)
    else:
        read = os.read
        def fail(fd, count):
            if destination.exists(): return b'X' * count
            return read(fd, count)
        monkeypatch.setattr(module.os, 'read', fail)
    with pytest.raises(RouterError) as exc: store.export_bound(bound, destination)
    assert_sanitized(exc)
    assert not destination.exists()
    assert source.read_bytes().startswith(b'PRIVATE-SENTINEL')
    assert unrelated.read_bytes() == b'keep'


@pytest.mark.parametrize('operation', ['ingest', 'export'])
def test_same_length_write_corruption_cannot_report_success(files, monkeypatch, operation):
    store, source, directory, destination_dir = files
    bound = ingest(files)
    write = os.write
    def corrupt(fd, data):
        payload = bytes(data)
        return write(fd, bytes([payload[0] ^ 1]) + payload[1:])
    monkeypatch.setattr(module.os, 'write', corrupt)
    with pytest.raises(RouterError):
        if operation == 'ingest': ingest(files)
        else: store.export_bound(bound, destination_dir / 'saved.cfg')
    assert len(list(directory.iterdir())) == 1
    assert not list(destination_dir.iterdir())
    assert source.read_bytes().startswith(b'PRIVATE-SENTINEL')


@pytest.mark.parametrize('fault', ['mode', 'hardlink'])
def test_created_inode_authority_rechecked_after_write(files, monkeypatch, fault):
    store, source, directory, destination_dir = files
    bound = ingest(files)
    destination = destination_dir / 'saved.cfg'
    write, changed = os.write, [False]
    def alter(fd, data):
        count = write(fd, data)
        if not changed[0]:
            changed[0] = True
            if fault == 'mode': os.fchmod(fd, 0o640)
            else: os.link(destination, destination_dir / 'other-link')
        return count
    monkeypatch.setattr(module.os, 'write', alter)
    with pytest.raises(RouterError): store.export_bound(bound, destination)
    assert not destination.exists()
    # Another same-user process can retain a link it created; no isolation claim.
    assert source.read_bytes().startswith(b'PRIVATE-SENTINEL')


def test_delete_ancestor_replacement_does_not_unlink_replacement(files, monkeypatch):
    store, source, directory, destination_dir = files
    bound = ingest(files)
    moved = directory.with_name('moved')
    read, called = os.read, [False]
    def race(fd, count):
        chunk = read(fd, count)
        if not called[0]:
            called[0] = True
            directory.rename(moved); directory.mkdir(mode=0o700)
            replacement = directory / (bound.ref + '.artifact')
            replacement.write_bytes(b'keep'); replacement.chmod(0o600)
        return chunk
    monkeypatch.setattr(module.os, 'read', race)
    with pytest.raises(RouterError): store.delete(bound.ref)
    assert (directory / (bound.ref + '.artifact')).read_bytes() == b'keep'
    assert (moved / (bound.ref + '.artifact')).exists()


@pytest.mark.parametrize('fault', ['store', 'export'])
def test_ancestor_substitution_during_write_cleans_pinned_inode(files, monkeypatch, fault):
    store, source, directory, destination_dir = files
    bound = ingest(files)
    parent = directory if fault == 'store' else destination_dir
    moved = parent.with_name(parent.name + '-moved')
    write, called = os.write, [False]
    def racing_write(fd, data):
        count = write(fd, data)
        if not called[0]:
            called[0] = True
            parent.rename(moved); parent.mkdir(mode=0o700)
            (parent / 'unrelated').write_bytes(b'keep')
        return count
    monkeypatch.setattr(module.os, 'write', racing_write)
    with pytest.raises(RouterError):
        if fault == 'store': ingest(files)
        else: store.export_bound(bound, destination_dir / 'saved.cfg')
    assert (parent / 'unrelated').read_bytes() == b'keep'
    assert len(list(moved.iterdir())) == (1 if fault == 'store' else 0)
    assert source.read_bytes().startswith(b'PRIVATE-SENTINEL')


@pytest.mark.parametrize('fault', ['back', 'nan', 'deadline', 'exception'])
def test_clock_faults_sanitized_and_source_preserved(files, fault):
    store, source, directory, destination_dir = files
    ticks = [0]
    def clock():
        ticks[0] += 1
        if ticks[0] > 1:
            if fault == 'back': return -1
            if fault == 'nan': return float('nan')
            if fault == 'deadline': return 30
            raise RouterError('private', 'PRIVATE-SENTINEL')
        return 0
    store._clock = clock
    with pytest.raises(RouterError) as exc: ingest(files)
    assert_sanitized(exc)
    assert not list(directory.iterdir()) and source.exists()


@pytest.mark.parametrize('value', ['', '../escape', 'a' * 31, 'A' * 32, None, 123])
def test_invalid_reference_never_mutates(files, value):
    for action in (files[0].describe, files[0].delete):
        with pytest.raises(RouterError): action(value)
    assert not list(files[2].iterdir())


def test_unknown_kind_no_transformations_and_git_store_rejected(files):
    store, source, directory, destination_dir = files
    with pytest.raises(RouterError): store.ingest(source, kind='wireguard')
    with pytest.raises(RouterError): store.ingest(source, kind='opaque_configuration', transform='normalize')
    (directory / '.git').mkdir()
    with pytest.raises(RouterError): ProtectedFileStore(directory, binding_key=b'k' * 32)
    with pytest.raises(RouterError): ingest(files)


def test_byte_io_errors_never_expose_exception_text(files, monkeypatch):
    def fail(*args): raise OSError('PRIVATE-SENTINEL')
    monkeypatch.setattr(module.os, 'read', fail)
    with pytest.raises(RouterError) as exc: ingest(files)
    assert_sanitized(exc)
