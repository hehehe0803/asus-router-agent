"""Private local snapshots; this module never stores unrestricted router payloads."""
from contextlib import contextmanager
from datetime import datetime, timezone, timedelta
import fcntl
import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
import stat
import tempfile
import uuid
from .errors import RouterError


def default_state_dir():
    return Path.home() / ".local/state/asus-router-agent"


def private_dir(path):
    path = Path(path).absolute()
    # Refuse symlinks in existing ancestors, including dangling links.
    for parent in [*reversed(path.parents), path]:
        if parent.is_symlink():
            raise RouterError("unsafe_path", "State paths must not contain symlinks.")
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = path.stat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise RouterError("unsafe_path", "State directory must be owned by this user with mode 0700.")
    return path


def private_read(path):
    path = Path(path)
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError as exc:
        raise RouterError("state_unavailable", "Private state file is unavailable.") from exc
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077 or info.st_nlink != 1:
            raise RouterError("unsafe_path", "Private state file must be owner-only and have one link.")
        return stream.read()


def atomic_write(path, payload):
    path = Path(path)
    private_dir(path.parent)
    if path.is_symlink() or (path.exists() and (not path.is_file() or path.stat().st_nlink != 1)):
        raise RouterError("unsafe_path", "Refusing unsafe state file.")
    fd, tmp = tempfile.mkstemp(prefix=".tmp-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


@contextmanager
def state_lock(directory):
    directory = private_dir(directory)
    path = directory / ".lock"
    try:
        fd = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    except OSError as exc:
        raise RouterError("unsafe_path", "Cannot safely acquire state lock.") from exc
    try:
        info = os.fstat(fd)
        if info.st_uid != os.getuid() or info.st_mode & 0o077 or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise RouterError("unsafe_path", "State lock must be owner-only.")
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise RouterError("state_busy", "Another router-agent operation is in progress.") from exc
        yield
    finally:
        os.close(fd)


VOLATILE = frozenset({"fetched_at", "observed_at", "collected_at", "last_success", "uptime", "uptime_seconds", "total_ticks", "used_ticks", "rx_bytes", "tx_bytes", "bytes_received", "bytes_sent", "timestamp", "snapshot_id"})
def semantic(value):
    if isinstance(value, dict):
        return {k: semantic(v) for k, v in value.items() if k not in VOLATILE}
    if isinstance(value, list):
        return [semantic(v) for v in value]
    return value


def client_alias(key, identifier):
    """Match the established live client/parental alias domain and width."""
    if not isinstance(key, bytes) or len(key) < 32:
        raise RouterError("identity_key_required", "A private identity key of at least 32 bytes is required.")
    return "client-" + hmac.new(key, b"client:" + str(identifier).upper().encode(), hashlib.sha256).hexdigest()[:16]


class SnapshotStore:
    def __init__(self, state_dir=None):
        self.state_dir = Path(state_dir) if state_dir is not None else default_state_dir()
        self.directory = self.state_dir / "snapshots"

    def ensure_key(self):
        """Initialize the private alias key without generating a fake alias."""
        with state_lock(self.state_dir):
            salt_path = self.state_dir / "alias.key"
            if not salt_path.exists() and not salt_path.is_symlink():
                atomic_write(salt_path, secrets.token_bytes(32))
            salt = private_read(salt_path)
            if len(salt) != 32:
                raise RouterError("invalid_state", "Alias key is invalid.")
            return salt

    def alias(self, identifier):
        return client_alias(self.ensure_key(), identifier)

    def save(self, data, identity, kind="status"):
        from .output import safe_data
        if kind not in {"status", "config"}:
            raise RouterError("invalid_snapshot", "Unsupported snapshot kind.")
        if set(identity) != {"schema", "device", "firmware", "catalog"} or not all(isinstance(v, (str, int)) for v in identity.values()):
            raise RouterError("invalid_snapshot", "Snapshot identity is incomplete.")
        with state_lock(self.state_dir):
            private_dir(self.directory)
            snapshot_id = uuid.uuid4().hex
            record = {"snapshot_id": snapshot_id, "created_at": datetime.now(timezone.utc).isoformat(), "identity": identity, "kind": kind, "data": safe_data(data)}
            atomic_write(self.directory / (snapshot_id + ".json"), json.dumps(record, separators=(",", ":")).encode())
            self._prune()
            return record

    def _paths(self):
        private_dir(self.directory)
        return sorted((p for p in self.directory.glob("*.json") if len(p.stem) == 32 and all(c in "0123456789abcdef" for c in p.stem)), key=lambda p: p.lstat().st_mtime, reverse=True)

    def _prune(self):
        cutoff = datetime.now(timezone.utc).timestamp() - timedelta(days=7).total_seconds()
        for i, path in enumerate(self._paths()):
            # Validate even candidates retained, and never follow a link for deletion.
            private_read(path)
            if i >= 20 or path.lstat().st_mtime < cutoff:
                path.unlink()

    def list(self):
        with state_lock(self.state_dir):
            records = [self._read(p.stem) for p in self._paths()[:20]]
            return [{key: record[key] for key in ("snapshot_id", "created_at", "kind", "identity")} for record in records]

    def _read(self, snapshot_id):
        if len(snapshot_id) != 32 or any(c not in "0123456789abcdef" for c in snapshot_id):
            raise RouterError("invalid_snapshot", "Invalid snapshot identifier.")
        try:
            return json.loads(private_read(self.directory / (snapshot_id + ".json")))
        except (ValueError, TypeError) as exc:
            raise RouterError("invalid_snapshot", "Snapshot data is invalid.") from exc

    def diff(self, before, after, *, offset=0, limit=20):
        if type(offset) is not int or offset < 0 or type(limit) is not int or not 1 <= limit <= 20:
            raise RouterError("invalid_arguments", "Diff limit must be 1..20 and offset nonnegative.", 2)
        with state_lock(self.state_dir):
            old, new = self._read(before), self._read(after)
        if old.get("identity") != new.get("identity") or old.get("kind") != new.get("kind"):
            raise RouterError("baseline_reset", "Snapshot schema, device, firmware or catalog changed.")
        a, b = semantic(old["data"]), semantic(new["data"])
        changes = []
        count = 0
        def walk(left, right, path="", before_present=True, after_present=True):
            nonlocal count
            if left == right and before_present == after_present:
                return
            if (left or right) and ((isinstance(left, dict) and (isinstance(right, dict) or right is None)) or (isinstance(right, dict) and left is None)):
                left, right = left or {}, right or {}
                for key in sorted(left.keys() | right.keys()):
                    escaped = str(key).replace("~", "~0").replace("/", "~1")
                    walk(left.get(key), right.get(key), path + "/" + escaped, key in left, key in right)
            elif (left or right) and ((isinstance(left, list) and (isinstance(right, list) or right is None)) or (isinstance(right, list) and left is None)):
                left, right = left or [], right or []
                for index in range(max(len(left), len(right))):
                    walk(left[index] if index < len(left) else None, right[index] if index < len(right) else None, path + "/" + str(index), index < len(left), index < len(right))
            else:
                count += 1
                if offset <= count - 1 < offset + limit:
                    record = {"path": path or "/", "before": left, "after": right}
                    if before_present != after_present:
                        record.update(before_present=before_present, after_present=after_present)
                    changes.append(record)
        walk(a, b)
        return {"changed": a != b, "changes": changes, "total_changes": count, "truncated": count > len(changes), "pagination": {"offset": offset, "limit": limit, "next_offset": offset + len(changes) if offset + len(changes) < count else None}}
