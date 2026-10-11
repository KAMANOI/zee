"""Explicit, per-state-directory permission and cross-process containment locks.

These files are operator state, not a defence against the same user or root.
Windows relies on the profile's ACL in addition to the requested POSIX modes.
"""
from __future__ import annotations

import errno
import hashlib
import json
import os
import re
import stat
import time
import uuid
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path

from ..config.schema import Config
from ..policy.asset_profile import resolve
from ..telemetry.events_log import default_log_dir

try:
    import fcntl
except ImportError:  # pragma: no cover - Windows
    fcntl = None
    import msvcrt

DISCLOSURE_VERSION = "1"


@dataclass(frozen=True)
class Permission:
    schema_version: int
    enabled: bool
    revision: int
    instance_id: str
    policy_hash: str
    disclosure_version: str
    changed_by: str
    changed_at: datetime


@dataclass(frozen=True)
class Invalid:
    reason: str


def default_permission_path() -> Path:
    return default_log_dir() / "auto_containment.json"


def instance_id(directory: Path | None = None) -> str:
    # Bound to the resolved state directory only: a hostname change must not
    # silently void a valid permission. Limit: a whole-machine clone (state
    # directory included) carries the permission along; re-run enable there.
    identity = str((directory or default_log_dir()).resolve())
    return hashlib.sha256(identity.encode()).hexdigest()


def policy_hash(config: Config) -> str:
    # Firing condition (decoy paths) is part of what the operator confirmed.
    policy = sorted((a.id, a.cut_method, sorted(a.decoy_paths))
                    for a in config.assets if a.response_mode == "auto")
    return hashlib.sha256(json.dumps(policy, ensure_ascii=False, separators=(",", ":")).encode()).hexdigest()


def _check_path(path: Path) -> None:
    # Refuse a link at the final element (including dangling links). Links
    # higher up (/tmp, /var, /home -> /var/home, a symlinked XDG_STATE_HOME)
    # are the operator's layout and are followed; Zee's own state directory
    # is checked as the final element by private_directory()/its callers.
    if path.is_symlink():
        raise ValueError(f"symlink refused: {path}")


def private_directory(path: Path) -> None:
    _check_path(path)
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(path, 0o700)


def private_temp(final: Path, text: str) -> Path:
    """Write and fsync a unique sibling at 0600; caller publishes it."""
    tmp = final.parent / f".{final.name}.{uuid.uuid4().hex}.tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise
    return tmp


def _decode(raw: dict) -> Permission:
    if not isinstance(raw, dict):
        raise ValueError("permission must be an object")
    if type(raw.get("schema_version")) is not int or raw["schema_version"] != 1:
        raise ValueError("unsupported schema_version")
    if type(raw.get("enabled")) is not bool:
        raise ValueError("enabled must be bool")
    if type(raw.get("revision")) is not int or raw["revision"] < 1:
        raise ValueError("revision must be a positive integer")
    for key in ("instance_id", "policy_hash", "disclosure_version", "changed_by", "changed_at"):
        if not isinstance(raw.get(key), str) or not raw[key].strip():
            raise ValueError(f"invalid {key}")
    if not re.fullmatch(r"[0-9a-f]{64}", raw["policy_hash"]):
        raise ValueError("invalid policy_hash")
    if raw["disclosure_version"] != DISCLOSURE_VERSION:
        raise ValueError("unsupported disclosure_version")
    raw = dict(raw)
    raw["changed_at"] = datetime.fromisoformat(raw["changed_at"])
    if raw["changed_at"].tzinfo is None:
        raise ValueError("changed_at must include timezone")
    return Permission(**raw)


def load(path: Path | None = None) -> Permission | Invalid | None:
    p = path or default_permission_path()
    try:
        _check_path(p.parent)
        _check_path(p)
        fd = os.open(p, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
        with os.fdopen(fd, "r", encoding="utf-8") as f:
            st = os.fstat(f.fileno())
            if not stat.S_ISREG(st.st_mode):
                return Invalid("not a regular file")
            if os.name != "nt" and (stat.S_IMODE(st.st_mode) != 0o600 or stat.S_IMODE(p.parent.stat().st_mode) != 0o700):
                return Invalid("permission file/directory must be 0600/0700")
            perm = _decode(json.load(f))
        if perm.instance_id != instance_id(p.parent):
            return Invalid("instance_id / state directory mismatch")
        return perm
    except FileNotFoundError:
        return None
    except (OSError, ValueError, TypeError, RecursionError) as e:
        return Invalid(str(e) or type(e).__name__)


def save(perm: Permission, path: Path | None = None) -> None:
    """Atomic publication. Mutating callers must hold HostLock."""
    p = path or default_permission_path()
    raw = asdict(perm)
    raw["changed_at"] = perm.changed_at.isoformat()
    _decode(raw)
    if perm.instance_id != instance_id(p.parent):
        raise ValueError("instance_id / state directory mismatch")
    _check_path(p)
    private_directory(p.parent)  # checks the directory itself
    tmp = private_temp(p, json.dumps(raw, sort_keys=True) + "\n")
    try:
        _check_path(p)
        os.replace(tmp, p)
    finally:
        tmp.unlink(missing_ok=True)


def decide(event, asset, config: Config, perm: Permission | Invalid | None) -> tuple[bool, str | None]:
    if resolve(asset).mode != "contain":
        return False, "mode_not_contain"
    if event.confidence != "high":
        return False, "confidence_not_high"
    if event.op_class != "change":
        return False, "op_class_not_change"
    if config.dry_run:
        return False, "dry_run"
    if perm is None:
        return False, "no_permission"
    if isinstance(perm, Invalid):
        return False, "state_invalid"
    if not perm.enabled:
        return False, "auto_off"
    if perm.policy_hash != policy_hash(config):
        return False, "policy_mismatch"
    return True, None


class HostLock:
    """Bounded exclusive lock, shared by threads and processes; never unlink."""
    def __init__(self, path: Path | None = None, *, timeout: float = 10, create: bool = True):
        self.path = path or default_log_dir() / "host.lock"
        self.timeout = timeout
        self.create = create
        self.fd = None

    def __enter__(self):
        _check_path(self.path.parent)
        _check_path(self.path)
        if self.create:
            private_directory(self.path.parent)
        flags = os.O_RDWR | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
        fd = os.open(self.path, flags | (os.O_CREAT if self.create else 0), 0o600)
        deadline = time.monotonic() + self.timeout
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                raise ValueError("lock is not a regular file")
            while True:
                try:
                    if fcntl is not None:
                        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    else:  # pragma: no cover - Windows
                        os.lseek(fd, 0, os.SEEK_SET)
                        msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
                    self.fd = fd
                    return self
                except OSError as e:
                    if e.errno not in (errno.EACCES, errno.EAGAIN, errno.EDEADLK):
                        raise
                    if time.monotonic() >= deadline:
                        raise TimeoutError(f"lock busy: {self.path}") from e
                    time.sleep(0.01)
        except BaseException:
            os.close(fd)
            raise

    def __exit__(self, *exc):
        if self.fd is not None:
            try:
                if fcntl is not None:
                    fcntl.flock(self.fd, fcntl.LOCK_UN)
                else:  # pragma: no cover - Windows
                    os.lseek(self.fd, 0, os.SEEK_SET)
                    msvcrt.locking(self.fd, msvcrt.LK_UNLCK, 1)
            finally:
                os.close(self.fd)
                self.fd = None


def watch_running(directory: Path | None = None) -> bool | None:
    """Probe an existing lock without creating files or directories.

    True = held by a running watch, False = not running, None = cannot tell
    (unreadable lock, link, ...). Callers must not read None as "protected".
    """
    try:
        with HostLock((directory or default_log_dir()) / "watch.lock", timeout=0, create=False):
            return False
    except FileNotFoundError:
        return False
    except TimeoutError:
        return True
    except (OSError, ValueError):
        return None
