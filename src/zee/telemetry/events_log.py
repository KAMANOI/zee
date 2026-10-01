"""Event log (JSON Lines) and latency metrics (spec §7, v4 owner-only).

All measurements are real, recorded values. No estimates, no
predictions get written here as if they were observations.

The log directory and the individual JSON Lines files are created
with owner-only permissions (0700 / 0600). The records contain
`decoy_path` in plaintext, which on a compromised host would let an
attacker map out every decoy's location and avoid them. Owner-only
permissions raise the bar against a non-root attacker reading them,
matching the same posture as `policy/allowlist.py`'s permission check.

This is not a complete defense — a root-equivalent attacker still
reads everything — but it removes the trivial case of any unprivileged
user on the same host enumerating decoys via the log.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import threading
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator, Optional

try:  # POSIX
    import fcntl
except ImportError:  # pragma: no cover - Windows
    fcntl = None  # type: ignore[assignment]
try:  # Windows
    import msvcrt
except ImportError:
    msvcrt = None  # type: ignore[assignment]

from ..events import TrapEvent

logger = logging.getLogger(__name__)

_LOG_ROTATE_MAX_BYTES: int = 10 * 1024 * 1024  # 10 MB

# Hash-chain genesis marker: the prev_hash of the very first hash-bearing
# record of a log (across all of its rotated segments). Pre-chain
# ("legacy") lines that come BEFORE the first hash-bearing record are
# reported as unverified; a legacy line AFTER a hash-bearing one is an
# anomaly (see verify_chain).
GENESIS_HASH: str = "0" * 64

_HEX64 = re.compile(r"[0-9a-f]{64}")
# Rotated segment names.
#   current: <name>.rNNNNNN_YYYYMMDD_HHMMSS — ordered by the sequence number
#            (max existing + 1), never by the wall clock, so a clock step
#            backwards cannot reorder segments. The timestamp is for humans.
#   legacy:  <name>.YYYYMMDD_HHMMSS[_NNN] — written by Zee <= 0.10.x; sorted by
#            name and always placed before every sequence-numbered segment.
_ROTATED_SEQ = re.compile(r"\.r(\d{6,})_\d{8}_\d{6}")
_ROTATED_LEGACY = re.compile(r"\.\d{8}_\d{6}(_\d{3,})?")
# How far back from EOF the writer looks for the last chained record.
# ponytail: a record is a few hundred bytes; if 64 KiB of trailing garbage
# hides every hash, the next record restarts at GENESIS and verify_chain
# reports the break — visible, not silent.
_TAIL_WINDOW: int = 64 * 1024
# ponytail: one in-process lock for every log file; per-path locks if
# contention between events.jsonl and metrics.jsonl ever matters.
_APPEND_LOCK = threading.Lock()
# Upper bound on waiting for either lock. A stuck holder (another thread, or
# another process holding the flock) must not stall notify / containment:
# on timeout the evidence record is logged as failed and the defence goes on.
_LOCK_TIMEOUT_SEC: float = 2.0
# Indirection so tests can simulate short writes / ENOSPC without patching
# os.write for the whole interpreter.
_raw_write = os.write

# verify_chain statuses that mean "something is wrong with the evidence".
TAMPER_STATUSES = frozenset({"corrupted", "chain_break", "head_missing", "legacy_after_chain"})


def _canonical_json(record: dict[str, Any]) -> str:
    """The exact byte form that is hashed — sorted keys, no whitespace.

    Both `_append` (write) and `verify_chain` (read) must use this one
    definition, or a hash computed at write time will never match a hash
    recomputed at verify time even with unmodified bytes.
    """
    return json.dumps(record, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def _record_hash(prev_hash: str, bare: dict[str, Any]) -> str:
    return hashlib.sha256((prev_hash + _canonical_json(bare)).encode("utf-8")).hexdigest()


def _is_hash(v: Any) -> bool:
    return isinstance(v, str) and _HEX64.fullmatch(v) is not None


def _rotated_segments(path: Path) -> list[Path]:
    """Rotated segments of `path`, oldest first. Raises OSError if the
    directory cannot be listed (a missing directory means "none")."""
    try:
        entries = list(os.scandir(path.parent))
    except FileNotFoundError:
        return []
    keyed: list[tuple[tuple[int, int, str], Path]] = []
    prefix = path.name + "."
    for e in entries:
        if not e.name.startswith(prefix):
            continue
        suffix = e.name[len(path.name):]
        m = _ROTATED_SEQ.fullmatch(suffix)
        if m:
            key = (1, int(m.group(1)), "")
        elif _ROTATED_LEGACY.fullmatch(suffix):
            key = (0, 0, e.name)
        else:
            continue
        if e.is_file():
            keyed.append((key, Path(e.path)))
    keyed.sort(key=lambda kp: kp[0])
    return [p for _, p in keyed]


def log_segments(path: Path) -> list[Path]:
    """Rotated segments of `path` (oldest first) followed by `path` itself.

    Raises OSError when the directory cannot be listed — callers must treat
    that as "unverifiable", never as "no records".
    """
    return _rotated_segments(path) + ([path] if path.exists() else [])


def _tail(path: Path) -> tuple[Optional[str], bool, bool]:
    """(last valid record_hash in the tail window, file non-empty, ends with newline).

    Reads only the last _TAIL_WINDOW bytes — never the whole file — so
    the cost of one append does not grow with the log size. Lines that do
    not parse, are not objects, or carry a malformed hash are skipped
    (verify_chain reports them); legacy lines (no hash) are skipped too.
    """
    try:
        f = path.open("rb")
    except FileNotFoundError:
        return None, False, True
    with f:
        size = f.seek(0, os.SEEK_END)
        if size == 0:
            return None, False, True
        start = max(0, size - _TAIL_WINDOW)
        f.seek(start)
        data = f.read()
    ends_nl = data.endswith(b"\n")
    lines = data.split(b"\n")
    if start > 0:
        lines = lines[1:]  # first piece may be the middle of a line
    if not ends_nl:
        lines = lines[:-1]  # unterminated last piece: possibly mid-write
    for raw in reversed(lines):
        try:
            rec = json.loads(raw.decode("utf-8"))
        except ValueError:
            continue
        if isinstance(rec, dict) and _is_hash(rec.get("record_hash")):
            return rec["record_hash"], True, ends_nl
    return None, True, ends_nl


def _chain_tail(path: Path) -> tuple[Optional[str], bool]:
    """(hash to chain the next record from, current file needs a leading newline).

    Looks at the current file first; only when it is missing/empty does it
    fall back to the newest rotated segment (directory listed only then).
    """
    h, nonempty, ends_nl = _tail(path)
    if h is not None or nonempty:
        return h, nonempty and not ends_nl
    for seg in reversed(_rotated_segments(path)):
        h, nonempty, _ = _tail(seg)
        if h is not None or nonempty:
            return h, False
    return None, False


def _write_all(fd: int, data: bytes) -> None:
    """os.write until every byte is written; no progress → OSError."""
    view = memoryview(data)
    while view:
        n = _raw_write(fd, view)
        if not n or n < 0:
            raise OSError(f"write made no progress ({len(view)} bytes left)")
        view = view[n:]


@contextmanager
def _locked(path: Path) -> Iterator[None]:
    """Serialise tail-read + rotate + append across threads AND processes.

    Both locks are bounded by _LOCK_TIMEOUT_SEC; on timeout this raises
    TimeoutError (caught in `_append`, so the defence continues). The file
    lock lives in a sidecar file (dot-prefixed, so it never matches the
    rotated-segment patterns) because rotation renames the data file.
    """
    timeout = _LOCK_TIMEOUT_SEC
    deadline = time.monotonic() + timeout
    if not _APPEND_LOCK.acquire(timeout=timeout):
        raise TimeoutError(f"zee log lock (in-process) not acquired within {timeout}s")
    try:
        lock_path = path.parent / f".{path.name}.lock"
        fd = os.open(
            lock_path, os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600
        )
        try:
            while True:
                try:
                    if fcntl is not None:
                        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    elif msvcrt is not None:  # pragma: no cover - Windows
                        msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
                    break
                except BlockingIOError:
                    pass
                except OSError:
                    if fcntl is not None:
                        raise
                    # pragma: no cover - msvcrt reports "locked" as OSError
                if time.monotonic() >= deadline:
                    raise TimeoutError(
                        f"zee log lock ({lock_path.name}) not acquired within {timeout}s"
                    )
                time.sleep(0.01)
            try:
                yield
            finally:
                if fcntl is not None:
                    fcntl.flock(fd, fcntl.LOCK_UN)
                elif msvcrt is not None:  # pragma: no cover - Windows
                    os.lseek(fd, 0, os.SEEK_SET)
                    msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
        finally:
            os.close(fd)
    finally:
        _APPEND_LOCK.release()


def default_log_dir() -> Path:
    """Return the default directory for zee logs.

    Prefers XDG_STATE_HOME, then ~/.local/state/zee, falls back to ~/.zee.
    """
    env = os.environ.get("XDG_STATE_HOME")
    if env:
        return Path(env) / "zee"
    home = Path.home()
    local_state_parent = home / ".local" / "state"
    if local_state_parent.exists():
        return local_state_parent / "zee"
    return home / ".zee"


class EventLog:
    """Append-only JSON-Lines log of trap events and latency metrics.

    Files are created owner-only (0700 for the directory, 0600 for the
    log files) so that another local user cannot enumerate decoys by
    reading the event log. Windows ignores POSIX modes; on that
    platform Zee relies on the per-user profile directory's ACL.
    """

    def __init__(self, log_dir: Optional[Path] = None) -> None:
        self.log_dir = log_dir or default_log_dir()
        self.log_dir.mkdir(parents=True, exist_ok=True)
        # Tighten the dir mode if it was created with a looser default
        # umask. Best-effort: ignore if the platform rejects chmod.
        try:
            os.chmod(self.log_dir, 0o700)
        except (OSError, NotImplementedError):
            pass
        self.events_path = self.log_dir / "events.jsonl"
        self.metrics_path = self.log_dir / "metrics.jsonl"

    def record_event(self, event: TrapEvent) -> None:
        # v0.3 (spec L4): we record `decoy_ref` (asset_id#index) instead
        # of the absolute `decoy_path`, so a root attacker reading the
        # log cannot enumerate every decoy's location in one file.
        # `decoy_ref` falls back to `asset_id#?` if the watcher did not
        # supply it (e.g. a behavior_anomaly event), so the column stays
        # populated.
        decoy_ref = event.decoy_ref or f"{event.asset_id}#?"
        record = {
            "type": "trap_event",
            "source": event.source,
            "confidence": event.confidence,
            "asset_id": event.asset_id,
            "decoy_ref": decoy_ref,
            "detected_at": event.detected_at.isoformat(),
            "detail": event.detail,
            "op_class": event.op_class,
        }
        self._append(self.events_path, record)

    def record_latency(
        self,
        *,
        asset_id: str,
        detected_at: datetime,
        alert_sent_at: Optional[datetime],
        cut_done_at: Optional[datetime],
        cut_would_have_done_at: Optional[datetime],
        dry_run: bool,
        mode: str,
    ) -> None:
        record: dict[str, Any] = {
            "type": "latency",
            "recorded_at": datetime.now(timezone.utc).isoformat(),
            "asset_id": asset_id,
            "mode": mode,
            "dry_run": dry_run,
            "detected_at": detected_at.isoformat(),
            "alert_sent_at": alert_sent_at.isoformat() if alert_sent_at else None,
            "cut_done_at": cut_done_at.isoformat() if cut_done_at else None,
            "cut_would_have_done_at": (
                cut_would_have_done_at.isoformat() if cut_would_have_done_at else None
            ),
        }
        # Real measured latencies only — derived if both ends exist.
        if alert_sent_at is not None:
            record["alert_latency_sec"] = (alert_sent_at - detected_at).total_seconds()
        end = cut_done_at or cut_would_have_done_at
        if end is not None:
            record["cut_latency_sec"] = (end - detected_at).total_seconds()
        self._append(self.metrics_path, record)

    def record_false_positive_marker(self, asset_id: str, note: str) -> None:
        """Operator-marked false positive (used to compute the counter in spec §7)."""
        record = {
            "type": "false_positive",
            "recorded_at": datetime.now(timezone.utc).isoformat(),
            "asset_id": asset_id,
            "note": note,
        }
        self._append(self.metrics_path, record)

    def record_webhook_result(self, asset_id: str, ok: bool, detail: str) -> None:
        """Result of an async webhook dispatch (after fire-and-forget completes)."""
        record = {
            "type": "webhook_result",
            "recorded_at": datetime.now(timezone.utc).isoformat(),
            "asset_id": asset_id,
            "ok": ok,
            "detail": detail,
        }
        self._append(self.metrics_path, record)

    @staticmethod
    def _rotate_if_needed(path: Path, max_bytes: int = _LOG_ROTATE_MAX_BYTES) -> None:
        """Rename path → path.rNNNNNN_YYYYMMDD_HHMMSS when it exceeds max_bytes.

        NNNNNN is the highest existing sequence number + 1, so segment order
        never depends on the wall clock. Old files are kept indefinitely —
        logs are evidence and must not be deleted automatically. Rotation
        failure is swallowed so it never blocks event recording. Called
        only under `_locked(path)`.
        """
        try:
            if path.exists() and path.stat().st_size >= max_bytes:
                seq = 1 + max(
                    (int(m.group(1)) for p in _rotated_segments(path)
                     if (m := _ROTATED_SEQ.fullmatch(p.name[len(path.name):]))),
                    default=0,
                )
                ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
                rotated = path.parent / f"{path.name}.r{seq:06d}_{ts}"
                if not rotated.exists():
                    path.rename(rotated)
        except OSError:
            pass

    @staticmethod
    def _append(path: Path, record: dict[str, Any]) -> None:
        """Append one hash-chained record. NEVER raises, never blocks for long.

        Every record_* call — including record_event(), which
        responder.sequence.handle() calls BEFORE notifying and cutting —
        routes through here. A broken, unreadable, full or locked evidence
        log must not stop the defence: lock waits are bounded, the failure
        is logged and swallowed, and the missing/broken record shows up
        later in verify_chain / zee export.
        """
        try:
            with _locked(path):
                # Read the tail BEFORE rotating and carry it over, so the new
                # segment chains from the record that was really last.
                try:
                    prev_hash, needs_nl = _chain_tail(path)
                except Exception:  # noqa: BLE001 - evidence side only
                    logger.exception("zee: could not read the tail of %s", path)
                    prev_hash, needs_nl = None, False
                EventLog._rotate_if_needed(path)
                if not path.exists():
                    needs_nl = False  # fresh segment after rotation
                prev_hash = prev_hash or GENESIS_HASH
                chained = dict(record)
                chained["prev_hash"] = prev_hash
                chained["record_hash"] = _record_hash(prev_hash, record)
                line = json.dumps(chained, ensure_ascii=False) + "\n"
                if needs_nl:
                    # The previous line is unterminated (crash mid-write):
                    # keep it as its own (corrupted) line instead of gluing
                    # this record onto it.
                    line = "\n" + line
                # O_CREAT with 0600 → owner-only from the first byte.
                fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
                try:
                    _write_all(fd, line.encode("utf-8"))
                finally:
                    os.close(fd)
        except Exception:  # noqa: BLE001 - never block notify/containment
            logger.exception(
                "zee: failed to append evidence record to %s "
                "(containment continues; verify with `zee export`)",
                path,
            )


def verify_chain(path: Path) -> dict[str, Any]:
    """Verify the hash chain of `path` and all of its rotated segments.

    Segments are read oldest-first (`log_segments`) and checked as one
    continuous chain. Returns
        {"files": [segment names], "read_error": str | None,
         "results": [{"file", "line", "status", ["reason"]}, ...]}

    Per-line status:
        ok                 — record_hash matches the content, and prev_hash
                             is GENESIS (first chained record) or the previous
                             chained record's hash.
        legacy             — no prev_hash/record_hash, and no chained record
                             came before it: written before the hash chain
                             existed. NOT verified.
        legacy_after_chain — no hashes, but a chained record came before it:
                             hashes stripped or a line inserted. Anomaly.
        corrupted          — not valid UTF-8/JSON, not an object, malformed
                             hash fields, or content does not match
                             record_hash (the line was edited).
        chain_break        — prev_hash does not match the previous chained
                             record: a line was deleted, reordered or replaced.
        head_missing       — the first chained record does not start at
                             GENESIS: the start of the log (or an older rotated
                             segment) is missing.
        partial            — unparsable final line of the newest segment with
                             no trailing newline: possibly still being written
                             (or a crash mid-write). Not counted as tampering.

    `read_error` is set (and verification stops) if any segment cannot be
    read — callers must report that as "unverifiable", never as "no anomaly".

    What this does NOT detect (honest limits): the hash is unkeyed, so
    anyone who can write the log can recompute every hash after editing;
    and removing records from the END of the log (truncation) leaves a
    valid shorter chain. Nothing here is compared against a record kept
    elsewhere.
    """
    out: dict[str, Any] = {"files": [], "read_error": None, "results": []}
    results: list[dict[str, Any]] = out["results"]
    expected: Optional[str] = None  # last chained record's (claimed) hash
    try:
        segs = log_segments(path)
    except OSError as e:
        out["read_error"] = f"{path.parent}: cannot list log segments: {e.__class__.__name__}: {e}"
        return out
    for si, seg in enumerate(segs):
        out["files"].append(seg.name)
        newest = si == len(segs) - 1
        try:
            with seg.open("rb") as f:
                for ln, raw in enumerate(f):
                    if not raw.strip():
                        continue
                    loc: dict[str, Any] = {"file": seg.name, "line": ln}
                    try:
                        rec = json.loads(raw.decode("utf-8"))
                    except ValueError:
                        if newest and not raw.endswith(b"\n"):
                            results.append({**loc, "status": "partial"})
                        else:
                            results.append({**loc, "status": "corrupted", "reason": "not valid UTF-8 JSON"})
                        continue
                    if not isinstance(rec, dict):
                        results.append({**loc, "status": "corrupted", "reason": "not a JSON object"})
                        continue
                    if "record_hash" not in rec and "prev_hash" not in rec:
                        results.append({**loc, "status": "legacy" if expected is None else "legacy_after_chain"})
                        continue
                    rh, ph = rec.get("record_hash"), rec.get("prev_hash")
                    if not (_is_hash(rh) and _is_hash(ph)):
                        results.append({**loc, "status": "corrupted", "reason": "malformed hash fields"})
                        continue
                    bare = {k: v for k, v in rec.items() if k not in ("record_hash", "prev_hash")}
                    try:
                        matches = _record_hash(ph, bare) == rh
                    except ValueError:
                        matches = False
                    if not matches:
                        results.append({**loc, "status": "corrupted", "reason": "content does not match record_hash"})
                    elif expected is None:
                        results.append({**loc, "status": "ok" if ph == GENESIS_HASH else "head_missing"})
                    elif ph != expected:
                        results.append({**loc, "status": "chain_break"})
                    else:
                        results.append({**loc, "status": "ok"})
                    # Keep following the claimed hash so damage stays localised
                    # to the edited line instead of cascading.
                    expected = rh
        except OSError as e:
            out["read_error"] = f"{seg.name}: {e.__class__.__name__}: {e}"
            return out
    return out
