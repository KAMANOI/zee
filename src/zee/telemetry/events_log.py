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

import json
import os
import stat
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

_LOG_ROTATE_MAX_BYTES: int = 10 * 1024 * 1024  # 10 MB

from ..events import TrapEvent


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
        """Rename path → path.YYYYMMDD_HHMMSS when it exceeds max_bytes.

        Old files are kept indefinitely — logs are evidence and must not be
        deleted automatically. Rotation failure is silently swallowed so it
        never blocks event recording.
        """
        try:
            if path.exists() and path.stat().st_size >= max_bytes:
                ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
                rotated = path.parent / f"{path.name}.{ts}"
                path.rename(rotated)
        except OSError:
            pass

    @staticmethod
    def _append(path: Path, record: dict[str, Any]) -> None:
        # Rotate before appending if the file has grown past the size threshold.
        EventLog._rotate_if_needed(path)
        # Create owner-only (0600) on first write. open(mode="a") respects
        # the existing file's mode if it already exists, and falls back to
        # umask otherwise — we explicitly tighten here to ensure 0600.
        existed = path.exists()
        with path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")
        if not existed:
            try:
                os.chmod(path, 0o600)
            except (OSError, NotImplementedError):
                pass
