"""Read-only view over Zee's local event store.

Opens ``events.jsonl`` / ``cut_state.jsonl`` for reading only and maps
records to a canonical, versioned schema (the "data moat"). Never
writes to those files. When ``redact_paths`` is true, the free-text
``detail`` field (which can contain a path) and ``decoy_paths`` in the
policy view are masked, because the on-disk log keeps ``decoy_path`` and
``assets.toml`` keeps customer file names in the clear.

Reuses the existing :mod:`zee.telemetry.status` aggregation so the MCP
summary and ``zee status`` can never disagree.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from ..telemetry import status as status_mod
from ..telemetry.events_log import default_log_dir

_REDACTED = "[redacted]"
SCHEMA_VERSION = "1"
# Sort sentinel for events whose timestamp cannot be parsed: oldest.
_MIN_TS = datetime.min.replace(tzinfo=timezone.utc)


def _event_id(detected_at: str, asset_id: str, detail: str) -> str:
    """Stable synthetic id — events.jsonl has no id of its own."""
    h = hashlib.sha1(f"{detected_at}|{asset_id}|{detail}".encode("utf-8"))
    return h.hexdigest()[:12]


def _parse_ts(s: Optional[str]) -> Optional[datetime]:
    """Parse an ISO8601 timestamp to an aware datetime (naive -> UTC).

    Filtering and sorting compare *real* instants, not raw strings, so
    that mixed timezone offsets (e.g. +09:00 vs +00:00) order correctly
    and agree with `zee status` (which also parses to datetimes)."""
    if not s:
        return None
    try:
        dt = datetime.fromisoformat(s)
    except (ValueError, TypeError):
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


class EventReader:
    def __init__(
        self, log_dir: Optional[Path] = None, redact_paths: bool = True
    ) -> None:
        self.log_dir = Path(log_dir) if log_dir else default_log_dir()
        self.redact_paths = redact_paths
        self.events_path = self.log_dir / "events.jsonl"
        self.cut_state_path = self.log_dir / "cut_state.jsonl"

    # ---- raw → canonical -------------------------------------------------

    def _iter_raw(self):
        if not self.events_path.exists():
            return
        try:
            content = self.events_path.read_text(encoding="utf-8")
        except OSError:
            return
        for line in content.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                # Malformed (e.g. partial line during a concurrent write):
                # skip, consistent with `zee status`.
                continue
            if rec.get("type") != "trap_event":
                continue
            yield rec

    def _canonical(self, rec: dict[str, Any]) -> dict[str, Any]:
        # Fields follow the *actual* events.jsonl record (trap_event:
        # source / confidence / op_class / decoy_ref), not the illustrative
        # enum in spec §6. schema_version lets the schema evolve later.
        detected_at = rec.get("detected_at", "")
        asset_id = rec.get("asset_id", "unknown")
        detail = rec.get("detail", "")
        return {
            "schema_version": SCHEMA_VERSION,
            "event_id": _event_id(detected_at, asset_id, detail),
            "timestamp": detected_at,
            "source": rec.get("source"),
            "confidence": rec.get("confidence"),
            "op_class": rec.get("op_class"),
            "asset_id": asset_id,
            # decoy_ref is already "asset_id#index" (no absolute path), so
            # it is safe to surface even when redacting.
            "decoy_ref": rec.get("decoy_ref"),
            "detail": _REDACTED if self.redact_paths else detail,
        }

    # ---- queries ---------------------------------------------------------

    def recent_events(self, limit: int = 50) -> list[dict[str, Any]]:
        evs = [self._canonical(r) for r in self._iter_raw()]
        evs.sort(key=lambda e: _parse_ts(e["timestamp"]) or _MIN_TS)
        evs.reverse()  # newest first
        return evs[:limit] if limit else evs

    def query_events(
        self,
        since: Optional[str] = None,
        until: Optional[str] = None,
        op_class: Optional[str] = None,
        confidence: Optional[str] = None,
        limit: int = 50,
    ) -> list[dict[str, Any]]:
        # Compare real instants, not raw strings (see _parse_ts).
        since_dt = _parse_ts(since)
        until_dt = _parse_ts(until)
        out: list[dict[str, Any]] = []
        for r in self._iter_raw():
            ev = self._canonical(r)
            ts = _parse_ts(ev["timestamp"])
            if since_dt and (ts is None or ts < since_dt):
                continue
            if until_dt and (ts is None or ts > until_dt):
                continue
            if op_class and ev["op_class"] != op_class:
                continue
            if confidence and ev["confidence"] != confidence:
                continue
            out.append(ev)
        out.sort(key=lambda e: _parse_ts(e["timestamp"]) or _MIN_TS)
        out.reverse()
        return out[:limit] if limit else out

    def get_event(self, event_id: str) -> Optional[dict[str, Any]]:
        for r in self._iter_raw():
            ev = self._canonical(r)
            if ev["event_id"] == event_id:
                return ev
        return None

    # ---- status / containment / policy / health --------------------------

    def status_summary(self) -> dict[str, Any]:
        rep = status_mod.compute(self.log_dir)
        return {
            "log_exists": rep.log_exists,
            "now": rep.now.isoformat(),
            "totals": {
                "all": rep.total,
                "read": rep.read_total,
                "change": rep.change_total,
            },
            "per_asset": [
                {
                    "asset_id": s.asset_id,
                    "counts": s.counts,
                    "read_counts": s.read_counts,
                    "change_counts": s.change_counts,
                    "cut_active": s.cut_record is not None,
                    "cut_method": (s.cut_record.method if s.cut_record else None),
                }
                for s in rep.per_asset
            ],
            "bursts": [
                {
                    "detected_at": b.detected_at.isoformat(),
                    "event_count": b.event_count,
                }
                for b in rep.bursts
            ],
            "read_error": rep.read_error,
            "skipped_lines": rep.skipped_lines,
        }

    def active_containments(self) -> list[dict[str, Any]]:
        from ..telemetry.cut_state import CutStateLog

        if not self.cut_state_path.exists():
            return []
        log = CutStateLog(path=self.cut_state_path)
        asset_ids: set[str] = set()
        try:
            for line in self.cut_state_path.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if rec.get("type") == "cut":
                    asset_ids.add(rec.get("asset_id", ""))
        except OSError:
            return []
        out: list[dict[str, Any]] = []
        for aid in sorted(a for a in asset_ids if a):
            cr = log.latest_unresolved_for(aid)
            if cr is None:
                continue
            out.append(
                {
                    "asset_id": cr.asset_id,
                    "method": cr.method,
                    "cut_at": cr.cut_at.isoformat(),
                    "platform": cr.platform,
                    # interface / rule names — not customer paths.
                    "modified": list(cr.modified),
                }
            )
        return out

    def policy_view(self, config_path: Optional[str | Path]) -> dict[str, Any]:
        if config_path is None:
            return {"error": "no config path provided"}
        from ..config.schema import Config

        try:
            cfg = Config.load(Path(config_path))
        except Exception as e:  # noqa: BLE001 - surface as in-band error
            return {"error": f"could not load policy: {e.__class__.__name__}"}
        assets = []
        for a in cfg.assets:
            paths = list(a.decoy_paths)
            assets.append(
                {
                    "asset_id": a.id,
                    "decoy_paths": (
                        [_REDACTED] * len(paths)
                        if self.redact_paths
                        else [str(p) for p in paths]
                    ),
                    "cut_method": getattr(a, "cut_method", None),
                }
            )
        return {"dry_run": getattr(cfg, "dry_run", None), "assets": assets}

    def health_check(self) -> dict[str, Any]:
        return {
            "event_store_path": str(self.events_path),
            "event_store_reachable": self.events_path.exists(),
            "redact_paths": self.redact_paths,
            "watcher_liveness": (
                "unknown — the watcher is a separate process; the MCP layer "
                "cannot observe its liveness directly"
            ),
        }
