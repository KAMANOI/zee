"""zee status — summary of trap activity and current cut state.

Reads events.jsonl and cut_state.jsonl from the state directory (no
config file required). Outputs a human-readable overview:
  • event counts over 24h / 7d / 30d
  • per-asset breakdown and cut state
  • burst detection: >= N change-class events within T seconds

Burst parameters (v0.6):
    BURST_MIN_EVENTS = 2
    BURST_WINDOW_SEC = 300
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

from .cut_state import CutRecord, CutStateLog
from .events_log import default_log_dir

BURST_WINDOW_SEC: int = 300
BURST_MIN_EVENTS: int = 2


@dataclass
class AssetStats:
    asset_id: str
    counts: dict[str, int] = field(
        default_factory=lambda: {"24h": 0, "7d": 0, "30d": 0}
    )
    read_counts: dict[str, int] = field(
        default_factory=lambda: {"24h": 0, "7d": 0, "30d": 0}
    )
    change_counts: dict[str, int] = field(
        default_factory=lambda: {"24h": 0, "7d": 0, "30d": 0}
    )
    cut_record: Optional[CutRecord] = None


@dataclass
class BurstEvent:
    detected_at: datetime
    event_count: int


@dataclass
class StatusReport:
    log_dir: Path
    now: datetime
    total: dict[str, int]
    read_total: dict[str, int]
    change_total: dict[str, int]
    per_asset: list[AssetStats]
    bursts: list[BurstEvent]
    log_exists: bool
    read_error: Optional[str] = None
    skipped_lines: int = 0  # malformed JSON lines silently skipped


def compute(log_dir: Optional[Path] = None) -> StatusReport:
    """Build a StatusReport from events.jsonl and cut_state.jsonl."""
    ldir = log_dir or default_log_dir()
    events_path = ldir / "events.jsonl"
    now = datetime.now(timezone.utc)

    cutoffs = {
        "24h": now - timedelta(hours=24),
        "7d": now - timedelta(days=7),
        "30d": now - timedelta(days=30),
    }

    _zero = lambda: {"24h": 0, "7d": 0, "30d": 0}  # noqa: E731

    if not events_path.exists():
        return StatusReport(
            log_dir=ldir,
            now=now,
            total=_zero(),
            read_total=_zero(),
            change_total=_zero(),
            per_asset=[],
            bursts=[],
            log_exists=False,
        )

    # Parse events (only trap_event records within the 30d window)
    cutoff_30d = cutoffs["30d"]
    raw: list[tuple[datetime, str, str]] = []  # (ts, asset_id, op_class)

    read_error: str | None = None
    skipped_lines: int = 0
    try:
        content = events_path.read_text(encoding="utf-8")
    except OSError as e:
        content = ""
        read_error = str(e)

    for line in content.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            skipped_lines += 1
            continue
        if rec.get("type") != "trap_event":
            continue
        try:
            ts = datetime.fromisoformat(rec["detected_at"])
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=timezone.utc)
        except (KeyError, ValueError, TypeError):
            continue
        if ts < cutoff_30d:
            continue
        raw.append((ts, rec.get("asset_id", "unknown"), rec.get("op_class", "read")))

    raw.sort(key=lambda x: x[0])

    # Aggregate counts
    total = _zero()
    read_total = _zero()
    change_total = _zero()
    per_asset_map: dict[str, AssetStats] = {}

    for ts, asset_id, op_class in raw:
        if asset_id not in per_asset_map:
            per_asset_map[asset_id] = AssetStats(asset_id=asset_id)
        stats = per_asset_map[asset_id]

        for window, cutoff in cutoffs.items():
            if ts >= cutoff:
                total[window] += 1
                stats.counts[window] += 1
                if op_class == "change":
                    change_total[window] += 1
                    stats.change_counts[window] += 1
                else:
                    read_total[window] += 1
                    stats.read_counts[window] += 1

    # Burst detection (greedy non-overlapping windows)
    change_events = [(ts, aid) for ts, aid, oc in raw if oc == "change"]
    bursts: list[BurstEvent] = []
    i = 0
    while i < len(change_events):
        window_start = change_events[i][0]
        j = i
        while (
            j < len(change_events)
            and (change_events[j][0] - window_start).total_seconds() <= BURST_WINDOW_SEC
        ):
            j += 1
        if j - i >= BURST_MIN_EVENTS:
            bursts.append(
                BurstEvent(detected_at=change_events[j - 1][0], event_count=j - i)
            )
            i = j
        else:
            i += 1

    # Cut states — also surface assets that have an active cut but no events
    cut_log = CutStateLog(path=ldir / "cut_state.jsonl")
    all_asset_ids = set(per_asset_map)
    cut_state_path = ldir / "cut_state.jsonl"
    if cut_state_path.exists():
        try:
            for line in cut_state_path.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                    if rec.get("type") == "cut":
                        all_asset_ids.add(rec.get("asset_id", ""))
                except json.JSONDecodeError:
                    continue
        except OSError:
            pass

    per_asset_list: list[AssetStats] = []
    for asset_id in sorted(all_asset_ids):
        if not asset_id:
            continue
        base = per_asset_map.get(asset_id, AssetStats(asset_id=asset_id))
        per_asset_list.append(
            AssetStats(
                asset_id=base.asset_id,
                counts=base.counts,
                read_counts=base.read_counts,
                change_counts=base.change_counts,
                cut_record=cut_log.latest_unresolved_for(asset_id),
            )
        )

    return StatusReport(
        log_dir=ldir,
        now=now,
        total=total,
        read_total=read_total,
        change_total=change_total,
        per_asset=per_asset_list,
        bursts=bursts,
        log_exists=True,
        read_error=read_error,
        skipped_lines=skipped_lines,
    )


def render(report: StatusReport) -> str:
    """Return a human-readable status string from a StatusReport."""
    SEP = "─" * 46
    lines: list[str] = []
    lines.append(f"Zee status  (log: {report.log_dir})")
    lines.append(SEP)

    if not report.log_exists:
        lines.append("no events recorded yet")
        lines.append(SEP)
        return "\n".join(lines)

    if report.read_error:
        lines.append(f"⚠  events.jsonl could not be read: {report.read_error}")
        lines.append("   (counts below reflect partial or no data)")
        lines.append("")
    if report.skipped_lines:
        lines.append(
            f"⚠  {report.skipped_lines} malformed line(s) skipped in events.jsonl"
        )
        lines.append("")

    any_cut = any(s.cut_record is not None for s in report.per_asset)
    cut_label = (
        "⚠  ACTIVE — run `zee restore <asset_id>` to clear" if any_cut else "clear"
    )
    lines.append(f"cut state:   {cut_label}")
    lines.append("")

    lines.append(f"{'':22}{'24h':>5}  {'7d':>5}  {'30d':>6}")
    lines.append(
        f"  {'all events':<20}{report.total['24h']:>5}  "
        f"{report.total['7d']:>5}  {report.total['30d']:>6}"
    )
    lines.append(
        f"    {'read-class':<18}{report.read_total['24h']:>5}  "
        f"{report.read_total['7d']:>5}  {report.read_total['30d']:>6}"
    )
    lines.append(
        f"    {'change-class':<18}{report.change_total['24h']:>5}  "
        f"{report.change_total['7d']:>5}  {report.change_total['30d']:>6}"
    )

    if report.per_asset:
        lines.append("")
        lines.append("per asset:")
        for s in report.per_asset:
            if s.cut_record:
                cr = s.cut_record
                ts_str = cr.cut_at.strftime("%Y-%m-%dT%H:%M:%SZ")
                cut_str = f"⚠ ACTIVE — method={cr.method} since {ts_str}"
            else:
                cut_str = "clear"
            n30 = s.counts.get("30d", 0)
            lines.append(f"  {s.asset_id:<22} 30d: {n30:<4} ({cut_str})")

    lines.append("")
    if not report.bursts:
        lines.append("burst activity (30d): none")
    else:
        lines.append(
            f"burst activity (30d): ⚠  {len(report.bursts)} burst(s) detected"
        )
        b = report.bursts[-1]
        ts_str = b.detected_at.strftime("%Y-%m-%dT%H:%M:%SZ")
        lines.append(
            f"  last: {b.event_count} change-class events within "
            f"{BURST_WINDOW_SEC}s at {ts_str}"
        )
        lines.append(
            "  → review events.jsonl  or  zee cut <asset_id>  if hostile"
        )

    lines.append(SEP)
    return "\n".join(lines)
