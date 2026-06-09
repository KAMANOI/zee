"""Tests for telemetry/status.py (zee status command, v0.6)."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from zee.telemetry.status import (
    BURST_MIN_EVENTS,
    BURST_WINDOW_SEC,
    compute,
    render,
)


def _ts(offset_sec: float, now: datetime) -> str:
    return (now - timedelta(seconds=offset_sec)).isoformat()


def _write_events(path: Path, records: list[dict]) -> None:
    with path.open("w", encoding="utf-8") as f:
        for rec in records:
            f.write(json.dumps(rec) + "\n")


def _trap(asset_id: str, op_class: str, ts: str) -> dict:
    return {
        "type": "trap_event",
        "source": "decoy_touch",
        "confidence": "high",
        "asset_id": asset_id,
        "decoy_ref": f"{asset_id}#0",
        "detected_at": ts,
        "detail": "test",
        "op_class": op_class,
    }


NOW = datetime.now(timezone.utc)


# ─── basic counts ──────────────────────────────────────────────────────────────

def test_no_log_returns_zeros(tmp_path):
    report = compute(log_dir=tmp_path)
    assert not report.log_exists
    assert report.total == {"24h": 0, "7d": 0, "30d": 0}
    assert report.per_asset == []
    assert report.bursts == []


def test_single_read_event_within_24h(tmp_path):
    events_path = tmp_path / "events.jsonl"
    _write_events(events_path, [
        _trap("host-a", "read", _ts(3600, NOW)),  # 1h ago
    ])
    report = compute(log_dir=tmp_path)
    assert report.log_exists
    assert report.total["24h"] == 1
    assert report.read_total["24h"] == 1
    assert report.change_total["24h"] == 0


def test_event_outside_30d_is_ignored(tmp_path):
    events_path = tmp_path / "events.jsonl"
    _write_events(events_path, [
        _trap("host-a", "read", _ts(31 * 86400, NOW)),  # 31 days ago
    ])
    report = compute(log_dir=tmp_path)
    assert report.total["30d"] == 0


def test_events_in_correct_time_buckets(tmp_path):
    events_path = tmp_path / "events.jsonl"
    _write_events(events_path, [
        _trap("host-a", "change", _ts(1800, NOW)),      # 30min ago → 24h + 7d + 30d
        _trap("host-a", "read",   _ts(3 * 86400, NOW)), # 3d ago → 7d + 30d
        _trap("host-a", "read",   _ts(10 * 86400, NOW)),# 10d ago → 30d only
    ])
    report = compute(log_dir=tmp_path)
    assert report.total["24h"] == 1
    assert report.total["7d"] == 2
    assert report.total["30d"] == 3
    assert report.change_total["24h"] == 1
    assert report.read_total["7d"] == 1  # 3d ago read


# ─── per-asset ─────────────────────────────────────────────────────────────────

def test_per_asset_breakdown(tmp_path):
    events_path = tmp_path / "events.jsonl"
    _write_events(events_path, [
        _trap("alpha", "read",   _ts(100, NOW)),
        _trap("beta",  "change", _ts(200, NOW)),
        _trap("alpha", "change", _ts(300, NOW)),
    ])
    report = compute(log_dir=tmp_path)
    ids = [s.asset_id for s in report.per_asset]
    assert "alpha" in ids
    assert "beta" in ids
    alpha = next(s for s in report.per_asset if s.asset_id == "alpha")
    assert alpha.counts["30d"] == 2
    assert alpha.change_counts["30d"] == 1
    beta = next(s for s in report.per_asset if s.asset_id == "beta")
    assert beta.change_counts["30d"] == 1


# ─── cut state integration ──────────────────────────────────────────────────────

def test_cut_state_shown_for_asset(tmp_path):
    events_path = tmp_path / "events.jsonl"
    _write_events(events_path, [_trap("host-a", "change", _ts(100, NOW))])

    cut_path = tmp_path / "cut_state.jsonl"
    with cut_path.open("w", encoding="utf-8") as f:
        f.write(json.dumps({
            "type": "cut",
            "asset_id": "host-a",
            "cut_at": _ts(50, NOW),
            "method": "full",
            "platform": "darwin",
            "modified": ["Wi-Fi"],
        }) + "\n")

    report = compute(log_dir=tmp_path)
    host_a = next(s for s in report.per_asset if s.asset_id == "host-a")
    assert host_a.cut_record is not None
    assert host_a.cut_record.method == "full"


def test_resolved_cut_shows_clear(tmp_path):
    events_path = tmp_path / "events.jsonl"
    _write_events(events_path, [_trap("host-a", "change", _ts(100, NOW))])

    cut_path = tmp_path / "cut_state.jsonl"
    with cut_path.open("w", encoding="utf-8") as f:
        f.write(json.dumps({
            "type": "cut",
            "asset_id": "host-a",
            "cut_at": _ts(50, NOW),
            "method": "full",
            "platform": "darwin",
            "modified": ["Wi-Fi"],
        }) + "\n")
        f.write(json.dumps({
            "type": "resolved",
            "asset_id": "host-a",
            "resolved_at": _ts(10, NOW),
        }) + "\n")

    report = compute(log_dir=tmp_path)
    host_a = next(s for s in report.per_asset if s.asset_id == "host-a")
    assert host_a.cut_record is None


# ─── burst detection ───────────────────────────────────────────────────────────

def test_no_burst_from_read_only_events(tmp_path):
    events_path = tmp_path / "events.jsonl"
    _write_events(events_path, [
        _trap("host-a", "read", _ts(100, NOW)),
        _trap("host-a", "read", _ts(110, NOW)),
        _trap("host-a", "read", _ts(120, NOW)),
    ])
    report = compute(log_dir=tmp_path)
    assert report.bursts == []


def test_two_change_events_within_window_is_burst(tmp_path):
    events_path = tmp_path / "events.jsonl"
    _write_events(events_path, [
        _trap("host-a", "change", _ts(200, NOW)),  # 200s ago
        _trap("host-a", "change", _ts(100, NOW)),  # 100s ago → diff=100s ≤ 300s
    ])
    report = compute(log_dir=tmp_path)
    assert len(report.bursts) == 1
    assert report.bursts[0].event_count == 2


def test_two_change_events_outside_window_no_burst(tmp_path):
    events_path = tmp_path / "events.jsonl"
    _write_events(events_path, [
        _trap("host-a", "change", _ts(400, NOW)),  # 400s ago
        _trap("host-a", "change", _ts(50, NOW)),   # 50s ago → diff=350s > 300s
    ])
    report = compute(log_dir=tmp_path)
    assert report.bursts == []


def test_three_change_events_two_within_window(tmp_path):
    events_path = tmp_path / "events.jsonl"
    # events at t=-400s, t=-200s, t=-50s
    # window [−400, −100]: diff=300s → exactly at boundary, ≤ BURST_WINDOW_SEC
    # [−400, −100] has 2 events: −400 and −200 (diff 200s ≤ 300) — burst
    # then −50 is a separate event
    _write_events(events_path, [
        _trap("host-a", "change", _ts(400, NOW)),
        _trap("host-a", "change", _ts(200, NOW)),  # 200s later → burst!
        _trap("host-a", "change", _ts(50, NOW)),   # 150s later, new window
    ])
    report = compute(log_dir=tmp_path)
    # Should find at least one burst
    assert len(report.bursts) >= 1


def test_burst_outside_30d_not_reported(tmp_path):
    events_path = tmp_path / "events.jsonl"
    # Both events are 31 days ago — outside the 30d window
    _write_events(events_path, [
        _trap("host-a", "change", _ts(31 * 86400 + 200, NOW)),
        _trap("host-a", "change", _ts(31 * 86400 + 100, NOW)),
    ])
    report = compute(log_dir=tmp_path)
    assert report.bursts == []


# ─── render ────────────────────────────────────────────────────────────────────

def test_render_no_log(tmp_path):
    report = compute(log_dir=tmp_path)
    output = render(report)
    assert "no events recorded yet" in output


def test_render_shows_counts(tmp_path):
    events_path = tmp_path / "events.jsonl"
    _write_events(events_path, [
        _trap("host-a", "change", _ts(100, NOW)),
        _trap("host-a", "read",   _ts(200, NOW)),
    ])
    report = compute(log_dir=tmp_path)
    output = render(report)
    assert "all events" in output
    assert "change-class" in output
    assert "read-class" in output
    assert "burst activity" in output


def test_render_burst_warning_present(tmp_path):
    events_path = tmp_path / "events.jsonl"
    _write_events(events_path, [
        _trap("host-a", "change", _ts(200, NOW)),
        _trap("host-a", "change", _ts(100, NOW)),
    ])
    report = compute(log_dir=tmp_path)
    output = render(report)
    assert "⚠" in output
    assert "burst" in output.lower()


def test_cut_without_events_still_shown(tmp_path):
    """An asset with an active cut but no events.jsonl entry must appear in per_asset."""
    # No events.jsonl — skip creating it
    cut_path = tmp_path / "cut_state.jsonl"
    with cut_path.open("w", encoding="utf-8") as f:
        f.write(json.dumps({
            "type": "cut",
            "asset_id": "orphan-host",
            "cut_at": _ts(50, NOW),
            "method": "egress",
            "platform": "darwin",
            "modified": ["__zee_pfctl_egress_anchor__"],
        }) + "\n")

    # Create an empty events.jsonl so log_exists=True
    (tmp_path / "events.jsonl").write_text("")

    report = compute(log_dir=tmp_path)
    ids = [s.asset_id for s in report.per_asset]
    assert "orphan-host" in ids
    orphan = next(s for s in report.per_asset if s.asset_id == "orphan-host")
    assert orphan.cut_record is not None
    assert orphan.cut_record.method == "egress"


def test_render_no_burst_message(tmp_path):
    events_path = tmp_path / "events.jsonl"
    _write_events(events_path, [
        _trap("host-a", "read", _ts(100, NOW)),
    ])
    report = compute(log_dir=tmp_path)
    output = render(report)
    assert "burst activity (30d): none" in output
