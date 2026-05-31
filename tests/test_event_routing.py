"""Confidence gate, dry_run, and mode resolution tests (spec §2, §4, §5, §6)."""

from __future__ import annotations

import json
import tempfile
from datetime import datetime, timezone
from pathlib import Path

import pytest

from zee.config.schema import AssetProfile
from zee.errors import ZeeError, Z403_INVALID_CONFIDENCE_FOR_CONTAIN
from zee.events import TrapEvent
from zee.responder.sequence import handle
from zee.telemetry.events_log import EventLog


def _make_event(
    confidence: str = "high",
    source: str = "decoy_touch",
    op_class: str = "change",
) -> TrapEvent:
    return TrapEvent.make(
        source=source,  # type: ignore[arg-type]
        confidence=confidence,  # type: ignore[arg-type]
        asset_id="t-host",
        decoy_path="/tmp/decoy",
        detail="test event",
        op_class=op_class,  # type: ignore[arg-type]
        detected_at=datetime.now(timezone.utc),
    )


def _make_asset(response_mode: str = "auto", cut_method: str = "egress") -> AssetProfile:
    return AssetProfile(
        id="t-host",
        type="workstation",
        overnight_active=False,
        decoy_paths=("/tmp/decoy",),
        response_mode=response_mode,  # type: ignore[arg-type]
        cut_method=cut_method,  # type: ignore[arg-type]
    )


def test_decoy_touch_must_be_high_confidence():
    with pytest.raises(ValueError):
        TrapEvent.make(
            source="decoy_touch",
            confidence="medium",
            asset_id="x", decoy_path=None, detail="x",
            op_class="change",
        )


def test_dry_run_never_calls_real_cut(monkeypatch):
    called = {"cut_full": 0, "cut_egress": 0}

    def boom_full():
        called["cut_full"] += 1
        return True, "should not be called"

    def boom_egress():
        called["cut_egress"] += 1
        return True, "should not be called"

    import zee.responder.sequence as seq
    monkeypatch.setattr(seq, "cut_full", boom_full)
    monkeypatch.setattr(seq, "cut_egress", boom_egress)

    with tempfile.TemporaryDirectory() as td:
        log = EventLog(log_dir=Path(td))
        result = handle(
            _make_event(),
            _make_asset(response_mode="auto", cut_method="egress"),
            dry_run=True,
            event_log=log,
        )
    assert called["cut_full"] == 0
    assert called["cut_egress"] == 0
    assert result.cut_executed is False
    assert result.cut_would_have_been_executed is True
    assert result.mode == "contain"


def test_notify_mode_skips_cut_entirely(monkeypatch):
    called = {"cut": 0}

    def boom():
        called["cut"] += 1
        return True, "should not be called"

    import zee.responder.sequence as seq
    monkeypatch.setattr(seq, "cut_full", boom)
    monkeypatch.setattr(seq, "cut_egress", boom)

    with tempfile.TemporaryDirectory() as td:
        log = EventLog(log_dir=Path(td))
        result = handle(
            _make_event(),
            _make_asset(response_mode="notify"),
            dry_run=False,  # even with dry_run=False, notify mode must not cut
            event_log=log,
        )
    assert called["cut"] == 0
    assert result.cut_executed is False
    assert result.cut_would_have_been_executed is False
    assert result.mode == "notify"


def test_contain_with_low_confidence_raises():
    """Even outside dry_run, low/medium confidence must not enter cut path."""
    # We can't construct a low-confidence decoy_touch (TrapEvent rejects it),
    # but a behavior_anomaly event can be low confidence.
    event = _make_event(confidence="medium", source="behavior_anomaly")
    asset = _make_asset(response_mode="auto")
    with tempfile.TemporaryDirectory() as td:
        log = EventLog(log_dir=Path(td))
        with pytest.raises(ZeeError) as exc:
            handle(event, asset, dry_run=False, event_log=log)
        assert exc.value.code == Z403_INVALID_CONFIDENCE_FOR_CONTAIN[0]


def test_latency_recorded(monkeypatch):
    monkeypatch.setattr("zee.responder.sequence.cut_egress",
                        lambda: (True, "stub"))
    with tempfile.TemporaryDirectory() as td:
        log = EventLog(log_dir=Path(td))
        handle(_make_event(), _make_asset(response_mode="auto", cut_method="egress"),
               dry_run=False, event_log=log)
        lines = log.metrics_path.read_text().strip().split("\n")
        assert len(lines) == 1
        record = json.loads(lines[0])
        assert record["type"] == "latency"
        assert record["asset_id"] == "t-host"
        assert record["mode"] == "contain"
        assert record["cut_done_at"] is not None
        assert record["dry_run"] is False


def test_events_jsonl_records_op_class(monkeypatch):
    """spec v4 addendum 2: op_class must be persisted in events.jsonl for audit."""
    monkeypatch.setattr("zee.responder.sequence.cut_egress",
                        lambda: (True, "stub"))
    with tempfile.TemporaryDirectory() as td:
        log = EventLog(log_dir=Path(td))
        handle(
            _make_event(op_class="change"),
            _make_asset(response_mode="auto", cut_method="egress"),
            dry_run=True,
            event_log=log,
        )
        # also exercise the read path
        handle(
            _make_event(op_class="read"),
            _make_asset(response_mode="auto", cut_method="egress"),
            dry_run=True,
            event_log=log,
        )
        lines = log.events_path.read_text().strip().split("\n")
        assert len(lines) == 2
        rec_change = json.loads(lines[0])
        rec_read = json.loads(lines[1])
        assert rec_change["type"] == "trap_event"
        assert rec_change["op_class"] == "change"
        assert rec_read["op_class"] == "read"
