"""Trigger limit on op_class — spec v4 block C.

Auto-cut is gated by ALL of:
  mode == "contain"
  AND confidence == "high"
  AND op_class == "change"   ← v4-added
  AND not dry_run

The decision is made on the structured op_class field, NOT by parsing
the detail string. read-class touches under mode=contain notify only;
they require manual `zee cut` to actually cut.
"""

from __future__ import annotations

import tempfile
from datetime import datetime, timezone
from pathlib import Path

from zee.config.schema import AssetProfile
from zee.events import TrapEvent
from zee.responder.sequence import handle
from zee.telemetry.events_log import EventLog


def _make_event(op_class: str) -> TrapEvent:
    return TrapEvent.make(
        source="decoy_touch",
        confidence="high",
        asset_id="t-host",
        decoy_path="/tmp/decoy-op-class",
        detail=f"decoy {op_class} (test)",
        op_class=op_class,  # type: ignore[arg-type]
        detected_at=datetime.now(timezone.utc),
    )


def _make_asset(response_mode: str = "auto", cut_method: str = "egress") -> AssetProfile:
    return AssetProfile(
        id="t-host",
        type="workstation",
        overnight_active=False,
        decoy_paths=("/tmp/decoy-op-class",),
        response_mode=response_mode,  # type: ignore[arg-type]
        cut_method=cut_method,  # type: ignore[arg-type]
    )


def test_read_op_class_does_not_cut_even_in_contain_mode(monkeypatch):
    """Spec v4 core: read touches never auto-cut, even with auto + no-dry-run."""
    cut_calls = {"egress": 0, "full": 0}

    def stub_egress(**kwargs):
        cut_calls["egress"] += 1
        return True, "should not be called"

    def stub_full(**kwargs):
        cut_calls["full"] += 1
        return True, "should not be called"

    import zee.responder.sequence as seq
    monkeypatch.setattr(seq, "cut_egress", stub_egress)
    monkeypatch.setattr(seq, "cut_full", stub_full)

    with tempfile.TemporaryDirectory() as td:
        log = EventLog(log_dir=Path(td))
        result = handle(
            _make_event("read"),
            _make_asset(response_mode="auto", cut_method="egress"),
            dry_run=False,  # no dry_run safety net
            event_log=log,
        )

    assert cut_calls["egress"] == 0, "read touch must not call cut_egress"
    assert cut_calls["full"] == 0, "read touch must not call cut_full"
    assert result.cut_executed is False
    assert result.cut_would_have_been_executed is False
    assert result.cut_skipped_reason == "op_class=read"
    assert result.mode == "contain"


def test_change_op_class_does_cut(monkeypatch):
    """change + contain + high + not dry_run → cut runs."""
    cut_calls = {"egress": 0}

    def stub_egress(**kwargs):
        cut_calls["egress"] += 1
        return True, "ok"

    import zee.responder.sequence as seq
    monkeypatch.setattr(seq, "cut_egress", stub_egress)

    with tempfile.TemporaryDirectory() as td:
        log = EventLog(log_dir=Path(td))
        result = handle(
            _make_event("change"),
            _make_asset(response_mode="auto", cut_method="egress"),
            dry_run=False,
            event_log=log,
        )

    assert cut_calls["egress"] == 1
    assert result.cut_executed is True
    assert result.cut_skipped_reason is None


def test_change_op_class_dry_run_records_would_have_cut(monkeypatch):
    """dry_run + change + contain → cut is NOT actually run, but recorded."""
    cut_calls = {"egress": 0}

    def stub_egress(**kwargs):
        cut_calls["egress"] += 1
        return True, "should not be called under dry_run"

    import zee.responder.sequence as seq
    monkeypatch.setattr(seq, "cut_egress", stub_egress)

    with tempfile.TemporaryDirectory() as td:
        log = EventLog(log_dir=Path(td))
        result = handle(
            _make_event("change"),
            _make_asset(response_mode="auto", cut_method="egress"),
            dry_run=True,
            event_log=log,
        )

    assert cut_calls["egress"] == 0
    assert result.cut_executed is False
    assert result.cut_would_have_been_executed is True
    assert result.cut_skipped_reason is None  # the dry_run path is not the op_class skip


def test_read_op_class_with_notify_mode_still_notifies(monkeypatch):
    """notify mode never cuts (existing behavior), regardless of op_class."""
    cut_calls = {"any": 0}

    def stub_any(**kwargs):
        cut_calls["any"] += 1
        return True, "should not be called"

    import zee.responder.sequence as seq
    monkeypatch.setattr(seq, "cut_egress", stub_any)
    monkeypatch.setattr(seq, "cut_full", stub_any)

    with tempfile.TemporaryDirectory() as td:
        log = EventLog(log_dir=Path(td))
        result = handle(
            _make_event("read"),
            _make_asset(response_mode="notify"),
            dry_run=False,
            event_log=log,
        )

    assert cut_calls["any"] == 0
    assert result.mode == "notify"


def test_hint_text_contains_zee_cut_for_read(monkeypatch):
    """Read hint must include the manual cut command, not say "ignore"."""
    from zee.responder.sequence import _hint_for
    h = _hint_for("read", "host-a")
    assert "zee cut host-a" in h
    assert "無視" not in h
    assert "可能性" in h


def test_hint_text_contains_zee_cut_for_change():
    from zee.responder.sequence import _hint_for
    h = _hint_for("change", "host-b")
    assert "zee cut host-b" in h
    assert "zee restore host-b" in h
    assert "無視" not in h


def test_decision_is_on_structured_field_not_detail_string(monkeypatch):
    """Smoke test: a read event whose detail happens to contain the
    word 'change' must still be treated as read (no cut)."""
    cut_calls = {"any": 0}

    def stub_any(**kwargs):
        cut_calls["any"] += 1
        return True, "should not be called"

    import zee.responder.sequence as seq
    monkeypatch.setattr(seq, "cut_egress", stub_any)
    monkeypatch.setattr(seq, "cut_full", stub_any)

    misleading = TrapEvent.make(
        source="decoy_touch",
        confidence="high",
        asset_id="t-host",
        decoy_path="/tmp/decoy-op-class",
        detail="this string mentions change but it is a read",
        op_class="read",
        detected_at=datetime.now(timezone.utc),
    )
    with tempfile.TemporaryDirectory() as td:
        log = EventLog(log_dir=Path(td))
        result = handle(
            misleading,
            _make_asset(response_mode="auto", cut_method="egress"),
            dry_run=False,
            event_log=log,
        )
    assert cut_calls["any"] == 0
    assert result.cut_skipped_reason == "op_class=read"
