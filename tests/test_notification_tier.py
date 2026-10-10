"""Notification impact tier (docs/design/notification-tier.md).

Display layer only. The core guarantee under test: whatever this module
computes (or if it raises), the containment decision in
`responder.sequence.handle` must not change.
"""

from __future__ import annotations

import tempfile
from datetime import datetime, timezone
from pathlib import Path

import pytest

from zee.config.schema import AssetProfile
from zee.events import TrapEvent
from zee.decoy.seeder import _TEMPLATES
from zee.notifier import tier as tier_mod
from zee.notifier.tier import (
    TierResult,
    _authority,
    _business_reach,
    _CREDENTIAL_TEMPLATES,
    classify,
    reason_line,
    safe_classify,
)
from zee.responder.sequence import handle
from zee.telemetry.events_log import EventLog


def _event(op_class: str = "change", decoy_path: str | None = "/srv/app/.env") -> TrapEvent:
    return TrapEvent.make(
        source="decoy_touch",
        confidence="high",
        asset_id="t-host",
        decoy_path=decoy_path,
        detail="test touch",
        op_class=op_class,  # type: ignore[arg-type]
        detected_at=datetime.now(timezone.utc),
    )


def _asset(
    asset_type: str = "workstation",
    overnight_active: bool = False,
    decoy_paths: tuple[str, ...] = ("/srv/app/.env",),
    response_mode: str = "auto",
    cut_method: str = "egress",
) -> AssetProfile:
    return AssetProfile(
        id="t-host",
        type=asset_type,  # type: ignore[arg-type]
        overnight_active=overnight_active,
        decoy_paths=decoy_paths,
        response_mode=response_mode,  # type: ignore[arg-type]
        cut_method=cut_method,  # type: ignore[arg-type]
    )


# ---------------------------------------------------------------------------
# Axis / level computation
# ---------------------------------------------------------------------------

def test_credential_path_on_shared_overnight_asset_is_tier4():
    """All three axes high: credential path, server, 3+ decoys, overnight."""
    event = _event(decoy_path="/srv/.env")
    asset = _asset(
        asset_type="server",
        overnight_active=True,
        decoy_paths=("/srv/.env", "/srv/notes.txt", "/srv/id_rsa"),
    )
    result = classify(event, asset)
    assert result.level == 4
    assert result.label == "重大"


def test_general_file_on_lone_workstation_is_tier1():
    event = _event(op_class="read", decoy_path="/home/u/readme.txt")
    asset = _asset(asset_type="workstation", overnight_active=False, decoy_paths=("/home/u/readme.txt",))
    result = classify(event, asset)
    assert result.level == 1
    assert result.label == "情報"


def test_personal_data_keyword_is_mid_sensitivity():
    event = _event(op_class="read", decoy_path="/data/customer_list.csv")
    asset = _asset(asset_type="workstation", decoy_paths=("/data/customer_list.csv",))
    result = classify(event, asset)
    assert "個人情報" in result.sensitivity_category


def test_missing_decoy_path_defaults_to_unknown_not_unclassifiable():
    """No '判定不能' category — unknown still gets a level and says so."""
    event = _event(op_class="read", decoy_path=None)
    asset = _asset()
    result = classify(event, asset)
    assert result.level in (1, 2, 3, 4)
    assert any("未確認" in axis for axis in result.confirmed_axes)


def test_change_op_class_floors_the_level_at_2():
    """A 'general file' workstation would compute level 1, but a change
    touch must not display below 注意 (contradicts the existing
    _hint_for 'high danger' wording otherwise)."""
    event = _event(op_class="change", decoy_path="/home/u/readme.txt")
    asset = _asset(asset_type="workstation", decoy_paths=("/home/u/readme.txt",))
    result = classify(event, asset)
    assert result.level >= 2


def test_single_high_axis_is_tier3_not_tier4():
    """Exactly one axis at level 2 (credential, workstation, no other
    high signal) -> 警戒(3), not 重大(4) (needs >=2 high axes)."""
    event = _event(op_class="read", decoy_path="/home/u/.env")
    asset = _asset(asset_type="workstation", overnight_active=False, decoy_paths=("/home/u/.env",))
    result = classify(event, asset)
    assert result.level == 3
    assert result.label == "警戒"


def test_mid_axis_only_is_tier2():
    """One axis at level 1, none at level 2 -> 注意(2)."""
    event = _event(op_class="read", decoy_path="/data/customer_list.csv")
    asset = _asset(asset_type="workstation", overnight_active=False, decoy_paths=("/data/customer_list.csv",))
    result = classify(event, asset)
    assert result.level == 2


def test_ot_asset_counts_as_shared_like_server():
    assert _authority(sensitivity_level=2, asset_type="ot") == 2
    assert _authority(sensitivity_level=2, asset_type="server") == 2
    assert _authority(sensitivity_level=2, asset_type="workstation") == 1
    assert _authority(sensitivity_level=0, asset_type="workstation") == 0


@pytest.mark.parametrize(
    "decoy_count,asset_type,overnight,expected",
    [
        (1, "workstation", False, 0),  # 0 of 3 signals true
        (2, "workstation", False, 0),  # 0 of 3
        (3, "workstation", False, 0),  # 1 of 3 (count only) -> still 0
        (1, "server", True, 1),        # 2 of 3 (shared + overnight)
        (3, "server", False, 1),       # 2 of 3 (count + shared)
        (3, "server", True, 2),        # 3 of 3
    ],
)
def test_business_reach_signal_counting(decoy_count, asset_type, overnight, expected):
    paths = tuple(f"/srv/f{i}" for i in range(decoy_count)) or ("/srv/f0",)
    asset = _asset(asset_type=asset_type, overnight_active=overnight, decoy_paths=paths)
    assert _business_reach(asset) == expected


def test_credential_templates_are_a_subset_of_seeder_templates():
    """If decoy.seeder._TEMPLATES ever drops a key, this must fail loudly
    instead of silently under-classifying sensitivity."""
    assert _CREDENTIAL_TEMPLATES <= set(_TEMPLATES)


def test_reason_line_has_no_counts_and_no_raw_path():
    event = _event(decoy_path="/srv/secret/credentials.txt")
    asset = _asset(decoy_paths=("/srv/secret/credentials.txt", "a", "b", "c"))
    result = classify(event, asset)
    line = reason_line(result, action="detect")
    assert "/srv/secret/credentials.txt" not in line
    assert "credentials.txt" not in line
    # no digit-prefixed file count ("対象Nファイル" style overclaim)
    assert not any(ch.isdigit() for ch in line)


def test_reason_line_does_not_claim_containment_when_cut_failed(monkeypatch):
    """cut_fn can return ok=False (e.g. the cut
    backend lacks privileges). The notification must not say '封じ込め'
    (contained) in that case."""
    import zee.responder.sequence as seq

    monkeypatch.setattr(seq, "cut_egress", lambda **_k: (False, "permission denied"))
    bodies: list[str] = []
    monkeypatch.setattr(seq, "notify_local", lambda title, body: bodies.append(body) or True)
    with tempfile.TemporaryDirectory() as td:
        log = EventLog(log_dir=Path(td))
        result = handle(
            _event(op_class="change"),
            _asset(response_mode="auto", cut_method="egress"),
            dry_run=False,
            event_log=log,
        )
    assert result.cut_executed is False
    cut_notification_bodies = [b for b in bodies if "recover with" in b]
    assert len(cut_notification_bodies) == 1
    assert "封じ込め。" not in cut_notification_bodies[0]
    assert "失敗" in cut_notification_bodies[0]


def test_safe_classify_degrades_to_lowest_tier_on_exception(monkeypatch):
    monkeypatch.setattr(tier_mod, "classify", lambda *_a, **_k: (_ for _ in ()).throw(RuntimeError("boom")))
    result = safe_classify(_event(), _asset())
    assert result.level == 1
    assert result.label == "情報"


# ---------------------------------------------------------------------------
# Independence from the containment decision (1-3 required test)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("forced_level", [1, 2, 3, 4])
def test_tier_value_does_not_change_cut_outcome(monkeypatch, forced_level):
    monkeypatch.setattr(
        "zee.responder.sequence.safe_classify",
        lambda *_a, **_k: TierResult(
            level=forced_level,
            label=tier_mod.LEVEL_LABELS[forced_level],
            sensitivity_category="一般ファイル",
            confirmed_axes=("test",),
        ),
    )
    import zee.responder.sequence as seq

    monkeypatch.setattr(seq, "cut_egress", lambda **_k: (True, "stubbed"))
    with tempfile.TemporaryDirectory() as td:
        log = EventLog(log_dir=Path(td))
        result = handle(
            _event(op_class="change"),
            _asset(response_mode="auto", cut_method="egress"),
            dry_run=False,
            event_log=log,
        )
    assert result.mode == "contain"
    assert result.cut_executed is True
    assert result.cut_skipped_reason is None


@pytest.mark.parametrize("forced_level", [1, 2, 3, 4])
def test_tier_value_does_not_change_dry_run_outcome(monkeypatch, forced_level):
    """Same independence check, but through the dry_run branch
    (cut_would_have_been_executed) instead of the real-cut branch."""
    monkeypatch.setattr(
        "zee.responder.sequence.safe_classify",
        lambda *_a, **_k: TierResult(
            level=forced_level,
            label=tier_mod.LEVEL_LABELS[forced_level],
            sensitivity_category="一般ファイル",
            confirmed_axes=("test",),
        ),
    )
    with tempfile.TemporaryDirectory() as td:
        log = EventLog(log_dir=Path(td))
        result = handle(
            _event(op_class="change"),
            _asset(response_mode="auto", cut_method="egress"),
            dry_run=True,
            event_log=log,
        )
    assert result.cut_executed is False
    assert result.cut_would_have_been_executed is True
    assert result.cut_skipped_reason is None


@pytest.mark.parametrize("forced_level", [1, 2, 3, 4])
def test_tier_value_does_not_change_read_skip_outcome(monkeypatch, forced_level):
    """Same independence check, but through the op_class=read skip branch
    (cut_skipped_reason) instead of the real-cut branch."""
    monkeypatch.setattr(
        "zee.responder.sequence.safe_classify",
        lambda *_a, **_k: TierResult(
            level=forced_level,
            label=tier_mod.LEVEL_LABELS[forced_level],
            sensitivity_category="一般ファイル",
            confirmed_axes=("test",),
        ),
    )
    with tempfile.TemporaryDirectory() as td:
        log = EventLog(log_dir=Path(td))
        result = handle(
            _event(op_class="read"),
            _asset(response_mode="auto", cut_method="egress"),
            dry_run=False,
            event_log=log,
        )
    assert result.cut_executed is False
    assert result.cut_would_have_been_executed is False
    assert result.cut_skipped_reason == "op_class=read"


def test_tier_classifier_raising_does_not_block_notify_or_cut(monkeypatch):
    """classify() (the inner, unwrapped function) raises. sequence.py calls
    safe_classify, which must catch it — notification still fires and the
    cut outcome is identical to the no-bug case."""

    def _boom(*_a, **_k):
        raise RuntimeError("tier is broken")

    monkeypatch.setattr(tier_mod, "classify", _boom)
    import zee.responder.sequence as seq

    monkeypatch.setattr(seq, "cut_egress", lambda **_k: (True, "stubbed"))
    # Don't depend on a real desktop-notification backend being present
    # (notify-send/osascript/powershell availability varies by machine/CI).
    notify_calls: list[str] = []
    monkeypatch.setattr(seq, "notify_local", lambda title, body: notify_calls.append(title) or True)
    with tempfile.TemporaryDirectory() as td:
        log = EventLog(log_dir=Path(td))
        result = handle(
            _event(op_class="change"),
            _asset(response_mode="auto", cut_method="egress"),
            dry_run=False,
            event_log=log,
        )
    assert len(notify_calls) >= 1, "step1 notification must still fire when tier classification raises"
    assert result.notified_locally is True
    assert result.mode == "contain"
    assert result.cut_executed is True
    assert result.cut_skipped_reason is None
