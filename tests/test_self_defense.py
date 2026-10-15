"""Self-defence stage 1 (docs/design/self-defense.md).

Regression tests for the cut/restore boundary:
  * a missing / damaged cut ledger must not turn into a broad restore
  * the broad (all-interfaces) restore is an explicit emergency path and
    reports the real per-command outcome
  * a partial cut records what it did change; an empty cut is not success
  * a failed cut is never announced as "applied"
  * the cut boundary re-validates every automatic cut request

No real network or firewall command runs: every OS call is mocked.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest

import zee.responder.sequence as seq
from zee.config.schema import AssetProfile
from zee.errors import ZeeError
from zee.events import TrapEvent
from zee.recovery import restore as restore_mod
from zee.responder import cut_full as full_mod
from zee.telemetry.cut_state import CutStateLog
from zee.telemetry.events_log import EventLog


def _asset(response_mode: str = "auto", cut_method: str = "egress") -> AssetProfile:
    return AssetProfile(
        id="t-host",
        type="workstation",
        overnight_active=False,
        decoy_paths=("/tmp/decoy-self-defense",),
        response_mode=response_mode,  # type: ignore[arg-type]
        cut_method=cut_method,  # type: ignore[arg-type]
    )


def _event(op_class: str = "change", confidence: str = "high") -> TrapEvent:
    return TrapEvent.make(
        source="decoy_touch" if confidence == "high" else "behavior_anomaly",
        confidence=confidence,  # type: ignore[arg-type]
        asset_id="t-host",
        decoy_path="/tmp/decoy-self-defense",
        detail=f"decoy {op_class} (test)",
        op_class=op_class,  # type: ignore[arg-type]
        detected_at=datetime.now(timezone.utc),
    )


@pytest.fixture
def quiet(monkeypatch):
    titles: list[str] = []
    monkeypatch.setattr(restore_mod, "notify_local", lambda t, b: titles.append(t) or True)
    monkeypatch.setattr(seq, "notify_local", lambda t, b: titles.append(t) or True)
    return titles


# ── restore: a missing ledger record never means "enable everything" ──


def _no_compat(monkeypatch):
    def boom():
        raise AssertionError("broad compat restore must not run")
    monkeypatch.setattr(restore_mod, "_restore_compat", boom)


def test_restore_without_record_refuses_and_does_not_enable_everything(tmp_path, monkeypatch, quiet):
    _no_compat(monkeypatch)
    log = CutStateLog(tmp_path / "cut_state.jsonl")
    with pytest.raises(ZeeError) as ei:
        restore_mod.restore("t-host", cut_state=log)
    assert ei.value.code == "Z605"
    assert any("REFUSED" in t for t in quiet)
    assert not (tmp_path / "cut_state.jsonl").exists()  # nothing marked resolved


def test_restore_with_damaged_ledger_refuses(tmp_path, monkeypatch, quiet):
    _no_compat(monkeypatch)
    p = tmp_path / "cut_state.jsonl"
    p.write_text("{not json\n\x00\x00garbage\n", encoding="utf-8")
    with pytest.raises(ZeeError) as ei:
        restore_mod.restore("t-host", cut_state=CutStateLog(p))
    assert ei.value.code == "Z605"


def test_restore_of_other_asset_does_not_touch_recorded_cut(tmp_path, monkeypatch, quiet):
    """Asset B has no record while asset A is cut: B's restore must not undo A."""
    _no_compat(monkeypatch)
    log = CutStateLog(tmp_path / "cut_state.jsonl")
    log.record_cut(asset_id="a", method="egress", platform="linux", modified=["__zee_nft_egress_table__"])
    with pytest.raises(ZeeError):
        restore_mod.restore("b", cut_state=log)
    assert log.latest_unresolved_for("a") is not None


def test_emergency_all_interfaces_restore_reports_real_failure(tmp_path, monkeypatch, quiet):
    monkeypatch.setattr(restore_mod.sys, "platform", "linux")
    monkeypatch.setattr(restore_mod.shutil, "which", lambda name: f"/usr/sbin/{name}")
    monkeypatch.setattr(restore_mod, "_run", lambda cmd: (False, "operation not permitted"))
    log = CutStateLog(tmp_path / "cut_state.jsonl")
    with pytest.raises(ZeeError) as ei:
        restore_mod.restore("t-host", cut_state=log, all_interfaces=True)
    assert ei.value.code == "Z601"
    assert any("FAILED" in t for t in quiet)


def test_emergency_all_interfaces_macos_reports_real_failure(monkeypatch):
    monkeypatch.setattr(restore_mod.shutil, "which", lambda name: f"/usr/sbin/{name}")
    monkeypatch.setattr(restore_mod, "list_macos_services", lambda: ["Wi-Fi"])
    monkeypatch.setattr(restore_mod, "_run", lambda cmd: (False, "denied"))
    ok, _ = restore_mod._restore_macos_compat()
    assert ok is False


def test_emergency_all_interfaces_windows_reports_real_failure(monkeypatch):
    monkeypatch.setattr(restore_mod.shutil, "which", lambda name: f"C:/{name}")
    monkeypatch.setattr(restore_mod, "list_windows_interfaces", lambda only_enabled: ["Ethernet"])
    monkeypatch.setattr(restore_mod, "_run", lambda cmd: (False, "denied"))
    ok, _ = restore_mod._restore_windows_compat()
    assert ok is False


def test_emergency_all_interfaces_with_no_tool_is_not_success(monkeypatch):
    monkeypatch.setattr(restore_mod.shutil, "which", lambda name: None)
    assert restore_mod._restore_linux_compat()[0] is False
    assert restore_mod._restore_macos_compat()[0] is False
    assert restore_mod._restore_windows_compat()[0] is False


def test_cli_restore_all_interfaces_flag(tmp_path, monkeypatch):
    from zee import cli
    cfg = tmp_path / "assets.toml"
    cfg.write_text(
        'dry_run = true\n[[assets]]\nid = "t-host"\ntype = "workstation"\n'
        'overnight_active = false\ndecoy_paths = ["/tmp/x"]\n'
        'response_mode = "notify"\ncut_method = "egress"\n',
        encoding="utf-8",
    )
    seen = {}
    monkeypatch.setattr(cli, "verify_token", lambda t: True)
    monkeypatch.setattr(cli, "restore", lambda a, **kw: seen.update(kw) or (True, "ok"))
    args = cli.build_parser().parse_args(
        ["-c", str(cfg), "restore", "t-host", "--token", "x", "--all-interfaces"])
    assert args.func(args) == 0
    assert seen == {"all_interfaces": True}
    args = cli.build_parser().parse_args(["-c", str(cfg), "restore", "t-host", "--token", "x"])
    args.func(args)
    assert seen == {"all_interfaces": False}


# ── cut: record what changed; empty is not success ────────────────────


def test_partial_cut_records_the_interfaces_that_went_down(tmp_path, monkeypatch):
    monkeypatch.setattr(full_mod.sys, "platform", "linux")
    monkeypatch.setattr(full_mod.shutil, "which", lambda name: "/sbin/ip" if name == "ip" else None)
    monkeypatch.setattr(full_mod, "list_linux_interfaces", lambda: ["eth0", "eth1"])
    monkeypatch.setattr(full_mod, "_run", lambda cmd: (cmd[3] == "eth0", ""))
    log = CutStateLog(tmp_path / "cut_state.jsonl")
    ok, _ = full_mod.cut_full(asset_id="t-host", cut_state=log)
    assert ok is False
    rec = log.latest_unresolved_for("t-host")
    assert rec is not None and rec.modified == ("eth0",)


@pytest.mark.parametrize("platform", ["linux", "darwin"])
def test_cut_with_nothing_to_disable_is_not_success(platform, monkeypatch):
    monkeypatch.setattr(full_mod.sys, "platform", platform)
    monkeypatch.setattr(full_mod.shutil, "which",
                        lambda name: f"/sbin/{name}" if name in ("ip", "networksetup") else None)
    monkeypatch.setattr(full_mod, "list_linux_interfaces", lambda: [])
    monkeypatch.setattr(full_mod, "list_macos_services", lambda: [])
    ok, _ = full_mod.cut_full()
    assert ok is False


# ── handle(): a failed cut is never announced as applied ──────────────


def test_failed_cut_is_announced_as_failed(tmp_path, monkeypatch, quiet):
    monkeypatch.setattr(seq, "cut_egress", lambda **_k: (False, "permission denied"))
    result = seq.handle(_event(), _asset(), dry_run=False, event_log=EventLog(log_dir=tmp_path))
    assert result.cut_executed is False
    assert not any("cut applied" in t for t in quiet)
    assert any("cut FAILED" in t for t in quiet)


# ── cut boundary: every automatic request is re-validated ─────────────


def test_boundary_accepts_the_one_allowed_shape():
    from zee.responder.blocker import CutRequest, refusal
    req = CutRequest(asset_id="t-host", op_class="change", confidence="high")
    assert refusal(req, _asset(), dry_run=False) is None


@pytest.mark.parametrize("req_kw, asset_kw, dry_run, reason", [
    ({"asset_id": "other"}, {}, False, "asset_mismatch"),
    ({"op_class": "read"}, {}, False, "op_class_not_change"),
    ({"confidence": "medium"}, {}, False, "confidence_not_high"),
    ({}, {"response_mode": "notify"}, False, "mode_not_contain"),
    ({}, {}, True, "dry_run"),
    ({"op_class": "CHANGE"}, {}, False, "op_class_not_change"),
    ({"asset_id": ""}, {}, False, "asset_mismatch"),
])
def test_boundary_refuses_everything_else(req_kw, asset_kw, dry_run, reason):
    from zee.responder.blocker import CutRequest, refusal
    base = {"asset_id": "t-host", "op_class": "change", "confidence": "high"}
    req = CutRequest(**{**base, **req_kw})
    assert refusal(req, _asset(**asset_kw), dry_run=dry_run) == reason


def test_handle_does_not_cut_when_boundary_refuses(tmp_path, monkeypatch, quiet):
    """Even if the gate in handle() were bypassed, the boundary must refuse."""
    import zee.responder.blocker as blocker
    cuts: list = []
    monkeypatch.setattr(seq, "cut_egress", lambda **k: cuts.append(k) or (True, "stub"))
    monkeypatch.setattr(blocker, "refusal", lambda *a, **k: "asset_mismatch")
    result = seq.handle(_event(), _asset(), dry_run=False, event_log=EventLog(log_dir=tmp_path))
    assert cuts == []
    assert result.cut_executed is False
    assert result.cut_skipped_reason == "boundary:asset_mismatch"
