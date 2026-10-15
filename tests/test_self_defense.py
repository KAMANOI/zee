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
    monkeypatch.setattr(restore_mod, "list_linux_interfaces", lambda: ["eth0"])
    monkeypatch.setattr(restore_mod, "_run", lambda cmd: (False, "operation not permitted"))
    log = CutStateLog(tmp_path / "cut_state.jsonl")
    with pytest.raises(ZeeError) as ei:
        restore_mod.restore("t-host", cut_state=log, all_interfaces=True)
    assert ei.value.code == "Z601"
    assert any("FAILED" in t for t in quiet)


def test_emergency_all_interfaces_macos_reports_real_failure(monkeypatch):
    monkeypatch.setattr(restore_mod.shutil, "which", lambda name: f"/usr/sbin/{name}")
    monkeypatch.setattr(restore_mod, "list_macos_services", lambda **k: ["Wi-Fi"])
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


# ── independent check (ASTRA) findings, 2026-10-15 ────────────────────


def test_emergency_macos_reenables_services_the_full_cut_disabled(monkeypatch):
    out = "An asterisk (*) denotes that a network service is disabled.\n*Wi-Fi\n*Ethernet\n"
    monkeypatch.setattr(full_mod.subprocess, "check_output", lambda *a, **k: out)
    monkeypatch.setattr(restore_mod, "list_macos_services", full_mod.list_macos_services)
    monkeypatch.setattr(restore_mod.shutil, "which", lambda name: f"/usr/sbin/{name}")
    calls: list = []
    monkeypatch.setattr(restore_mod, "_run", lambda cmd: calls.append(cmd) or (True, ""))
    ok, _ = restore_mod._restore_macos_compat()
    assert ok is True
    enabled = [c[2] for c in calls if c[0] == "networksetup"]
    assert enabled == ["Wi-Fi", "Ethernet"]
    assert full_mod.list_macos_services() == []  # cut still skips disabled ones


def test_emergency_linux_removes_egress_rule_even_when_nmcli_succeeds(monkeypatch):
    monkeypatch.setattr(restore_mod.shutil, "which", lambda name: f"/usr/bin/{name}")
    monkeypatch.setattr(restore_mod, "list_linux_interfaces", lambda: ["eth0"])
    calls: list = []
    monkeypatch.setattr(restore_mod, "_run", lambda cmd: calls.append(cmd) or (True, ""))
    ok, _ = restore_mod._restore_linux_compat()
    assert ok is True
    assert ["nft", "delete", "table", "inet", "zee_egress"] in calls
    assert ["iptables", "-X", "ZEE_EGRESS"] in calls


def test_emergency_linux_does_not_hide_one_failed_firewall_removal(monkeypatch):
    monkeypatch.setattr(restore_mod.shutil, "which", lambda name: f"/usr/bin/{name}")
    monkeypatch.setattr(restore_mod, "_run",
                        lambda cmd: (False, "Operation not permitted") if cmd[0] == "nft" else (True, ""))
    ok, detail = restore_mod._restore_linux_compat()
    assert ok is False and "nft:fail" in detail


def test_emergency_treats_already_absent_rule_as_removed(monkeypatch):
    monkeypatch.setattr(restore_mod.shutil, "which", lambda name: f"/usr/bin/{name}")
    def run(cmd):
        if cmd[0] == "nft":
            return False, "Error: Could not process rule: No such file or directory"
        if cmd[0] == "iptables":
            return False, "iptables: No chain/target/match by that name."
        return True, ""
    monkeypatch.setattr(restore_mod, "_run", run)
    assert restore_mod._restore_linux_compat()[0] is True


@pytest.mark.parametrize("content", ["[]\n", "null\n", b"\xff\xfe\n"])
def test_emergency_restore_works_with_any_ledger_damage(tmp_path, monkeypatch, quiet, content):
    p = tmp_path / "cut_state.jsonl"
    (p.write_bytes if isinstance(content, bytes) else p.write_text)(content)
    monkeypatch.setattr(restore_mod, "_restore_compat", lambda: (True, "all on"))
    assert restore_mod.restore("t-host", cut_state=CutStateLog(p), all_interfaces=True)[0] is True


@pytest.mark.parametrize("content", ["[]\n", "null\n", b"\xff\xfe\n"])
def test_normal_restore_refuses_any_ledger_damage(tmp_path, monkeypatch, quiet, content):
    _no_compat(monkeypatch)
    p = tmp_path / "cut_state.jsonl"
    (p.write_bytes if isinstance(content, bytes) else p.write_text)(content)
    with pytest.raises(ZeeError) as ei:
        restore_mod.restore("t-host", cut_state=CutStateLog(p))
    assert ei.value.code == "Z605"


def test_good_old_record_plus_damaged_line_refuses(tmp_path, monkeypatch, quiet):
    _no_compat(monkeypatch)
    log = CutStateLog(tmp_path / "cut_state.jsonl")
    log.record_cut(asset_id="t-host", method="full", platform="darwin", modified=["Wi-Fi"])
    with log.path.open("a") as f:
        f.write('{"type": "cut", "asset_id": "t-host"\n')
    targeted: list = []
    monkeypatch.setattr(restore_mod, "_restore_targeted", lambda r: targeted.append(r) or (True, ""))
    with pytest.raises(ZeeError) as ei:
        restore_mod.restore("t-host", cut_state=log)
    assert ei.value.code == "Z605" and targeted == []


def test_cut_record_with_empty_modified_is_damage(tmp_path):
    p = tmp_path / "cut_state.jsonl"
    p.write_text('{"type":"cut","asset_id":"t-host","cut_at":"2026-10-15T00:00:00+00:00","modified":[]}\n')
    rec, damaged = CutStateLog(p).unresolved_for("t-host")
    assert rec is None and damaged is True


def test_second_cut_does_not_hide_what_the_first_changed(tmp_path):
    log = CutStateLog(tmp_path / "cut_state.jsonl")
    log.record_cut(asset_id="t-host", method="full", platform="darwin", modified=["Wi-Fi"])
    log.record_cut(asset_id="t-host", method="full", platform="darwin", modified=["Ethernet", "Wi-Fi"])
    rec, damaged = log.unresolved_for("t-host")
    assert rec.modified == ("Wi-Fi", "Ethernet") and damaged is False
    log.mark_resolved("t-host")
    assert log.latest_unresolved_for("t-host") is None


def test_iptables_partial_install_is_recorded(monkeypatch):
    from zee.responder import cut_egress as egress_mod
    monkeypatch.setattr(egress_mod.sys, "platform", "linux")
    monkeypatch.setattr(egress_mod.shutil, "which", lambda name: "/sbin/iptables" if name == "iptables" else None)
    monkeypatch.setattr(egress_mod, "_run", lambda cmd: (cmd[1] != "-I", "boom"))
    ok, _detail, modified = egress_mod._cut_egress_dispatch()
    assert ok is False and modified == [full_mod.SENTINEL_LINUX_IPTABLES_EGRESS]


@pytest.mark.parametrize("msg, expect_ok", [("pfctl: pf already enabled", True), ("permission denied", False)])
def test_pf_enable_failure_is_a_failed_cut(monkeypatch, msg, expect_ok):
    from zee.responder import cut_egress as egress_mod
    import subprocess
    monkeypatch.setattr(egress_mod.sys, "platform", "darwin")
    monkeypatch.setattr(egress_mod.shutil, "which", lambda name: "/sbin/pfctl")
    monkeypatch.setattr(egress_mod.subprocess, "run",
                        lambda *a, **k: subprocess.CompletedProcess(a[0], 0, "", ""))
    monkeypatch.setattr(egress_mod, "_run", lambda cmd: (False, msg))
    ok, _detail, modified = egress_mod._cut_egress_dispatch()
    assert ok is expect_ok and modified == [full_mod.SENTINEL_MACOS_PFCTL_EGRESS]


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
