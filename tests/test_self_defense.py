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


class _AllEnabled(dict):
    """interface_states stub: every name reads back as enabled."""
    def get(self, key, default=None):
        return "enabled"


@pytest.fixture
def quiet(monkeypatch):
    titles: list[str] = []
    monkeypatch.setattr(restore_mod, "notify_local", lambda t, b: titles.append(t) or True)
    monkeypatch.setattr(seq, "notify_local", lambda t, b: titles.append(t) or True)
    monkeypatch.setattr(restore_mod, "interface_states", lambda: _AllEnabled())  # readback: all enabled
    return titles


# ── restore: a missing ledger record never means "enable everything" ──


def _absent_on_show(cmd):
    """_run stub: every command succeeds; rule listings report 'absent'."""
    if cmd[:3] == ["nft", "list", "table"]:
        return False, "Error: No such file or directory"
    if cmd[:2] == ["iptables", "-S"]:
        return False, "iptables: No chain/target/match by that name."
    if cmd[:4] == ["netsh", "advfirewall", "firewall", "show"]:
        return False, "No rules match the specified criteria."
    return True, ""


def _no_compat(monkeypatch):
    def boom(*_a, **_k):
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
    monkeypatch.setattr(restore_mod, "_which", lambda name: f"/usr/sbin/{name}")
    monkeypatch.setattr(restore_mod, "list_linux_interfaces", lambda: ["eth0"])
    monkeypatch.setattr(restore_mod, "_run", lambda cmd: (False, "operation not permitted"))
    log = CutStateLog(tmp_path / "cut_state.jsonl")
    with pytest.raises(ZeeError) as ei:
        restore_mod.restore("t-host", cut_state=log, all_interfaces=True)
    assert ei.value.code == "Z601"
    assert any("FAILED" in t for t in quiet)


def test_emergency_all_interfaces_macos_reports_real_failure(monkeypatch):
    monkeypatch.setattr(restore_mod, "_which", lambda name: f"/usr/sbin/{name}")
    monkeypatch.setattr(restore_mod, "list_macos_services", lambda **k: ["Wi-Fi"])
    monkeypatch.setattr(restore_mod, "_run", lambda cmd: (False, "denied"))
    ok, _ = restore_mod._restore_macos_compat()
    assert ok is False


def test_emergency_all_interfaces_windows_reports_real_failure(monkeypatch):
    monkeypatch.setattr(restore_mod, "_which", lambda name: f"C:/{name}")
    monkeypatch.setattr(restore_mod, "list_windows_interfaces", lambda only_enabled: ["Ethernet"])
    monkeypatch.setattr(restore_mod, "_run", lambda cmd: (False, "denied"))
    ok, _ = restore_mod._restore_windows_compat()
    assert ok is False


def test_emergency_all_interfaces_with_no_tool_is_not_success(monkeypatch):
    monkeypatch.setattr(restore_mod, "_which", lambda name: None)
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
    monkeypatch.setattr(restore_mod, "_which", lambda name: f"/usr/sbin/{name}")
    calls: list = []
    monkeypatch.setattr(restore_mod, "_run", lambda cmd: calls.append(cmd) or (True, ""))
    ok, _ = restore_mod._restore_macos_compat()
    assert ok is True
    enabled = [c[2] for c in calls if c[0] == "networksetup"]
    assert enabled == ["Wi-Fi", "Ethernet"]
    assert full_mod.list_macos_services() == []  # cut still skips disabled ones


def test_emergency_linux_removes_egress_rule_even_when_nmcli_succeeds(monkeypatch):
    monkeypatch.setattr(restore_mod, "_which", lambda name: f"/usr/bin/{name}")
    monkeypatch.setattr(restore_mod, "list_linux_interfaces", lambda: ["eth0"])
    calls: list = []
    monkeypatch.setattr(restore_mod, "_run", lambda cmd: calls.append(cmd) or _absent_on_show(cmd))
    ok, _ = restore_mod._restore_linux_compat()
    assert ok is True
    assert ["nft", "delete", "table", "inet", "zee_egress"] in calls
    assert ["iptables", "-X", "ZEE_EGRESS"] in calls


def test_emergency_linux_does_not_hide_one_failed_firewall_removal(monkeypatch):
    monkeypatch.setattr(restore_mod, "_which", lambda name: f"/usr/bin/{name}")
    monkeypatch.setattr(restore_mod, "_run",
                        lambda cmd: (False, "Operation not permitted") if cmd[0] == "nft" else (True, ""))
    ok, detail = restore_mod._restore_linux_compat()
    assert ok is False and "nft:fail" in detail


def test_emergency_treats_already_absent_rule_as_removed(monkeypatch):
    monkeypatch.setattr(restore_mod, "_which", lambda name: f"/usr/bin/{name}")
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
    monkeypatch.setattr(restore_mod, "_restore_compat", lambda *_a, **_k: (True, "all on"))
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


# ── independent re-check findings (fix commit), 2026-10-15 ────────────


def test_missing_binary_is_not_an_absent_rule(monkeypatch):
    def launch_fails(*a, **k):
        raise FileNotFoundError(2, "No such file or directory", "nft")
    monkeypatch.setattr(restore_mod.subprocess, "run", launch_fails)
    assert restore_mod._run_removal(["nft", "delete", "table", "inet", "zee_egress"])[0] is False


@pytest.mark.parametrize("platform_fn", ["_restore_linux_compat", "_restore_macos_compat", "_restore_windows_compat"])
def test_firewall_success_alone_is_not_a_full_restore(monkeypatch, platform_fn):
    """Interface enumeration failed (empty): firewall steps alone must not pass."""
    monkeypatch.setattr(restore_mod, "_which", lambda name: None if name == "nmcli" else f"/x/{name}")
    monkeypatch.setattr(restore_mod, "list_linux_interfaces", lambda: [])
    monkeypatch.setattr(restore_mod, "list_macos_services", lambda **k: [])
    monkeypatch.setattr(restore_mod, "list_windows_interfaces", lambda **k: [])
    monkeypatch.setattr(restore_mod, "_run", lambda cmd: (True, ""))
    assert getattr(restore_mod, platform_fn)()[0] is False


def _line(**kw) -> str:
    import json
    return json.dumps(kw) + "\n"


CUT = dict(type="cut", cut_at="2026-10-15T00:00:00+00:00", method="full", platform="linux")


def test_malformed_resolved_line_is_damage_and_does_not_erase_earlier_cut(tmp_path):
    p = tmp_path / "cut_state.jsonl"
    p.write_text(_line(**CUT, asset_id="a", modified=["eth0"])
                 + _line(type="resolved", asset_id="a")
                 + _line(**CUT, asset_id="a", modified=["eth1"]))
    rec, damaged = CutStateLog(p).unresolved_for("a")
    assert damaged is True


def test_other_assets_lines_are_validated_too(tmp_path):
    p = tmp_path / "cut_state.jsonl"
    p.write_text(_line(**CUT, asset_id="a", modified=["eth0"]) + _line(type="cut", asset_id="b"))
    assert CutStateLog(p).unresolved_for("a")[1] is True


@pytest.mark.parametrize("bad", [{"platform": None}, {"method": "nuke"}, {"platform": "plan9"}])
def test_cut_record_field_types_are_validated(tmp_path, monkeypatch, quiet, bad):
    _no_compat(monkeypatch)
    p = tmp_path / "cut_state.jsonl"
    p.write_text(_line(**{**CUT, **bad}, asset_id="a", modified=["eth0"]))
    with pytest.raises(ZeeError) as ei:
        restore_mod.restore("a", cut_state=CutStateLog(p))
    assert ei.value.code == "Z605"


def test_cuts_from_different_platforms_are_not_merged(tmp_path):
    p = tmp_path / "cut_state.jsonl"
    p.write_text(_line(**{**CUT, "platform": "darwin"}, asset_id="a", modified=["Wi-Fi"])
                 + _line(**CUT, asset_id="a", modified=["eth0"]))
    assert CutStateLog(p).unresolved_for("a")[1] is True


# ── coordinator external review (Codex), 2026-10-15 ───────────────────


def test_linux_no_firewall_tool_at_all_is_unverified(monkeypatch):
    """No tool that could confirm the rule is gone: unverified, not success."""
    monkeypatch.setattr(restore_mod, "_which", lambda n: "/x/ip" if n == "ip" else None)
    monkeypatch.setattr(restore_mod, "list_linux_interfaces", lambda: ["eth0"])
    monkeypatch.setattr(restore_mod, "_run", lambda cmd: (True, ""))
    ok, detail = restore_mod._restore_linux_compat()
    assert ok is None and "nft:not-found:unverified" in detail


def test_macos_missing_pfctl_is_not_rule_absent(monkeypatch):
    monkeypatch.setattr(restore_mod, "_which", lambda n: "/x/networksetup" if n == "networksetup" else None)
    monkeypatch.setattr(restore_mod, "list_macos_services", lambda **k: ["Wi-Fi"])
    monkeypatch.setattr(restore_mod, "_run", lambda cmd: (True, ""))
    assert restore_mod._restore_macos_compat()[0] is None


@pytest.mark.parametrize("state, expect", [("disabled", False), ("enabled", True)])
def test_nmcli_failure_is_kept_unless_networking_is_confirmed_on(monkeypatch, state, expect):
    monkeypatch.setattr(restore_mod, "_which", lambda n: f"/x/{n}")
    monkeypatch.setattr(restore_mod, "list_linux_interfaces", lambda: ["eth0"])
    def run(cmd):
        if cmd == ["nmcli", "networking", "on"]:
            return False, "not authorized"
        if cmd == ["nmcli", "networking"]:
            return True, state
        return _absent_on_show(cmd)
    monkeypatch.setattr(restore_mod, "_run", run)
    ok, detail = restore_mod._restore_linux_compat()
    assert ok is expect and "nmcli" in detail
    # A cut may have used `ip link down` (nmcli off failed): sweep regardless.
    assert "eth0:ok" in detail


class _BrokenLedger(CutStateLog):
    def record_cut(self, **kw):
        raise OSError(28, "No space left on device")


@pytest.mark.parametrize("mod_name", ["cut_full", "cut_egress"])
def test_ledger_write_failure_is_reported_not_raised(tmp_path, monkeypatch, mod_name):
    import importlib
    mod = importlib.import_module(f"zee.responder.{mod_name}")
    monkeypatch.setattr(mod, f"_{mod_name}_dispatch", lambda: (True, "os cut done", ["eth0"]))
    ok, detail = getattr(mod, mod_name)(asset_id="t-host", cut_state=_BrokenLedger(tmp_path / "c.jsonl"))
    assert ok is False
    assert "os=ok" in detail and "ledger=FAILED" in detail and "--all-interfaces" in detail


def test_handle_shows_ledger_failure_and_remedy(tmp_path, monkeypatch):
    import zee.responder.cut_egress as egress_mod
    bodies: list = []
    monkeypatch.setattr(seq, "notify_local", lambda t, b: bodies.append((t, b)) or True)
    monkeypatch.setattr(egress_mod, "_cut_egress_dispatch", lambda: (True, "rules installed", ["r"]))
    monkeypatch.setattr(seq, "cut_egress", egress_mod.cut_egress)
    seq.handle(_event(), _asset(), dry_run=False, event_log=EventLog(log_dir=tmp_path),
               cut_state=_BrokenLedger(tmp_path / "c.jsonl"))
    title, body = bodies[-1]
    assert "FAILED" in title and "ledger=FAILED" in body and "--all-interfaces" in body


# ── ASTRA x Fable debate: verify by re-reading the OS, 2026-10-15 ───────
# Zee's fixed-name firewall rules are removed and re-read on every backend
# on both restore paths, regardless of the ledger.

NFT = full_mod.SENTINEL_LINUX_NFT_EGRESS
IPT = full_mod.SENTINEL_LINUX_IPTABLES_EGRESS
NFT_SHOW = ["nft", "list", "table", "inet", "zee_egress"]
IPT_SHOW = ["iptables", "-S", "ZEE_EGRESS"]
ABSENT = {"nft": "Error: No such file or directory", "iptables": "iptables: No chain/target/match by that name."}


def _fake_linux(monkeypatch, *, tools, present_rules=(), deny=()):
    """OS stub: `tools` installed; rules in `present_rules` exist and survive
    removal when the tool is in `deny` (permission error)."""
    rules = set(present_rules)
    calls: list = []
    monkeypatch.setattr(restore_mod, "_which", lambda n: f"/usr/sbin/{n}" if n in tools else None)
    monkeypatch.setattr(restore_mod, "list_linux_interfaces", lambda: ["eth0"])

    def run(cmd):
        calls.append(cmd)
        tool = cmd[0]
        if tool in deny and cmd not in (NFT_SHOW, IPT_SHOW):
            return False, "Operation not permitted"
        if cmd in (NFT_SHOW, IPT_SHOW):
            if tool in deny:
                return False, "Operation not permitted"
            return (True, "table ...") if tool in rules else (False, ABSENT[tool])
        if cmd[:2] == ["nft", "delete"] or cmd[:2] == ["iptables", "-X"]:
            rules.discard(tool)
        return True, ""
    monkeypatch.setattr(restore_mod, "_run", run)
    return calls


def _record(tmp_path, modified, platform="linux"):
    log = CutStateLog(tmp_path / "cut_state.jsonl")
    log.record_cut(asset_id="t-host", method="full", platform=platform, modified=modified)
    return log


def test_forged_ledger_still_removes_and_rechecks_rules(tmp_path, monkeypatch, quiet):
    """Ledger forged to ['eth0'] while the nft rule exists: removal is still
    run, and a rule that survives makes the restore fail."""
    monkeypatch.setattr(restore_mod, "_host_platform", lambda: "linux")
    calls = _fake_linux(monkeypatch, tools={"ip", "nft", "iptables"}, present_rules={"nft"}, deny={"nft"})
    with pytest.raises(ZeeError) as ei:
        restore_mod.restore("t-host", cut_state=_record(tmp_path, ["eth0"]))
    assert ei.value.code == "Z601"
    assert ["nft", "delete", "table", "inet", "zee_egress"] in calls
    assert _record(tmp_path, ["eth0"]).latest_unresolved_for("t-host") is not None


def test_forged_ledger_rule_removed_then_success(tmp_path, monkeypatch, quiet):
    monkeypatch.setattr(restore_mod, "_host_platform", lambda: "linux")
    _fake_linux(monkeypatch, tools={"ip", "nft", "iptables"}, present_rules={"nft"})
    assert restore_mod.restore("t-host", cut_state=_record(tmp_path, ["eth0"]))[0] is True


def test_recorded_nft_with_nft_missing_is_unverified(tmp_path, monkeypatch, quiet):
    """Recorded nft cut but nft is not installed: cannot confirm → Z606."""
    monkeypatch.setattr(restore_mod, "_host_platform", lambda: "linux")
    _fake_linux(monkeypatch, tools={"ip", "iptables"})
    log = _record(tmp_path, [NFT])
    with pytest.raises(ZeeError) as ei:
        restore_mod.restore("t-host", cut_state=log)
    assert ei.value.code == "Z606"
    assert log.latest_unresolved_for("t-host") is not None  # stays unresolved


def test_no_ledger_nft_missing_iptables_ok_is_unverified(tmp_path, monkeypatch, quiet):
    monkeypatch.setattr(restore_mod.sys, "platform", "linux")
    _fake_linux(monkeypatch, tools={"ip", "iptables"})
    with pytest.raises(ZeeError) as ei:
        restore_mod.restore("t-host", cut_state=CutStateLog(tmp_path / "none.jsonl"), all_interfaces=True)
    assert ei.value.code == "Z606"
    assert any("UNVERIFIED" in t for t in quiet)


def test_one_backend_permission_error_continues_then_fails(monkeypatch):
    calls = _fake_linux(monkeypatch, tools={"ip", "nft", "iptables"}, present_rules={"nft"}, deny={"nft"})
    ok, detail = restore_mod._restore_linux_compat()
    assert ok is False
    assert IPT_SHOW in calls  # kept going after nft failed
    assert "nft:fail" in detail and "iptables:ok" in detail


def test_both_backends_absent_is_success(monkeypatch):
    _fake_linux(monkeypatch, tools={"ip", "nft", "iptables"})
    assert restore_mod._restore_linux_compat()[0] is True


def test_rule_still_listed_after_removal_is_failure(monkeypatch):
    monkeypatch.setattr(restore_mod, "_which", lambda n: f"/sbin/{n}")
    monkeypatch.setattr(restore_mod, "list_macos_services", lambda **k: ["Wi-Fi"])
    monkeypatch.setattr(restore_mod, "_run",
                        lambda cmd: (True, "block drop out all") if cmd[-1] == "rules" else (True, ""))
    ok, detail = restore_mod._restore_macos_compat()
    assert ok is False and "pfctl:fail" in detail


def test_tools_resolved_with_sbin_and_run_with_absolute_path(monkeypatch):
    seen = {}
    monkeypatch.setattr(full_mod.shutil, "which",
                        lambda name, path=None: seen.setdefault("path", path) and f"/usr/sbin/{name}")
    import subprocess
    monkeypatch.setattr(restore_mod.subprocess, "run",
                        lambda argv, **k: seen.setdefault("argv", argv) and subprocess.CompletedProcess(argv, 0, "", ""))
    restore_mod._run(["pfctl", "-s", "info"])
    assert "/usr/sbin" in seen["path"].split(":") and "/sbin" in seen["path"].split(":")
    assert seen["argv"][0] == "/usr/sbin/pfctl"


def test_readback_fails_when_recorded_interface_still_disabled(tmp_path, monkeypatch, quiet):
    monkeypatch.setattr(restore_mod, "_host_platform", lambda: "linux")
    _fake_linux(monkeypatch, tools={"ip", "nft", "iptables"})
    monkeypatch.setattr(restore_mod, "interface_states", lambda: {"eth0": "disabled", "wlan9": "disabled"})
    with pytest.raises(ZeeError) as ei:
        restore_mod.restore("t-host", cut_state=_record(tmp_path, ["eth0"]))
    assert ei.value.code == "Z601" and "still disabled eth0" in str(ei.value)
    assert "wlan9" in str(ei.value)  # outside the record: reported as a warning


def test_readback_outside_record_is_only_a_warning(tmp_path, monkeypatch, quiet):
    monkeypatch.setattr(restore_mod, "_host_platform", lambda: "linux")
    _fake_linux(monkeypatch, tools={"ip", "nft", "iptables"})
    monkeypatch.setattr(restore_mod, "interface_states", lambda: {"eth0": "enabled", "wlan9": "disabled"})
    ok, detail = restore_mod.restore("t-host", cut_state=_record(tmp_path, ["eth0"]))
    assert ok is True and "warning" in detail and "wlan9" in detail


def test_unreadable_state_is_unverified(tmp_path, monkeypatch, quiet):
    monkeypatch.setattr(restore_mod, "_host_platform", lambda: "linux")
    _fake_linux(monkeypatch, tools={"ip", "nft", "iptables"})
    monkeypatch.setattr(restore_mod, "interface_states", lambda: None)
    with pytest.raises(ZeeError) as ei:
        restore_mod.restore("t-host", cut_state=_record(tmp_path, ["eth0"]))
    assert ei.value.code == "Z606"


def test_notifications_say_the_ledger_is_user_writable(tmp_path, monkeypatch):
    bodies: list = []
    monkeypatch.setattr(restore_mod, "notify_local", lambda t, b: bodies.append(b) or True)
    monkeypatch.setattr(restore_mod, "interface_states", lambda: _AllEnabled())
    monkeypatch.setattr(restore_mod, "_restore_compat", lambda: (True, "all on"))
    restore_mod.restore("t-host", cut_state=CutStateLog(tmp_path / "c.jsonl"), all_interfaces=True)
    assert "writable by the same user" in bodies[-1]


def test_ledger_exception_does_not_block_emergency_restore(tmp_path, monkeypatch, quiet):
    class Exploding(CutStateLog):
        def unresolved_for(self, asset_id):
            raise RuntimeError("boom")
    monkeypatch.setattr(restore_mod, "_restore_compat", lambda: (True, "all on"))
    assert restore_mod.restore("t-host", cut_state=Exploding(tmp_path / "c.jsonl"), all_interfaces=True)[0] is True


def test_windows_both_rules_always_checked(monkeypatch):
    monkeypatch.setattr(restore_mod, "_which", lambda n: f"C:/{n}")
    monkeypatch.setattr(restore_mod, "list_windows_interfaces", lambda **k: ["Ethernet"])
    calls: list = []
    def run(cmd):
        calls.append(cmd)
        return (False, "No rules match the specified criteria.") if "show" in cmd else (True, "")
    monkeypatch.setattr(restore_mod, "_run", run)
    ok, _ = restore_mod._restore_windows_compat()
    shown = [c[-1] for c in calls if "show" in c]
    assert ok is True and shown == ["name=zee-egress-cut-block", "name=zee-egress-cut-allow-local"]


# ── reviewer: read-back parsing, sbin lookup, targeted branches ─────────


def _stub_check_output(monkeypatch, outputs):
    """outputs: {tool basename: str | Exception}."""
    def fake(argv, **k):
        out = outputs[argv[0].rsplit("/", 1)[-1]]
        if isinstance(out, Exception):
            raise out
        return out
    monkeypatch.setattr(full_mod.subprocess, "check_output", fake)
    monkeypatch.setattr(full_mod, "sbin_which", lambda n: f"/sbin/{n}" if n in outputs else None)


IP_OUT = ("1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536\n"
          "2: eth0: <BROADCAST,MULTICAST> mtu 1500 state DOWN\n"
          "3: veth1@if5: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500\n")


def test_interface_states_linux(monkeypatch):
    import subprocess
    monkeypatch.setattr(full_mod.sys, "platform", "linux")
    _stub_check_output(monkeypatch, {"ip": IP_OUT, "nmcli": "disabled\n"})
    assert full_mod.interface_states() == {
        "eth0": "disabled", "veth1": "enabled", full_mod.SENTINEL_LINUX_NMCLI: "disabled"}
    # NetworkManager not answering: interfaces kept, nmcli state is unknown.
    _stub_check_output(monkeypatch, {"ip": IP_OUT, "nmcli": subprocess.TimeoutExpired("nmcli", 5)})
    assert full_mod.interface_states()[full_mod.SENTINEL_LINUX_NMCLI] == "unknown"
    _stub_check_output(monkeypatch, {"ip": IP_OUT, "nmcli": "asleep\n"})
    assert full_mod.interface_states()[full_mod.SENTINEL_LINUX_NMCLI] == "unknown"


def test_interface_states_macos_and_windows(monkeypatch):
    monkeypatch.setattr(full_mod.sys, "platform", "darwin")
    _stub_check_output(monkeypatch, {"networksetup": "An asterisk (*) denotes ...\n*Wi-Fi\nEthernet\n"})
    assert full_mod.interface_states() == {"Wi-Fi": "disabled", "Ethernet": "enabled"}
    monkeypatch.setattr(full_mod.sys, "platform", "win32")
    _stub_check_output(monkeypatch, {"powershell": '[{"Name":"Ethernet","Status":"Disabled"},'
                                                   '{"Name":"Wi-Fi","Status":"Up"},{"Name":"BT"}]'})
    assert full_mod.interface_states() == {"Ethernet": "disabled", "Wi-Fi": "enabled", "BT": "unknown"}
    _stub_check_output(monkeypatch, {"powershell": ""})
    assert full_mod.interface_states() is None  # empty listing is not "all enabled"


def test_interface_states_unreadable_is_none(monkeypatch):
    monkeypatch.setattr(full_mod.sys, "platform", "linux")
    _stub_check_output(monkeypatch, {"ip": OSError("no ip")})
    assert full_mod.interface_states() is None


@pytest.mark.parametrize("states, expect", [
    ({"eth0": "enabled"}, True),
    ({"eth0": "disabled"}, False),
    ({"eth0": "unknown"}, None),
    ({}, None),                      # vanished / not enumerated
    (None, None),                    # unreadable
])
def test_readback_needs_positive_enabled(monkeypatch, states, expect):
    monkeypatch.setattr(restore_mod, "interface_states", lambda: states)
    assert restore_mod._readback(("eth0",))[0] is expect


@pytest.mark.parametrize("nm_state, expect", [("enabled", True), ("unknown", None), ("disabled", False)])
def test_readback_nmcli_sentinel_three_states(monkeypatch, nm_state, expect):
    monkeypatch.setattr(restore_mod, "interface_states",
                        lambda: {full_mod.SENTINEL_LINUX_NMCLI: nm_state})
    assert restore_mod._readback((full_mod.SENTINEL_LINUX_NMCLI,))[0] is expect


def test_readback_without_record(monkeypatch):
    monkeypatch.setattr(restore_mod, "interface_states", lambda: {"eth0": "enabled"})
    ok, detail = restore_mod._readback(None)
    assert ok is True and "no recorded targets to verify" in detail
    monkeypatch.setattr(restore_mod, "interface_states", lambda: None)
    assert restore_mod._readback(None)[0] is None


def test_readback_nmcli_missing_is_unverified(monkeypatch):
    monkeypatch.setattr(restore_mod, "interface_states", lambda: {"eth0": "enabled"})
    assert restore_mod._readback((full_mod.SENTINEL_LINUX_NMCLI,))[0] is None


def test_sbin_which_returns_absolute_path(monkeypatch):
    import os
    monkeypatch.setattr(full_mod.shutil, "which", lambda name, path=None: "bin/ip")
    assert full_mod.sbin_which("ip") == os.path.abspath("bin/ip")


def test_interface_listing_uses_sbin_absolute_path(monkeypatch):
    seen: list = []
    monkeypatch.setattr(full_mod, "sbin_which", lambda n: f"/sbin/{n}")
    monkeypatch.setattr(full_mod.subprocess, "check_output", lambda argv, **k: seen.append(argv[0]) or "")
    full_mod.list_linux_interfaces()
    full_mod.list_macos_services()
    assert seen == ["/sbin/ip", "/sbin/networksetup"]


def test_targeted_platform_mismatch_fails(monkeypatch):
    monkeypatch.setattr(restore_mod, "_host_platform", lambda: "darwin")
    rec = CutStateLog.__new__(CutStateLog)  # unused; build a record directly
    from zee.telemetry.cut_state import CutRecord
    r = CutRecord("t-host", datetime.now(timezone.utc), "full", "linux", ("eth0",))
    ok, detail = restore_mod._restore_targeted(r)
    assert ok is False and "linux" in detail


@pytest.mark.parametrize("platform, expect_cmd", [
    ("darwin", ["networksetup", "-setnetworkserviceenabled", "Wi-Fi", "on"]),
    ("win32", ["netsh", "interface", "set", "interface", "Wi-Fi", "admin=enable"]),
])
def test_targeted_darwin_and_windows_branches(monkeypatch, platform, expect_cmd):
    from zee.telemetry.cut_state import CutRecord
    monkeypatch.setattr(restore_mod, "_host_platform", lambda: platform)
    monkeypatch.setattr(restore_mod, "_which", lambda n: f"/x/{n}")
    calls: list = []
    monkeypatch.setattr(restore_mod, "_run", lambda cmd: calls.append(cmd) or _absent_on_show(cmd))
    r = CutRecord("t-host", datetime.now(timezone.utc), "full", platform, ("Wi-Fi",))
    ok, _ = restore_mod._restore_targeted(r)
    assert expect_cmd in calls and ok is True
