"""v0.13.0 pre-release reviews (Codex external + 4-persona), 2026-10-15.

Every OS call is mocked; nothing touches a real network or firewall.
"""

from __future__ import annotations

import json
import subprocess

import pytest

from zee.recovery import restore as restore_mod
from zee.responder import cut_egress as egress_mod
from zee.responder import cut_full as full_mod
from zee.telemetry.cut_state import CutStateLog

IPT = full_mod.SENTINEL_LINUX_IPTABLES_EGRESS
NFT = full_mod.SENTINEL_LINUX_NFT_EGRESS
PF = full_mod.SENTINEL_MACOS_PFCTL_EGRESS
TOKEN = full_mod.PF_TOKEN_PREFIX + "987654321"
ABSENT_IPT = "iptables: No chain/target/match by that name."


# ── Codex #1: iptables legacy / nf_tables are checked separately ───────


def test_legacy_chain_left_behind_is_not_restored(monkeypatch):
    """Cut with iptables-legacy, then `iptables` switched to nf_tables: the
    legacy ZEE_EGRESS chain must still be removed and read back."""
    calls: list = []
    legacy_present = {"chain": True}
    monkeypatch.setattr(restore_mod, "_which", lambda n: f"/usr/sbin/{n}")
    monkeypatch.setattr(restore_mod, "list_linux_interfaces", lambda: ["eth0"])

    def run(cmd):
        calls.append(cmd)
        if cmd[0] == "nft" and cmd[1] == "list":
            return False, "Error: No such file or directory\nlist table inet zee_egress\n ^^^^^^^^^^"
        if cmd == ["iptables-legacy", "-S", "ZEE_EGRESS"]:
            return (True, "-N ZEE_EGRESS\n-A ZEE_EGRESS -j DROP") if legacy_present["chain"] else (False, ABSENT_IPT)
        if cmd[0].startswith("iptables") and cmd[1] == "-S":
            return False, ABSENT_IPT
        if cmd[:2] == ["iptables-legacy", "-X"]:
            return False, "Operation not permitted"  # removal fails: chain stays
        return True, ""
    monkeypatch.setattr(restore_mod, "_run", run)
    ok, detail, _t = restore_mod._restore_linux_compat()
    assert ok is False and "iptables-legacy:fail" in detail
    assert ["iptables-nft", "-S", "ZEE_EGRESS"] in calls


def test_legacy_table_never_initialised_counts_as_absent(monkeypatch):
    msg = ("iptables v1.8.7 (legacy): can't initialize iptables table `filter': "
           "Table does not exist (do you need to insmod?)")
    monkeypatch.setattr(restore_mod, "_run", lambda cmd: (False, msg))
    assert restore_mod._verify_absent("iptables-legacy", ["iptables-legacy", "-S", "ZEE_EGRESS"]) is True


def test_recorded_iptables_cut_with_no_iptables_installed_is_unverified(monkeypatch):
    monkeypatch.setattr(restore_mod, "_which", lambda n: "/usr/sbin/nft" if n == "nft" else None)
    monkeypatch.setattr(restore_mod, "_run", lambda cmd: (
        False, "Error: No such file or directory\nlist table inet zee_egress\n ^") if cmd[1] == "list" else (True, ""))
    steps = dict(restore_mod._firewall_steps("linux", (IPT,)))
    assert steps["iptables:not-found"] is None
    steps = dict(restore_mod._firewall_steps("linux", ()))
    assert steps["iptables:not-installed"] is True


# ── Codex #2: Linux full leaves no interface up ───────────────────────


def test_nmcli_success_still_takes_every_interface_down(monkeypatch):
    monkeypatch.setattr(full_mod.sys, "platform", "linux")
    monkeypatch.setattr(full_mod.shutil, "which", lambda n: f"/sbin/{n}")
    monkeypatch.setattr(full_mod, "list_linux_interfaces", lambda: ["eth0"])
    calls: list = []
    monkeypatch.setattr(full_mod, "_run", lambda cmd: calls.append(cmd) or (True, ""))
    ok, detail, modified = full_mod._cut_full_linux()
    assert ok is True and ["ip", "link", "set", "eth0", "down"] in calls
    assert modified == [full_mod.SENTINEL_LINUX_NMCLI, "eth0"]


def test_full_cut_with_an_unmanaged_interface_still_up_is_not_confirmed(tmp_path, monkeypatch):
    """Codex repro: NM=disabled but eth0=enabled must not be reported as cut."""
    monkeypatch.setattr(full_mod, "_cut_full_dispatch",
                        lambda: (True, "nmcli networking off", [full_mod.SENTINEL_LINUX_NMCLI]))
    monkeypatch.setattr(full_mod, "interface_states",
                        lambda: {full_mod.SENTINEL_LINUX_NMCLI: "disabled", "eth0": "enabled"})
    log = CutStateLog(tmp_path / "c.jsonl")
    ok, detail = full_mod.cut_full(asset_id="t-host", cut_state=log)
    assert ok is False and "eth0" in detail


def test_full_cut_with_only_the_nm_switch_readable_is_unverified(tmp_path, monkeypatch):
    monkeypatch.setattr(full_mod, "_cut_full_dispatch",
                        lambda: (True, "nmcli networking off", [full_mod.SENTINEL_LINUX_NMCLI]))
    monkeypatch.setattr(full_mod, "interface_states", lambda: {full_mod.SENTINEL_LINUX_NMCLI: "disabled"})
    log = CutStateLog(tmp_path / "c.jsonl")
    ok, _d = full_mod.cut_full(asset_id="t-host", cut_state=log)
    assert ok is False and json.loads(log.path.read_text())["verified"] == "unverified"


# ── Codex #3 / 4-persona #3: pf reference and rule order ──────────────


@pytest.mark.parametrize("main, verdict", [
    ('scrub-anchor "com.apple/*" all fragment reassemble\nanchor "com.apple/*" all', "confirmed"),
    ('anchor "com.apple/*"', "confirmed"),
    ('anchor "com.apple/*" in on lo0 all', "missing"),          # conditional: not outbound traffic
    ('anchor "com.apple/*" all fragment', "missing"),
    ('pass out quick all\nanchor "com.apple/*" all', "unverified"),   # decides first
    ('anchor "vpn/*" all\nanchor "com.apple/*" all', "unverified"),   # unseen anchor first
    ('pass out all\nanchor "com.apple/*" all', "confirmed"),          # non-quick: Zee's quick block wins
])
def test_pf_anchor_reference_must_be_unconditional_and_first(main, verdict):
    assert egress_mod._pf_anchor_referenced(main, set()) == verdict


@pytest.mark.parametrize("rules, verdict", [
    ("pass out quick on lo0 all flags S/SA keep state\n"
     "pass out quick inet from any to 10.0.0.0/8 flags S/SA keep state\n"
     "pass out quick inet from any to 172.16.0.0/12 flags S/SA keep state\n"
     "pass out quick inet from any to 192.168.0.0/16 flags S/SA keep state\n"
     "block drop out quick all", "confirmed"),
    ("pass out quick all flags S/SA keep state\nblock drop out quick all", "unverified"),
    ("pass out quick inet from any to 8.8.8.0/24\nblock drop out quick all", "unverified"),
    ("block drop out all", "missing"),   # pre-0.13 rule without quick: later rules could pass
])
def test_pf_block_rule_is_quick_and_only_zee_passes_precede_it(rules, verdict):
    assert egress_mod._pf_block_rule(rules, set()) == verdict


def test_pf_rules_loaded_are_quick_with_block_last(monkeypatch):
    seen: list = []
    monkeypatch.setattr(egress_mod.shutil, "which", lambda n: f"/sbin/{n}")
    monkeypatch.setattr(egress_mod.subprocess, "run",
                        lambda argv, **k: seen.append((argv, k.get("input"))) or
                        subprocess.CompletedProcess(argv, 0, "", "Token : 1"))
    egress_mod._cut_egress_macos()
    rules = [ln for ln in seen[0][1].splitlines() if ln]
    assert all(" quick " in f" {ln} " for ln in rules) and rules[-1] == "block drop out quick all"


# ── Codex #5: uncertain outcomes are recorded ────────────────────────


def _timeout(argv, **k):
    raise subprocess.TimeoutExpired(argv, 10)


def test_nft_timeout_is_recorded(monkeypatch):
    monkeypatch.setattr(egress_mod.sys, "platform", "linux")
    monkeypatch.setattr(egress_mod.shutil, "which", lambda n: "/sbin/nft" if n == "nft" else None)
    monkeypatch.setattr(egress_mod.subprocess, "run", _timeout)
    ok, _d, modified = egress_mod._cut_egress_dispatch()
    assert ok is False and modified == [NFT]


def test_pf_timeout_is_recorded(monkeypatch):
    monkeypatch.setattr(egress_mod.sys, "platform", "darwin")
    monkeypatch.setattr(egress_mod.shutil, "which", lambda n: "/sbin/pfctl")
    monkeypatch.setattr(egress_mod.subprocess, "run", _timeout)
    ok, _d, modified = egress_mod._cut_egress_dispatch()
    assert ok is False and modified == [PF]


def test_windows_failed_add_is_recorded(tmp_path, monkeypatch):
    monkeypatch.setattr(egress_mod.sys, "platform", "win32")
    monkeypatch.setattr(egress_mod.shutil, "which", lambda n: f"C:/{n}")
    monkeypatch.setattr(egress_mod, "_run", lambda cmd: (False, "timed out"))
    log = CutStateLog(tmp_path / "c.jsonl")
    ok, _d = egress_mod.cut_egress(asset_id="t-host", cut_state=log)
    assert ok is False
    assert log.latest_unresolved_for("t-host").modified == ("zee-egress-cut-block",)


def test_iptables_first_command_timeout_is_recorded(monkeypatch):
    monkeypatch.setattr(egress_mod.sys, "platform", "linux")
    monkeypatch.setattr(egress_mod.shutil, "which", lambda n: "/sbin/iptables" if n == "iptables" else None)
    monkeypatch.setattr(egress_mod, "_run", lambda cmd: (False, "timed out"))
    assert egress_mod._cut_egress_dispatch()[2] == [IPT]


# ── 4-persona #1: pf enable reference released on restore ─────────────


@pytest.mark.parametrize("rc_msg, expect", [
    ((True, ""), True),
    ((False, "pfctl: pf: token invalid"), True),     # already released / dropped by pfctl -d
    ((False, "pfctl: pf not enabled"), True),
    ((False, "pfctl: DIOCSTOPREF: Operation not permitted"), False),
])
def test_restore_releases_the_recorded_pf_token(monkeypatch, rc_msg, expect):
    calls: list = []
    monkeypatch.setattr(restore_mod, "_which", lambda n: f"/sbin/{n}")
    monkeypatch.setattr(restore_mod, "_run",
                        lambda cmd: calls.append(cmd) or (rc_msg if cmd[1] == "-X" else (True, "")))
    steps = restore_mod._firewall_steps("darwin", (PF, TOKEN))
    assert ["pfctl", "-X", "987654321"] in calls
    assert dict(steps)["pf enable reference 987654321"] is expect


def test_targeted_restore_passes_the_token_through(tmp_path, monkeypatch):
    log = CutStateLog(tmp_path / "c.jsonl")
    log.record_cut(asset_id="t-host", method="egress", platform="darwin", modified=[PF, TOKEN])
    seen: list = []
    monkeypatch.setattr(restore_mod, "_host_platform", lambda: "darwin")
    monkeypatch.setattr(restore_mod, "_firewall_steps", lambda p, r=(): seen.append(r) or [("x", True)])
    restore_mod._restore_targeted(log.latest_unresolved_for("t-host"))
    assert seen == [(PF, TOKEN)]


def test_token_entry_is_not_read_back_as_a_rule(tmp_path, monkeypatch):
    outputs = {
        ("pfctl", "-a", "com.apple/zee-egress-cut", "-s", "rules"): (True, "block drop out quick all"),
        ("pfctl", "-s", "info"): (True, "Status: Enabled"),
        ("pfctl", "-s", "rules"): (True, 'anchor "com.apple/*" all'),
    }
    monkeypatch.setattr(egress_mod, "sbin_which", lambda n: f"/sbin/{n}")
    monkeypatch.setattr(egress_mod, "_run",
                        lambda cmd: outputs.get(tuple([cmd[0].rsplit("/", 1)[-1], *cmd[1:]]), (False, "boom")))
    assert egress_mod._verify_egress([PF, TOKEN]) == ("confirmed", [])


# ── 4-persona #2: IPv6 gap is said where it exists ────────────────────


def test_iptables_and_windows_cuts_say_ipv6_is_not_blocked(monkeypatch):
    monkeypatch.setattr(egress_mod.shutil, "which", lambda n: f"/sbin/{n}" if n != "nft" else None)
    monkeypatch.setattr(egress_mod, "_run", lambda cmd: (True, ""))
    assert "IPv6 NOT blocked" in egress_mod._cut_egress_linux()[1]
    assert "IPv6 NOT blocked" in egress_mod._cut_egress_windows()[1]


# ── 4-persona #14: a failed cut says so, with a code; no dead restore hint ──


def test_failed_cut_notification_has_code_and_no_restore_hint_without_record(tmp_path, monkeypatch):
    import zee.responder.sequence as seq
    from datetime import datetime, timezone
    from zee.config.schema import AssetProfile
    from zee.events import TrapEvent
    from zee.telemetry.events_log import EventLog
    bodies: list = []
    monkeypatch.setattr(seq, "notify_local", lambda t, b: bodies.append((t, b)) or True)
    monkeypatch.setattr(seq, "cut_egress", lambda **_k: (False, "permission denied"))
    asset = AssetProfile(id="t-host", type="workstation", overnight_active=False,
                         decoy_paths=("/tmp/d",), response_mode="auto", cut_method="egress")
    event = TrapEvent.make(source="decoy_touch", confidence="high", asset_id="t-host",
                           decoy_path="/tmp/d", detail="decoy change (test)", op_class="change",
                           detected_at=datetime.now(timezone.utc))
    result = seq.handle(event, asset, dry_run=False, event_log=EventLog(log_dir=tmp_path),
                        cut_state=CutStateLog(tmp_path / "c.jsonl"))
    assert result.cut_failed is True and result.cut_executed is False
    title, body = bodies[-1]
    assert "FAILED (Z404)" in title and "may NOT be stopped" in body
    assert "recover with" not in body and "Z605" in body


def test_recover_hint_only_with_an_unresolved_record(tmp_path):
    from zee.responder.sequence import recover_hint
    log = CutStateLog(tmp_path / "c.jsonl")
    assert "recover with" not in recover_hint(log, "a")
    log.record_cut(asset_id="a", method="egress", platform="linux", modified=[NFT])
    assert recover_hint(log, "a") == "recover with: zee restore a"
    assert "recover with" not in recover_hint(None, "a")
