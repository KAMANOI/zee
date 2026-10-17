"""Windows firewall read-back through PowerShell objects (display-language independent).

The PowerShell outputs below are synthetic (built from the cmdlet documentation,
not captured from a Windows machine); real output is collected by the real-cut
workflow. Nothing here claims a Japanese netsh string: the point is that the
verdicts no longer depend on any localized text.
"""
from __future__ import annotations

import json
import subprocess

import pytest

from zee.recovery import restore as restore_mod
from zee.responder import cut_egress as egress_mod
from zee.responder import cut_full as full_mod

BLOCK = "zee-egress-cut-block"
OLD_ALLOW = "zee-egress-cut-allow-local"
RANGES = list(egress_mod.WINDOWS_BLOCK_RANGES)


def rule(name=BLOCK, *, display=None, enabled="True", direction="Outbound", action="Block",
         profile="Any", remote=RANGES):
    return {"name": name, "display": display or name, "enabled": enabled, "direction": direction,
            "action": action, "profile": profile, "remote": remote}


PROFILES_ON = {"Domain": "True", "Private": "True", "Public": "True"}


def snap(active=(), persistent=(), profiles=PROFILES_ON):
    return {"active": list(active), "persistent": list(persistent), "profiles": dict(profiles)}


# ── the PowerShell reader ──────────────────────────────────────────────


def _fake_ps(monkeypatch, stdout="", rc=0, exe="C:/ps.exe", raises=None):
    monkeypatch.setattr(full_mod.sys, "platform", "win32")
    monkeypatch.setattr(full_mod, "sbin_which", lambda n: exe if n == "powershell" else None)
    calls = []

    def run(argv, **k):
        calls.append(argv)
        if raises:
            raise raises
        return subprocess.CompletedProcess(argv, rc, stdout, "")
    monkeypatch.setattr(full_mod.subprocess, "run", run)
    return calls


def _envelope(active=(), persistent=(), profiles=()):
    return json.dumps({"ok": True, "active": list(active), "persistent": list(persistent),
                       "profiles": [{"name": k, "enabled": v} for k, v in dict(profiles).items()]})


def test_reader_zero_rules_is_an_empty_list_not_a_failure(monkeypatch):
    fn = full_mod.read_windows_firewall
    _fake_ps(monkeypatch, _envelope(profiles=PROFILES_ON))
    got = fn([BLOCK])
    assert got == {"active": [], "persistent": [], "profiles": PROFILES_ON}


def test_reader_accepts_powershell_51_single_object_forms(monkeypatch):
    fn = full_mod.read_windows_firewall
    r = rule()
    out = json.dumps({"ok": True, "active": r, "persistent": None, "profiles": {"name": "Public", "enabled": "True"}})
    _fake_ps(monkeypatch, out)
    got = fn([BLOCK])
    assert got["active"] == [r] and got["persistent"] is None and got["profiles"] == {"Public": "True"}  # null = that query failed


@pytest.mark.parametrize("stdout, rc, raises", [
    ("", 0, None),                                           # no output
    ("not json", 0, None),                                   # uninterpretable
    (json.dumps({"ok": False, "error": "x"}), 0, None),      # the script caught an error
    (_envelope(), 1, None),                                  # PowerShell failed
    (json.dumps({"ok": True}), 0, None),                      # store keys missing: not an empty read
    (json.dumps({"ok": True, "active": [], "persistent": []}), 0, None),  # profiles key missing
    (json.dumps({"ok": True, "active": [{"name": "x"}], "persistent": [], "profiles": []}), 0, None),  # rule keys missing
    (json.dumps({"ok": True, "active": [rule(enabled=True)], "persistent": [], "profiles": []}), 0, None),  # wrong type
    ("", 0, subprocess.TimeoutExpired("ps", 60)),
])
def test_reader_failure_is_none_never_empty(monkeypatch, stdout, rc, raises):
    fn = full_mod.read_windows_firewall
    _fake_ps(monkeypatch, stdout, rc=rc, raises=raises)
    assert fn([BLOCK]) is None


def test_reader_without_powershell_or_off_windows_is_none(monkeypatch):
    fn = full_mod.read_windows_firewall
    _fake_ps(monkeypatch, _envelope())
    monkeypatch.setattr(full_mod, "sbin_which", lambda n: None)
    assert fn([BLOCK]) is None
    monkeypatch.setattr(full_mod, "sbin_which", lambda n: "C:/ps.exe")
    monkeypatch.setattr(full_mod.sys, "platform", "linux")
    assert fn([BLOCK]) is None


def test_reader_refuses_names_it_cannot_embed_safely(monkeypatch):
    fn = full_mod.read_windows_firewall
    calls = _fake_ps(monkeypatch, _envelope())
    monkeypatch.setattr(full_mod, "sbin_which", lambda n: "C:/ps.exe")
    assert fn(["x'; calc; '"]) is None and not calls


# ── cut read-back (ActiveStore) ────────────────────────────────────────


def _verify(monkeypatch, snapshot, modified=(BLOCK,)):
    netsh_calls = []
    monkeypatch.setattr(egress_mod, "windows_firewall_snapshot", lambda names: snapshot)
    monkeypatch.setattr(egress_mod, "sbin_which", lambda n: f"C:/{n}")
    monkeypatch.setattr(egress_mod, "_run", lambda cmd: netsh_calls.append(cmd) or (False, "boom"))
    return egress_mod._verify_egress(list(modified)), netsh_calls


def test_confirmed_without_any_netsh_call(monkeypatch):
    (verdict, bad), netsh = _verify(monkeypatch, snap(active=[rule()]))
    assert (verdict, bad) == ("confirmed", []) and netsh == []


def test_zero_rules_is_missing_and_netsh_does_not_overrule(monkeypatch):
    (verdict, bad), netsh = _verify(monkeypatch, snap())
    assert verdict == "missing" and bad == [BLOCK] and netsh == []


@pytest.mark.parametrize("bad_rule", [
    rule(enabled="False"),
    rule(direction="Inbound"),
    rule(action="Allow"),
    rule(remote=RANGES[:5]),                 # IPv4 only
    rule(remote=["Any"]) ,
])
def test_rule_not_in_force_is_missing(monkeypatch, bad_rule):
    (verdict, _bad), netsh = _verify(monkeypatch, snap(active=[bad_rule]))
    assert verdict in ("missing", "unverified") and netsh == []
    if bad_rule["remote"] != ["Any"]:
        assert verdict == "missing"


@pytest.mark.parametrize("odd", [rule(enabled="Maybe"), rule(direction="Sideways"), rule(remote=None),
                                 rule(remote=["not an address"])])
def test_unexpected_values_are_unverified(monkeypatch, odd):
    (verdict, _bad), _n = _verify(monkeypatch, snap(active=[odd]))
    assert verdict == "unverified"


def test_two_rules_same_name_one_disabled_one_in_force(monkeypatch):
    (verdict, _b), _n = _verify(monkeypatch, snap(active=[rule(enabled="False"), rule()]))
    assert verdict == "confirmed"


def test_two_rules_same_name_all_disabled_is_missing(monkeypatch):
    (verdict, _b), _n = _verify(monkeypatch, snap(active=[rule(enabled="False"), rule(enabled="False")]))
    assert verdict == "missing"


def test_rule_found_by_display_name_when_name_differs(monkeypatch):
    (verdict, _b), _n = _verify(monkeypatch, snap(active=[rule(name="{GUID}", display=BLOCK)]))
    assert verdict == "confirmed"


@pytest.mark.parametrize("profile, states, verdict", [
    ("Any", PROFILES_ON, "confirmed"),
    ("Domain, Private, Public", PROFILES_ON, "confirmed"),
    ("Public", PROFILES_ON, "missing"),         # covers one profile only: the host's network may be another
    ("Domain, Private", PROFILES_ON, "missing"),
    ("Any", {**PROFILES_ON, "Public": "False"}, "missing"),
    ("Any", {**PROFILES_ON, "Public": "NotConfigured"}, "unverified"),
    ("Any", {"Domain": "True", "Private": "True"}, "unverified"),                         # profile not listed
    ("Weird", PROFILES_ON, "unverified"),
])
def test_profiles_must_be_on(monkeypatch, profile, states, verdict):
    (got, _b), _n = _verify(monkeypatch, snap(active=[rule(profile=profile)], profiles=states))
    assert got == verdict


def test_legacy_allow_rule_is_read_with_action_allow(monkeypatch):
    allow = rule(OLD_ALLOW, action="Allow", remote=["10.0.0.0/8"])
    (verdict, _b), _n = _verify(monkeypatch, snap(active=[rule(), allow]), modified=(BLOCK, OLD_ALLOW))
    assert verdict == "confirmed"


def test_powershell_unavailable_falls_back_to_netsh_text(monkeypatch):
    (verdict, bad), netsh = _verify(monkeypatch, None)
    assert netsh and netsh[0][:2] == ["C:/netsh", "advfirewall"] and verdict == "unverified"


def test_fallback_keeps_missing_vs_unverified_distinct(monkeypatch):
    monkeypatch.setattr(egress_mod, "windows_firewall_snapshot", lambda names: None)
    monkeypatch.setattr(egress_mod, "sbin_which", lambda n: f"C:/{n}")
    monkeypatch.setattr(egress_mod, "_run", lambda cmd: (False, "No rules match the specified criteria."))
    assert egress_mod._verify_egress([BLOCK])[0] == "missing"
    monkeypatch.setattr(egress_mod, "_run", lambda cmd: (False, "指定された条件に一致する規則はありません。"))
    assert egress_mod._verify_egress([BLOCK])[0] == "unverified"


# ── restore: removed from the creating store and from the ActiveStore ───


def _absent(monkeypatch, snapshot, netsh=(False, "boom")):
    monkeypatch.setattr(restore_mod, "windows_firewall_snapshot", lambda names: snapshot)
    monkeypatch.setattr(restore_mod, "_which", lambda n: f"C:/{n}")
    monkeypatch.setattr(restore_mod, "_run", lambda cmd: netsh)
    return restore_mod._verify_absent("netsh", ["netsh", "advfirewall", "firewall", "show", "rule", f"name={BLOCK}"])


def test_restore_absent_when_both_stores_are_empty(monkeypatch):
    assert _absent(monkeypatch, snap()) is True


def test_restore_not_absent_if_only_the_active_store_still_has_it(monkeypatch):
    assert _absent(monkeypatch, snap(active=[rule()])) is False


def test_restore_not_absent_if_only_the_creating_store_still_has_it(monkeypatch):
    assert _absent(monkeypatch, snap(persistent=[rule()])) is False


def test_restore_checks_every_copy_with_the_same_name(monkeypatch):
    assert _absent(monkeypatch, snap(persistent=[rule(), rule(name="{G2}", display=BLOCK)])) is False


def test_restore_powershell_answer_is_not_overruled_by_netsh(monkeypatch):
    # PowerShell says zero rules; netsh text says something else: PowerShell wins.
    assert _absent(monkeypatch, snap(), netsh=(True, "Rule Name: zee-egress-cut-block")) is True


def test_restore_without_powershell_uses_english_netsh_or_stays_unverified(monkeypatch):
    assert _absent(monkeypatch, None, netsh=(False, "No rules match the specified criteria.")) is True
    assert _absent(monkeypatch, None, netsh=(False, "指定された条件に一致する規則はありません。")) is None
    assert _absent(monkeypatch, None, netsh=(True, "Rule Name: zee-egress-cut-block")) is False


# ── review findings (ASTRA 2026-10-17) ─────────────────────────────────


def test_a_failed_query_is_null_and_the_others_keep_their_answer(monkeypatch):
    out = json.dumps({"ok": True, "active": [rule()], "persistent": None, "profiles": None})
    _fake_ps(monkeypatch, out)
    got = full_mod.read_windows_firewall([BLOCK])
    assert got["active"] == [rule()] and got["persistent"] is None and got["profiles"] is None


def test_name_match_ignores_case_in_cut_and_restore(monkeypatch):
    upper = rule(name="{GUID}", display=BLOCK.upper())
    (verdict, _b), _n = _verify(monkeypatch, snap(active=[upper]))
    assert verdict == "confirmed"
    assert _absent(monkeypatch, snap(active=[upper])) is False  # a surviving copy in other case


def test_restore_survivor_seen_survives_a_failed_other_store(monkeypatch):
    s = snap(active=[rule()])
    s["persistent"] = None
    netsh = []
    monkeypatch.setattr(restore_mod, "windows_firewall_snapshot", lambda names: s)
    monkeypatch.setattr(restore_mod, "_which", lambda n: f"C:/{n}")
    monkeypatch.setattr(restore_mod, "_run", lambda cmd: netsh.append(cmd) or (False, "No rules match the specified criteria."))
    show = ["netsh", "advfirewall", "firewall", "show", "rule", f"name={BLOCK}"]
    assert restore_mod._verify_absent("netsh", show) is False and netsh == []


def test_restore_zero_rules_but_a_store_unreadable_is_unverified_without_netsh(monkeypatch):
    s = snap()
    s["active"] = None
    netsh = []
    monkeypatch.setattr(restore_mod, "windows_firewall_snapshot", lambda names: s)
    monkeypatch.setattr(restore_mod, "_which", lambda n: f"C:/{n}")
    monkeypatch.setattr(restore_mod, "_run", lambda cmd: netsh.append(cmd) or (False, "No rules match the specified criteria."))
    show = ["netsh", "advfirewall", "firewall", "show", "rule", f"name={BLOCK}"]
    assert restore_mod._verify_absent("netsh", show) is None and netsh == []  # netsh text must not fill the gap


def test_cut_rule_mismatch_stands_when_the_profile_query_failed(monkeypatch):
    (verdict, bad), _n = _verify(monkeypatch, snap(active=[rule(enabled="False")], profiles=None))
    assert verdict == "missing" and bad == [BLOCK]


def test_cut_in_force_but_profile_query_failed_is_unverified(monkeypatch):
    (verdict, bad), _n = _verify(monkeypatch, snap(active=[rule()], profiles=None))
    assert verdict == "unverified" and bad == ["firewall profiles"]


def test_cut_active_query_failed_means_powershell_is_of_no_use(monkeypatch):
    s = snap()
    s["active"] = None
    (verdict, _bad), netsh = _verify(monkeypatch, s)
    assert netsh and verdict == "unverified"  # fell back to netsh text, which cannot confirm here
