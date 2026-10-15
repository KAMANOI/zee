"""v0.13.1: outbound IPv6 on the iptables and Windows egress paths.

Every OS call is mocked; nothing touches a real network or firewall.
"""

from __future__ import annotations

import ipaddress

import pytest

from zee.recovery import restore as restore_mod
from zee.responder import cut_egress as egress_mod
from zee.responder import cut_full as full_mod
from zee.telemetry.cut_state import CutStateLog

IPT = full_mod.SENTINEL_LINUX_IPTABLES_EGRESS
IP6T = full_mod.SENTINEL_LINUX_IP6TABLES_EGRESS
LEGACY = full_mod.IPT_BACKEND_PREFIX + "legacy"


# ── Windows: the block ranges are exactly the complement of the local ones ──


def _nets(ranges):
    out = []
    for r in ranges:
        a, b = (ipaddress.ip_address(x) for x in r.split("-"))
        out += ipaddress.summarize_address_range(a, b)
    return out


@pytest.mark.parametrize("version, allowed", [
    (4, ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8"]),
    (6, ["::/127", *egress_mod.IPV6_LOCAL]),  # ::/127 = :: and ::1
])
def test_windows_ranges_tile_the_whole_space_without_overlap(version, allowed):
    blocked = [n for n in _nets(egress_mod.WINDOWS_BLOCK_RANGES) if n.version == version]
    allowed = [ipaddress.ip_network(a) for a in allowed]
    whole = ipaddress.ip_network("0.0.0.0/0" if version == 4 else "::/0")
    assert list(ipaddress.collapse_addresses(blocked + allowed)) == [whole]
    total = sum(n.num_addresses for n in blocked + allowed)
    assert total == whole.num_addresses  # equal sizes + full cover = no overlap


def test_windows_rule_carries_ipv4_and_ipv6(monkeypatch):
    calls: list = []
    monkeypatch.setattr(egress_mod.shutil, "which", lambda n: f"C:/{n}")
    monkeypatch.setattr(egress_mod, "_run", lambda cmd: calls.append(cmd) or (True, ""))
    ok, detail, added = egress_mod._cut_egress_windows()
    assert ok and "NOT blocked" not in detail and added == ["zee-egress-cut-block"]
    remote = calls[0][-1].removeprefix("remoteip=").split(",")
    assert "::2-fbff:ffff:ffff:ffff:ffff:ffff:ffff:ffff" in remote and "0.0.0.0-9.255.255.255" in remote
    assert not any(r in ("0.0.0.0/0", "::/0") for r in remote)  # netsh rejects the whole-space form


def _show(remote):
    return ("Rule Name: zee-egress-cut-block\n" "Enabled: Yes\n" "Direction: Out\n"
            "Profiles: Domain,Private,Public\n" "Action: Block\n" f"RemoteIP: {remote}\n")


@pytest.mark.parametrize("remote, verdict", [
    (",".join(egress_mod.WINDOWS_BLOCK_RANGES), "confirmed"),
    # Printed differently (subnet form, no zero compression, other order): same set.
    (",".join([*egress_mod.WINDOWS_BLOCK_RANGES[5:], *egress_mod.WINDOWS_BLOCK_RANGES[:5]])
     .replace("fe00::-fe7f:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "fe00::/9")
     .replace("::2-", "0:0:0:0:0:0:0:2-"), "confirmed"),
    (",".join(egress_mod.WINDOWS_BLOCK_RANGES[:5]), "missing"),  # IPv4 only
    (",".join(egress_mod.WINDOWS_BLOCK_RANGES).replace("ff03::", "ff02::"), "missing"),  # wider
    ("Any", "unverified"),
    (",".join(egress_mod.WINDOWS_BLOCK_RANGES) + ",garbage", "unverified"),
])
def test_netsh_read_back_compares_address_sets(remote, verdict):
    assert egress_mod._netsh_rule_check("zee-egress-cut-block")(_show(remote), set()) == verdict


# ── Linux iptables path: ip6tables of the same backend, or a failed cut ──


def _linux(monkeypatch, tools, versions, fail=None):
    calls: list = []
    monkeypatch.setattr(egress_mod.shutil, "which", lambda n: f"/sbin/{n}" if n in tools else None)

    def run(cmd):
        calls.append(cmd)
        if cmd[1:] == ["--version"]:
            return True, versions[cmd[0]]
        if fail and cmd[0] == fail[0] and cmd[1] == fail[1]:
            return False, "can't initialize ip6tables table `filter'"
        return True, ""
    monkeypatch.setattr(egress_mod, "_run", run)
    return calls


def test_iptables_cut_adds_the_ip6tables_chain(monkeypatch):
    calls = _linux(monkeypatch, {"iptables", "ip6tables"},
                   {"iptables": "iptables v1.8.7 (legacy)", "ip6tables": "ip6tables v1.8.7 (legacy)"})
    ok, detail, modified = egress_mod._cut_egress_linux()
    assert ok and "NOT blocked" not in detail
    assert modified == [IPT, LEGACY, IP6T]
    v6 = [c for c in calls if c[0] == "ip6tables" and c[1] != "--version"]
    assert v6[0] == ["ip6tables", "-N", "ZEE_EGRESS"]
    assert ["ip6tables", "-A", "ZEE_EGRESS", "-o", "lo", "-j", "ACCEPT"] in v6
    for net in ("fe80::/10", "fc00::/7", "ff02::/16"):
        assert ["ip6tables", "-A", "ZEE_EGRESS", "-d", net, "-j", "ACCEPT"] in v6
    assert v6[-2:] == [["ip6tables", "-A", "ZEE_EGRESS", "-j", "DROP"],
                       ["ip6tables", "-I", "OUTPUT", "-j", "ZEE_EGRESS"]]


def test_ip6tables_of_the_other_backend_is_not_used(monkeypatch):
    """`ip6tables` points at nf_tables while the cut's iptables is legacy:
    ip6tables-legacy is used; without it the cut fails."""
    versions = {"iptables": "iptables v1.8.7 (legacy)", "ip6tables": "ip6tables v1.8.7 (nf_tables)",
                "ip6tables-legacy": "ip6tables v1.8.7 (legacy)"}
    calls = _linux(monkeypatch, {"iptables", "ip6tables", "ip6tables-legacy"}, versions)
    assert egress_mod._cut_egress_linux()[0] is True
    assert ["ip6tables-legacy", "-A", "ZEE_EGRESS", "-j", "DROP"] in calls
    _linux(monkeypatch, {"iptables", "ip6tables"}, versions)
    ok, detail, modified = egress_mod._cut_egress_linux()
    assert ok is False and "IPv6 NOT blocked" in detail and IP6T not in modified


def test_ip6tables_failure_fails_the_cut_and_is_recorded(monkeypatch, tmp_path):
    _linux(monkeypatch, {"iptables", "ip6tables"},
           {"iptables": "iptables v1.8.7 (legacy)", "ip6tables": "ip6tables v1.8.7 (legacy)"},
           fail=("ip6tables", "-N"))
    monkeypatch.setattr(egress_mod.sys, "platform", "linux")
    log = CutStateLog(tmp_path / "c.jsonl")
    ok, detail = egress_mod.cut_egress(asset_id="t", cut_state=log)
    assert ok is False and "IPv6 NOT blocked" in detail
    # The IPv4 chain (and a possibly half-made IPv6 one) is recorded for restore.
    assert set(log.latest_unresolved_for("t").modified) == {IPT, LEGACY, IP6T}


V4_CHAIN = ("-N ZEE_EGRESS\n-A ZEE_EGRESS -o lo -j ACCEPT\n"
            "-A ZEE_EGRESS -d 10.0.0.0/8 -j ACCEPT\n-A ZEE_EGRESS -j DROP")
V6_CHAIN = ("-N ZEE_EGRESS\n-A ZEE_EGRESS -o lo -j ACCEPT\n-A ZEE_EGRESS -d fe80::/10 -j ACCEPT\n"
            "-A ZEE_EGRESS -d fc00::/7 -j ACCEPT\n-A ZEE_EGRESS -d ff02::/16 -j ACCEPT\n"
            "-A ZEE_EGRESS -j DROP")


@pytest.mark.parametrize("v6_chain, expect", [(V6_CHAIN, "confirmed"),
                                             ("-N ZEE_EGRESS\n-A ZEE_EGRESS -j ACCEPT", "missing")])
def test_ipv6_chain_is_read_back(monkeypatch, v6_chain, expect):
    monkeypatch.setattr(egress_mod, "sbin_which", lambda n: f"/sbin/{n}")
    monkeypatch.setattr(egress_mod.shutil, "which", lambda n: f"/sbin/{n}")

    def run(cmd):
        tool = cmd[0].rsplit("/", 1)[-1]
        if cmd[1:] == ["--version"]:
            return True, f"{tool} v1.8.7 (legacy)"
        if cmd[1:] == ["-S", "OUTPUT"]:
            return True, "-P OUTPUT ACCEPT\n-A OUTPUT -j ZEE_EGRESS"
        return True, V4_CHAIN if tool == "iptables" else v6_chain
    monkeypatch.setattr(egress_mod, "_run", run)
    verdict, missing = egress_mod._verify_egress([IPT, LEGACY, IP6T])
    assert verdict == expect
    assert (missing == []) if expect == "confirmed" else ("ip6tables chain" in missing)


# ── restore: the ip6tables chain is removed and read back on every backend ──


def test_ip6tables_absent_answer_is_absent(monkeypatch):
    monkeypatch.setattr(restore_mod, "_run", lambda cmd: (False, "ip6tables: No chain/target/match by that name."))
    assert restore_mod._verify_absent("ip6tables-legacy", ["ip6tables-legacy", "-S", "ZEE_EGRESS"]) is True
    msg = ("ip6tables v1.8.7 (legacy): can't initialize ip6tables table `filter': "
           "Table does not exist (do you need to insmod?)")
    monkeypatch.setattr(restore_mod, "_run", lambda cmd: (False, msg))
    assert restore_mod._verify_absent("ip6tables", ["ip6tables", "-S", "ZEE_EGRESS"]) is True


def test_ipv6_chain_left_behind_fails_restore(monkeypatch):
    monkeypatch.setattr(restore_mod, "_which", lambda n: f"/usr/sbin/{n}")

    def run(cmd):
        if cmd[0] == "nft":
            return False, "Error: No such file or directory\nlist table inet zee_egress\n ^"
        if cmd[1] == "-S" and cmd[0] == "ip6tables-nft":
            return True, V6_CHAIN  # still there
        if cmd[1] == "-S":
            return False, f"{cmd[0].split('-')[0]}: No chain/target/match by that name."
        if cmd[1] == "--version":
            return True, f"{cmd[0]} v1.8.10 ({'legacy' if 'legacy' in cmd[0] else 'nf_tables'})"
        return True, ""
    monkeypatch.setattr(restore_mod, "_run", run)
    steps = dict(restore_mod._firewall_steps("linux", (IPT, LEGACY, IP6T)))
    assert steps["ip6tables-nft"] is False
    assert steps["ip6tables"] is True and steps["ip6tables-legacy"] is True


def test_recorded_ipv6_chain_needs_an_ip6tables_of_that_backend(monkeypatch):
    tools = {"iptables", "iptables-legacy", "ip6tables"}
    monkeypatch.setattr(restore_mod, "_which", lambda n: f"/usr/sbin/{n}" if n in tools else None)

    def run(cmd):
        if cmd[1] == "--version":
            return True, f"{cmd[0]} v1.8.10 ({'legacy' if 'legacy' in cmd[0] else 'nf_tables'})"
        if cmd[1] == "-S":
            return False, f"{cmd[0].split('-')[0]}: No chain/target/match by that name."
        return True, ""
    monkeypatch.setattr(restore_mod, "_run", run)
    steps = dict(restore_mod._firewall_steps("linux", (IPT, LEGACY, IP6T)))
    assert steps["ip6tables legacy backend:not-found"] is None
    # A v0.13.0 record (no IPv6 chain) does not need ip6tables coverage.
    steps = dict(restore_mod._firewall_steps("linux", (IPT, LEGACY)))
    assert not any(k.startswith("ip6tables legacy") for k in steps)


def test_unreadable_ledger_needs_both_backends_for_ip6tables_too(monkeypatch):
    tools = {"iptables-legacy", "iptables-nft", "ip6tables-legacy"}
    monkeypatch.setattr(restore_mod, "_which", lambda n: f"/usr/sbin/{n}" if n in tools else None)

    def run(cmd):
        if cmd[1] == "--version":
            return True, f"{cmd[0]} v1.8.10 ({'legacy' if 'legacy' in cmd[0] else 'nf_tables'})"
        if cmd[1] == "-S":
            return False, f"{cmd[0].split('-')[0]}: No chain/target/match by that name."
        return True, ""
    monkeypatch.setattr(restore_mod, "_run", run)
    steps = dict(restore_mod._firewall_steps("linux", restore_mod._LEDGER_UNREADABLE))
    assert steps["ip6tables nf_tables backend:not-found"] is None
    assert "iptables nf_tables backend:not-found" not in steps


def test_record_with_only_the_ipv6_chain_gets_an_unknown_backend(tmp_path):
    log = CutStateLog(tmp_path / "c.jsonl")
    log.record_cut(asset_id="a", method="egress", platform="linux", modified=[IP6T])
    assert full_mod.IPT_BACKEND_PREFIX + "unknown" in log.latest_unresolved_for("a").modified


# ── 4-persona review of v0.13.1 ───────────────────────────────────────

# libiptc TC_INIT: socket(AF_INET6, ...) fails with EAFNOSUPPORT when the
# kernel has no IPv6; TC_STRERROR has no entry for it, so strerror() prints:
NO_V6 = ("ip6tables v1.8.7 (legacy): can't initialize ip6tables table `filter': "
         "Address family not supported by protocol")


@pytest.mark.parametrize("host_has_no_ipv6, expect", [(True, True), (False, None)])
def test_ipv6_disabled_kernel_answer_is_absent_only_when_the_host_has_no_ipv6(monkeypatch, host_has_no_ipv6, expect):
    """Codex round 6: a process only forbidden AF_INET6 (seccomp) gets the
    same answer while the chain may still exist: then unverified."""
    monkeypatch.setattr(restore_mod, "kernel_ipv6_absent", lambda: host_has_no_ipv6)
    monkeypatch.setattr(restore_mod, "_run", lambda cmd: (False, NO_V6))
    assert restore_mod._verify_absent("ip6tables-legacy", ["ip6tables-legacy", "-S", "ZEE_EGRESS"]) is expect
    msg4 = NO_V6.replace("ip6tables", "iptables")
    monkeypatch.setattr(restore_mod, "_run", lambda cmd: (False, msg4))
    assert restore_mod._verify_absent("iptables-legacy", ["iptables-legacy", "-S", "ZEE_EGRESS"]) is None


@pytest.mark.parametrize("absent, expect_ok", [(True, True), (False, False)])
def test_ipv6_disabled_kernel_needs_no_ipv6_rule(monkeypatch, absent, expect_ok):
    calls = _linux(monkeypatch, {"iptables", "ip6tables"},
                   {"iptables": "iptables v1.8.7 (legacy)", "ip6tables": "ip6tables v1.8.7 (legacy)"},
                   fail=("ip6tables", "-N"))
    monkeypatch.setattr(egress_mod, "kernel_ipv6_absent", lambda: absent)
    ok, detail, modified = egress_mod._cut_egress_linux()
    assert ok is expect_ok
    if absent:
        assert "IPv6 is disabled in the kernel" in detail and IP6T not in modified
        assert not any(c[0].startswith("ip6tables") for c in calls)
    else:  # e.g. only this process is denied AF_INET6: never a success
        assert "IPv6 NOT blocked" in detail


class _Sock:
    def __init__(self, code):
        self.code = code

    def __call__(self, *a):
        if self.code is not None:
            raise OSError(self.code, "x")
        return self

    def close(self):
        pass


@pytest.mark.parametrize("sock_err, disable, expect", [
    (None, "1", False),                 # IPv6 socket opens
    ("EACCES", "1", False),             # other error: cannot tell
    ("EAFNOSUPPORT", "1", True),        # ipv6.disable=1
    ("EAFNOSUPPORT", "0", False),       # seccomp-only (RestrictAddressFamilies)
    ("EAFNOSUPPORT", None, False),      # no parameter file: cannot tell
    ("EAFNOSUPPORT", PermissionError, False),  # Codex round 7: unreadable is not "absent"
])
def test_kernel_ipv6_absent_needs_two_independent_signs(monkeypatch, sock_err, disable, expect):
    import builtins
    import errno as errno_mod
    import io
    code = getattr(errno_mod, sock_err) if sock_err else None
    monkeypatch.setattr(full_mod.socket, "socket", _Sock(code))
    real_open = builtins.open

    def fake_open(path, *a, **k):
        if path == "/sys/module/ipv6/parameters/disable":
            if disable is None:
                raise FileNotFoundError(path)
            if disable is PermissionError:
                raise PermissionError(path)
            return io.StringIO(disable + "\n")
        return real_open(path, *a, **k)
    monkeypatch.setattr(builtins, "open", fake_open)
    assert full_mod.kernel_ipv6_absent() is expect


def test_ip6tables_failure_says_the_ipv4_chain_stays(monkeypatch):
    _linux(monkeypatch, {"iptables", "ip6tables"},
           {"iptables": "iptables v1.8.7 (legacy)", "ip6tables": "ip6tables v1.8.7 (legacy)"},
           fail=("ip6tables", "-A"))
    ok, detail, _m = egress_mod._cut_egress_linux()
    assert ok is False and detail.startswith("iptables ZEE_EGRESS chain installed, but ip6tables -A")
