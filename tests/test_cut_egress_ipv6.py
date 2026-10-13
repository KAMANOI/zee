"""cut_egress must block IPv6 on iptables and Windows (command-list checks)."""
from zee.responder import cut_egress as ce


def _capture(monkeypatch, platform, have):
    calls = []
    monkeypatch.setattr(ce.sys, "platform", platform)
    monkeypatch.setattr(ce.shutil, "which", lambda n: n if n in have else None)
    monkeypatch.setattr(ce, "_run", lambda c: (calls.append(c) or (True, "")))
    return calls


def test_iptables_adds_ip6tables_chain(monkeypatch):
    calls = _capture(monkeypatch, "linux", {"iptables", "ip6tables"})
    ok, detail, _ = ce._cut_egress_linux()
    v6 = [c for c in calls if c[0] == "ip6tables"]
    assert ok and ["ip6tables", "-A", "ZEE_EGRESS", "-j", "DROP"] in v6
    assert not any("-d" in c for c in v6)  # no RFC1918-style pass-through for v6


def test_iptables_without_ip6tables_says_so(monkeypatch):
    _capture(monkeypatch, "linux", {"iptables"})
    ok, detail, _ = ce._cut_egress_linux()
    assert ok and "IPv6 NOT blocked" in detail


def test_windows_blocks_v6_and_allows_loopback(monkeypatch):
    calls = _capture(monkeypatch, "win32", {"netsh"})
    ce._cut_egress_windows()
    assert any("remoteip=0.0.0.0/0,::/0" in c for c in calls)
    assert any(any("::1/128" in a for a in c) for c in calls)
