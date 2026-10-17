"""Egress-only cut backends (spec §8).

`egress` blocks outbound traffic to non-local destinations while keeping
loopback and the local subnet reachable. Less destructive than `full`,
but still requires admin privileges.

Each backend returns (success: bool, detail: str). Callers must not
invoke these on dry_run.
"""

from __future__ import annotations

import ipaddress
import logging
import re
import shutil
import subprocess
import sys
from typing import Optional

from ..telemetry.cut_state import CutStateLog
from .cut_full import (
    SENTINEL_LINUX_IP6TABLES_EGRESS,
    SENTINEL_LINUX_IPTABLES_EGRESS,
    SENTINEL_LINUX_NFT_EGRESS,
    SENTINEL_MACOS_PFCTL_EGRESS,
    IPT_BACKEND_PREFIX,
    PF_TOKEN_PREFIX,
    iptables_backend,
    kernel_ipv6_absent,
    record_or_report,
    sbin_which,
    windows_firewall_snapshot,
)

logger = logging.getLogger(__name__)

# A single rule name we own end-to-end, so recovery can find it back.
ZEE_RULE_TAG = "zee-egress-cut"
# pf only evaluates an anchor that the main ruleset references
# (https://man.openbsd.org/pf.conf, "ANCHORS"). macOS's stock /etc/pf.conf
# references `anchor "com.apple/*"`, so Zee loads its rules as a child of it.
# The cut is confirmed only if the loaded main ruleset still references it.
PF_ANCHOR = "com.apple/" + ZEE_RULE_TAG
PF_LEGACY_ANCHOR = ZEE_RULE_TAG  # pre-fix cuts loaded here (never evaluated)


def cut_egress(
    *,
    asset_id: Optional[str] = None,
    cut_state: Optional[CutStateLog] = None,
) -> tuple[bool, str]:
    ok, detail, modified = _cut_egress_dispatch()
    verified: Optional[str] = None
    if ok and modified:
        # Exit codes are not proof: Zee's rules must be listed back by the
        # same backend before the cut is reported as applied.
        verified, missing = _verify_egress(modified)
        if verified != "confirmed":
            ok = False
            detail += f"; cut not confirmed by read-back ({verified}): {', '.join(missing)}"
    # Same as cut_full: record partial changes too (restore needs the record).
    if asset_id and cut_state is not None and modified:
        return record_or_report(cut_state, ok, detail, asset_id=asset_id,
                                method="egress", modified=modified, verified=verified)
    return ok, detail


# Messages meaning "nothing by that name" (the rule really is not there).
_ABSENT = ("No such file or directory", "No chain/target/match by that name",
           "does a matching rule exist", "No rules match the specified criteria")


def _verify_egress(modified: list[str]) -> tuple[str, list[str]]:
    """Read Zee's rules back. Returns ("confirmed" | "missing" | "unverified",
    labels of the checks that did not confirm). "missing" = the tool says the
    rule is not there or not in force; "unverified" = tool absent, output
    unreadable or in an unexpected form."""
    checks: list[tuple[str, list[str], object]] = []
    win_names: list[str] = []
    for m in modified:
        if m.startswith((PF_TOKEN_PREFIX, IPT_BACKEND_PREFIX)):
            continue  # notes for restore, not rules to read back
        if m == SENTINEL_LINUX_NFT_EGRESS:
            checks.append(("nft", ["nft", "list", "table", "inet", "zee_egress"], _nft_structure))
        elif m == SENTINEL_LINUX_IPTABLES_EGRESS:
            checks.append(("iptables chain", ["iptables", "-S", "ZEE_EGRESS"], _iptables_chain_structure))
            checks.append(("iptables jump", ["iptables", "-S", "OUTPUT"], _iptables_jump_first))
        elif m == SENTINEL_LINUX_IP6TABLES_EGRESS:
            # Same tool the cut picked (deterministic from the recorded backend).
            v6 = _ip6tables_tool(_recorded_backend(modified)) or "ip6tables"
            checks.append(("ip6tables chain", [v6, "-S", "ZEE_EGRESS"], _iptables_chain_structure))
            checks.append(("ip6tables jump", [v6, "-S", "OUTPUT"], _iptables_jump_first))
        elif m == SENTINEL_MACOS_PFCTL_EGRESS:
            checks.append(("pfctl rules", ["pfctl", "-a", PF_ANCHOR, "-s", "rules"], _pf_block_rule))
            checks.append(("pf enabled", ["pfctl", "-s", "info"], "Status: Enabled"))
            checks.append(("pf anchor reference", ["pfctl", "-s", "rules"], _pf_anchor_referenced))
            checks.append(("pf other com.apple anchors", ["pfctl", "-a", "com.apple", "-s", "Anchors"],
                           _pf_siblings_clear))
        else:  # Windows rule name
            win_names.append(m)
    missing: list[str] = []
    unverified: list[str] = []
    # PowerShell objects first (the same in every display language). netsh
    # text, English only, is read only when PowerShell cannot be used at all:
    # a clean PowerShell answer (rule absent, disabled, ...) is never
    # overruled by netsh.
    snapshot = windows_firewall_snapshot(win_names) if win_names else None
    if snapshot is not None and snapshot["active"] is None:
        snapshot = None  # the one query the cut verdict needs failed: PowerShell is of no use here
    if snapshot is not None:
        miss, unver = _windows_verdicts(snapshot, win_names)
        missing += miss
        unverified += unver
    else:
        for m in win_names:
            checks.append((m, ["netsh", "advfirewall", "firewall", "show", "rule", f"name={m}"],
                           _netsh_rule_check(m)))
    if any(cmd[0] == "netsh" for _l, cmd, _m in checks):
        # Last, so the Profiles of every rule above are already collected.
        checks.append(("firewall profiles", ["netsh", "advfirewall", "show", "allprofiles", "state"], None))
    rule_profiles: set[str] = set()
    for label, cmd, must in checks:
        exe = sbin_which(cmd[0])
        if exe is None:
            unverified.append(label)
            continue
        ok, out = _run([exe, *cmd[1:]])
        if label == "firewall profiles":
            verdict = _netsh_profiles_on(out, rule_profiles) if ok else "unverified"
        elif callable(must):
            verdict = must(out, rule_profiles) if ok else None
        else:
            verdict = "confirmed" if ok and must in out else None
        if verdict is None:  # generic: tool's own "not there" answer, else unverified
            absent = (not ok and not out.startswith("launch failed") and any(a in out for a in _ABSENT)) or (
                ok and cmd[:2] == ["pfctl", "-a"] and not out.strip())  # empty anchor = no rules
            verdict = "missing" if absent else "unverified"
        if verdict == "missing":
            missing.append(label)
        elif verdict == "unverified":
            unverified.append(label)
    if missing:
        return "missing", missing + unverified
    return ("unverified", unverified) if unverified else ("confirmed", [])


def _lines(out: str) -> list[str]:
    """Rule lines with comments and blank lines removed."""
    return [ln.split("#", 1)[0].strip() for ln in out.splitlines() if ln.split("#", 1)[0].strip()]


def _nft_structure(out: str, _profiles: set[str]) -> str:
    """`nft list table inet zee_egress`: the table must hold a chain hooked on
    output whose policy is drop (comments and other text do not count)."""
    lines = _lines(out)
    if not lines or not lines[0].startswith("table inet zee_egress"):
        return "unverified"
    hooked = [ln for ln in lines if ln.startswith("type filter hook ")]
    if not hooked:
        return "unverified"
    ok = any(" hook output " in f" {ln} " and "policy drop;" in ln for ln in hooked)
    return "confirmed" if ok else "missing"


def _iptables_chain_structure(out: str, _profiles: set[str]) -> str:
    """`iptables -S ZEE_EGRESS`: an unconditional `-j DROP` must exist and no
    unconditional ACCEPT may come before it."""
    lines = _lines(out)
    if not lines or lines[0] != "-N ZEE_EGRESS":
        return "unverified"
    for ln in lines[1:]:
        # A comment does not narrow a rule: drop it before judging.
        bare = re.sub(r'\s-m comment --comment ("[^"]*"|\S+)', "", ln)
        if bare == "-A ZEE_EGRESS -j ACCEPT":
            return "missing"
        if ln == "-A ZEE_EGRESS -j DROP":
            return "confirmed"
    return "missing"


def _iptables_jump_first(out: str, _profiles: set[str]) -> str:
    """`iptables -S OUTPUT`: the first OUTPUT rule must be the jump to Zee's
    chain (Zee inserts it with -I; anything earlier could bypass it)."""
    lines = _lines(out)
    if not lines or not lines[0].startswith("-P OUTPUT "):
        return "unverified"
    rules = [ln for ln in lines if ln.startswith("-A OUTPUT")]
    return "confirmed" if rules and rules[0] == "-A OUTPUT -j ZEE_EGRESS" else "missing"


# The pass rules Zee loads ahead of its block, as `pfctl -s rules` prints them
# (pfctl may add `inet`, `from any` and `flags ... keep state`).
_PF_ZEE_PASS = re.compile(
    r"^pass out quick (?:on lo0 all|(?:inet )?(?:from any )?to "
    r"(?:10\.0\.0\.0/8|172\.16\.0\.0/12|192\.168\.0\.0/16))(?:\s|$)")
_PF_REF = re.compile(r'^anchor "(?:com\.apple/\*|' + re.escape(PF_ANCHOR) + r')"(?: all)?$')


def _pf_block_rule(out: str, _profiles: set[str]) -> str:
    """`pfctl -a <anchor> -s rules`: the quick block-all rule Zee loads, with
    nothing but Zee's own pass rules ahead of it (with quick, first match wins)."""
    lines = _lines(out)
    if "block drop out quick all" not in lines:
        return "missing"
    ahead = lines[:lines.index("block drop out quick all")]
    return "confirmed" if all(_PF_ZEE_PASS.match(ln) for ln in ahead) else "unverified"


def _pf_anchor_referenced(out: str, _profiles: set[str]) -> str:
    """Main ruleset (`pfctl -s rules`): an unconditional filter `anchor` line
    must reach Zee's anchor. A conditional one (`... on lo0`, `in`) is not a
    reference for outbound traffic. Before it, any other anchor (contents not
    inspected here) or `pass ... quick` rule could decide a packet first:
    unverified. (Other anchors under com.apple/* are not inspected either;
    see docs/design/self-defense.md.)"""
    lines = _lines(out)
    for i, ln in enumerate(lines):
        if _PF_REF.match(ln):
            for prev in lines[:i]:
                if prev.startswith("anchor ") or (prev.startswith("pass") and " quick" in f" {prev} "):
                    return "unverified"
            return "confirmed"
    return "missing"


def _pf_siblings_clear(out: str, _profiles: set[str]) -> str:
    """`pfctl -a com.apple -s Anchors`: every other anchor under com.apple/*
    is evaluated with Zee's, possibly first, and a `quick` pass rule there
    would end evaluation before Zee's block (pf.conf(5) ANCHORS). Each one's
    rules must be readable and hold no outbound-capable `pass ... quick`
    rule and no nested anchor; otherwise unverified."""
    names = []
    for ln in out.splitlines():
        name = ln.strip()
        if not name or "ALTQ" in name:
            continue
        name = name if name.startswith("com.apple/") else f"com.apple/{name}"
        if name != PF_ANCHOR:
            names.append(name)
    exe = sbin_which("pfctl") or "pfctl"
    for name in names:
        ok, rules = _run([exe, "-a", name, "-s", "rules"])
        if not ok:
            return "unverified"
        for ln in _lines(rules):
            if ln.startswith("anchor ") or (
                    ln.startswith("pass") and " quick" in f" {ln} " and not ln.startswith("pass in ")):
                return "unverified"
    return "confirmed"


# IPv6 destinations the egress cut leaves open (the IPv6 side of "loopback
# and the local network"): link-local, ULA (fc00::/7, the RFC 1918
# counterpart) and link-scope multicast ff02::/16, which carries neighbor
# discovery (ICMPv6, filtered by OUTPUT unlike ARP): without it the
# link-local / ULA allowances stop working once the neighbor cache expires.
IPV6_LOCAL = ("fe80::/10", "fc00::/7", "ff02::/16")

# IPv4 outside RFC 1918 (10/8, 172.16/12, 192.168/16) and loopback (127/8),
# then IPv6 outside ::/127 (:: and ::1; a connect to :: reaches the host
# itself) and IPV6_LOCAL. netsh takes IPv4 and IPv6 ranges as `start-end`
# in one comma list ("Netsh AdvFirewall Firewall Commands", remoteip:
# IPAddress / IPSubnet / IPRange). Tests check that these ranges plus the
# allowed ones tile the whole address space with no overlap.
WINDOWS_BLOCK_RANGES = (
    "0.0.0.0-9.255.255.255",
    "11.0.0.0-126.255.255.255",
    "128.0.0.0-172.15.255.255",
    "172.32.0.0-192.167.255.255",
    "192.169.0.0-255.255.255.255",
    "::2-fbff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
    "fe00::-fe7f:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
    "fec0::-ff01:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
    "ff03::-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
)


def _intervals(entries) -> Optional[set[tuple[int, int, int]]]:
    """Address set of netsh RemoteIP entries as merged (version, first, last)
    intervals, so the comparison does not depend on how netsh prints them
    (zero compression, a range shown as a subnet). None if any entry is
    unreadable."""
    raw: list[tuple[int, int, int]] = []
    try:
        for e in entries:
            if "-" in e:
                a, b = (ipaddress.ip_address(x.strip()) for x in e.split("-", 1))
            else:
                net = ipaddress.ip_network(e.strip(), strict=False)
                a, b = net[0], net[-1]
            if a.version != b.version or int(a) > int(b):
                return None
            raw.append((a.version, int(a), int(b)))
    except ValueError:
        return None
    merged: list[list[int]] = []
    for v, a, b in sorted(raw):
        if merged and merged[-1][0] == v and a <= merged[-1][2] + 1:
            merged[-1][2] = max(merged[-1][2], b)
        else:
            merged.append([v, a, b])
    return {(v, a, b) for v, a, b in merged}


_WIN_PROFILES = ("Domain", "Private", "Public")


def _windows_rule_state(rule: dict, want_action: str) -> str:
    """One PowerShell rule object against what Zee set: "confirmed" |
    "missing" (readable, and not enabled / outbound / the action / the range)
    | "unverified" (a value in a form not understood). Enum names (Outbound,
    Block, True) are the same in every display language."""
    if (rule["enabled"] not in ("True", "False") or rule["direction"] not in ("Inbound", "Outbound")
            or rule["action"] not in ("Allow", "Block", "NotConfigured")):
        return "unverified"
    if rule["enabled"] != "True" or rule["direction"] != "Outbound" or rule["action"] != want_action:
        return "missing"
    if want_action == "Block":
        # Zee installs the rule for every profile; one that covers fewer
        # leaves the others (e.g. the network the host is on) unrestricted.
        profiles = _windows_profile_set(rule)
        if profiles is None:
            return "unverified"
        if profiles != set(_WIN_PROFILES):
            return "missing"
        if rule["remote"] is None:
            return "unverified"
        shown = _intervals(rule["remote"])
        if shown is None:
            return "unverified"
        if shown != _intervals(WINDOWS_BLOCK_RANGES):
            return "missing"
    return "confirmed"


def _windows_profile_set(rule: dict) -> Optional[set[str]]:
    """Profiles a rule applies to (`Any` = all three); None if unreadable."""
    names = {p.strip() for p in rule["profile"].split(",") if p.strip()}
    if names == {"Any"}:
        return set(_WIN_PROFILES)
    return names if names and names <= set(_WIN_PROFILES) else None


def _name_is(rule: dict, name: str) -> bool:
    """Windows compares rule names without regard to case (PowerShell -contains
    and netsh alike), so a copy in other case is still the same rule."""
    return name.casefold() in (rule["name"].casefold(), rule["display"].casefold())


def _windows_verdicts(snap: dict, names: list[str]) -> tuple[list[str], list[str]]:
    """(missing, unverified) labels from the ActiveStore (the policy in
    force; snap["active"] is not None here). Every rule with the name is
    looked at: one that is in force is enough, extra copies do not matter, and
    a copy that cannot be read does not count as one that is. A rule verdict
    from the ActiveStore stands even if the profile query then failed."""
    missing: list[str] = []
    unverified: list[str] = []
    in_force = False
    for name in names:
        want = "Block" if name.endswith("-block") else "Allow"
        states = [_windows_rule_state(r, want) for r in snap["active"] if _name_is(r, name)]
        if "confirmed" in states:
            in_force = True
        elif "unverified" in states:
            unverified.append(name)
        else:
            missing.append(name)  # zero rules, or only rules that are not in force
    if not missing and in_force:  # a rule that is not in force already fails; the firewall must be on for it to matter
        state = snap["profiles"]
        if state is None or any(state.get(p) not in ("True", "False") for p in _WIN_PROFILES):
            unverified.append("firewall profiles")
        elif any(state[p] != "True" for p in _WIN_PROFILES):
            missing.append("firewall profiles")
    return missing, unverified


def _netsh_rule_check(name: str):
    """`netsh advfirewall firewall show rule` must show the rule enabled,
    outbound, with the action and remote range Zee set. English field names
    only: any other form is unverified."""
    want_action = "Block" if name.endswith("-block") else "Allow"

    def check(out: str, profiles: set[str]) -> str:
        fields: dict[str, str] = {}
        for line in out.splitlines():
            key, sep, value = line.partition(":")
            if sep:
                fields.setdefault(key.strip(), value.strip())
        need = ("Enabled", "Direction", "Action", "RemoteIP", "Profiles")
        if fields.get("Rule Name") != name or any(k not in fields for k in need):
            return "unverified"
        profiles.update(p.strip() for p in fields["Profiles"].split(",") if p.strip())
        if fields["Enabled"] != "Yes" or fields["Direction"] != "Out" or fields["Action"] != want_action:
            return "missing"
        if want_action == "Block":
            shown = _intervals(r for r in fields["RemoteIP"].split(",") if r.strip())
            if shown is None:
                return "unverified"
            if shown != _intervals(WINDOWS_BLOCK_RANGES):
                return "missing"
        return "confirmed"
    return check


def _netsh_profiles_on(out: str, profiles: set[str]) -> str:
    """Every profile the block rule applies to must have the firewall ON
    (`netsh advfirewall show allprofiles state`)."""
    state: dict[str, str] = {}
    current = None
    for line in out.splitlines():
        line = line.strip()
        if line.endswith("Profile Settings:"):
            current = line.split()[0]
        elif current and line.startswith("State"):
            state[current] = line.split()[-1]
    wanted = profiles or {"Domain", "Private", "Public"}
    if any(p not in state for p in wanted):
        return "unverified"
    return "confirmed" if all(state[p] == "ON" for p in wanted) else "missing"



def _cut_egress_dispatch() -> tuple[bool, str, list[str]]:
    if sys.platform.startswith("linux"):
        return _cut_egress_linux()
    if sys.platform == "darwin":
        return _cut_egress_macos()
    if sys.platform == "win32":
        return _cut_egress_windows()
    return False, f"unsupported platform: {sys.platform}", []


def _cut_egress_linux() -> tuple[bool, str, list[str]]:
    # Prefer nftables when available; fall back to iptables.
    if shutil.which("nft"):
        script = (
            "add table inet zee_egress\n"
            "add chain inet zee_egress out "
            "{ type filter hook output priority 0; policy drop; }\n"
            "add rule inet zee_egress out oif lo accept\n"
            "add rule inet zee_egress out ip daddr 10.0.0.0/8 accept\n"
            "add rule inet zee_egress out ip daddr 172.16.0.0/12 accept\n"
            "add rule inet zee_egress out ip daddr 192.168.0.0/16 accept\n"
        )
        try:
            cp = subprocess.run(
                ["nft", "-f", "-"],
                input=script,
                capture_output=True,
                text=True,
                timeout=10,
            )
        except (subprocess.SubprocessError, OSError) as e:
            # A timeout may come after nft applied the table: record it.
            return False, f"nft failed: {e}", [SENTINEL_LINUX_NFT_EGRESS]
        if cp.returncode != 0:  # nft -f is atomic: nothing was applied
            return False, (cp.stderr or cp.stdout).strip(), []
        return True, "nftables zee_egress table installed", [SENTINEL_LINUX_NFT_EGRESS]

    if shutil.which("iptables"):
        commands = [
            ["iptables", "-N", "ZEE_EGRESS"],
            ["iptables", "-A", "ZEE_EGRESS", "-o", "lo", "-j", "ACCEPT"],
            ["iptables", "-A", "ZEE_EGRESS", "-d", "10.0.0.0/8", "-j", "ACCEPT"],
            ["iptables", "-A", "ZEE_EGRESS", "-d", "172.16.0.0/12", "-j", "ACCEPT"],
            ["iptables", "-A", "ZEE_EGRESS", "-d", "192.168.0.0/16", "-j", "ACCEPT"],
            ["iptables", "-A", "ZEE_EGRESS", "-j", "DROP"],
            ["iptables", "-I", "OUTPUT", "-j", "ZEE_EGRESS"],
        ]
        ok_v, version = _run(["iptables", "--version"])
        backend = iptables_backend(version) if ok_v else None
        # The kernel backend the cut's `iptables` used, so restore insists on
        # a tool that reads that backend back ("unknown" = check both).
        tags = [SENTINEL_LINUX_IPTABLES_EGRESS, IPT_BACKEND_PREFIX + (backend or "unknown")]
        for cmd in commands:
            ok, msg = _run(cmd)
            if not ok:
                # Recorded even when the first command fails: a timed-out
                # `-N` may still have created the chain, which restore removes.
                return False, f"{' '.join(cmd)}: {msg} (IPv6 NOT blocked)", tags
        # IPv6 has its own table: the same chain through ip6tables of the
        # same kernel backend. Without it the cut is a failure, never an
        # IPv4-only success -- unless the host kernel has no IPv6 at all
        # (ipv6.disable=1, confirmed by two independent signs, see
        # kernel_ipv6_absent): nothing can leave over IPv6 then, and
        # ip6tables-legacy cannot even initialise.
        if kernel_ipv6_absent():
            return True, ("iptables ZEE_EGRESS chain installed; IPv6 is disabled in the kernel "
                          "(no IPv6 socket can be opened): no IPv6 rule needed"), tags
        v6 = _ip6tables_tool(backend)
        if v6 is None:
            return False, ("iptables ZEE_EGRESS chain installed, but no ip6tables of the "
                           f"{backend or 'unknown'} backend: IPv6 NOT blocked"), tags
        tags.append(SENTINEL_LINUX_IP6TABLES_EGRESS)
        v6_commands = [[v6, "-N", "ZEE_EGRESS"], [v6, "-A", "ZEE_EGRESS", "-o", "lo", "-j", "ACCEPT"]]
        v6_commands += [[v6, "-A", "ZEE_EGRESS", "-d", net, "-j", "ACCEPT"] for net in IPV6_LOCAL]
        v6_commands += [[v6, "-A", "ZEE_EGRESS", "-j", "DROP"], [v6, "-I", "OUTPUT", "-j", "ZEE_EGRESS"]]
        for cmd in v6_commands:
            ok, msg = _run(cmd)
            if not ok:
                return False, (f"iptables ZEE_EGRESS chain installed, but {' '.join(cmd)}: {msg} "
                               "(IPv6 NOT blocked)"), tags
        return True, f"iptables + {v6} ZEE_EGRESS chains installed (IPv4 and IPv6)", tags

    return False, "no supported backend (need nft or iptables)", []


def _recorded_backend(modified) -> Optional[str]:
    for m in modified:
        if m.startswith(IPT_BACKEND_PREFIX):
            b = m.removeprefix(IPT_BACKEND_PREFIX)
            return None if b == "unknown" else b
    return None


def _ip6tables_tool(backend: Optional[str]) -> Optional[str]:
    """The ip6tables front end of the same kernel backend as the cut's
    iptables (backend None = unknown: ip6tables must then be unknown too,
    and restore checks both backends), or None."""
    for tool in ("ip6tables", "ip6tables-legacy" if backend == "legacy" else "ip6tables-nft"):
        if shutil.which(tool):
            ok, out = _run([tool, "--version"])
            if ok and iptables_backend(out) == backend:
                return tool
    return None


def _cut_egress_macos() -> tuple[bool, str, list[str]]:
    if not shutil.which("pfctl"):
        return False, "pfctl not available", []
    # `quick`: the first matching rule is final, so no later rule in the main
    # ruleset or another anchor can pass what Zee blocks (pf.conf(5) ANCHORS).
    rules = (
        "pass out quick on lo0 all\n"
        "pass out quick to 10.0.0.0/8\n"
        "pass out quick to 172.16.0.0/12\n"
        "pass out quick to 192.168.0.0/16\n"
        "block drop out quick all\n"
    )
    try:
        cp = subprocess.run(
            ["pfctl", "-a", PF_ANCHOR, "-f", "-"],
            input=rules,
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (subprocess.SubprocessError, OSError) as e:
        # A timeout may still have loaded the rules: record the anchor.
        return False, f"pfctl failed: {e}", [SENTINEL_MACOS_PFCTL_EGRESS]
    if cp.returncode != 0:
        return False, (cp.stderr or cp.stdout).strip(), []
    # Enable pf with a reference of Zee's own (`pfctl -E`, pfctl(8)); restore
    # releases exactly that reference (`pfctl -X <token>`), so pf goes back
    # off only if nobody else holds it on. The anchor does nothing while pf
    # is off, so a failure here is a failed cut (the anchor is still recorded).
    modified = [SENTINEL_MACOS_PFCTL_EGRESS]
    try:
        cp = subprocess.run(["pfctl", "-E"], capture_output=True, text=True, errors="replace", timeout=10)
        out, failed = f"{cp.stdout or ''}\n{cp.stderr or ''}", cp.returncode != 0
    except (subprocess.SubprocessError, OSError) as e:
        # A timeout may come after pf took the reference: keep any token it printed.
        out, failed = f"{_text(getattr(e, 'stdout', None))}\n{_text(getattr(e, 'stderr', None))}\n{e}", True
    m = re.search(r"Token\s*:\s*(\d+)", out)
    if failed:
        # Whether pf took a reference is unknown without a token: recorded as
        # "unknown", which restore reports as unverified (never as released).
        modified.append(PF_TOKEN_PREFIX + (m.group(1) if m else "unknown"))
        return False, f"pfctl -E failed: {out.strip()}", modified
    note = ""
    modified.append(PF_TOKEN_PREFIX + (m.group(1) if m else "unknown"))
    if not m:
        note = "; pf enable token not reported (restore will report pf's state as unverified)"
    return True, (f"pfctl anchor {PF_ANCHOR} loaded (new connections only: connections "
                  f"already open keep their pf state){note}"), modified


def _cut_egress_windows() -> tuple[bool, str, list[str]]:
    if not shutil.which("netsh"):
        return False, "netsh not available", []
    # One block rule over every IPv4 / IPv6 range except the local ones.
    # (netsh rejects remoteip=0.0.0.0/0, and in Windows Firewall a block rule
    # beats any allow rule, so "block all + allow local" cannot work; both
    # were found by the real-cut workflow run on 2026-10-15.)
    commands = [
        [
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name={ZEE_RULE_TAG}-block",
            "dir=out", "action=block", "enable=yes",
            "remoteip=" + ",".join(WINDOWS_BLOCK_RANGES),
        ],
    ]
    added: list[str] = []
    for cmd in commands:
        # Recorded before the outcome is known: a failed or timed-out add may
        # still have installed the rule, and restore needs the record.
        added.append(cmd[5].removeprefix("name="))
        ok, msg = _run(cmd)
        if not ok:
            return False, f"{cmd[3:6]}: {msg}", added
    return True, "netsh advfirewall rule installed (IPv4 and IPv6)", added


def _text(v) -> str:
    if isinstance(v, bytes):
        return v.decode("utf-8", "replace")
    return v or ""


def _run(cmd: list[str]) -> tuple[bool, str]:
    try:
        cp = subprocess.run(cmd, capture_output=True, text=True, errors="replace", timeout=10)
    except (subprocess.SubprocessError, OSError) as e:
        return False, str(e)
    if cp.returncode in (126, 127):  # not executable / loader failure: never "absent"
        return False, f"launch failed: exit {cp.returncode}: {(cp.stderr or cp.stdout or '').strip()}"
    if cp.returncode != 0:
        return False, (cp.stderr or cp.stdout or "").strip()
    return True, (cp.stdout or "").strip()
