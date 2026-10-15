"""Egress-only cut backends (spec §8).

`egress` blocks outbound traffic to non-local destinations while keeping
loopback and the local subnet reachable. Less destructive than `full`,
but still requires admin privileges.

Each backend returns (success: bool, detail: str). Callers must not
invoke these on dry_run.
"""

from __future__ import annotations

import logging
import re
import shutil
import subprocess
import sys
from typing import Optional

from ..telemetry.cut_state import CutStateLog
from .cut_full import (
    SENTINEL_LINUX_IPTABLES_EGRESS,
    SENTINEL_LINUX_NFT_EGRESS,
    SENTINEL_MACOS_PFCTL_EGRESS,
    record_or_report,
    sbin_which,
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
    for m in modified:
        if m == SENTINEL_LINUX_NFT_EGRESS:
            checks.append(("nft", ["nft", "list", "table", "inet", "zee_egress"], _nft_structure))
        elif m == SENTINEL_LINUX_IPTABLES_EGRESS:
            checks.append(("iptables chain", ["iptables", "-S", "ZEE_EGRESS"], _iptables_chain_structure))
            checks.append(("iptables jump", ["iptables", "-S", "OUTPUT"], _iptables_jump_first))
        elif m == SENTINEL_MACOS_PFCTL_EGRESS:
            checks.append(("pfctl rules", ["pfctl", "-a", PF_ANCHOR, "-s", "rules"], _pf_block_rule))
            checks.append(("pf enabled", ["pfctl", "-s", "info"], "Status: Enabled"))
            checks.append(("pf anchor reference", ["pfctl", "-s", "rules"], _pf_anchor_referenced))
        else:  # Windows rule name
            checks.append((m, ["netsh", "advfirewall", "firewall", "show", "rule", f"name={m}"],
                           _netsh_rule_check(m)))
    if any(cmd[0] == "netsh" for _l, cmd, _m in checks):
        # Last, so the Profiles of every rule above are already collected.
        checks.append(("firewall profiles", ["netsh", "advfirewall", "show", "allprofiles", "state"], None))
    missing: list[str] = []
    unverified: list[str] = []
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


def _pf_block_rule(out: str, _profiles: set[str]) -> str:
    """`pfctl -a <anchor> -s rules`: the outbound block-all rule Zee loads."""
    lines = _lines(out)
    return "confirmed" if "block drop out all" in lines else "missing"


def _pf_anchor_referenced(out: str, _profiles: set[str]) -> str:
    # A filter `anchor` line at the start of a rule: scrub-/nat-/rdr-anchor
    # lines merely contain the same text and do not evaluate filter rules.
    refs = ('anchor "com.apple/*"', f'anchor "{PF_ANCHOR}"')
    hit = any(line.strip().startswith(r) for line in out.splitlines() for r in refs)
    return "confirmed" if hit else "missing"


# Forms netsh may show for the block rule's remoteip (Zee sets 0.0.0.0/0).
# ponytail: exact display not checked on a real Windows host; any other form
# is "missing" (the cut is then reported FAILED, never applied).
_ANY_V4 = ("0.0.0.0/0", "0.0.0.0-255.255.255.255", "Any")


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
        if want_action == "Block" and fields["RemoteIP"] not in _ANY_V4:
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
            return False, f"nft failed: {e}", []
        if cp.returncode != 0:
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
        for i, cmd in enumerate(commands):
            ok, msg = _run(cmd)
            if not ok:
                # Once the chain exists it must be recorded, or it is left
                # behind and blocks the next `-N`.
                return False, f"{' '.join(cmd)}: {msg}", [SENTINEL_LINUX_IPTABLES_EGRESS] if i else []
        return True, "iptables ZEE_EGRESS chain installed", [SENTINEL_LINUX_IPTABLES_EGRESS]

    return False, "no supported backend (need nft or iptables)", []


def _cut_egress_macos() -> tuple[bool, str, list[str]]:
    if not shutil.which("pfctl"):
        return False, "pfctl not available", []
    rules = (
        "block drop out all\n"
        "pass out on lo0 all\n"
        "pass out to 10.0.0.0/8\n"
        "pass out to 172.16.0.0/12\n"
        "pass out to 192.168.0.0/16\n"
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
        return False, f"pfctl failed: {e}", []
    if cp.returncode != 0:
        return False, (cp.stderr or cp.stdout).strip(), []
    # Enable pf if it isn't already. The anchor does nothing while pf is off,
    # so a failure here is a failed cut (the anchor is still recorded).
    ok, msg = _run(["pfctl", "-e"])
    if not ok and "already enabled" not in msg:
        return False, f"pfctl -e failed: {msg}", [SENTINEL_MACOS_PFCTL_EGRESS]
    return True, f"pfctl anchor {PF_ANCHOR} loaded", [SENTINEL_MACOS_PFCTL_EGRESS]


def _cut_egress_windows() -> tuple[bool, str, list[str]]:
    if not shutil.which("netsh"):
        return False, "netsh not available", []
    # Block all outbound by default; allow local subnets.
    commands = [
        [
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name={ZEE_RULE_TAG}-block",
            "dir=out", "action=block", "enable=yes",
            "remoteip=0.0.0.0/0",
        ],
        [
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name={ZEE_RULE_TAG}-allow-local",
            "dir=out", "action=allow", "enable=yes",
            "remoteip=10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,127.0.0.0/8",
        ],
    ]
    added: list[str] = []
    for cmd in commands:
        ok, msg = _run(cmd)
        if not ok:
            # The block rule may already be in place: report it so it is recorded.
            return False, f"{cmd[3:6]}: {msg}", added
        added.append(cmd[5].removeprefix("name="))
    return True, "netsh advfirewall rules installed", added


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
