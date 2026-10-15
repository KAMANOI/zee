"""Egress-only cut backends (spec §8).

`egress` blocks outbound traffic to non-local destinations while keeping
loopback and the local subnet reachable. Less destructive than `full`,
but still requires admin privileges.

Each backend returns (success: bool, detail: str). Callers must not
invoke these on dry_run.
"""

from __future__ import annotations

import logging
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
    names of the checks that did not confirm). "missing" = the tool says the
    rule is not there; "unverified" = tool absent / unreadable / odd output."""
    checks: list[tuple[str, list[str], str]] = []  # (label, show command, text that must appear)
    for m in modified:
        if m == SENTINEL_LINUX_NFT_EGRESS:
            checks.append(("nft", ["nft", "list", "table", "inet", "zee_egress"], "drop"))
        elif m == SENTINEL_LINUX_IPTABLES_EGRESS:
            checks.append(("iptables chain", ["iptables", "-S", "ZEE_EGRESS"], "-j DROP"))
            checks.append(("iptables jump", ["iptables", "-C", "OUTPUT", "-j", "ZEE_EGRESS"], ""))
        elif m == SENTINEL_MACOS_PFCTL_EGRESS:
            checks.append(("pfctl rules", ["pfctl", "-a", ZEE_RULE_TAG, "-s", "rules"], "block"))
            checks.append(("pf enabled", ["pfctl", "-s", "info"], "Status: Enabled"))
        else:  # Windows rule name
            checks.append((m, ["netsh", "advfirewall", "firewall", "show", "rule", f"name={m}"], m))
    missing: list[str] = []
    unverified: list[str] = []
    for label, cmd, must in checks:
        exe = sbin_which(cmd[0])
        if exe is None:
            unverified.append(label)
            continue
        ok, out = _run([exe, *cmd[1:]])
        if ok and must in out:
            continue
        absent = (not ok and any(a in out for a in _ABSENT)) or (
            ok and cmd[:2] == ["pfctl", "-a"] and not out.strip())  # empty anchor = no rules
        (missing if absent else unverified).append(label)
    if missing:
        return "missing", missing + unverified
    return ("unverified", unverified) if unverified else ("confirmed", [])


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
            ["pfctl", "-a", ZEE_RULE_TAG, "-f", "-"],
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
    return True, f"pfctl anchor {ZEE_RULE_TAG} loaded", [SENTINEL_MACOS_PFCTL_EGRESS]


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
    if cp.returncode != 0:
        return False, (cp.stderr or cp.stdout or "").strip()
    return True, (cp.stdout or "").strip()
