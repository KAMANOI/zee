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
    if ok and asset_id and cut_state is not None and modified:
        cut_state.record_cut(
            asset_id=asset_id,
            method="egress",
            platform=sys.platform,
            modified=modified,
        )
    return ok, detail


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
        for cmd in commands:
            ok, msg = _run(cmd)
            if not ok:
                return False, f"{' '.join(cmd)}: {msg}", []
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
    # Enable pf if it isn't already.
    _run(["pfctl", "-e"])
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
    for cmd in commands:
        ok, msg = _run(cmd)
        if not ok:
            return False, f"{cmd[3:6]}: {msg}", []
    return True, "netsh advfirewall rules installed", [f"{ZEE_RULE_TAG}-block", f"{ZEE_RULE_TAG}-allow-local"]


def _run(cmd: list[str]) -> tuple[bool, str]:
    try:
        cp = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
    except (subprocess.SubprocessError, OSError) as e:
        return False, str(e)
    if cp.returncode != 0:
        return False, (cp.stderr or cp.stdout or "").strip()
    return True, (cp.stdout or "").strip()
