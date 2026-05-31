"""Full network cut backends (spec §8).

`full` brings down the network interfaces. This is destructive to all
traffic on the host, including legitimate sessions. Only invoked when the
asset profile sets cut_method='full' AND mode='contain' AND dry_run=False.

Each backend returns (success: bool, detail: str). On dry_run, callers
must not invoke these functions at all; they are not safe-by-default.
"""

from __future__ import annotations

import json
import logging
import shutil
import subprocess
import sys
from typing import Optional

from ..telemetry.cut_state import CutStateLog

logger = logging.getLogger(__name__)

# Sentinels recorded in cut_state.modified for cut paths that are not
# tied to a specific interface name. recovery/restore.py branches on
# these to undo the right side-effect.
SENTINEL_LINUX_NMCLI = "__zee_nmcli_networking__"
SENTINEL_LINUX_NFT_EGRESS = "__zee_nft_egress_table__"
SENTINEL_LINUX_IPTABLES_EGRESS = "__zee_iptables_egress_chain__"
SENTINEL_MACOS_PFCTL_EGRESS = "__zee_pfctl_egress_anchor__"


def cut_full(
    *,
    asset_id: Optional[str] = None,
    cut_state: Optional[CutStateLog] = None,
) -> tuple[bool, str]:
    """Disable all network interfaces / services for this host.

    ``asset_id`` and ``cut_state`` are optional only for test stubs.
    Production callers (responder/sequence.handle, ``zee cut``) MUST
    supply both: without them, no cut-state record is written and the
    subsequent ``zee restore`` falls back to the v0.2 "enable
    everything" behaviour with a stderr warning.
    """
    ok, detail, modified = _cut_full_dispatch()
    if ok and asset_id and cut_state is not None and modified:
        cut_state.record_cut(
            asset_id=asset_id,
            method="full",
            platform=sys.platform,
            modified=modified,
        )
    return ok, detail


def _cut_full_dispatch() -> tuple[bool, str, list[str]]:
    if sys.platform.startswith("linux"):
        return _cut_full_linux()
    if sys.platform == "darwin":
        return _cut_full_macos()
    if sys.platform == "win32":
        return _cut_full_windows()
    return False, f"unsupported platform: {sys.platform}", []


def _cut_full_linux() -> tuple[bool, str, list[str]]:
    # Prefer nmcli when available (handles WiFi cleanly).
    if shutil.which("nmcli"):
        result = _run(["nmcli", "networking", "off"])
        if result[0]:
            return True, "nmcli networking off", [SENTINEL_LINUX_NMCLI]
        logger.warning("nmcli failed (%s); falling back to `ip link`", result[1])
    # Fallback: bring all non-loopback interfaces down.
    if shutil.which("ip"):
        ifaces = list_linux_interfaces()
        all_ok = True
        details: list[str] = []
        modified: list[str] = []
        for ifname in ifaces:
            ok, msg = _run(["ip", "link", "set", ifname, "down"])
            details.append(f"{ifname}:{'ok' if ok else 'fail'}")
            if ok:
                modified.append(ifname)
            all_ok = all_ok and ok
        return all_ok, "ip link down: " + ", ".join(details), modified
    return False, "no supported backend (need nmcli or ip)", []


def list_linux_interfaces() -> list[str]:
    """Enumerate non-loopback Linux interfaces. Used by both cut and restore."""
    try:
        out = subprocess.check_output(
            ["ip", "-o", "link", "show"], text=True, timeout=3
        )
    except (subprocess.SubprocessError, OSError):
        return []
    ifs: list[str] = []
    for line in out.splitlines():
        parts = line.split(":")
        if len(parts) >= 2:
            name = parts[1].strip().split("@")[0]
            if name and name != "lo":
                ifs.append(name)
    return ifs


def _cut_full_macos() -> tuple[bool, str, list[str]]:
    if not shutil.which("networksetup"):
        return False, "networksetup not available", []
    services = list_macos_services()
    all_ok = True
    details: list[str] = []
    modified: list[str] = []
    for svc in services:
        ok, _msg = _run(["networksetup", "-setnetworkserviceenabled", svc, "off"])
        details.append(f"{svc}:{'ok' if ok else 'fail'}")
        if ok:
            modified.append(svc)
        all_ok = all_ok and ok
    return all_ok, "networksetup -setnetworkserviceenabled off: " + ", ".join(details), modified


def list_macos_services() -> list[str]:
    """Enumerate currently-enabled macOS network services. Used by both cut and restore.

    Disabled services (those marked with '*' by networksetup) are excluded.
    """
    try:
        out = subprocess.check_output(
            ["networksetup", "-listallnetworkservices"], text=True, timeout=3
        )
    except (subprocess.SubprocessError, OSError):
        return []
    services: list[str] = []
    for line in out.splitlines()[1:]:  # skip header
        name = line.strip()
        if name and not name.startswith("*"):  # '*' marks disabled services
            services.append(name)
    return services


def _cut_full_windows() -> tuple[bool, str, list[str]]:
    # netsh requires the visible interface name; enumerate first.
    ifaces = list_windows_interfaces(only_enabled=True)
    if not ifaces:
        return False, "no enabled interfaces found via netsh", []
    all_ok = True
    details: list[str] = []
    modified: list[str] = []
    for ifname in ifaces:
        ok, _msg = _run(
            ["netsh", "interface", "set", "interface", ifname, "admin=disable"]
        )
        details.append(f"{ifname}:{'ok' if ok else 'fail'}")
        if ok:
            modified.append(ifname)
        all_ok = all_ok and ok
    return all_ok, "netsh disable: " + ", ".join(details), modified


def list_windows_interfaces(*, only_enabled: bool = True) -> list[str]:
    """Enumerate Windows interfaces.

    v0.3 (spec L1): the primary path is PowerShell ``Get-NetAdapter``,
    whose output is structured JSON and locale-independent (column
    names are fixed regardless of the system display language).
    The legacy ``netsh interface show interface`` parser is kept as
    a fallback for environments where PowerShell ``Get-NetAdapter``
    is unavailable (PowerShell execution policy restrictions, very old
    Windows versions, or non-Windows hosts running unit tests).

    Args:
        only_enabled: when True (default), return only interfaces whose
            admin state is "Up". cut_full uses this to find disable-able
            interfaces. recovery/restore passes only_enabled=False so
            that previously-disabled interfaces are also re-enabled.

    Status mapping (Get-NetAdapter):
        "Up"        -> enabled
        "Disabled"  -> disabled
        "NotPresent"/"Disconnected" -> treated as disabled for cut/restore
            purposes (we won't try to disable something not present, and
            we won't re-enable a disconnected adapter on restore)
    """
    ifs = _list_windows_interfaces_via_powershell(only_enabled=only_enabled)
    if ifs is not None:
        return ifs
    return _list_windows_interfaces_via_netsh(only_enabled=only_enabled)


def _list_windows_interfaces_via_powershell(*, only_enabled: bool) -> list[str] | None:
    """Return the interface list via PowerShell, or None on any failure.

    Returning None signals the caller to fall back to the netsh parser.
    """
    if not shutil.which("powershell") and not shutil.which("pwsh"):
        return None
    cmd = shutil.which("powershell") or shutil.which("pwsh")
    try:
        out = subprocess.check_output(
            [
                cmd,
                "-NoProfile",
                "-Command",
                "Get-NetAdapter | Select-Object Name,Status | ConvertTo-Json -Compress",
            ],
            text=True,
            timeout=10,
        )
    except (subprocess.SubprocessError, OSError):
        return None
    out = out.strip()
    if not out:
        # Empty output: no adapters. Return an empty list (not None) so we
        # don't fall back to netsh and double-report.
        return []
    try:
        data = json.loads(out)
    except json.JSONDecodeError:
        return None
    if isinstance(data, dict):
        data = [data]
    if not isinstance(data, list):
        return None
    ifs: list[str] = []
    for item in data:
        if not isinstance(item, dict):
            continue
        name = item.get("Name")
        status = item.get("Status")
        if not isinstance(name, str) or not name:
            continue
        if only_enabled and status != "Up":
            continue
        ifs.append(name)
    return ifs


def _list_windows_interfaces_via_netsh(*, only_enabled: bool = True) -> list[str]:
    """Fallback parser of `netsh interface show interface`.

    Known limitation: parses the English-locale output (filters on
    ``cols[0].lower() == "enabled"``). On non-English Windows the
    header text differs and enumeration may return zero entries.
    See SECURITY.md "Known limitations".
    """
    try:
        out = subprocess.check_output(
            ["netsh", "interface", "show", "interface"], text=True, timeout=3
        )
    except (subprocess.SubprocessError, OSError):
        return []
    ifs: list[str] = []
    for line in out.splitlines()[3:]:
        cols = line.split()
        # Columns (en-US): AdminState, State, Type, Interface Name
        if len(cols) < 4:
            continue
        if only_enabled and cols[0].lower() != "enabled":
            continue
        ifs.append(" ".join(cols[3:]))
    return ifs


def _run(cmd: list[str]) -> tuple[bool, str]:
    try:
        cp = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
    except (subprocess.SubprocessError, OSError) as e:
        return False, str(e)
    if cp.returncode != 0:
        return False, (cp.stderr or cp.stdout or "").strip()
    return True, (cp.stdout or "").strip()
