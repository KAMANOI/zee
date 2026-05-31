"""Full network cut backends (spec §8).

`full` brings down the network interfaces. This is destructive to all
traffic on the host, including legitimate sessions. Only invoked when the
asset profile sets cut_method='full' AND mode='contain' AND dry_run=False.

Each backend returns (success: bool, detail: str). On dry_run, callers
must not invoke these functions at all; they are not safe-by-default.
"""

from __future__ import annotations

import logging
import shutil
import subprocess
import sys

logger = logging.getLogger(__name__)


def cut_full() -> tuple[bool, str]:
    if sys.platform.startswith("linux"):
        return _cut_full_linux()
    if sys.platform == "darwin":
        return _cut_full_macos()
    if sys.platform == "win32":
        return _cut_full_windows()
    return False, f"unsupported platform: {sys.platform}"


def _cut_full_linux() -> tuple[bool, str]:
    # Prefer nmcli when available (handles WiFi cleanly).
    if shutil.which("nmcli"):
        result = _run(["nmcli", "networking", "off"])
        if result[0]:
            return True, "nmcli networking off"
        logger.warning("nmcli failed (%s); falling back to `ip link`", result[1])
    # Fallback: bring all non-loopback interfaces down.
    if shutil.which("ip"):
        ifaces = list_linux_interfaces()
        all_ok = True
        details: list[str] = []
        for ifname in ifaces:
            ok, msg = _run(["ip", "link", "set", ifname, "down"])
            details.append(f"{ifname}:{'ok' if ok else 'fail'}")
            all_ok = all_ok and ok
        return all_ok, "ip link down: " + ", ".join(details)
    return False, "no supported backend (need nmcli or ip)"


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


def _cut_full_macos() -> tuple[bool, str]:
    if not shutil.which("networksetup"):
        return False, "networksetup not available"
    services = list_macos_services()
    all_ok = True
    details: list[str] = []
    for svc in services:
        ok, _msg = _run(["networksetup", "-setnetworkserviceenabled", svc, "off"])
        details.append(f"{svc}:{'ok' if ok else 'fail'}")
        all_ok = all_ok and ok
    return all_ok, "networksetup -setnetworkserviceenabled off: " + ", ".join(details)


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


def _cut_full_windows() -> tuple[bool, str]:
    # netsh requires the visible interface name; enumerate first.
    ifaces = list_windows_interfaces(only_enabled=True)
    if not ifaces:
        return False, "no enabled interfaces found via netsh"
    all_ok = True
    details: list[str] = []
    for ifname in ifaces:
        ok, _msg = _run(
            ["netsh", "interface", "set", "interface", ifname, "admin=disable"]
        )
        details.append(f"{ifname}:{'ok' if ok else 'fail'}")
        all_ok = all_ok and ok
    return all_ok, "netsh disable: " + ", ".join(details)


def list_windows_interfaces(*, only_enabled: bool = True) -> list[str]:
    """Enumerate Windows interfaces visible to netsh.

    Args:
        only_enabled: when True (default), return only interfaces whose
            admin-state column is "enabled". cut_full uses this to find
            disable-able interfaces. recovery/restore passes only_enabled=False
            so that previously-disabled interfaces (which is what cut left
            behind) are also re-enabled.

    Known limitation: this parses the English-locale `netsh interface show
    interface` output. On non-English Windows the header text differs and
    enumeration may return zero entries. See SECURITY.md known issues.
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
        # Columns: AdminState, State, Type, Interface Name
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
