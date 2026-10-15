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
import os
import re
import shutil
import subprocess
import sys
from typing import Optional

from ..telemetry.cut_state import SENTINEL_LINUX_NMCLI, CutStateLog

logger = logging.getLogger(__name__)

# Sentinels recorded in cut_state.modified for cut paths that are not
# tied to a specific interface name. recovery/restore.py branches on
# these to undo the right side-effect.
SENTINEL_LINUX_NFT_EGRESS = "__zee_nft_egress_table__"
SENTINEL_LINUX_IPTABLES_EGRESS = "__zee_iptables_egress_chain__"
SENTINEL_MACOS_PFCTL_EGRESS = "__zee_pfctl_egress_anchor__"

# Admin tools often live in /usr/sbin or /sbin, which a service / sudo PATH
# may lack. Lookups add them, and commands then run by absolute path.
SBIN_PATH = os.pathsep.join(filter(None, [os.environ.get("PATH", ""), "/usr/sbin", "/sbin"]))


def sbin_which(name: str) -> Optional[str]:
    found = shutil.which(name, path=SBIN_PATH)
    return os.path.abspath(found) if found else None


def _abs(cmd: list[str]) -> list[str]:
    return [sbin_which(cmd[0]) or cmd[0], *cmd[1:]]


def cut_full(
    *,
    asset_id: Optional[str] = None,
    cut_state: Optional[CutStateLog] = None,
) -> tuple[bool, str]:
    """Disable all network interfaces / services for this host.

    ``asset_id`` and ``cut_state`` are optional only for test stubs.
    Production callers (responder/sequence.handle, ``zee cut``) MUST
    supply both: without them, no cut-state record is written and the
    subsequent ``zee restore`` refuses (Z605) and only the explicit
    ``--all-interfaces`` emergency restore can undo it.
    """
    ok, detail, modified = _cut_full_dispatch()
    verified: Optional[str] = None
    if ok and modified:
        # Exit codes are not proof: every changed interface / service must
        # read back as disabled, or the cut is not reported as applied.
        states = interface_states()
        # When the ip-link fallback ran, the NetworkManager switch was only
        # attempted (it stays recorded so restore covers it) and is not what
        # cut the host: confirm the interfaces themselves.
        required = [m for m in modified if m != SENTINEL_LINUX_NMCLI] or modified
        unconfirmed = [m for m in required if (states or {}).get(m) != "disabled"]
        if states is None or unconfirmed:
            ok = False
            verified = "unverified" if states is None or any(
                (states or {}).get(m) != "enabled" for m in unconfirmed) else "missing"
            detail += (f"; cut not confirmed by read-back ({verified}): "
                       + ("state unreadable" if states is None else ", ".join(unconfirmed)))
        else:
            verified = "confirmed"
    # Record whatever actually changed, even on a partial failure: restore
    # refuses without a record, so an unrecorded partial cut could only be
    # undone by the broad emergency restore.
    if asset_id and cut_state is not None and modified:
        return record_or_report(cut_state, ok, detail, asset_id=asset_id,
                                method="full", modified=modified, verified=verified)
    return ok, detail


def record_or_report(cut_state, ok: bool, detail: str, *, asset_id: str,
                     method: str, modified: list[str],
                     verified: Optional[str] = None) -> tuple[bool, str]:
    """Write the cut record; a write failure turns the result into a failure.

    The OS cut and the ledger write are reported separately in ``detail``
    (``os=ok|FAILED ledger=ok|FAILED``) so a cut without a record is never
    announced as applied and the operator sees the only way back.
    """
    try:
        cut_state.record_cut(asset_id=asset_id, method=method,
                             platform=sys.platform, modified=modified, verified=verified)
    except OSError as e:
        logger.error("cut_state write failed for %s: %s", asset_id, e)
        return False, (
            f"os={'ok' if ok else 'FAILED'} ledger=FAILED ({e}) — {detail}. "
            f"Changed but not recorded: {', '.join(modified)}. "
            f"`zee restore {asset_id}` may refuse (Z605) or miss them; undo with "
            f"`zee restore {asset_id} --all-interfaces`."
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
    # Every attempted target is recorded, success or not: a command that
    # failed or timed out may still have taken effect, and restore must
    # bring it back and read it back.
    attempted: list[str] = []
    if shutil.which("nmcli"):
        attempted.append(SENTINEL_LINUX_NMCLI)
        result = _run(["nmcli", "networking", "off"])
        if result[0]:
            return True, "nmcli networking off", attempted
        logger.warning("nmcli failed (%s); falling back to `ip link`", result[1])
    # Fallback: bring all non-loopback interfaces down.
    if shutil.which("ip"):
        ifaces = list_linux_interfaces()
        if not ifaces:
            return False, "no non-loopback interfaces found via ip", attempted
        all_ok = True
        details: list[str] = []
        for ifname in ifaces:
            ok, msg = _run(["ip", "link", "set", ifname, "down"])
            details.append(f"{ifname}:{'ok' if ok else 'fail'}")
            attempted.append(ifname)
            all_ok = all_ok and ok
        return all_ok, "ip link down: " + ", ".join(details), attempted
    return False, "no supported backend (need nmcli or ip)", attempted


def list_linux_interfaces() -> list[str]:
    """Enumerate non-loopback Linux interfaces. Used by both cut and restore."""
    try:
        out = subprocess.check_output(
            _abs(["ip", "-o", "link", "show"]), text=True, timeout=3
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
    if not services:
        return False, "no enabled network services found via networksetup", []
    all_ok = True
    details: list[str] = []
    modified: list[str] = []
    for svc in services:
        ok, _msg = _run(["networksetup", "-setnetworkserviceenabled", svc, "off"])
        details.append(f"{svc}:{'ok' if ok else 'fail'}")
        modified.append(svc)  # attempted: record even on failure / timeout
        all_ok = all_ok and ok
    return all_ok, "networksetup -setnetworkserviceenabled off: " + ", ".join(details), modified


def list_macos_services(*, include_disabled: bool = False) -> list[str]:
    """Enumerate macOS network services. Used by both cut and restore.

    Disabled services (marked with '*' by networksetup) are excluded unless
    ``include_disabled`` — the emergency restore needs them, because a full
    cut is exactly what disabled them.
    """
    try:
        out = subprocess.check_output(
            _abs(["networksetup", "-listallnetworkservices"]), text=True, timeout=3
        )
    except (subprocess.SubprocessError, OSError):
        return []
    services: list[str] = []
    for line in out.splitlines()[1:]:  # skip header
        name = line.strip()
        if name.startswith("*"):  # '*' marks disabled services
            if not include_disabled:
                continue
            name = name[1:].strip()
        if name:
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
        modified.append(ifname)  # attempted: record even on failure / timeout
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
        only_enabled: when True (default), return every interface not
            confirmed admin-disabled (Get-NetAdapter Status other than
            "Disabled", including unknown ones). cut_full uses this to find
            the interfaces to disable; its read-back then requires each to
            read as disabled. recovery/restore passes only_enabled=False so
            that previously-disabled interfaces are also re-enabled.

    Status mapping (Get-NetAdapter) for only_enabled=True:
        "Disabled" -> excluded (already admin-disabled)
        anything else (Up, Disconnected, NotPresent, missing) -> included
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
        # Cut targets: everything not confirmed admin-disabled (Up,
        # Disconnected, unknown or missing status). The cut's read-back then
        # requires each one to read as disabled.
        if only_enabled and status == "Disabled":
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
        cp = subprocess.run(cmd, capture_output=True, text=True, errors="replace", timeout=10)
    except (subprocess.SubprocessError, OSError) as e:
        return False, str(e)
    if cp.returncode != 0:
        return False, (cp.stderr or cp.stdout or "").strip()
    return True, (cp.stdout or "").strip()


# `ip -o link show`: "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu ..."
# (name may carry "@peer"). The flag field must be complete and well formed.
_IP_LINE = re.compile(r"^\s*\d+:\s+([^\s:@]+)(?:@[^\s:]+)?:\s+<([A-Z0-9_-]+(?:,[A-Z0-9_-]+)*)>(?:\s|$)")
_IP_NAME = re.compile(r"^\s*\d+:\s+([^\s:@]+)")


def _windows_states_via_netsh() -> Optional[dict[str, str]]:
    """Fallback when PowerShell is unavailable (the cut can use netsh too).
    Admin State is read as written; any other word (a non-English locale)
    is "unknown", never enabled."""
    out = subprocess.check_output(_abs(["netsh", "interface", "show", "interface"]), text=True, timeout=5)
    states: dict[str, str] = {}
    for line in out.splitlines()[3:]:
        cols = line.split()
        if len(cols) < 4:
            continue
        states[" ".join(cols[3:])] = {"enabled": "enabled", "disabled": "disabled"}.get(cols[0].lower(), "unknown")
    return states or None


def interface_states() -> Optional[dict[str, str]]:
    """Read back every interface / service and its state right now.

    Maps the name the cut records (interface / service name;
    ``SENTINEL_LINUX_NMCLI`` for NetworkManager networking) to "enabled",
    "disabled" or "unknown". A name that is absent was not enumerated.
    Returns None when the listing cannot be read or is empty. Callers must
    treat absent / "unknown" / None as unverified, never as enabled.
    """
    try:
        if sys.platform.startswith("linux"):
            states: dict[str, str] = {}
            try:
                out = subprocess.check_output(_abs(["ip", "-o", "link", "show"]), text=True, timeout=5)
            except (subprocess.SubprocessError, OSError):
                out = ""  # still try NetworkManager below
            for line in out.splitlines():
                m = _IP_LINE.match(line)
                if m:
                    name, flags = m.group(1), m.group(2).split(",")
                    state = "enabled" if "UP" in flags else "disabled"
                else:
                    # A line we cannot fully parse (truncated, odd flags):
                    # its interface is "unknown", never enabled.
                    loose = _IP_NAME.match(line)
                    if not loose:
                        continue
                    name, state = loose.group(1), "unknown"
                if name != "lo":
                    states[name] = state
            if sbin_which("nmcli"):
                # Separate try: NetworkManager not answering must not discard
                # the interface states; its own state is then "unknown".
                try:
                    nm = subprocess.check_output(_abs(["nmcli", "networking"]), text=True, timeout=5).strip()
                except (subprocess.SubprocessError, OSError):
                    nm = ""
                states[SENTINEL_LINUX_NMCLI] = nm if nm in ("enabled", "disabled") else "unknown"
            return states or None
        if sys.platform == "darwin":
            out = subprocess.check_output(_abs(["networksetup", "-listallnetworkservices"]), text=True, timeout=5)
            states = {}
            for line in out.splitlines()[1:]:  # skip the asterisk legend
                name = line.strip()
                if name.startswith("*"):
                    states[name[1:].strip()] = "disabled"
                elif name:
                    states[name] = "enabled"
            return states or None
        if sys.platform == "win32":
            cmd = sbin_which("powershell") or sbin_which("pwsh")
            if not cmd:
                return _windows_states_via_netsh()
            out = subprocess.check_output(
                [cmd, "-NoProfile", "-Command",
                 "Get-NetAdapter | Select-Object Name,Status | ConvertTo-Json -Compress"],
                text=True, timeout=10).strip()
            if not out:
                return None
            data = json.loads(out)
            data = [data] if isinstance(data, dict) else data
            if not isinstance(data, list):
                return None
            # Admin state is what Zee changes: "Disabled" vs. admin-enabled
            # (Up / Disconnected). Anything else is unknown.
            mapping = {"Disabled": "disabled", "Up": "enabled", "Disconnected": "enabled"}
            states = {d["Name"]: mapping.get(d.get("Status"), "unknown")
                      for d in data if isinstance(d, dict) and isinstance(d.get("Name"), str) and d["Name"]}
            return states or None
    except (subprocess.SubprocessError, OSError, ValueError, TypeError):
        return None
    return None
