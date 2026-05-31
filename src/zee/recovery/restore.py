"""Manual recovery commands (spec §11).

Recovery is always manual. There is no timer-based auto-reconnect. After
running this, Zee re-enables the network and emits a short summary of
what happened while the asset was contained.
"""

from __future__ import annotations

import logging
import shutil
import subprocess
import sys

from ..errors import ZeeError, Z601_RESTORE_FAILED
from ..notifier.local import notify_local
from ..responder.cut_egress import ZEE_RULE_TAG
from ..responder.cut_full import list_macos_services, list_windows_interfaces

logger = logging.getLogger(__name__)


def restore(asset_id: str) -> tuple[bool, str]:
    """Re-enable network for `asset_id`.

    The MVP applies the same OS-level restore regardless of asset (one host
    is one asset at the network level). Multi-asset hosts are a future
    extension.
    """
    if sys.platform.startswith("linux"):
        ok, detail = _restore_linux()
    elif sys.platform == "darwin":
        ok, detail = _restore_macos()
    elif sys.platform == "win32":
        ok, detail = _restore_windows()
    else:
        return False, f"unsupported platform: {sys.platform}"

    if ok:
        notify_local(
            f"Zee restored: {asset_id}",
            f"network re-enabled — {detail}",
        )
    else:
        notify_local(
            f"Zee restore FAILED: {asset_id}",
            detail,
        )
        raise ZeeError(Z601_RESTORE_FAILED, f"asset={asset_id}: {detail}")
    return ok, detail


def _restore_linux() -> tuple[bool, str]:
    # Bring network back if nmcli was used to take it down.
    if shutil.which("nmcli"):
        ok, _ = _run(["nmcli", "networking", "on"])
        if ok:
            return True, "nmcli networking on"
    # Remove ZEE_EGRESS rules if they exist.
    if shutil.which("nft"):
        _run(["nft", "delete", "table", "inet", "zee_egress"])
    if shutil.which("iptables"):
        _run(["iptables", "-D", "OUTPUT", "-j", "ZEE_EGRESS"])
        _run(["iptables", "-F", "ZEE_EGRESS"])
        _run(["iptables", "-X", "ZEE_EGRESS"])
    return True, "nft/iptables ZEE_EGRESS removed (best-effort)"


def _restore_macos() -> tuple[bool, str]:
    if shutil.which("networksetup"):
        for svc in list_macos_services():
            _run(["networksetup", "-setnetworkserviceenabled", svc, "on"])
    if shutil.which("pfctl"):
        _run(["pfctl", "-a", ZEE_RULE_TAG, "-F", "all"])
    return True, "networksetup on + pfctl anchor flushed (best-effort)"


def _restore_windows() -> tuple[bool, str]:
    if shutil.which("netsh"):
        # Re-enable interfaces. We pass only_enabled=False because cut_full
        # set admin=disable on every interface that was enabled at cut time;
        # those interfaces now appear with admin-state "disabled" and would
        # be skipped by the cut-side filter. See SECURITY.md known issues
        # for the side-effect of re-enabling interfaces disabled by other
        # software at the same time.
        for ifname in list_windows_interfaces(only_enabled=False):
            _run(["netsh", "interface", "set", "interface", ifname, "admin=enable"])
        # Delete the Zee-tagged firewall rules.
        _run(["netsh", "advfirewall", "firewall", "delete", "rule",
              f"name={ZEE_RULE_TAG}-block"])
        _run(["netsh", "advfirewall", "firewall", "delete", "rule",
              f"name={ZEE_RULE_TAG}-allow-local"])
    return True, "netsh interfaces re-enabled + rules deleted (best-effort)"


def _run(cmd: list[str]) -> tuple[bool, str]:
    try:
        cp = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
    except (subprocess.SubprocessError, OSError) as e:
        return False, str(e)
    if cp.returncode != 0:
        return False, (cp.stderr or cp.stdout or "").strip()
    return True, (cp.stdout or "").strip()
