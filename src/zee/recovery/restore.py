"""Manual recovery commands (spec §11, v0.3 cut-state-aware).

Recovery is always manual. There is no timer-based auto-reconnect.

v0.3 reads ``cut_state.jsonl`` (telemetry/cut_state.py) to undo only
what Zee changed: the specific interface / service / firewall-rule
names recorded at cut time.

Fail-closed (docs/design/self-defense.md): when no unresolved cut record
exists for the asset (ledger missing, damaged, or cleared — the ledger is
writable by the same user Zee runs as), the normal restore REFUSES (Z605)
instead of re-enabling everything. The broad v0.2 "enable everything"
restore remains as an explicit emergency path (``all_interfaces=True`` /
``zee restore --all-interfaces``), still behind the restore token, and it
reports the real outcome of every OS command it runs.
"""

from __future__ import annotations

import logging
import shutil
import subprocess
import sys
from typing import Optional

from ..errors import ZeeError, Z601_RESTORE_FAILED, Z605_RESTORE_NO_CUT_RECORD
from ..notifier.local import notify_local
from ..responder.cut_egress import ZEE_RULE_TAG
from ..responder.cut_full import (
    SENTINEL_LINUX_IPTABLES_EGRESS,
    SENTINEL_LINUX_NFT_EGRESS,
    SENTINEL_LINUX_NMCLI,
    SENTINEL_MACOS_PFCTL_EGRESS,
    list_linux_interfaces,
    list_macos_services,
    list_windows_interfaces,
)
from ..telemetry.cut_state import CutRecord, CutStateLog

logger = logging.getLogger(__name__)


def restore(
    asset_id: str,
    *,
    cut_state: Optional[CutStateLog] = None,
    all_interfaces: bool = False,
) -> tuple[bool, str]:
    """Re-enable network for ``asset_id``.

    Undoes exactly the unresolved cut record for this asset. Without such
    a record it refuses (Z605) unless ``all_interfaces`` is set, which runs
    the broad emergency restore (may re-enable interfaces disabled by other
    tools).
    """
    cut_state = cut_state or CutStateLog()
    latest = cut_state.latest_unresolved_for(asset_id)

    if all_interfaces:
        logger.warning(
            "emergency restore for asset %s: enabling every interface / "
            "service (may re-enable interfaces disabled by other tools)",
            asset_id,
        )
        ok, detail = _restore_compat()
    elif latest is None:
        notify_local(
            f"Zee restore REFUSED: {asset_id}",
            "no cut record for this asset (ledger missing, damaged or "
            "cleared). Nothing was re-enabled. Check the host state; "
            "`zee restore <asset_id> --all-interfaces` re-enables everything.",
        )
        raise ZeeError(Z605_RESTORE_NO_CUT_RECORD, f"asset={asset_id}")
    else:
        ok, detail = _restore_targeted(latest)

    if ok:
        if latest is not None:
            cut_state.mark_resolved(asset_id)
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


# ── targeted restore (v0.3) ───────────────────────────────────────────


def _restore_targeted(rec: CutRecord) -> tuple[bool, str]:
    """Restore exactly the things ``rec.modified`` lists."""
    if rec.platform.startswith("linux"):
        return _restore_targeted_linux(list(rec.modified))
    if rec.platform == "darwin":
        return _restore_targeted_macos(list(rec.modified))
    if rec.platform == "win32":
        return _restore_targeted_windows(list(rec.modified))
    return False, f"unsupported platform recorded in cut_state: {rec.platform}"


def _restore_targeted_linux(modified: list[str]) -> tuple[bool, str]:
    if not modified:
        return True, "no Linux changes recorded"
    details: list[str] = []
    all_ok = True
    for entry in modified:
        if entry == SENTINEL_LINUX_NMCLI:
            ok, msg = _run(["nmcli", "networking", "on"])
            details.append(f"nmcli:{'ok' if ok else 'fail'}")
            all_ok = all_ok and ok
        elif entry == SENTINEL_LINUX_NFT_EGRESS:
            ok, msg = _run(["nft", "delete", "table", "inet", "zee_egress"])
            details.append(f"nft:{'ok' if ok else 'fail'}")
            all_ok = all_ok and ok
        elif entry == SENTINEL_LINUX_IPTABLES_EGRESS:
            # Remove the OUTPUT jump first, then flush + delete the chain.
            ok1, _ = _run(["iptables", "-D", "OUTPUT", "-j", "ZEE_EGRESS"])
            ok2, _ = _run(["iptables", "-F", "ZEE_EGRESS"])
            ok3, _ = _run(["iptables", "-X", "ZEE_EGRESS"])
            ok = ok1 and ok2 and ok3
            details.append(f"iptables:{'ok' if ok else 'fail'}")
            all_ok = all_ok and ok
        else:
            # Specific interface name from `ip link set <if> down`.
            ok, msg = _run(["ip", "link", "set", entry, "up"])
            details.append(f"{entry}:{'ok' if ok else 'fail'}")
            all_ok = all_ok and ok
    return all_ok, "linux restore: " + ", ".join(details)


def _restore_targeted_macos(modified: list[str]) -> tuple[bool, str]:
    if not modified:
        return True, "no macOS changes recorded"
    details: list[str] = []
    all_ok = True
    for entry in modified:
        if entry == SENTINEL_MACOS_PFCTL_EGRESS:
            ok, _ = _run(["pfctl", "-a", ZEE_RULE_TAG, "-F", "all"])
            details.append(f"pfctl:{'ok' if ok else 'fail'}")
            all_ok = all_ok and ok
        else:
            # Specific networksetup service name.
            ok, _ = _run(
                ["networksetup", "-setnetworkserviceenabled", entry, "on"]
            )
            details.append(f"{entry}:{'ok' if ok else 'fail'}")
            all_ok = all_ok and ok
    return all_ok, "macos restore: " + ", ".join(details)


def _restore_targeted_windows(modified: list[str]) -> tuple[bool, str]:
    if not modified:
        return True, "no Windows changes recorded"
    details: list[str] = []
    all_ok = True
    egress_rule_names = (
        f"{ZEE_RULE_TAG}-block",
        f"{ZEE_RULE_TAG}-allow-local",
    )
    for entry in modified:
        if entry in egress_rule_names:
            ok, _ = _run([
                "netsh", "advfirewall", "firewall", "delete", "rule",
                f"name={entry}",
            ])
            details.append(f"rule({entry}):{'ok' if ok else 'fail'}")
            all_ok = all_ok and ok
        else:
            # Specific interface name.
            ok, _ = _run(
                ["netsh", "interface", "set", "interface", entry, "admin=enable"]
            )
            details.append(f"{entry}:{'ok' if ok else 'fail'}")
            all_ok = all_ok and ok
    return all_ok, "windows restore: " + ", ".join(details)


# ── emergency: v0.2 "enable everything" (explicit opt-in only) ────────


def _restore_compat() -> tuple[bool, str]:
    if sys.platform.startswith("linux"):
        return _restore_linux_compat()
    if sys.platform == "darwin":
        return _restore_macos_compat()
    if sys.platform == "win32":
        return _restore_windows_compat()
    return False, f"unsupported platform: {sys.platform}"


def _restore_linux_compat() -> tuple[bool, str]:
    if shutil.which("nmcli"):
        ok, _ = _run(["nmcli", "networking", "on"])
        if ok:
            return True, "nmcli networking on (all-interfaces)"
    results: list[tuple[str, bool]] = []
    if shutil.which("ip"):
        for ifname in list_linux_interfaces():
            ok, _ = _run(["ip", "link", "set", ifname, "up"])
            results.append((ifname, ok))
    # nft and iptables are alternatives: Zee installs its egress rule in one.
    fw: list[bool] = []
    if shutil.which("nft"):
        fw.append(_run(["nft", "delete", "table", "inet", "zee_egress"])[0])
    if shutil.which("iptables"):
        ok1, _ = _run(["iptables", "-D", "OUTPUT", "-j", "ZEE_EGRESS"])
        ok2, _ = _run(["iptables", "-F", "ZEE_EGRESS"])
        ok3, _ = _run(["iptables", "-X", "ZEE_EGRESS"])
        fw.append(ok1 and ok2 and ok3)
    if fw:
        results.append(("zee_egress rule", any(fw)))
    return _summary("linux all-interfaces restore", results)


def _restore_macos_compat() -> tuple[bool, str]:
    results: list[tuple[str, bool]] = []
    if shutil.which("networksetup"):
        for svc in list_macos_services():
            ok, _ = _run(["networksetup", "-setnetworkserviceenabled", svc, "on"])
            results.append((svc, ok))
    if shutil.which("pfctl"):
        ok, _ = _run(["pfctl", "-a", ZEE_RULE_TAG, "-F", "all"])
        results.append(("pfctl", ok))
    return _summary("macos all-interfaces restore", results)


def _restore_windows_compat() -> tuple[bool, str]:
    results: list[tuple[str, bool]] = []
    if shutil.which("netsh"):
        for ifname in list_windows_interfaces(only_enabled=False):
            ok, _ = _run(["netsh", "interface", "set", "interface", ifname, "admin=enable"])
            results.append((ifname, ok))
        for rule in (f"{ZEE_RULE_TAG}-block", f"{ZEE_RULE_TAG}-allow-local"):
            ok, _ = _run(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule}"])
            results.append((f"rule({rule})", ok))
    return _summary("windows all-interfaces restore", results)


def _summary(label: str, results: list[tuple[str, bool]]) -> tuple[bool, str]:
    """Success only if something ran and every step succeeded.

    ponytail: a Zee rule that was already absent (e.g. after a full cut by
    `ip link`) shows as a failed step; the per-step detail tells the operator
    which. Upgrade path: probe each rule before removing it.
    """
    if not results:
        return False, f"{label}: no supported tool found"
    detail = ", ".join(f"{name}:{'ok' if ok else 'fail'}" for name, ok in results)
    return all(ok for _, ok in results), f"{label}: {detail}"


def _run(cmd: list[str]) -> tuple[bool, str]:
    try:
        cp = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
    except (subprocess.SubprocessError, OSError) as e:
        return False, str(e)
    if cp.returncode != 0:
        return False, (cp.stderr or cp.stdout or "").strip()
    return True, (cp.stdout or "").strip()
