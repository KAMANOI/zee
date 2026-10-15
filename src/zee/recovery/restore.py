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

    if all_interfaces:
        # Never read the ledger first: a damaged ledger must not block the
        # emergency path.
        logger.warning(
            "emergency restore for asset %s: enabling every interface / "
            "service (may re-enable interfaces disabled by other tools)",
            asset_id,
        )
        ok, detail = _restore_compat()
    else:
        latest, damaged = cut_state.unresolved_for(asset_id)
        if latest is None or damaged:
            why = "cut ledger is damaged" if damaged else "no cut record for this asset"
            notify_local(
                f"Zee restore REFUSED: {asset_id}",
                f"{why}. Nothing was re-enabled. Check the host state; "
                "`zee restore <asset_id> --all-interfaces` re-enables everything.",
            )
            raise ZeeError(Z605_RESTORE_NO_CUT_RECORD, f"asset={asset_id}: {why}")
        ok, detail = _restore_targeted(latest)

    if ok:
        try:
            cut_state.mark_resolved(asset_id)
        except OSError as e:  # restore already happened; do not report failure
            logger.warning("could not mark cut_state resolved: %s", e)
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
            ok, msg = _run_removal(["nft", "delete", "table", "inet", "zee_egress"])
            details.append(f"nft:{'ok' if ok else 'fail'}")
            all_ok = all_ok and ok
        elif entry == SENTINEL_LINUX_IPTABLES_EGRESS:
            # Remove the OUTPUT jump first, then flush + delete the chain.
            ok = _remove_iptables_chain()
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
            ok, _ = _run_removal([
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
    # Interfaces and the egress rule are restored independently: a cut may
    # have done either (full = nmcli / ip link, egress = nft / iptables).
    # An interface step is always counted: no tool / nothing enumerated is a
    # failure, never silently dropped.
    # A missing tool is never read as "no rule": the step fails.
    results: list[tuple[str, bool]] = []
    on_ok = False
    if shutil.which("nmcli"):
        # A failed `networking on` stays a failure unless NetworkManager
        # itself then reports networking enabled (the nmcli cut is undone).
        # The ip sweep still runs whenever `on` itself failed: the cut may
        # have fallen back to `ip link down` without touching nmcli.
        on_ok = _run(["nmcli", "networking", "on"])[0]
        nm_ok = on_ok or _run(["nmcli", "networking"])[1].strip() == "enabled"
        results.append(("nmcli", nm_ok))
    if not on_ok:
        if shutil.which("ip"):
            results += [(i, _run(["ip", "link", "set", i, "up"])[0])
                        for i in list_linux_interfaces()] or [("interfaces:none-found", False)]
        else:
            results.append(("ip:not-found", False))
    results.append(("nft", _run_removal(["nft", "delete", "table", "inet", "zee_egress"])[0])
                   if shutil.which("nft") else ("nft:not-found", False))
    results.append(("iptables", _remove_iptables_chain())
                   if shutil.which("iptables") else ("iptables:not-found", False))
    return _summary("linux all-interfaces restore", results)


def _restore_macos_compat() -> tuple[bool, str]:
    results: list[tuple[str, bool]] = []
    if shutil.which("networksetup"):
        # include_disabled: a full cut leaves the services disabled ('*').
        results += [(svc, _run(["networksetup", "-setnetworkserviceenabled", svc, "on"])[0])
                    for svc in list_macos_services(include_disabled=True)] \
            or [("services:none-found", False)]
    else:
        results.append(("services:no-networksetup", False))
    results.append(("pfctl", _run(["pfctl", "-a", ZEE_RULE_TAG, "-F", "all"])[0])
                   if shutil.which("pfctl") else ("pfctl:not-found", False))
    return _summary("macos all-interfaces restore", results)


def _restore_windows_compat() -> tuple[bool, str]:
    results: list[tuple[str, bool]] = []
    if shutil.which("netsh"):
        results += [(i, _run(["netsh", "interface", "set", "interface", i, "admin=enable"])[0])
                    for i in list_windows_interfaces(only_enabled=False)] \
            or [("interfaces:none-found", False)]
        for rule in (f"{ZEE_RULE_TAG}-block", f"{ZEE_RULE_TAG}-allow-local"):
            ok, _ = _run_removal(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule}"])
            results.append((f"rule({rule})", ok))
    else:
        results.append(("netsh:not-found", False))
    return _summary("windows all-interfaces restore", results)


# Messages meaning "the thing to remove is not there" (already removed).
# ponytail: substring match on tool output (these tools print English
# regardless of locale on the hosts we test; netsh may be localized —
# then an absent rule shows as a failed step).
_LAUNCH_FAILED = "launch failed: "
_ABSENT_MARKERS = (
    "No such file or directory",          # nft delete table (absent)
    "No chain/target/match by that name",  # iptables (absent chain)
    "does a matching rule exist",          # iptables -D (absent jump)
    "No rules match the specified criteria",  # netsh delete rule (absent)
)


def _run_removal(cmd: list[str]) -> tuple[bool, str]:
    """Run a removal; an already-absent target counts as removed.

    Only an answer from the tool itself counts: a launch failure (missing
    binary also says "No such file or directory") stays a failure.
    """
    ok, msg = _run(cmd)
    if not ok and not msg.startswith(_LAUNCH_FAILED) and any(m in msg for m in _ABSENT_MARKERS):
        return True, f"absent: {msg}"
    return ok, msg


def _remove_iptables_chain() -> bool:
    ok1, _ = _run_removal(["iptables", "-D", "OUTPUT", "-j", "ZEE_EGRESS"])
    ok2, _ = _run_removal(["iptables", "-F", "ZEE_EGRESS"])
    ok3, _ = _run_removal(["iptables", "-X", "ZEE_EGRESS"])
    return ok1 and ok2 and ok3


def _summary(label: str, results: list[tuple[str, bool]]) -> tuple[bool, str]:
    """Success only if something ran and every step succeeded.

    An already-absent Zee rule counts as removed (see ``_run_removal``).
    """
    if not results:
        return False, f"{label}: no supported tool found"
    detail = ", ".join(f"{name}:{'ok' if ok else 'fail'}" for name, ok in results)
    return all(ok for _, ok in results), f"{label}: {detail}"


def _run(cmd: list[str]) -> tuple[bool, str]:
    try:
        cp = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
    except (subprocess.SubprocessError, OSError) as e:
        return False, f"{_LAUNCH_FAILED}{e}"
    if cp.returncode != 0:
        return False, (cp.stderr or cp.stdout or "").strip()
    return True, (cp.stdout or "").strip()
