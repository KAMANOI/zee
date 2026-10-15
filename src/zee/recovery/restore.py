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
``zee restore --all-interfaces``), still behind the restore token.

Both paths judge success by re-reading the OS (Zee's firewall rules gone,
recorded interfaces back), never by a command's exit code or the ledger
alone. See ``restore()``.
"""

from __future__ import annotations

import logging
import subprocess
import sys
from typing import Optional

from ..errors import (
    ZeeError,
    Z601_RESTORE_FAILED,
    Z605_RESTORE_NO_CUT_RECORD,
    Z606_RESTORE_UNVERIFIED,
)
from ..notifier.local import notify_local
from ..responder.cut_egress import ZEE_RULE_TAG
from ..responder.cut_full import (
    SENTINEL_LINUX_IPTABLES_EGRESS,
    SENTINEL_LINUX_NFT_EGRESS,
    SENTINEL_LINUX_NMCLI,
    SENTINEL_MACOS_PFCTL_EGRESS,
    interface_states,
    list_linux_interfaces,
    sbin_which as _which,
    list_macos_services,
    list_windows_interfaces,
)
from ..telemetry.cut_state import CutRecord, CutStateLog

logger = logging.getLogger(__name__)


# Status of one step: True = done and confirmed, False = failed,
# None = could not be confirmed (tool missing / state unreadable).
Step = tuple[str, Optional[bool]]

LEDGER_NOTE = (
    "Note: the cut ledger is writable by the same user Zee runs as; a "
    "forged ledger can change what is restored and checked "
    "(docs/design/self-defense.md)."
)

_FIREWALL_ENTRIES = (
    SENTINEL_LINUX_NFT_EGRESS,
    SENTINEL_LINUX_IPTABLES_EGRESS,
    SENTINEL_MACOS_PFCTL_EGRESS,
    f"{ZEE_RULE_TAG}-block",
    f"{ZEE_RULE_TAG}-allow-local",
)


def restore(
    asset_id: str,
    *,
    cut_state: Optional[CutStateLog] = None,
    all_interfaces: bool = False,
) -> tuple[bool, str]:
    """Re-enable network for ``asset_id``.

    Normal: undo the interfaces / services of the unresolved cut record
    (refuses with Z605 without a well-formed one). ``all_interfaces``:
    emergency, enable everything. Both paths then remove Zee's own firewall
    rules (fixed names; egress rules are host-wide, not per asset) on EVERY
    backend regardless of the ledger, re-read that they are gone, and re-read
    that the recorded interfaces / services are back.

    Success only when all of that is confirmed. A step that cannot be
    confirmed (tool missing, state unreadable) gives Z606 and the cut stays
    unresolved; a failed step gives Z601.
    """
    cut_state = cut_state or CutStateLog()

    if all_interfaces:
        logger.warning(
            "emergency restore for asset %s: enabling every interface / "
            "service (may re-enable interfaces disabled by other tools)",
            asset_id,
        )
        # The ledger is only used to name what must be back afterwards;
        # reading it can never fail or block this path.
        targets = _recorded_targets(cut_state, asset_id)
        status, detail = _restore_compat()
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
        targets = latest.modified
        status, detail = _restore_targeted(latest)

    rb_status, rb_detail = _readback(targets)
    status = _combine(status, rb_status)
    detail = f"{detail}; {rb_detail}"

    if status is True:
        try:
            cut_state.mark_resolved(asset_id)
        except OSError as e:  # restore already happened; do not report failure
            logger.warning("could not mark cut_state resolved: %s", e)
        notify_local(f"Zee restored: {asset_id}", f"network re-enabled — {detail}\n{LEDGER_NOTE}")
        return True, detail
    if status is None:
        notify_local(f"Zee restore UNVERIFIED: {asset_id}", f"{detail}\n{LEDGER_NOTE}")
        raise ZeeError(Z606_RESTORE_UNVERIFIED, f"asset={asset_id}: {detail}")
    notify_local(f"Zee restore FAILED: {asset_id}", f"{detail}\n{LEDGER_NOTE}")
    raise ZeeError(Z601_RESTORE_FAILED, f"asset={asset_id}: {detail}")


def _combine(*statuses: Optional[bool]) -> Optional[bool]:
    """False if any failed, None if any is unconfirmed, else True."""
    if any(s is False for s in statuses):
        return False
    if any(s is None for s in statuses):
        return None
    return True


# ── targeted restore ──────────────────────────────────────────────────


def _restore_targeted(rec: CutRecord) -> tuple[Optional[bool], str]:
    """Undo the recorded interfaces / services, then Zee's firewall rules."""
    if rec.platform != _host_platform():
        return False, f"cut recorded on {rec.platform}, this host is {sys.platform}"
    steps: list[Step] = []
    for entry in rec.modified:
        if entry in _FIREWALL_ENTRIES:
            continue  # handled below on every backend, record or not
        if entry == SENTINEL_LINUX_NMCLI:
            steps.append(("nmcli", _run(["nmcli", "networking", "on"])[0]))
        elif rec.platform == "linux":
            steps.append((entry, _run(["ip", "link", "set", entry, "up"])[0]))
        elif rec.platform == "darwin":
            steps.append((entry, _run(["networksetup", "-setnetworkserviceenabled", entry, "on"])[0]))
        else:
            steps.append((entry, _run(["netsh", "interface", "set", "interface", entry, "admin=enable"])[0]))
    return _summary(f"{rec.platform} restore", steps + _firewall_steps(rec.platform))


def _host_platform() -> str:
    return "linux" if sys.platform.startswith("linux") else sys.platform


# ── emergency: enable everything (explicit opt-in only) ───────────────


def _recorded_targets(cut_state: CutStateLog, asset_id: str) -> Optional[tuple[str, ...]]:
    """What the unresolved cut recorded, or None (no / damaged / unreadable
    ledger). Never raises: the emergency path must not depend on the ledger."""
    try:
        rec, damaged = cut_state.unresolved_for(asset_id)
    except Exception as e:  # noqa: BLE001 - any ledger problem = no record
        logger.warning("cut_state unusable for emergency restore: %s", e)
        return None
    return None if rec is None or damaged else rec.modified


def _restore_compat() -> tuple[Optional[bool], str]:
    if sys.platform.startswith("linux"):
        return _restore_linux_compat()
    if sys.platform == "darwin":
        return _restore_macos_compat()
    if sys.platform == "win32":
        return _restore_windows_compat()
    return False, f"unsupported platform: {sys.platform}"


def _restore_linux_compat() -> tuple[Optional[bool], str]:
    # An interface step is always counted: no tool / nothing enumerated is a
    # failure, never silently dropped.
    steps: list[Step] = []
    on_ok = False
    if _which("nmcli"):
        # A failed `networking on` stays a failure unless NetworkManager
        # itself then reports networking enabled. The ip sweep still runs
        # whenever `on` failed: the cut may have used `ip link down`.
        on_ok = _run(["nmcli", "networking", "on"])[0]
        nm_ok = on_ok or _run(["nmcli", "networking"])[1].strip() == "enabled"
        steps.append(("nmcli", nm_ok))
    if not on_ok:
        if _which("ip"):
            steps += [(i, _run(["ip", "link", "set", i, "up"])[0])
                      for i in list_linux_interfaces()] or [("interfaces:none-found", False)]
        else:
            steps.append(("ip:not-found", False))
    return _summary("linux all-interfaces restore", steps + _firewall_steps("linux"))


def _restore_macos_compat() -> tuple[Optional[bool], str]:
    steps: list[Step] = []
    if _which("networksetup"):
        # include_disabled: a full cut leaves the services disabled ('*').
        steps += [(svc, _run(["networksetup", "-setnetworkserviceenabled", svc, "on"])[0])
                  for svc in list_macos_services(include_disabled=True)] \
            or [("services:none-found", False)]
    else:
        steps.append(("services:no-networksetup", False))
    return _summary("macos all-interfaces restore", steps + _firewall_steps("darwin"))


def _restore_windows_compat() -> tuple[Optional[bool], str]:
    steps: list[Step] = []
    if _which("netsh"):
        steps += [(i, _run(["netsh", "interface", "set", "interface", i, "admin=enable"])[0])
                  for i in list_windows_interfaces(only_enabled=False)] \
            or [("interfaces:none-found", False)]
    else:
        steps.append(("netsh:not-found", False))
    return _summary("windows all-interfaces restore", steps + _firewall_steps("win32"))


# ── Zee's own firewall rules: always removed, then verified absent ────


# Messages meaning "the thing is not there".
# ponytail: substring match on tool output (English on the hosts we test;
# a localized netsh shows an absent rule as a failed step, never as ok).
_LAUNCH_FAILED = "launch failed: "
_ABSENT_MARKERS = (
    "No such file or directory",          # nft (absent table)
    "No chain/target/match by that name",  # iptables (absent chain)
    "does a matching rule exist",          # iptables -D (absent jump)
    "No rules match the specified criteria",  # netsh (absent rule)
)


def _firewall_steps(platform: str) -> list[Step]:
    """Remove Zee's fixed-name firewall rules on every backend of this OS and
    re-read that they are gone. The ledger plays no part (a forged ledger
    cannot hide a rule). Tool missing = None (unverified), still present or
    unreadable = False."""
    if platform == "linux":
        backends = [
            ("nft", lambda: _run(["nft", "delete", "table", "inet", "zee_egress"]),
             ["nft", "list", "table", "inet", "zee_egress"], False),
            ("iptables", _remove_iptables_chain, ["iptables", "-S", "ZEE_EGRESS"], False),
        ]
    elif platform == "darwin":
        backends = [
            ("pfctl", lambda: _run(["pfctl", "-a", ZEE_RULE_TAG, "-F", "all"]),
             ["pfctl", "-a", ZEE_RULE_TAG, "-s", "rules"], True),
        ]
    elif platform == "win32":
        backends = [
            (f"netsh rule {r}",
             (lambda r=r: _run(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={r}"])),
             ["netsh", "advfirewall", "firewall", "show", "rule", f"name={r}"], False)
            for r in (f"{ZEE_RULE_TAG}-block", f"{ZEE_RULE_TAG}-allow-local")
        ]
    else:
        return [("firewall:unsupported-platform", False)]
    steps: list[Step] = []
    for name, remove, show, empty_means_absent in backends:
        tool = show[0]
        if not _which(tool):
            steps.append((f"{name}:not-found", None))
            continue
        remove()  # the verdict is the re-read below, not the remove's exit code
        steps.append((name, _verify_absent(show, empty_means_absent)))
    return steps


def _verify_absent(show: list[str], empty_means_absent: bool) -> bool:
    ok, msg = _run(show)
    if ok:
        return empty_means_absent and not msg.strip()
    return not msg.startswith(_LAUNCH_FAILED) and any(m in msg for m in _ABSENT_MARKERS)


def _run_removal(cmd: list[str]) -> tuple[bool, str]:
    """Run a removal; an already-absent target (as the tool itself reports)
    counts as removed. A launch failure stays a failure."""
    ok, msg = _run(cmd)
    if not ok and not msg.startswith(_LAUNCH_FAILED) and any(m in msg for m in _ABSENT_MARKERS):
        return True, f"absent: {msg}"
    return ok, msg


def _remove_iptables_chain() -> tuple[bool, str]:
    ok1, _ = _run_removal(["iptables", "-D", "OUTPUT", "-j", "ZEE_EGRESS"])
    ok2, _ = _run_removal(["iptables", "-F", "ZEE_EGRESS"])
    ok3, m3 = _run_removal(["iptables", "-X", "ZEE_EGRESS"])
    return ok1 and ok2 and ok3, m3


# ── read back what the cut recorded ───────────────────────────────────


def _readback(targets: Optional[tuple[str, ...]]) -> tuple[Optional[bool], str]:
    """Re-read the OS. Each recorded interface / service must be positively
    read back as enabled: disabled = failed; not enumerated, unknown or an
    unreadable listing = unverified. Disabled ones outside the record are
    only reported (warning)."""
    wanted = [t for t in (targets or ()) if t not in _FIREWALL_ENTRIES]
    states = interface_states()
    if states is None:
        return None, "readback: state unreadable"
    verdicts = {t: states.get(t) for t in wanted}
    still = [t for t, v in verdicts.items() if v == "disabled"]
    unsure = [t for t, v in verdicts.items() if v not in ("enabled", "disabled")]
    others = sorted(n for n, v in states.items() if v == "disabled" and n not in wanted)
    parts = ["readback: " + ("; ".join(filter(None, [
        f"still disabled {', '.join(still)}" if still else "",
        f"not confirmed {', '.join(unsure)}" if unsure else "",
    ])) or ("recorded targets enabled" if wanted else "no recorded targets to verify"))]
    if others:
        parts.append(f"warning: also disabled (not in the record): {', '.join(others)}")
    return _combine(*[False if v == "disabled" else None if t in unsure else True
                      for t, v in verdicts.items()]), "; ".join(parts)


def _summary(label: str, steps: list[Step]) -> tuple[Optional[bool], str]:
    """False if any step failed, None if any could not be confirmed, else True."""
    if not steps:
        return False, f"{label}: no supported tool found"
    detail = ", ".join(f"{n}:{'ok' if ok else 'unverified' if ok is None else 'fail'}"
                       for n, ok in steps)
    return _combine(*[ok for _, ok in steps]), f"{label}: {detail}"


def _run(cmd: list[str]) -> tuple[bool, str]:
    """Run with the tool's absolute path (PATH + /usr/sbin:/sbin)."""
    exe = _which(cmd[0])
    if exe is None:
        return False, f"{_LAUNCH_FAILED}{cmd[0]} not found"
    try:
        cp = subprocess.run([exe, *cmd[1:]], capture_output=True, text=True, timeout=10)
    except (subprocess.SubprocessError, OSError) as e:
        return False, f"{_LAUNCH_FAILED}{e}"
    if cp.returncode != 0:
        return False, (cp.stderr or cp.stdout or "").strip()
    return True, (cp.stdout or "").strip()
