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
from ..responder.cut_egress import PF_ANCHOR, PF_LEGACY_ANCHOR, ZEE_RULE_TAG
from ..responder.cut_full import (
    IPT_BACKEND_PREFIX,
    PF_TOKEN_PREFIX,
    iptables_backend,
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
        # Read back what this restore actually touched, plus whatever the
        # ledger recorded (if usable — reading it never blocks this path).
        status, detail, touched = _restore_compat()
        targets = tuple(dict.fromkeys(touched + (_recorded_targets(cut_state, asset_id) or ())))
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
        targets = tuple(n for k, n in latest.entries() if k != "firewall")
        status, detail = _restore_targeted(latest)

    if targets or all_interfaces:
        rb_status, rb_detail = _readback(targets)
        status = _combine(status, rb_status)
        detail = f"{detail}; {rb_detail}"
    else:
        # egress-only record: no interface was changed; the firewall re-read
        # in _firewall_steps is the verification.
        detail = f"{detail}; readback: no interface in the record (egress cut)"

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
    """False if any failed, None if any is unconfirmed or there is nothing
    to judge (an empty check is never success), else True."""
    if any(s is False for s in statuses):
        return False
    if not statuses or any(s is None for s in statuses):
        return None
    return True


# ── targeted restore ──────────────────────────────────────────────────


def _restore_targeted(rec: CutRecord) -> tuple[Optional[bool], str]:
    """Undo the recorded interfaces / services, then Zee's firewall rules."""
    if rec.platform != _host_platform():
        return False, f"cut recorded on {rec.platform}, this host is {sys.platform}"
    steps: list[Step] = []
    for kind, entry in rec.entries():
        if kind == "firewall":
            continue  # handled below on every backend, record or not
        if kind == "nmcli":
            steps.append(("nmcli", _run(["nmcli", "networking", "on"])[0]))
        elif rec.platform == "linux":
            steps.append((entry, _run(["ip", "link", "set", entry, "up"])[0]))
        elif rec.platform == "darwin":
            steps.append((entry, _run(["networksetup", "-setnetworkserviceenabled", entry, "on"])[0]))
        else:
            steps.append((entry, _run(["netsh", "interface", "set", "interface", entry, "admin=enable"])[0]))
    recorded = tuple(n for k, n in rec.entries() if k == "firewall")
    return _summary(f"{rec.platform} restore", steps + _firewall_steps(rec.platform, recorded))


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
    return None if rec is None or damaged else tuple(n for k, n in rec.entries() if k != "firewall")


def _restore_compat() -> tuple[Optional[bool], str, tuple[str, ...]]:
    """Returns (status, detail, names of the interfaces / services touched)."""
    if sys.platform.startswith("linux"):
        return _restore_linux_compat()
    if sys.platform == "darwin":
        return _restore_macos_compat()
    if sys.platform == "win32":
        return _restore_windows_compat()
    return False, f"unsupported platform: {sys.platform}", ()


def _restore_linux_compat() -> tuple[Optional[bool], str, tuple[str, ...]]:
    # An interface step is always counted: no tool / nothing enumerated is a
    # failure, never silently dropped.
    # `touched` is collected where each name is operated on, never parsed
    # back out of step labels (names may contain ":").
    steps: list[Step] = []
    touched: list[str] = []
    on_ok = False
    if _which("nmcli"):
        # A failed `networking on` stays a failure unless NetworkManager
        # itself then reports networking enabled. The ip sweep still runs
        # whenever `on` failed: the cut may have used `ip link down`.
        on_ok = _run(["nmcli", "networking", "on"])[0]
        nm_ok = on_ok or _run(["nmcli", "networking"])[1].strip() == "enabled"
        steps.append(("nmcli", nm_ok))
        touched.append(SENTINEL_LINUX_NMCLI)
    # Always sweep every interface too, whatever nmcli did: a cut (or an
    # attacker) may have used `ip link down`, which NetworkManager's switch
    # does not undo. Each swept interface is read back afterwards.
    if _which("ip"):
        ifaces = list_linux_interfaces()
        touched += ifaces
        # After a working nmcli, a failing `ip link set up` (e.g. a vanished
        # veth) is not a failure by itself: the read-back of that name
        # decides (disabled = failure, missing = unverified).
        steps += [(i, _run(["ip", "link", "set", i, "up"])[0] or (None if on_ok else False))
                  for i in ifaces] or [("interfaces:none-found", False)]
    else:
        # Cannot enumerate interfaces: after a working nmcli this is
        # unverified; with nothing restored at all it is a failure.
        steps.append(("ip:not-found", None if on_ok else False))
    return (*_summary("linux all-interfaces restore", steps + _firewall_steps("linux")), tuple(touched))


def _restore_macos_compat() -> tuple[Optional[bool], str, tuple[str, ...]]:
    steps: list[Step] = []
    touched: tuple[str, ...] = ()
    if _which("networksetup"):
        # include_disabled: a full cut leaves the services disabled ('*').
        touched = tuple(list_macos_services(include_disabled=True))
        steps += [(svc, _run(["networksetup", "-setnetworkserviceenabled", svc, "on"])[0])
                  for svc in touched] or [("services:none-found", False)]
    else:
        steps.append(("services:no-networksetup", False))
    return (*_summary("macos all-interfaces restore", steps + _firewall_steps("darwin")), touched)


def _restore_windows_compat() -> tuple[Optional[bool], str, tuple[str, ...]]:
    steps: list[Step] = []
    touched: tuple[str, ...] = ()
    if _which("netsh"):
        touched = tuple(list_windows_interfaces(only_enabled=False))
        steps += [(i, _run(["netsh", "interface", "set", "interface", i, "admin=enable"])[0])
                  for i in touched] or [("interfaces:none-found", False)]
    else:
        steps.append(("netsh:not-found", False))
    return (*_summary("windows all-interfaces restore", steps + _firewall_steps("win32")), touched)


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


# iptables front ends: each talks to its own kernel backend (legacy x_tables
# or nf_tables), and `iptables` may point at either; the cut used whichever
# `iptables` was then, so restore checks every one installed now.
_IPTABLES = ("iptables", "iptables-legacy", "iptables-nft")


def _firewall_steps(platform: str, recorded: tuple[str, ...] = ()) -> list[Step]:
    """Remove Zee's fixed-name firewall rules on every backend of this OS and
    re-read that they are gone. The ledger does not decide what is removed (a
    forged ledger cannot hide a rule). ``recorded``: firewall entries of the
    cut record (empty without one).

    A backend whose tool is not installed cannot hold a rule Zee made with
    it: reported "not-installed" and not counted — unless the record says the
    cut used it, or no firewall tool of this OS is installed at all, which is
    None (unverified). Still present = False; unreadable = None.
    """
    if platform == "linux":
        groups = [
            (SENTINEL_LINUX_NFT_EGRESS, "nft", [
                ("nft", lambda: _run(["nft", "delete", "table", "inet", "zee_egress"]),
                 ["nft", "list", "table", "inet", "zee_egress"])]),
            (SENTINEL_LINUX_IPTABLES_EGRESS, "iptables", [
                (t, (lambda t=t: _remove_iptables_chain(t)), [t, "-S", "ZEE_EGRESS"])
                for t in _IPTABLES]),
        ]
    elif platform == "darwin":
        groups = [(SENTINEL_MACOS_PFCTL_EGRESS, "pfctl", [
            (f"pfctl {a}", (lambda a=a: _run(["pfctl", "-a", a, "-F", "all"])),
             ["pfctl", "-a", a, "-s", "rules"])
            for a in (PF_ANCHOR, PF_LEGACY_ANCHOR)])]
    elif platform == "win32":
        groups = [(None, "netsh", [
            (f"netsh rule {r}",
             (lambda r=r: _run(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={r}"])),
             ["netsh", "advfirewall", "firewall", "show", "rule", f"name={r}"])
            for r in (f"{ZEE_RULE_TAG}-block", f"{ZEE_RULE_TAG}-allow-local")])]
    else:
        return [("firewall:unsupported-platform", False)]
    installed = [[b for b in backends if _which(b[2][0])] for _s, _g, backends in groups]
    none_at_all = not any(installed)
    steps: list[Step] = []
    for (sentinel, group, _b), present in zip(groups, installed):
        if not present:
            if none_at_all or platform != "linux" or sentinel in recorded:
                steps.append((f"{group}:not-found", None))
            else:
                steps.append((f"{group}:not-installed", True))
            continue
        for name, remove, show in present:
            remove()  # the verdict is the re-read below, not the remove's exit code
            steps.append((name, _verify_absent(show[0], show)))
    if platform == "linux":
        steps += _iptables_backend_coverage(recorded)
    if platform == "darwin":
        steps += _release_pf_tokens(recorded)
    return steps


def _iptables_backend_coverage(recorded: tuple[str, ...]) -> list[Step]:
    """An iptables cut must be read back by a tool of the same kernel
    backend (legacy / nf_tables): `iptables` may point at the other one now.
    The record names the backend; a record without it (before v0.13.0)
    needs both. No tool for a needed backend = None (unverified)."""
    need = {r.removeprefix(IPT_BACKEND_PREFIX) for r in recorded if r.startswith(IPT_BACKEND_PREFIX)}
    if not need and SENTINEL_LINUX_IPTABLES_EGRESS in recorded:
        need = {"legacy", "nf_tables"}
    if not need:
        return []
    covered: set[str] = set()
    for tool in _IPTABLES:
        if _which(tool):
            ok, out = _run([tool, "--version"])
            backend = iptables_backend(out) if ok else None
            if backend:
                covered.add(backend)
    return [(f"iptables {b} backend:not-found", None) for b in sorted(need - covered)]


def _release_pf_tokens(recorded: tuple[str, ...]) -> list[Step]:
    """Release the pf enable references the cut took (`pfctl -X <token>`).
    pf turns off only when no one else holds a reference (pfctl(8) -E/-X).
    "token invalid" (already released, or every token dropped by `pfctl -d`)
    and "pf not enabled" mean Zee holds nothing: done."""
    steps: list[Step] = []
    for entry in recorded:
        if not entry.startswith(PF_TOKEN_PREFIX):
            continue
        token = entry.removeprefix(PF_TOKEN_PREFIX)
        if not token.isdigit():
            # "unknown": `pfctl -E` failed or timed out without a token, so
            # whether pf holds a reference of Zee's cannot be confirmed.
            steps.append((f"pf enable reference {token}", None))
            continue
        ok, msg = _run(["pfctl", "-X", token])
        if ok or "token invalid" in msg or "pf not enabled" in msg:
            steps.append((f"pf enable reference {token}", True))
        else:
            steps.append((f"pf enable reference {token}", None if msg.startswith(_LAUNCH_FAILED) else False))
    return steps


def _verify_absent(tool: str, show: list[str]) -> Optional[bool]:
    """True = the backend itself answered "no such table / chain / rule";
    False = the rule is still listed; None = anything else (launch or loader
    failure, permission error, unexpected output) — never read as absent."""
    ok, msg = _run(show)
    if ok:
        if tool == "pfctl":
            return not msg.strip()  # empty anchor = no rules
        return False  # listed
    if msg.startswith(_LAUNCH_FAILED):
        return None
    if tool == "nft":
        absent = (msg.startswith("Error:") and "No such file or directory" in msg
                  and "zee_egress" in msg)
    elif tool in _IPTABLES:
        # iptables-nft first prints "# Warning: iptables-legacy tables
        # present, ..." when the other backend has tables (seen on GitHub's
        # Ubuntu runner); the answer is the line after it.
        msg = "\n".join(ln for ln in msg.splitlines() if not ln.startswith("# Warning:")).strip()
        # "Table does not exist": that backend's filter table was never set
        # up, so no chain of Zee's can be in it.
        absent = msg.startswith("iptables") and (
            "No chain/target/match by that name" in msg or "Table does not exist" in msg)
    elif tool == "netsh":
        absent = "No rules match the specified criteria" in msg
    else:
        absent = False
    if not absent:  # say what the tool answered, so the operator can judge
        logger.warning("%s: absence not confirmed; the tool answered: %s", " ".join(show), msg[:300])
    return True if absent else None


def _run_removal(cmd: list[str]) -> tuple[bool, str]:
    """Run a removal; an already-absent target (as the tool itself reports)
    counts as removed. A launch failure stays a failure."""
    ok, msg = _run(cmd)
    if not ok and not msg.startswith(_LAUNCH_FAILED) and any(m in msg for m in _ABSENT_MARKERS):
        return True, f"absent: {msg}"
    return ok, msg


def _remove_iptables_chain(tool: str = "iptables") -> tuple[bool, str]:
    ok1, _ = _run_removal([tool, "-D", "OUTPUT", "-j", "ZEE_EGRESS"])
    ok2, _ = _run_removal([tool, "-F", "ZEE_EGRESS"])
    ok3, m3 = _run_removal([tool, "-X", "ZEE_EGRESS"])
    return ok1 and ok2 and ok3, m3


# ── read back what the cut recorded ───────────────────────────────────


def _readback(targets: Optional[tuple[str, ...]]) -> tuple[Optional[bool], str]:
    """Re-read the OS. Each recorded interface / service must be positively
    read back as enabled: disabled = failed; not enumerated, unknown or an
    unreadable listing = unverified. Disabled ones outside the record are
    only reported (warning)."""
    # Callers pass only interface / service / nmcli targets (classified by
    # kind, never by name).
    wanted = list(dict.fromkeys(targets or ()))
    states = interface_states()
    if states is None:
        return None, "readback: state unreadable"
    verdicts = {t: states.get(t) for t in wanted}
    still = [t for t, v in verdicts.items() if v == "disabled"]
    unsure = [t for t, v in verdicts.items() if v not in ("enabled", "disabled")]
    others = sorted(f"{n} ({v})" for n, v in states.items() if v != "enabled" and n not in wanted)
    parts = ["readback: " + ("; ".join(filter(None, [
        f"still disabled {', '.join(still)}" if still else "",
        f"not confirmed {', '.join(unsure)}" if unsure else "",
    ])) or ("recorded targets enabled" if wanted else "no recorded targets to verify"))]
    if others:
        parts.append(f"warning: not enabled (not in the record): {', '.join(others)}")
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
        cp = subprocess.run([exe, *cmd[1:]], capture_output=True, text=True, errors="replace", timeout=10)
    except (subprocess.SubprocessError, OSError) as e:
        return False, f"{_LAUNCH_FAILED}{e}"
    if cp.returncode in (126, 127):  # not executable / loader failure
        return False, f"{_LAUNCH_FAILED}exit {cp.returncode}: {(cp.stderr or cp.stdout or '').strip()}"
    if cp.returncode != 0:
        return False, (cp.stderr or cp.stdout or "").strip()
    return True, (cp.stdout or "").strip()
