"""Audit pinned artifacts for Rug Pull drift (Phase 3).

Re-hash every pinned install location and compare against the hash that
passed the gate. Three outcomes per pin:

    clean    — bytes on disk still match the pinned hash.
    drifted  — the artifact changed since it was pinned (self-update /
               silent rewrite = a Rug Pull). HIGH. The new hash is added
               to the local denylist so re-installing this exact version
               is blocked (input/output share the threat record), and
               with ``rescan=True`` the changed artifact is re-inspected
               (static, plus behavioural if requested) to show *what* it
               became.
    missing  — the install location is gone (uninstalled or moved).

Honest scope (invariant I5): this catches on-disk modification and
self-update, which is the dominant Rug Pull shape for skills / MCP /
packages. It is an on-demand integrity check, not a live process monitor
— it does not watch a running artifact's syscalls or network in real
time. Re-run it (e.g. from cron or a pre-run hook) to keep pins honest.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from . import denylist
from .fetch import sha256_tree
from .model import RiskLevel, Verdict
from .pins import Pin, PinRegistry

logger = logging.getLogger(__name__)

CLEAN = "clean"
DRIFTED = "drifted"
MISSING = "missing"


@dataclass
class PinAudit:
    pin: Pin
    status: str
    current_hash: Optional[str] = None
    rescan: Optional[Verdict] = None
    rescan_error: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "name": self.pin.name,
            "install_dir": self.pin.install_dir,
            "status": self.status,
            "pinned_hash": self.pin.content_hash,
            "current_hash": self.current_hash,
        }
        if self.rescan is not None:
            d["rescan"] = self.rescan.to_dict()
        if self.rescan_error is not None:
            d["rescan_error"] = self.rescan_error
        return d


@dataclass
class AuditReport:
    results: list[PinAudit] = field(default_factory=list)

    @property
    def drifted(self) -> list[PinAudit]:
        return [r for r in self.results if r.status == DRIFTED]

    @property
    def missing(self) -> list[PinAudit]:
        return [r for r in self.results if r.status == MISSING]

    @property
    def exit_code(self) -> int:
        # Drift is the actionable, high-severity outcome (verdict HIGH=2).
        # A missing pin is a notice (1). All clean is 0.
        if self.drifted:
            return 2
        if self.missing:
            return 1
        return 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "pins": len(self.results),
            "drifted": len(self.drifted),
            "missing": len(self.missing),
            "results": [r.to_dict() for r in self.results],
        }

    def to_text(self) -> str:
        if not self.results:
            return "zee gate audit — no pinned artifacts"
        lines = [f"zee gate audit — {len(self.results)} pinned artifact(s)"]
        for r in self.results:
            mark = {CLEAN: "ok ", DRIFTED: "!! ", MISSING: "?? "}[r.status]
            lines.append(f"  [{mark}] {r.status:7} {r.pin.name}")
            lines.append(f"           {r.pin.install_dir}")
            if r.status == DRIFTED:
                lines.append(
                    f"           pinned {r.pin.content_hash[:16]}… "
                    f"-> now {(r.current_hash or '?')[:16]}…"
                )
                lines.append(
                    "           Rug Pull: changed since it passed the gate. "
                    "Review/remove it; its new hash is now denylisted."
                )
                if r.rescan is not None:
                    lines.append(
                        f"           rescan verdict: {r.rescan.risk_level.value}"
                    )
                elif r.rescan_error is not None:
                    lines.append(f"           rescan failed: {r.rescan_error}")
            elif r.status == MISSING:
                lines.append(
                    "           moved or uninstalled — re-run "
                    "`zee gate add --promote-to …` to re-pin if intentional."
                )
        n_drift, n_miss = len(self.drifted), len(self.missing)
        lines.append(
            f"  summary: {n_drift} drifted, {n_miss} missing, "
            f"{len(self.results) - n_drift - n_miss} clean"
        )
        return "\n".join(lines)


def audit_pins(
    registry: PinRegistry,
    *,
    rescan: bool = False,
    behavioral: bool = False,
) -> AuditReport:
    report = AuditReport()
    for pin in registry.all():
        path = Path(pin.install_dir)
        if not path.exists():
            report.results.append(PinAudit(pin=pin, status=MISSING))
            continue
        current = sha256_tree(path)
        if current == pin.content_hash:
            report.results.append(
                PinAudit(pin=pin, status=CLEAN, current_hash=current)
            )
            continue
        # Drift = Rug Pull. Record the new (bad) hash as shared threat info
        # so this exact version is blocked on any future `gate add`.
        denylist.add_local(hashes=(current,))
        rescan_verdict: Optional[Verdict] = None
        rescan_error: Optional[str] = None
        if rescan:
            # Re-inspect the changed bytes in place. inspect_source copies
            # into quarantine first (never runs unless behavioral=True).
            from .inspector import inspect_source

            try:
                rescan_verdict = inspect_source(
                    pin.install_dir, kind=pin.kind, behavioral=behavioral,
                )
            except Exception as e:  # a rescan failure must not abort the audit
                rescan_error = f"{type(e).__name__}: {e}"
                logger.warning(
                    "gate audit rescan failed for %s (%s)",
                    pin.install_dir, rescan_error,
                )
        report.results.append(
            PinAudit(
                pin=pin, status=DRIFTED, current_hash=current,
                rescan=rescan_verdict, rescan_error=rescan_error,
            )
        )
    return report
