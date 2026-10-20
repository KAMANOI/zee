"""Contracts for the entry gate: the artifact model and verdict schema.

Phase 0 deliverable — the minimal common representation of a skill / mcp
/ package, plus the LOW/MEDIUM/HIGH verdict (safeinspect heritage:
risk_level, risk_score, flags with evidence, and an exit code
LOW=0 / MEDIUM=1 / HIGH=2; 3 = incomplete inspection, 4 = no verdict).
stdlib only.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional


class ArtifactKind(str, Enum):
    SKILL = "skill"
    MCP = "mcp"
    NPM = "npm"
    PYPI = "pypi"
    VSCODE = "vscode"
    PACKAGE = "package"


class RiskLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"

    @property
    def exit_code(self) -> int:
        return {"LOW": 0, "MEDIUM": 1, "HIGH": 2}[self.value]


class InspectionStatus(str, Enum):
    """How completely the artifact was inspected. Kept apart from the risk
    level: a LOW risk over an incomplete inspection is not a clean pass."""

    COMPLETE = "complete"  # every in-scope file and manifest was read
    PARTIAL = "partial"  # a verdict exists, but some scope was not inspected
    ERROR = "error"  # no trustworthy verdict could be produced


# Exit codes for "not fully trustworthy" / "no verdict". They sit above the
# risk codes so the Action's `>= threshold` check fails them at any fail-on
# setting. Exit 1 is no longer used for internal errors: a Python traceback
# also exits 1, which used to read as MEDIUM and pass fail-on: high.
EXIT_PARTIAL = 3
EXIT_ERROR = 4

# Flags that say what was NOT inspected or could not be read. They set the
# inspection status but are kept out of the risk score.
GAP_CODES = frozenset({"G909", "G910", "G911", "G912", "G809"})


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"

    @property
    def weight(self) -> int:
        return {"low": 1, "medium": 4, "high": 10}[self.value]


def printable(s: str) -> str:
    """Keep spaces and printable characters; drop control and other non-printable ones."""
    return "".join(c for c in s if c == " " or c.isprintable())


@dataclass(frozen=True)
class Flag:
    """A single finding. `code` (G1xx..G9xx) makes user reports precise
    ("G501 fired") and `evidence` shows *why* without re-running.
    G1xx-G7xx are static, G8xx are behavioural (sandboxed run), G9xx are
    imported from an external scanner (Semgrep / SARIF)."""

    severity: Severity
    code: str
    message: str
    evidence: str = ""

    def __post_init__(self) -> None:
        # message / evidence quote the inspected artifact (file names, server names, lines):
        # attacker-chosen text. Control characters (ANSI escapes, CR, BEL) are removed here, for
        # every flag, so no output path (terminal or --json) can be spoofed by them.
        object.__setattr__(self, "message", printable(self.message))
        object.__setattr__(self, "evidence", printable(self.evidence))

    def to_dict(self) -> dict[str, Any]:
        return {
            "severity": self.severity.value,
            "code": self.code,
            "message": self.message,
            "evidence": self.evidence,
        }


@dataclass(frozen=True)
class Artifact:
    kind: ArtifactKind
    source: str  # where it came from (path / url / name)
    name: str
    content_hash: str  # sha256 over the fetched tree (pin point for Rug Pull)
    declared_capabilities: tuple[str, ...] = ()
    install_hooks: tuple[str, ...] = ()
    root: Optional[str] = None  # quarantine dir it was fetched into (NOT run)
    version: Optional[str] = None  # declared version (npm/pypi/vscode), if any

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind.value,
            "source": self.source,
            "name": self.name,
            "version": self.version,
            "content_hash": self.content_hash,
            "declared_capabilities": list(self.declared_capabilities),
            "install_hooks": list(self.install_hooks),
            "root": self.root,
        }


@dataclass
class Verdict:
    artifact: Artifact
    risk_level: RiskLevel
    risk_score: int
    flags: list[Flag] = field(default_factory=list)
    # Non-scored, human-facing context (e.g. whether the behavioural
    # sandbox ran, was skipped, or found nothing). Kept out of the score
    # so an honesty note can never change the verdict.
    notes: list[str] = field(default_factory=list)
    inspection: InspectionStatus = InspectionStatus.COMPLETE

    @property
    def gaps(self) -> list[str]:
        """What was not inspected, taken from the gap flags."""
        return [f.evidence or f.message for f in self.flags if f.code in GAP_CODES]

    @property
    def exit_code(self) -> int:
        # An incomplete inspection never passes, even at LOW: the gate cannot
        # vouch for bytes it did not read.
        if self.inspection is InspectionStatus.ERROR:
            return EXIT_ERROR
        if self.inspection is InspectionStatus.PARTIAL:
            return EXIT_PARTIAL
        return self.risk_level.exit_code

    def to_dict(self) -> dict[str, Any]:
        return {
            "artifact": self.artifact.to_dict(),
            "inspection": {"status": self.inspection.value, "gaps": self.gaps},
            "risk_level": self.risk_level.value,
            "risk_score": self.risk_score,
            "flags": [f.to_dict() for f in self.flags],
            "notes": list(self.notes),
        }

    def to_text(self) -> str:
        name = self.artifact.name
        if self.artifact.version:
            name = f"{name}@{self.artifact.version}"
        lines = [
            f"zee gate — {self.artifact.kind.value}: {name}",
            f"  source : {self.artifact.source}",
            f"  sha256 : {self.artifact.content_hash[:16]}…",
            f"  verdict: {self.risk_level.value}  (score {self.risk_score})",
            f"  inspect: {self.inspection.value}",
        ]
        for gap in self.gaps:
            lines.append(f"    not inspected: {gap}")
        if not self.flags:
            lines.append("  flags  : none")
        else:
            lines.append("  flags  :")
            for f in sorted(
                self.flags, key=lambda x: -x.severity.weight
            ):
                lines.append(
                    f"    [{f.severity.value:^6}] {f.code} {f.message}"
                )
                if f.evidence:
                    ev = f.evidence if len(f.evidence) <= 120 else (
                        f.evidence[:117] + "…"
                    )
                    lines.append(f"            ↳ {ev}")
        for note in self.notes:
            lines.append(f"  note   : {note}")
        return "\n".join(lines)


def error_payload(source: str, detail: str) -> dict[str, Any]:
    """Machine-readable result when no verdict could be produced. No risk
    level is reported: inventing one would present an unknown as a fact."""
    return {
        "source": source,
        "inspection": {"status": InspectionStatus.ERROR.value, "gaps": []},
        "error": detail,
        "risk_level": None,
        "flags": [],
        "notes": [],
    }
