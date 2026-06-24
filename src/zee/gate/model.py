"""Contracts for the entry gate: the artifact model and verdict schema.

Phase 0 deliverable — the minimal common representation of a skill / mcp
/ package, plus the LOW/MEDIUM/HIGH verdict (safeinspect heritage:
risk_level, risk_score, flags with evidence, and an exit code
LOW=0 / MEDIUM=1 / HIGH=2). stdlib only.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional


class ArtifactKind(str, Enum):
    SKILL = "skill"
    MCP = "mcp"
    PACKAGE = "package"


class RiskLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"

    @property
    def exit_code(self) -> int:
        return {"LOW": 0, "MEDIUM": 1, "HIGH": 2}[self.value]


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"

    @property
    def weight(self) -> int:
        return {"low": 1, "medium": 4, "high": 10}[self.value]


@dataclass(frozen=True)
class Flag:
    """A single finding. `code` (G1xx..G8xx) makes user reports precise
    ("G501 fired") and `evidence` shows *why* without re-running.
    G1xx-G7xx are static; G8xx are behavioural (sandboxed run)."""

    severity: Severity
    code: str
    message: str
    evidence: str = ""

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

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind.value,
            "source": self.source,
            "name": self.name,
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

    @property
    def exit_code(self) -> int:
        return self.risk_level.exit_code

    def to_dict(self) -> dict[str, Any]:
        return {
            "artifact": self.artifact.to_dict(),
            "risk_level": self.risk_level.value,
            "risk_score": self.risk_score,
            "flags": [f.to_dict() for f in self.flags],
            "notes": list(self.notes),
        }

    def to_text(self) -> str:
        lines = [
            f"zee gate — {self.artifact.kind.value}: {self.artifact.name}",
            f"  source : {self.artifact.source}",
            f"  sha256 : {self.artifact.content_hash[:16]}…",
            f"  verdict: {self.risk_level.value}  (score {self.risk_score})",
        ]
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
