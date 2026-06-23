"""Zee entry gate (`zee gate`) — pre-install inspection for AI artifacts.

Intercepts a Claude Code skill / MCP server / package *before* it is
installed, fetches it into a quarantine directory **without executing
it**, inspects it statically, and promotes only LOW-risk artifacts into
the real install location.

Hard invariants (handover doc I1-I7):

* I1 zero running cost — everything is local, no server, no paid backend.
* I2 never execute untrusted code on the host that runs Zee core. In
  this phase the gate only *fetches and statically reads*; the
  behavioural "detonator" (sandboxed execution) is a later phase and a
  separate module/process.
* I3 nothing reaches the real install location until it passes the gate.
* I5 no overclaiming — this is risk reduction, not complete detection.
* I6 neither the inspected artifact nor the user's secrets leave the host.
* I7 keep the detonator out of Zee core's risk surface; the gate is an
  optional module and core works without it.

stdlib only. Optional external scanners (Semgrep/Snyk/Socket) are
*complemented*, never required (I4).
"""

from __future__ import annotations

__all__ = [
    "Artifact",
    "ArtifactKind",
    "Verdict",
    "RiskLevel",
    "Severity",
    "Flag",
    "score",
]

from .model import (
    Artifact,
    ArtifactKind,
    Flag,
    RiskLevel,
    Severity,
    Verdict,
)
from .scorer import score
