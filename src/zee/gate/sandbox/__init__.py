"""Behavioural sandbox — the *detonator* (Phase 2, invariant I7).

This subpackage is the one place in Zee that actually executes an
untrusted artifact. It is deliberately kept as a separate module / risk
surface from the Zee core: the core never imports it, and a bug in here
can only blow up the disposable sandbox, never the last line of defence
(I7). The hard rule is I2 — if no real isolation backend is available we
do **not** run the artifact on the bare host; behavioural inspection is
skipped and the static verdict stands.

Public API:
    run_behavioral(artifact, ...) -> BehavioralResult
    detect_backend() / available_backends()

Flag codes raised here (G8xx, behavioural):
    G801  HIGH    decoy credential token exfiltrated (read + sent outbound)
    G802  MEDIUM  outbound network attempt during the sandboxed run
    G803  HIGH    persistence write (shell rc / LaunchAgent / autostart / agent config)
    G804  MEDIUM  decoy credential file read (access time advanced; best-effort)
    G805  MEDIUM  sandboxed run timed out / was killed
    G808  LOW     no runnable install hook — nothing to detonate
    G809  LOW     behavioural inspection skipped — no isolation backend (NOT executed)
"""

from __future__ import annotations

from .backends import available_backends, detect_backend
from .runner import BehavioralResult, run_behavioral

__all__ = [
    "run_behavioral",
    "BehavioralResult",
    "detect_backend",
    "available_backends",
]
