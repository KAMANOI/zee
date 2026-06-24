"""Orchestrates the gate flow: fetch (no exec) -> classify -> static
inspect -> denylist -> score -> verdict, and promote only on LOW.

This is the end-to-end path behind `zee gate add`. It never executes the
artifact; the only filesystem effects are the quarantine copy and, on a
LOW verdict with --promote-to, the copy into the real install location.
"""

from __future__ import annotations

import shutil
from pathlib import Path
from typing import Optional

from . import denylist, scorer, static_checks
from .adapters import pick_adapter
from .fetch import fetch_local
from .model import Flag, RiskLevel, Severity, Verdict


def _install_hook_flags(install_hooks: tuple[str, ...]) -> list[Flag]:
    return [
        Flag(
            Severity.MEDIUM, "G101",
            "declares an install / post-install hook",
            evidence=hook,
        )
        for hook in install_hooks
    ]


def inspect_source(
    source: str | Path,
    kind: Optional[str] = None,
    quarantine_base: Optional[Path] = None,
    *,
    behavioral: bool = False,
    behavioral_timeout: int = 20,
    import_scans: tuple[str, ...] = (),
) -> Verdict:
    root = fetch_local(source, base=quarantine_base)  # copy only, NO exec
    adapter = pick_adapter(root, kind)
    artifact = adapter.build(source, root)

    flags: list[Flag] = []
    flags += static_checks.scan_tree(root)
    flags += denylist.check(artifact)
    flags += _install_hook_flags(artifact.install_hooks)

    if import_scans:
        # Interop (I4): fold existing scanners' findings into the same
        # verdict instead of re-implementing them.
        from .imports import import_scans as _import_scans

        flags += _import_scans(import_scans)

    notes: list[str] = []
    if behavioral:
        # Opt-in: this is the one path that EXECUTES the artifact, always
        # inside the isolation backend (or not at all — see I2/I7). Its
        # G8xx flags fold into the same score as the static findings.
        from .sandbox import run_behavioral

        result = run_behavioral(artifact, timeout=behavioral_timeout)
        flags += result.flags
        notes.append(f"behavioural: {result.summary}")

    level, sc = scorer.score(flags)
    return Verdict(
        artifact=artifact, risk_level=level, risk_score=sc,
        flags=flags, notes=notes,
    )


def promote_if_low(verdict: Verdict, dest_dir: str | Path) -> tuple[bool, str]:
    """Copy the quarantined artifact into the real install dir, but only
    if the verdict is LOW (invariant I3: nothing reaches the real
    location until it passes)."""
    if verdict.risk_level is not RiskLevel.LOW:
        return (
            False,
            f"refused to promote: verdict is {verdict.risk_level.value} "
            f"(only LOW is promoted)",
        )
    if not verdict.artifact.root:
        return False, "refused to promote: no quarantine root recorded"

    # The artifact name comes from the source and is untrusted. Reject
    # anything that is not a single, plain path component so a crafted
    # name (".." / absolute / nested) cannot escape the install dir.
    name = verdict.artifact.name
    if name in ("", ".", "..") or Path(name).name != name:
        return False, f"refused to promote: unsafe artifact name {name!r}"

    root = Path(verdict.artifact.root)
    # Defence in depth (HIGH symlinks already block LOW, but never trust a
    # single layer): never promote a tree that links outside itself.
    root_resolved = str(root.resolve())
    for p in root.rglob("*"):
        if p.is_symlink():
            try:
                tgt = str(p.resolve())
                inside = tgt == root_resolved or tgt.startswith(
                    root_resolved + "/"
                )
            except OSError:
                inside = False
            if not inside:
                return (
                    False,
                    f"refused to promote: symlink escapes artifact: "
                    f"{p.relative_to(root)}",
                )

    base = Path(dest_dir).expanduser()
    dest = base / name
    # Containment: the destination must resolve to a direct child of base.
    if dest.resolve().parent != base.resolve():
        return False, "refused to promote: destination escapes install dir"
    if dest.exists():
        return False, f"refused to promote: destination already exists: {dest}"
    base.mkdir(parents=True, exist_ok=True)
    shutil.copytree(root, dest, symlinks=True)
    return True, f"promoted (LOW) to {dest}"
