"""Orchestrate one behavioural run: build a disposable HOME, seed decoy
credentials, detonate the artifact's install hook inside the isolation
backend with a loopback-only FakeNet sink, then read the runtime signals
back out as G8xx flags.

Flow:
    detect backend  --none-->  G809, do NOT execute (I2)
    find runnable hook  --none-->  G808, nothing to detonate
    seed decoys + persistence baseline
    run hook under backend (rlimits + wall timeout + loopback proxy)
    collect: token exfil (G801) / outbound attempt (G802) /
             persistence write (G803) / decoy read (G804) / killed (G805)

Everything lives in a TemporaryDirectory that is removed when the run
ends, so neither the bait nor the artifact's work copy lingers on disk.
"""

from __future__ import annotations

import os
import shutil
import signal
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from ..model import Artifact, Flag, Severity
from . import decoys as decoy_mod
from .backends import IsolationBackend, detect_backend
from .netsink import NetSink

# Files / dirs under the sandbox HOME whose appearance or mutation means
# the artifact tried to persist itself. None of these are decoys, so a
# change here is unambiguous (vs. a decoy read, which we track separately).
_PERSISTENCE_PATHS: tuple[str, ...] = (
    ".zshrc", ".zprofile", ".zshenv",
    ".bashrc", ".bash_profile", ".profile",
    "Library/LaunchAgents", ".config/autostart",
    ".claude", ".config/zee",
)

# Install hooks we know how to detonate, in priority order. MVP scope:
# POSIX shell hooks (the common skill/MCP/installer shape). Node/python
# hooks usually need a toolchain + network we deliberately withhold, so
# they fall through to G808 ("nothing to detonate") rather than a partial
# run that proves nothing.
_RUNNABLE_HOOKS: tuple[str, ...] = (
    "install.sh", "setup.sh", "preinstall.sh", "postinstall.sh",
)

_DEFAULT_WALL_TIMEOUT = 20      # seconds of wall clock
_DEFAULT_CPU_SECONDS = 10       # seconds of CPU
_MAX_WRITE_BYTES = 64 * 1024 * 1024  # RLIMIT_FSIZE: cap runaway writes


@dataclass
class BehavioralResult:
    flags: list[Flag] = field(default_factory=list)
    ran: bool = False
    backend_name: Optional[str] = None
    summary: str = ""


def _find_hook(root: Path) -> Optional[Path]:
    by_name: dict[str, Path] = {}
    for p in sorted(root.rglob("*")):
        if p.is_file() and not p.is_symlink() and p.name in _RUNNABLE_HOOKS:
            by_name.setdefault(p.name, p)
    for name in _RUNNABLE_HOOKS:
        if name in by_name:
            return by_name[name]
    return None


def _snapshot(home: Path) -> dict[str, tuple[float, int]]:
    """Map watched persistence path -> (mtime, size) for files present."""
    snap: dict[str, tuple[float, int]] = {}
    for rel in _PERSISTENCE_PATHS:
        base = home / rel
        if base.is_dir():
            for f in base.rglob("*"):
                if f.is_file():
                    try:
                        st = f.stat()
                        snap[str(f.relative_to(home))] = (st.st_mtime, st.st_size)
                    except OSError:
                        pass
        elif base.is_file():
            try:
                st = base.stat()
                snap[rel] = (st.st_mtime, st.st_size)
            except OSError:
                pass
    return snap


def _persistence_changes(home: Path, before: dict[str, tuple[float, int]]) -> list[str]:
    after = _snapshot(home)
    changed: list[str] = []
    for rel, meta in after.items():
        if before.get(rel) != meta:
            changed.append(rel)
    return sorted(changed)


def _atimes(home: Path, rels: list[str]) -> dict[str, float]:
    out: dict[str, float] = {}
    for rel in rels:
        try:
            out[rel] = (home / rel).stat().st_atime
        except OSError:
            pass
    return out


def _limits_preexec():
    """Return a preexec_fn that caps CPU + file size for the child tree.

    Best-effort: a platform that rejects a limit is skipped rather than
    failing the run. preexec_fn is POSIX-only, which is fine — every
    isolation backend we ship is POSIX.
    """
    def _apply() -> None:
        import resource

        for res, val in (
            (resource.RLIMIT_CPU, _DEFAULT_CPU_SECONDS),
            (resource.RLIMIT_FSIZE, _MAX_WRITE_BYTES),
        ):
            try:
                resource.setrlimit(res, (val, val))
            except (ValueError, OSError):
                pass

    return _apply


def run_behavioral(
    artifact: Artifact,
    *,
    timeout: int = _DEFAULT_WALL_TIMEOUT,
    backend: Optional[IsolationBackend] = None,
) -> BehavioralResult:
    """Detonate ``artifact`` inside an isolation backend and report G8xx flags.

    Never executes anything if no backend is available (I2): returns a
    G809 notice and ran=False, leaving the static verdict authoritative.
    """
    backend = backend or detect_backend()
    if backend is None:
        return BehavioralResult(
            flags=[Flag(
                Severity.LOW, "G809",
                "behavioural inspection skipped: no isolation backend "
                "available; the artifact was NOT executed",
                evidence="install a backend (e.g. Docker) or run on a host "
                         "with macOS sandbox-exec for runtime checks",
            )],
            ran=False,
            backend_name=None,
            summary="skipped (no isolation backend)",
        )

    if not artifact.root:
        return BehavioralResult(
            flags=[Flag(
                Severity.LOW, "G808",
                "no quarantined artifact tree to run",
            )],
            ran=False,
            backend_name=backend.name,
            summary="skipped (no artifact root)",
        )

    quarantine_root = Path(artifact.root)
    hook = _find_hook(quarantine_root)
    if hook is None:
        return BehavioralResult(
            flags=[Flag(
                Severity.LOW, "G808",
                "no runnable install hook found; nothing to detonate "
                f"(looked for: {', '.join(_RUNNABLE_HOOKS)})",
            )],
            ran=False,
            backend_name=backend.name,
            summary="skipped (no runnable hook)",
        )

    with tempfile.TemporaryDirectory(prefix="zee-gate-sbx-") as tmp:
        session = Path(tmp)
        home = session / "home"
        profile_dir = session / "profile"
        home.mkdir(parents=True)
        profile_dir.mkdir(parents=True)
        (home / "tmp").mkdir()
        # Pre-create persistence dirs so a write into them shows up as a
        # NEW file against the baseline rather than being missed.
        (home / "Library" / "LaunchAgents").mkdir(parents=True, exist_ok=True)
        (home / ".config" / "autostart").mkdir(parents=True, exist_ok=True)

        # The artifact runs from a writable copy inside HOME (so its own
        # legitimate writes don't trip containment); the quarantine copy
        # stays pristine.
        work = home / "work"
        shutil.copytree(quarantine_root, work, symlinks=True)
        hook_in_work = work / hook.relative_to(quarantine_root)

        seeded = decoy_mod.seed(home)
        baseline = _snapshot(home)
        decoy_rels = decoy_mod.decoy_relpaths()
        atimes_before = _atimes(home, decoy_rels)

        flags: list[Flag] = []
        timed_out = False

        with NetSink() as sink:
            proxy = f"http://localhost:{sink.port}"
            env = {
                "HOME": str(home.resolve()),
                "TMPDIR": str((home / "tmp").resolve()),
                "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
                "HTTP_PROXY": proxy, "HTTPS_PROXY": proxy, "ALL_PROXY": proxy,
                "http_proxy": proxy, "https_proxy": proxy, "all_proxy": proxy,
                "ZEE_SANDBOX": "1",
            }
            command = ["/bin/sh", str(hook_in_work.name)]
            argv = backend.wrap(
                command,
                workhome=home,
                loopback_port=sink.port,
                profile_dir=profile_dir,
            )
            proc = subprocess.Popen(
                argv,
                cwd=str(hook_in_work.parent),
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                preexec_fn=_limits_preexec(),
                start_new_session=True,
            )
            try:
                proc.communicate(timeout=timeout)
            except subprocess.TimeoutExpired:
                timed_out = True
                # Kill the whole process group first (sandbox-exec -> sh ->
                # grandchildren all share the session we started), then fall
                # back to killing the direct child so nothing survives.
                try:
                    os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                except (ProcessLookupError, OSError):
                    pass
                try:
                    proc.kill()
                except (ProcessLookupError, OSError):
                    pass
                try:
                    proc.communicate(timeout=5)
                except subprocess.TimeoutExpired:
                    pass

            # ── read the runtime signals back out ──────────────────────
            exfil = sink.exfiltrated_tokens(seeded.tokens)
            destinations = sink.outbound_destinations()

        # G801: a planted credential token left the box (read + exfil).
        for tok, dest in exfil.items():
            flags.append(Flag(
                Severity.HIGH, "G801",
                "decoy credential was read and exfiltrated during install",
                evidence=f"{seeded.path_for(tok)} -> {dest or 'outbound'}",
            ))
        # G802: any outbound attempt at all (network during install is
        # unexpected for the kinds of artifacts the gate inspects).
        for dest in destinations:
            flags.append(Flag(
                Severity.MEDIUM, "G802",
                "outbound network attempt during sandboxed install",
                evidence=dest,
            ))
        # G803: persistence — wrote into a shell rc / autostart / agent dir.
        for rel in _persistence_changes(home, baseline):
            flags.append(Flag(
                Severity.HIGH, "G803",
                "wrote to a persistence / autostart location during install",
                evidence=rel,
            ))
        # G804: best-effort decoy read (atime advanced) not already proven
        # by an exfil. Unreliable on noatime mounts, hence MEDIUM + dedup.
        exfil_paths = {seeded.path_for(t) for t in exfil}
        atimes_after = _atimes(home, decoy_rels)
        for rel in decoy_rels:
            if rel in exfil_paths:
                continue
            b = atimes_before.get(rel)
            a = atimes_after.get(rel)
            if b is not None and a is not None and a > b:
                flags.append(Flag(
                    Severity.MEDIUM, "G804",
                    "decoy credential file was read during install "
                    "(access time advanced)",
                    evidence=rel,
                ))
        # G805: the hook didn't finish on its own.
        if timed_out:
            flags.append(Flag(
                Severity.MEDIUM, "G805",
                f"sandboxed install did not complete within {timeout}s "
                "and was killed",
                evidence=hook.name,
            ))

    n = len(flags)
    summary = (
        f"ran via {backend.name}: "
        + ("no suspicious runtime signals" if n == 0
           else f"{n} runtime finding{'s' if n != 1 else ''}")
    )
    return BehavioralResult(
        flags=flags, ran=True, backend_name=backend.name, summary=summary,
    )
