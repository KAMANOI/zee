#!/usr/bin/env python3
"""DEMO ONLY — this is NOT a real card skimmer or malware.

A scripted stand-in that reproduces, at the *file layer only*, the
tampering techniques described in the Gambit Security report
(2026-09-22, "autonomous AI agents ... online retailers"). It exists
purely to give Zee's decoy tripwire + containment something realistic to
react to for the HDR note/X article screenshots and logs. It:

  1. sweeps the sandbox for JavaScript decoy files and appends a FAKE,
     inert loader line to the end of each (the report's most common
     technique: "append a loader to a legitimate JS file"), then resets
     the file's mtime to the original value (the report's "restore the
     timestamp" trick) — to show that Zee's event-based detection is not
     fooled by a restored timestamp,
  2. simulates the report's "write-back cron": a short loop that, after
     the loader is "removed" (truncated away), re-appends it — to show
     the cron keeps *re-tripping* Zee rather than evading it,
  3. deletes one decoy file (the report's cleanup step, where an agent's
     over-broad name match dropped ~180 tables) — at the file layer this
     is a delete-class event Zee also flags.

The appended "loader" is a harmless comment string. There is NO real
skimmer code, NO network code (no socket/urllib/requests import — check
the imports below), NO persistence outside the sandbox, and NO real cron
is installed (the "cron" is just an in-process loop).

Like demo/mock_attacker.py, it refuses to run against any directory that
does not contain the ".zee-demo-sandbox" marker, and only touches files
it finds *inside* the given sandbox directory. It is intentionally narrow
and must not be adapted into a real tool.

Usage:
    python3 demo/mock_skimmer.py <sandbox_dir>
"""
from __future__ import annotations

import os
import sys
import time
from pathlib import Path

MARKER = ".zee-demo-sandbox"
# Inert, obviously-fake loader. Mirrors the SHAPE of a skimmer loader
# (one appended line referencing an external script) without being one:
# it is a JS comment, so even if this decoy JS were ever executed it does
# nothing.
FAKE_LOADER = (
    "\n// [DEMO-FAKE-LOADER] inert string appended by mock_skimmer.py — "
    "not real code; stands in for an injected external-script loader\n"
)
CRON_PASSES = 3
PACE_SECONDS = 0.5


def _confined(sandbox_root: Path, p: Path) -> bool:
    """True only if p resolves inside sandbox_root (symlink defense)."""
    rp = p.resolve()
    return sandbox_root == rp or sandbox_root in rp.parents


def _js_decoys(sandbox_root: Path) -> list[Path]:
    return [
        p
        for p in sorted(sandbox_root.rglob("*.js"))
        if p.is_file() and _confined(sandbox_root, p)
    ]


def _append_loader_preserving_mtime(path: Path) -> None:
    """Append the fake loader, then restore the original mtime/atime —
    the report's 'reset the timestamp so the change looks untouched'."""
    st = path.stat()
    with path.open("a", encoding="utf-8") as fh:
        fh.write(FAKE_LOADER)
    os.utime(path, ns=(st.st_atime_ns, st.st_mtime_ns))


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: mock_skimmer.py <sandbox_dir>", file=sys.stderr)
        return 1

    sandbox_root = Path(sys.argv[1]).resolve()
    if not (sandbox_root / MARKER).exists():
        print(
            f"[mock_skimmer] refusing: {sandbox_root} has no {MARKER} marker. "
            "Run make_dummy_files.py on a throwaway directory first.",
            file=sys.stderr,
        )
        return 2

    targets = _js_decoys(sandbox_root)
    if not targets:
        print(
            f"[mock_skimmer] no .js decoy files under {sandbox_root}; "
            "nothing to tamper with.",
            file=sys.stderr,
        )
        return 3

    print(f"[mock_skimmer] DEMO ONLY — simulated JS-skimmer tampering in {sandbox_root}")

    # Technique 1: append loader to each JS decoy, hide via timestamp reset.
    for path in targets:
        _append_loader_preserving_mtime(path)
        print(f"[mock_skimmer]   appended fake loader + reset mtime -> {path.name}")
        time.sleep(PACE_SECONDS)

    # Technique 2: write-back "cron". Simulate the defender removing the
    # loader (truncate the file back), then the cron re-adds it. Each
    # re-add is a fresh change-class event on a watched decoy.
    primary = targets[0]
    for pass_no in range(1, CRON_PASSES + 1):
        if not primary.exists():
            break
        # defender "cleans" the file
        base = primary.read_text(encoding="utf-8").replace(FAKE_LOADER, "")
        primary.write_text(base, encoding="utf-8")
        print(f"[mock_skimmer]   cron pass {pass_no}: loader removed by defender")
        time.sleep(PACE_SECONDS)
        # cron writes it back
        _append_loader_preserving_mtime(primary)
        print(f"[mock_skimmer]   cron pass {pass_no}: loader re-written to {primary.name}")
        time.sleep(PACE_SECONDS)

    # Technique 3: cleanup over-broad delete (file-layer analogue of the
    # report's ~180-table drop). Delete the last JS decoy.
    victim = targets[-1]
    if victim.exists():
        victim.unlink()
        print(f"[mock_skimmer]   deleted (cleanup over-match) -> {victim.name}")

    print("[mock_skimmer] done. No network activity occurred (demo script).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
