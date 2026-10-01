#!/usr/bin/env python3
"""DEMO ONLY — this is NOT real ransomware.

A scripted stand-in for "an attacker tampering with files", built purely
to give Zee's decoy tripwire + containment something to react to on
camera (YouTube Short / X / note screenshots). It:

  1. overwrites every file in the target sandbox directory with random
     bytes (simulated encryption — no real cryptography, no ransom note,
     no persistence, no process injection),
  2. renames each one with a ".locked" extension (the visual cue),
  3. repeats the overwrite pass a second time (simulated "repeated
     tampering" burst).

It never touches the network (no socket/urllib/requests import — check
the import list below) and it refuses to run against any directory that
does not contain the ".zee-demo-sandbox" marker file created by
make_dummy_files.py, so it cannot be pointed at a real folder by mistake.

This script is intentionally narrow: it only operates on the files it
finds inside the given sandbox directory. It is not a general-purpose
attack tool and should not be adapted into one.

Usage:
    python3 demo/mock_attacker.py <sandbox_dir>
"""
from __future__ import annotations

import os
import sys
import time
from pathlib import Path

MARKER = ".zee-demo-sandbox"
PASSES = 2
PACE_SECONDS = 0.4


def _confined_files(sandbox_root: Path) -> list[Path]:
    """Every regular file directly under sandbox_root, marker excluded."""
    out = []
    for p in sorted(sandbox_root.iterdir()):
        if p.name == MARKER or not p.is_file():
            continue
        # Defense in depth: refuse anything that resolves outside the
        # sandbox (e.g. a symlink planted by accident).
        if sandbox_root not in p.resolve().parents and p.resolve() != sandbox_root:
            continue
        out.append(p)
    return out


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: mock_attacker.py <sandbox_dir>", file=sys.stderr)
        return 1

    sandbox_root = Path(sys.argv[1]).resolve()
    if not (sandbox_root / MARKER).exists():
        print(
            f"[mock_attacker] refusing: {sandbox_root} has no {MARKER} marker. "
            "Run make_dummy_files.py on a throwaway directory first.",
            file=sys.stderr,
        )
        return 2

    print(f"[mock_attacker] DEMO ONLY — simulated tampering in {sandbox_root}")

    current = {p: p for p in _confined_files(sandbox_root)}
    for pass_no in range(1, PASSES + 1):
        print(f"[mock_attacker] pass {pass_no}/{PASSES}")
        for original, path in list(current.items()):
            if not path.exists():
                continue
            size = max(path.stat().st_size, 64)
            path.write_bytes(os.urandom(size))
            target = path
            if path.suffix != ".locked":
                target = path.with_name(path.name + ".locked")
                path.rename(target)
                current[original] = target
            print(f"[mock_attacker]   overwrote + renamed -> {target.name}")
            time.sleep(PACE_SECONDS)

    print("[mock_attacker] done. No network activity occurred (demo script).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
