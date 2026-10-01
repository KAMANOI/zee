#!/usr/bin/env python3
"""Create a throwaway sandbox directory full of fake "documents" for the
Zee containment demo (demo/README.md). Every file is plain-text filler
generated here — no real user data is copied or referenced.

Usage:
    python3 demo/make_dummy_files.py <sandbox_dir>
"""
from __future__ import annotations

import sys
from pathlib import Path

MARKER = ".zee-demo-sandbox"

FAKE_DOCS = [
    "invoice_2026_09.txt",
    "client_notes.txt",
    "family_photo_caption.txt",
    "budget_draft.txt",
    "meeting_minutes.txt",
    "vacation_plan.txt",
]


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: make_dummy_files.py <sandbox_dir>", file=sys.stderr)
        return 1

    sandbox_dir = Path(sys.argv[1])
    sandbox_dir.mkdir(parents=True, exist_ok=True)
    (sandbox_dir / MARKER).write_text(
        "This directory is a disposable Zee demo sandbox. "
        "Everything inside is fake. Safe to delete.\n"
    )

    for name in FAKE_DOCS:
        (sandbox_dir / name).write_text(
            f"[DUMMY FILE — not real data]\n"
            f"This is placeholder content for the Zee demo ({name}).\n"
        )

    print(f"[make_dummy_files] wrote {len(FAKE_DOCS)} dummy files + marker to {sandbox_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
