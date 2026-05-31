"""Seed a handful of decoys under ~/Documents/zee-decoys/ for a demo run.

Usage:
    python examples/seed_demo_decoys.py [--canary-base-url URL] [--target DIR]

What it does:
    1. Creates the target directory (defaults to ~/Documents/zee-decoys/)
       with mode 0700 if Zee created it.
    2. Writes 3 plausible-looking decoy files (env / credentials / notes).
    3. Optionally embeds canary URLs if --canary-base-url is supplied;
       otherwise the seeder runs without canary (matching the v0.3
       default-safe behaviour).
    4. Prints the absolute paths so you can paste them into
       assets.toml.

This script is a thin wrapper around zee.decoy.seeder.seed_all and
zee.decoy.canary_token.CanaryTokenRegistry — it makes the
"reproducible local demo" path explicit so the README's quick-start
is not the only way to get a working decoy directory.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from zee.decoy.canary_token import CanaryTokenRegistry
from zee.decoy.seeder import seed_all


DEFAULT_NAMES = [
    "service.env",
    "aws-credentials.decoy",
    "internal_notes.txt",
]


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Seed example Zee decoys under a directory you control.",
    )
    ap.add_argument(
        "--target",
        type=Path,
        default=Path.home() / "Documents" / "zee-decoys",
        help="directory to write decoys into (default: ~/Documents/zee-decoys/)",
    )
    ap.add_argument(
        "--canary-base-url",
        default=None,
        help=(
            "https:// URL of your canary receiver. When set, the seeder "
            "embeds <base_url>/<token_id> into env / credentials / notes "
            "templates (see README 'canary base_url')."
        ),
    )
    args = ap.parse_args()

    registry = None
    if args.canary_base_url:
        try:
            registry = CanaryTokenRegistry(base_url=args.canary_base_url)
        except ValueError as e:
            print(f"error: {e}", file=sys.stderr)
            return 1

    target: Path = args.target
    paths = [str(target / name) for name in DEFAULT_NAMES]
    seeded = seed_all(paths, registry=registry)

    print(f"# seeded {len(seeded)} decoys under {target}")
    for p in seeded:
        print(p)
    print()
    print("# paste into your assets.toml:")
    print("[[assets]]")
    print('id = "demo-host"')
    print('type = "workstation"')
    print("overnight_active = false")
    # Use TOML literal strings (single quotes) so Windows paths with
    # backslashes (C:\Users\...) survive without escape interpretation.
    # Basic strings (double quotes) would parse \U / \s as escapes.
    print("decoy_paths = [")
    for p in seeded:
        print(f"    '{p}',")
    print("]")
    print('response_mode = "notify"')
    print('cut_method = "egress"')
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
