"""Layer 1 — fictional town (町字) names, confirmed absent from the real
national town-name master.

v1 input is a one-column CSV of real town names, a stand-in for the
アドレス・ベース・レジストリ 町字マスター (confirmed public, PDL1.0,
redistributable — see design doc §1). The real master is nationwide and
machine-readable as-is; no parser beyond csv is needed for this layer.
"""

from __future__ import annotations

import csv
import random
from pathlib import Path

_FICTIONAL_STEMS = (
    "架空台", "仮称野", "試作丘", "見本原", "雛形沢", "模擬坂",
)
_CHOME = ("一丁目", "二丁目", "三丁目", "四丁目")


def load_real_town_names(path: Path) -> frozenset[str]:
    with Path(path).open(encoding="utf-8", newline="") as f:
        return frozenset(row[0].strip() for row in csv.reader(f) if row and row[0].strip())


def is_real_town(name: str, real_towns: frozenset[str]) -> bool:
    return name in real_towns


def generate_fictional_town_name(rng: random.Random, real_towns: frozenset[str]) -> str:
    """A town name shaped like a real one, verified absent from the master.

    Retries with a different stem/chōme combination on an (extremely
    unlikely) collision rather than ever returning a name present in
    real_towns.
    """
    for _ in range(100):
        candidate = rng.choice(_FICTIONAL_STEMS) + rng.choice(_CHOME)
        if not is_real_town(candidate, real_towns):
            return candidate
    raise RuntimeError("could not find a non-colliding fictional town name after 100 tries")
