"""Name / age / gender generation with a rough statistical shape.

Not census data. This is a small curated list weighted into frequency
tiers so a dummy record doesn't look conspicuously uniform — it is an
approximation, not a claim of matching real Japanese demographic
statistics (see design doc §3). Replace with a licensed frequency table
if a sharper match is ever required.
"""

from __future__ import annotations

import random
from dataclasses import dataclass

# (name, relative weight) — weight is an arbitrary frequency-tier proxy,
# not a measured statistic.
_SURNAMES = (
    ("佐藤", 10), ("鈴木", 10), ("高橋", 9), ("田中", 9), ("伊藤", 7),
    ("渡辺", 7), ("山本", 6), ("中村", 6), ("小林", 5), ("加藤", 5),
    ("吉田", 3), ("山田", 3), ("佐々木", 2), ("松本", 2), ("井上", 1),
)
_GIVEN_MALE = (
    ("大翔", 8), ("蓮", 8), ("悠真", 6), ("陽翔", 6), ("湊", 5),
    ("樹", 4), ("颯太", 3), ("和也", 2), ("修", 2), ("浩", 1),
)
_GIVEN_FEMALE = (
    ("陽菜", 8), ("結衣", 8), ("さくら", 6), ("美咲", 6), ("葵", 5),
    ("明子", 4), ("恵子", 3), ("久美子", 2), ("千代", 2), ("静", 1),
)

# Rough age-bucket weights, not a verified population pyramid.
_AGE_BUCKETS = (
    ((0, 9), 8), ((10, 19), 9), ((20, 29), 11), ((30, 39), 12),
    ((40, 49), 14), ((50, 59), 13), ((60, 69), 12), ((70, 79), 11),
    ((80, 99), 10),
)


@dataclass(frozen=True)
class DummyPerson:
    surname: str
    given_name: str
    gender: str  # "M" or "F"
    age: int


def _weighted_choice(rng: random.Random, items: tuple[tuple[object, int], ...]) -> object:
    total = sum(w for _, w in items)
    pick = rng.uniform(0, total)
    upto = 0.0
    for value, weight in items:
        upto += weight
        if pick <= upto:
            return value
    return items[-1][0]


def generate_person(rng: random.Random) -> DummyPerson:
    gender = rng.choice(("M", "F"))
    given_pool = _GIVEN_MALE if gender == "M" else _GIVEN_FEMALE
    surname = _weighted_choice(rng, _SURNAMES)
    given_name = _weighted_choice(rng, given_pool)
    lo, hi = _weighted_choice(rng, _AGE_BUCKETS)
    age = rng.randint(lo, hi)
    return DummyPerson(surname=surname, given_name=given_name, gender=gender, age=age)
