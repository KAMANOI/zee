"""Build the two address layers (design doc §2).

Layer 1 (fictional town): real-looking but absent town name + free-form
banchi/building/room — safe because the town itself doesn't exist.

Layer 2 (real town, non-residential banchi): a real town + a real chiban
that geometry.py/parcels.py confirmed sits fully inside public land
(park/river) + a fake building name and room number.
"""

from __future__ import annotations

import random

from .parcels import Parcel

_BUILDING_STEMS = ("ハイツ", "コーポ", "レジデンス", "荘", "マンション")
_BUILDING_NAMES = ("さくら", "みどり", "はなみずき", "けやき", "ひまわり", "あおば")


def generate_building_room(rng: random.Random) -> tuple[str, str]:
    building = rng.choice(_BUILDING_NAMES) + rng.choice(_BUILDING_STEMS)
    room = f"{rng.randint(1, 9)}0{rng.randint(1, 9)}"
    return building, room


def layer1_address(rng: random.Random, fictional_town: str) -> str:
    building, room = generate_building_room(rng)
    banchi = rng.randint(1, 40)
    go = rng.randint(1, 20)
    return f"{fictional_town}{banchi}番{go}号 {building}{room}"


def layer2_address(rng: random.Random, parcel: Parcel) -> str:
    building, room = generate_building_room(rng)
    return f"{parcel.chiban} {building}{room}"
