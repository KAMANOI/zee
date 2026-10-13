"""Re-check Layer-2 dummies against fresh parcel/public-land data (design
doc §8). Reads the seed-encrypted parcel store, re-runs the §1 judgement,
and writes the ledger HMACs of dummies whose chiban no longer qualifies to
expired.jsonl. The ledger itself is never modified.
"""

from __future__ import annotations

import json
from pathlib import Path

from ..errors import Z806_WEAK_SEED, Z808_OUTPUT_EXISTS, Z811_NO_PARCEL_STORE, ZeeError
from .generate import MIN_SEED_LENGTH
from .parcel_store import read_store
from .parcels import find_nonresidential_parcels, load_parcels, load_public_land
from .towns import load_real_town_names


def run_refresh(dir_: Path, parcels_path: Path, public_land_path: Path,
                abr_towns_path: Path, seed: str) -> tuple[Path, int, int]:
    """Returns (expired_path, expired_dummy_count, still_valid_dummy_count)."""
    if len(seed) < MIN_SEED_LENGTH:
        raise ZeeError(Z806_WEAK_SEED)
    store_path, expired_path = dir_ / "parcels.enc", dir_ / "expired.jsonl"
    if not store_path.exists():
        raise ZeeError(Z811_NO_PARCEL_STORE)
    if expired_path.exists():
        raise ZeeError(Z808_OUTPUT_EXISTS)
    entries = read_store(store_path, seed)

    parcels, p_crs = load_parcels(parcels_path)
    land, l_crs = load_public_land(public_land_path)
    still_ok = {p.chiban for p in find_nonresidential_parcels(
        parcels, p_crs, land, l_crs, load_real_town_names(abr_towns_path))}

    expired = [h for e in entries if e["chiban"] not in still_ok for h in e["hmacs"]]
    valid = sum(len(e["hmacs"]) for e in entries) - len(expired)
    with expired_path.open("w", encoding="utf-8") as f:
        for h in expired:
            f.write(json.dumps({"record_hmac": h}) + "\n")
    return expired_path, len(expired), valid
