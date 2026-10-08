"""Orchestration: generate dummy records + ledger, write them to files.

v1 scope only (design doc §4): writes records.csv + ledger.jsonl. Does
not touch any database, backup, or network — mixing the output into a
backup/export is the operator's own step.
"""

from __future__ import annotations

import csv
import random
from dataclasses import dataclass
from pathlib import Path

from . import ledger as ledger_mod
from ..errors import (
    Z801_NO_ELIGIBLE_PARCEL,
    Z802_EMAIL_DOMAIN_REQUIRED,
    Z803_MISSING_LAYER2_INPUT,
    Z806_WEAK_SEED,
    Z807_INVALID_COUNT,
    Z808_OUTPUT_EXISTS,
    Z809_ADDRESS_POOL_EXHAUSTED,
    Z901_INTERNAL,
    ZeeError,
)
from .address import layer1_address, layer2_address
from .names import generate_person
from .parcels import Parcel, find_nonresidential_parcels, load_parcels, load_public_land
from .postal import load_zip_by_town, zip_for_town
from .towns import generate_fictional_town_name, load_real_town_names

_RECORD_FIELDS = ("surname", "given_name", "gender", "age", "postal_code",
                   "address", "phone", "email")

MIN_SEED_LENGTH = 16


@dataclass(frozen=True)
class DiluteConfig:
    parcels_path: Path | None
    public_land_path: Path | None
    abr_towns_path: Path
    zipcode_path: Path
    seed: str
    count: int
    layer: str  # "fictional-town" | "real-nonresidential" | "both"
    email_mode: str  # "omit" | "user-domain"
    email_domain: str | None
    fallback_zip: str
    out_dir: Path


def _email_for(rng: random.Random, cfg: DiluteConfig) -> str:
    if cfg.email_mode == "omit":
        return ""
    if cfg.email_mode == "user-domain":
        if not cfg.email_domain:
            raise ZeeError(Z802_EMAIL_DOMAIN_REQUIRED)
        # Derived from the seeded rng (not secrets.token_hex): must be
        # reproducible under the same --seed like every other field, and
        # must NOT reuse any id that also lives in the ledger — otherwise
        # a leaked ledger alone (no seed needed) could match this email
        # straight back to its row, defeating the HMAC-key protection.
        token = format(rng.getrandbits(64), "016x")
        return f"d{token}@{cfg.email_domain}"
    raise ZeeError(Z901_INTERNAL, f"unknown email_mode: {cfg.email_mode!r}")


def run(cfg: DiluteConfig) -> tuple[Path, Path]:
    if cfg.count <= 0:
        raise ZeeError(Z807_INVALID_COUNT)
    if len(cfg.seed) < MIN_SEED_LENGTH:
        raise ZeeError(Z806_WEAK_SEED)
    if cfg.email_mode == "user-domain" and not cfg.email_domain:
        raise ZeeError(Z802_EMAIL_DOMAIN_REQUIRED)

    cfg.out_dir.mkdir(parents=True, exist_ok=True)
    records_path = cfg.out_dir / "records.csv"
    ledger_path = cfg.out_dir / "ledger.jsonl"
    if records_path.exists() or ledger_path.exists():
        raise ZeeError(Z808_OUTPUT_EXISTS)

    rng = random.Random(cfg.seed)

    real_towns = load_real_town_names(cfg.abr_towns_path)
    zip_by_town = load_zip_by_town(cfg.zipcode_path)

    eligible_parcels: list[Parcel] = []
    if cfg.layer in ("real-nonresidential", "both"):
        if cfg.parcels_path is None or cfg.public_land_path is None:
            raise ZeeError(Z803_MISSING_LAYER2_INPUT)
        parcels, parcels_crs = load_parcels(cfg.parcels_path)
        public_land, public_land_crs = load_public_land(cfg.public_land_path)
        eligible_parcels = find_nonresidential_parcels(
            parcels, parcels_crs, public_land, public_land_crs, real_towns,
        )
        if not eligible_parcels:
            raise ZeeError(Z801_NO_ELIGIBLE_PARCEL)

    rows: list[dict[str, str]] = []
    hmacs: list[str] = []
    used_addresses: set[str] = set()

    for _ in range(cfg.count):
        person = generate_person(rng)
        if cfg.layer == "fictional-town":
            use_layer2 = False
        elif cfg.layer == "real-nonresidential":
            use_layer2 = True
        else:
            use_layer2 = rng.random() < 0.5

        # Retry on an in-batch address collision (same chiban/town +
        # building + room drawn twice) rather than ever silently writing
        # two different "people" at an identical address in one batch.
        # Exhausting retries means the eligible pool is too small for the
        # requested --count — fail rather than write the duplicate anyway.
        for _attempt in range(50):
            if use_layer2:
                parcel = rng.choice(eligible_parcels)
                address = layer2_address(rng, parcel)
                town = parcel.town
            else:
                town = generate_fictional_town_name(rng, real_towns)
                address = layer1_address(rng, town)
            if address not in used_addresses:
                used_addresses.add(address)
                break
        else:
            raise ZeeError(Z809_ADDRESS_POOL_EXHAUSTED)

        postal_code = zip_for_town(rng, town, zip_by_town, cfg.fallback_zip)
        email = _email_for(rng, cfg)

        fields = {
            "surname": person.surname,
            "given_name": person.given_name,
            "gender": person.gender,
            "age": str(person.age),
            "postal_code": postal_code,
            "address": address,
            "phone": "",
            "email": email,
        }
        # rows carries ONLY the plain PII fields — no id/marker column
        # (design doc §5: the record itself must carry no tell).
        rows.append(dict(fields))
        hmacs.append(ledger_mod.record_hmac(fields, cfg.seed))

    with records_path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(_RECORD_FIELDS))
        writer.writeheader()
        writer.writerows(rows)

    ledger_mod.write_ledger(ledger_path, hmacs)

    return records_path, ledger_path
