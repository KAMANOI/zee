"""Orchestration: generate dummy records + ledger, write them to files.

v1 scope only (design doc §4): writes records.csv + ledger.jsonl. Does
not touch any database, backup, or network — mixing the output into a
backup/export is the operator's own step.
"""

from __future__ import annotations

import csv
import random
import secrets
from dataclasses import dataclass
from pathlib import Path

from . import ledger as ledger_mod
from ..errors import (
    Z801_NO_ELIGIBLE_PARCEL,
    Z802_EMAIL_DOMAIN_REQUIRED,
    Z803_MISSING_LAYER2_INPUT,
    ZeeError,
)
from .address import layer1_address, layer2_address
from .names import generate_person
from .parcels import Parcel, find_nonresidential_parcels, load_parcels, load_public_land
from .postal import load_zip_by_town, zip_for_town
from .towns import generate_fictional_town_name, load_real_town_names

_RECORD_FIELDS = ("surname", "given_name", "gender", "age", "postal_code",
                   "address", "phone", "email")


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


def _email_for(dummy_id: str, cfg: DiluteConfig) -> str:
    if cfg.email_mode == "omit":
        return ""
    if cfg.email_mode == "user-domain":
        if not cfg.email_domain:
            raise ZeeError(Z802_EMAIL_DOMAIN_REQUIRED)
        return f"dummy+{dummy_id}@{cfg.email_domain}"
    raise ValueError(f"unknown email_mode: {cfg.email_mode!r}")


def run(cfg: DiluteConfig) -> tuple[Path, Path]:
    cfg.out_dir.mkdir(parents=True, exist_ok=True)
    rng = random.Random(cfg.seed)

    real_towns = load_real_town_names(cfg.abr_towns_path)
    zip_by_town = load_zip_by_town(cfg.zipcode_path)

    eligible_parcels: list[Parcel] = []
    if cfg.layer in ("real-nonresidential", "both"):
        if cfg.parcels_path is None or cfg.public_land_path is None:
            raise ZeeError(Z803_MISSING_LAYER2_INPUT)
        parcels = load_parcels(cfg.parcels_path)
        public_land = load_public_land(cfg.public_land_path)
        eligible_parcels = find_nonresidential_parcels(parcels, public_land)
        if not eligible_parcels:
            raise ZeeError(Z801_NO_ELIGIBLE_PARCEL)

    rows: list[dict[str, str]] = []
    ledger_entries: list[ledger_mod.LedgerEntry] = []

    for _ in range(cfg.count):
        person = generate_person(rng)
        if cfg.layer == "fictional-town":
            use_layer2 = False
        elif cfg.layer == "real-nonresidential":
            use_layer2 = True
        else:
            use_layer2 = rng.random() < 0.5

        if use_layer2:
            parcel = rng.choice(eligible_parcels)
            address = layer2_address(rng, parcel)
            town = parcel.town
        else:
            town = generate_fictional_town_name(rng, real_towns)
            address = layer1_address(rng, town)

        postal_code = zip_for_town(town, zip_by_town, cfg.fallback_zip)
        dummy_id = secrets.token_hex(8)

        fields = {
            "surname": person.surname,
            "given_name": person.given_name,
            "gender": person.gender,
            "age": str(person.age),
            "postal_code": postal_code,
            "address": address,
            "phone": "",
            "email": _email_for(dummy_id, cfg),
        }
        # rows carries ONLY the plain PII fields — no id/marker column.
        # dummy_id lives in the ledger only, purely as a human-readable
        # label for that ledger line; it is never written into records.csv
        # (design doc §5: the record itself must carry no tell).
        rows.append(dict(fields))
        ledger_entries.append(ledger_mod.LedgerEntry(
            dummy_id=dummy_id,
            record_hmac=ledger_mod.record_hmac(fields, cfg.seed),
        ))

    records_path = cfg.out_dir / "records.csv"
    with records_path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(_RECORD_FIELDS))
        writer.writeheader()
        writer.writerows(rows)

    ledger_path = cfg.out_dir / "ledger.jsonl"
    ledger_mod.write_ledger(ledger_path, ledger_entries)

    return records_path, ledger_path
