"""Tests for zee.dilution — decoy PII value-dilution generator.

Covers the task's four acceptance checks:
1. every layer-2 (real-nonresidential) address uses a chiban that passed
   the non-residential (fully-inside-public-land) check
2. the ledger lets every dummy be recognized by re-hashing its own fields
3. the output record itself carries no marker distinguishing it as a dummy
4. changing the seed changes the output
"""

from __future__ import annotations

import csv
import json
from pathlib import Path

import pytest

from zee.dilution import ledger as ledger_mod
from zee.dilution.generate import DiluteConfig, run
from zee.dilution.geometry import point_in_polygon, polygon_fully_inside
from zee.dilution.parcels import find_nonresidential_parcels, load_parcels, load_public_land
from zee.dilution.towns import generate_fictional_town_name, is_real_town, load_real_town_names
from zee.errors import ZeeError as _ZeeError

FIXTURES = Path(__file__).parent / "fixtures" / "dilution"


# ---------------------------------------------------------------- geometry

def test_point_in_polygon_basic():
    square = ((0, 0), (10, 0), (10, 10), (0, 10))
    assert point_in_polygon((5, 5), square)
    assert not point_in_polygon((15, 5), square)
    assert point_in_polygon((0, 0), square)  # boundary counts as inside


def test_polygon_fully_inside_rejects_straddling():
    container = ((0, 0), (100, 0), (100, 100), (0, 100))
    fully_in = ((10, 10), (20, 10), (20, 20), (10, 20))
    straddling = ((90, 90), (110, 90), (110, 110), (90, 110))
    assert polygon_fully_inside(fully_in, container)
    assert not polygon_fully_inside(straddling, container)


# ----------------------------------------------------------------- parcels

def test_find_nonresidential_parcels_fixture():
    parcels = load_parcels(FIXTURES / "parcels.json")
    public_land = load_public_land(FIXTURES / "public_land.json")
    eligible = find_nonresidential_parcels(parcels, public_land)
    chibans = {p.chiban for p in eligible}
    assert chibans == {"サンプル町一丁目45番", "サンプル町一丁目46番"}
    # outside parcel and boundary-straddling parcel must NOT be eligible
    assert "サンプル町二丁目10番" not in chibans
    assert "サンプル町一丁目50番" not in chibans


# ------------------------------------------------------------------- towns

def test_fictional_town_never_collides_with_real_master():
    real_towns = load_real_town_names(FIXTURES / "abr_towns.csv")
    import random
    rng = random.Random("town-seed")
    for _ in range(50):
        name = generate_fictional_town_name(rng, real_towns)
        assert not is_real_town(name, real_towns)


# ------------------------------------------------------------- end-to-end

def _base_cfg(tmp_path: Path, seed: str, **overrides) -> DiluteConfig:
    defaults = dict(
        parcels_path=FIXTURES / "parcels.json",
        public_land_path=FIXTURES / "public_land.json",
        abr_towns_path=FIXTURES / "abr_towns.csv",
        zipcode_path=FIXTURES / "zipcodes.csv",
        seed=seed,
        count=30,
        layer="both",
        email_mode="omit",
        email_domain=None,
        fallback_zip="0000000",
        out_dir=tmp_path / "out",
    )
    defaults.update(overrides)
    return DiluteConfig(**defaults)


def test_generate_no_marker_on_records(tmp_path):
    records_path, _ = run(_base_cfg(tmp_path, seed="seedA"))
    with records_path.open(encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        fieldnames = set(reader.fieldnames)
        rows = list(reader)
    # exactly the plain PII fields — nothing that tags a row as a dummy
    assert fieldnames == {"surname", "given_name", "gender", "age",
                           "postal_code", "address", "phone", "email"}
    assert len(rows) == 30


def test_generate_all_layer2_addresses_passed_check(tmp_path):
    records_path, _ = run(_base_cfg(tmp_path, seed="seedA", layer="real-nonresidential"))
    eligible = {"サンプル町一丁目45番", "サンプル町一丁目46番"}
    with records_path.open(encoding="utf-8", newline="") as f:
        rows = list(csv.DictReader(f))
    assert rows
    for row in rows:
        assert any(row["address"].startswith(chiban) for chiban in eligible), row["address"]


def test_ledger_identifies_every_dummy(tmp_path):
    records_path, ledger_path = run(_base_cfg(tmp_path, seed="seedA"))
    with records_path.open(encoding="utf-8", newline="") as f:
        rows = list(csv.DictReader(f))
    ledger_hmacs = frozenset(
        json.loads(line)["record_hmac"]
        for line in ledger_path.read_text(encoding="utf-8").splitlines()
    )
    assert len(ledger_hmacs) == len(rows)
    for row in rows:
        assert ledger_mod.is_dummy(row, "seedA", ledger_hmacs)
    # a record that was never generated must not match
    fake = dict(rows[0])
    fake["given_name"] = fake["given_name"] + "_not_a_real_dummy"
    assert not ledger_mod.is_dummy(fake, "seedA", ledger_hmacs)


def test_different_seed_changes_output(tmp_path):
    records_a, _ = run(_base_cfg(tmp_path, seed="seedA", out_dir=tmp_path / "a"))
    records_b, _ = run(_base_cfg(tmp_path, seed="seedB", out_dir=tmp_path / "b"))
    assert records_a.read_text(encoding="utf-8") != records_b.read_text(encoding="utf-8")


def test_same_seed_is_reproducible(tmp_path):
    records_a, _ = run(_base_cfg(tmp_path, seed="seedA", out_dir=tmp_path / "a"))
    records_c, _ = run(_base_cfg(tmp_path, seed="seedA", out_dir=tmp_path / "c"))
    assert records_a.read_text(encoding="utf-8") == records_c.read_text(encoding="utf-8")


def test_fail_closed_when_no_eligible_parcel(tmp_path):
    empty_land = tmp_path / "empty_public_land.json"
    empty_land.write_text(json.dumps({"polygons": []}), encoding="utf-8")
    cfg = _base_cfg(tmp_path, seed="seedA", layer="real-nonresidential",
                     public_land_path=empty_land)
    with pytest.raises(_ZeeError):
        run(cfg)


def test_email_user_domain_requires_domain(tmp_path):
    cfg = _base_cfg(tmp_path, seed="seedA", email_mode="user-domain", email_domain=None)
    with pytest.raises(_ZeeError):
        run(cfg)


def test_email_user_domain_produces_addressable_email(tmp_path):
    records_path, _ = run(_base_cfg(
        tmp_path, seed="seedA", email_mode="user-domain", email_domain="example-operator.test",
    ))
    with records_path.open(encoding="utf-8", newline="") as f:
        rows = list(csv.DictReader(f))
    assert all(row["email"].endswith("@example-operator.test") for row in rows)
