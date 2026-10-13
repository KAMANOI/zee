"""Tests for zee.dilution — decoy PII value-dilution generator.

Covers the task's four acceptance checks:
1. every layer-2 (real-nonresidential) address uses a chiban that passed
   the non-residential (fully-inside-public-land) check
2. the ledger lets every dummy be recognized by re-hashing its own fields
3. the output record itself carries no marker distinguishing it as a dummy
4. changing the seed changes the output

Plus regression coverage for the independent-review findings (both the
in-house 4-persona review and an external Codex pass flagged the same
geometry defect independently): concave (non-convex) containers must not
pass vertex-only containment, CRS mismatches must be rejected, an
un-mastered town must not qualify a parcel, and a reused/weak seed or a
clobbered output directory must fail closed.
"""

from __future__ import annotations

import csv
import json
import random
from pathlib import Path

import pytest

from zee.dilution import ledger as ledger_mod
from zee.dilution.generate import DiluteConfig, run
from zee.dilution.geometry import point_in_polygon, polygon_fully_inside
from zee.dilution.parcels import find_nonresidential_parcels, load_parcels, load_public_land
from zee.dilution.postal import load_zip_by_town, zip_for_town
from zee.dilution.towns import generate_fictional_town_name, is_real_town, load_real_town_names
from zee.errors import ZeeError

FIXTURES = Path(__file__).parent / "fixtures" / "dilution"
SEED_A = "seedA-0123456789abcdef"
SEED_B = "seedB-0123456789abcdef"


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


def test_polygon_fully_inside_rejects_concave_escape():
    """Independent-review regression (both Codex and the in-house 4-persona
    review reproduced this): a U-shaped (concave) container where every
    candidate vertex sits inside, but an edge cuts through the notch and
    exits the container in between vertices. Vertex-only containment
    wrongly passed this; the edge-intersection check must reject it."""
    u_shape = (
        (0, 0), (100, 0), (100, 100), (70, 100), (70, 30),
        (30, 30), (30, 100), (0, 100),
    )
    # both endpoints sit in the two "arms" of the U; the segment between
    # them cuts straight across the notch, outside the container.
    bridges_the_notch = ((10, 90), (90, 90))
    assert not polygon_fully_inside(bridges_the_notch, u_shape)


def test_polygon_fully_inside_rejects_degenerate():
    container = ((0, 0), (100, 0), (100, 100), (0, 100))
    assert not polygon_fully_inside((), container)
    assert not polygon_fully_inside(((10, 10), (20, 20)), container)  # 2 points


# ----------------------------------------------------------------- parcels

def _load_fixture_real_towns():
    return load_real_town_names(FIXTURES / "abr_towns.csv")


def test_find_nonresidential_parcels_fixture():
    parcels, parcels_crs = load_parcels(FIXTURES / "parcels.json")
    public_land, land_crs = load_public_land(FIXTURES / "public_land.json")
    real_towns = _load_fixture_real_towns()
    eligible = find_nonresidential_parcels(parcels, parcels_crs, public_land, land_crs, real_towns)
    chibans = {p.chiban for p in eligible}
    assert chibans == {"サンプル町一丁目45番", "サンプル町一丁目46番"}
    # outside parcel and boundary-straddling parcel must NOT be eligible
    assert "サンプル町二丁目10番" not in chibans
    assert "サンプル町一丁目50番" not in chibans


def test_find_nonresidential_parcels_rejects_crs_mismatch():
    parcels, _ = load_parcels(FIXTURES / "parcels.json")
    public_land, _ = load_public_land(FIXTURES / "public_land.json")
    real_towns = _load_fixture_real_towns()
    with pytest.raises(ZeeError):
        find_nonresidential_parcels(parcels, "crs-A", public_land, "crs-B", real_towns)


def test_find_nonresidential_parcels_rejects_untrusted_town(tmp_path):
    parcels, crs = load_parcels(FIXTURES / "parcels.json")
    public_land, land_crs = load_public_land(FIXTURES / "public_land.json")
    # a town master that doesn't recognize サンプル町一丁目 at all
    other_towns_path = tmp_path / "other_towns.csv"
    other_towns_path.write_text("別の町一丁目\n", encoding="utf-8")
    real_towns = load_real_town_names(other_towns_path)
    eligible = find_nonresidential_parcels(parcels, crs, public_land, land_crs, real_towns)
    assert eligible == []


def test_load_public_land_ignores_unrecognized_kind(tmp_path):
    bad = tmp_path / "public_land_bad_kind.json"
    bad.write_text(json.dumps({
        "crs": "fixture-local-grid-v1",
        "polygons": [
            {"kind": "parking_lot", "vertices": [[0, 0], [100, 0], [100, 100], [0, 100]]},
        ],
    }), encoding="utf-8")
    polys, _ = load_public_land(bad)
    assert polys == []  # parking lots are explicitly out of scope (design doc §2)


# ------------------------------------------------------------------- towns

def test_fictional_town_never_collides_with_real_master():
    real_towns = _load_fixture_real_towns()
    rng = random.Random("town-seed")
    for _ in range(50):
        name = generate_fictional_town_name(rng, real_towns)
        assert not is_real_town(name, real_towns)


def test_unmatched_town_gets_a_real_zip_not_a_constant_placeholder():
    """Regression (advisor-caught, post-review): a fixed fallback zip
    (e.g. "0000000") on every unmatched town is itself a value-level tell
    — every Layer-1 row would carry an identical, obviously-fake zip,
    greppable without the ledger. Must draw a real zip from the dataset."""
    zip_by_town = load_zip_by_town(FIXTURES / "zipcodes.csv")
    rng = random.Random("zip-fallback-seed")
    seen = {zip_for_town(rng, "架空台一丁目", zip_by_town, "0000000") for _ in range(20)}
    assert "0000000" not in seen
    assert seen <= set(zip_by_town.values())


def test_empty_town_master_is_rejected(tmp_path):
    empty = tmp_path / "empty_towns.csv"
    empty.write_text("", encoding="utf-8")
    with pytest.raises(ZeeError):
        load_real_town_names(empty)


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
    records_path, _ = run(_base_cfg(tmp_path, seed=SEED_A))
    with records_path.open(encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        fieldnames = set(reader.fieldnames)
        rows = list(reader)
    # exactly the plain PII fields — nothing that tags a row as a dummy
    assert fieldnames == {"surname", "given_name", "gender", "age",
                           "postal_code", "address", "phone", "email"}
    assert len(rows) == 30
    assert all(row["postal_code"] != "0000000" for row in rows)


def test_generate_all_layer2_addresses_passed_check(tmp_path):
    records_path, _ = run(_base_cfg(tmp_path, seed=SEED_A, layer="real-nonresidential"))
    eligible = {"サンプル町一丁目45番", "サンプル町一丁目46番"}
    with records_path.open(encoding="utf-8", newline="") as f:
        rows = list(csv.DictReader(f))
    assert rows
    for row in rows:
        assert any(row["address"].startswith(chiban) for chiban in eligible), row["address"]


def test_ledger_identifies_every_dummy(tmp_path):
    records_path, ledger_path = run(_base_cfg(tmp_path, seed=SEED_A))
    with records_path.open(encoding="utf-8", newline="") as f:
        rows = list(csv.DictReader(f))
    ledger_hmacs = ledger_mod.load_ledger_hmacs(ledger_path)
    assert len(ledger_hmacs) == len(rows)
    for row in rows:
        assert ledger_mod.is_dummy(row, SEED_A, ledger_hmacs)
    # a record that was never generated must not match
    fake = dict(rows[0])
    fake["given_name"] = fake["given_name"] + "_not_a_real_dummy"
    assert not ledger_mod.is_dummy(fake, SEED_A, ledger_hmacs)


def test_different_seed_changes_output(tmp_path):
    records_a, _ = run(_base_cfg(tmp_path, seed=SEED_A, out_dir=tmp_path / "a"))
    records_b, _ = run(_base_cfg(tmp_path, seed=SEED_B, out_dir=tmp_path / "b"))
    assert records_a.read_text(encoding="utf-8") != records_b.read_text(encoding="utf-8")


def test_same_seed_is_reproducible(tmp_path):
    records_a, _ = run(_base_cfg(tmp_path, seed=SEED_A, out_dir=tmp_path / "a"))
    records_c, _ = run(_base_cfg(tmp_path, seed=SEED_A, out_dir=tmp_path / "c"))
    assert records_a.read_text(encoding="utf-8") == records_c.read_text(encoding="utf-8")


def test_same_seed_is_reproducible_with_user_domain_email(tmp_path):
    """Regression: the email token used to be a fresh secrets.token_hex()
    per run, which silently broke reproducibility under --email-mode
    user-domain (independent-review finding)."""
    kwargs = dict(email_mode="user-domain", email_domain="example-operator.test")
    records_a, _ = run(_base_cfg(tmp_path, seed=SEED_A, out_dir=tmp_path / "a", **kwargs))
    records_c, _ = run(_base_cfg(tmp_path, seed=SEED_A, out_dir=tmp_path / "c", **kwargs))
    assert records_a.read_text(encoding="utf-8") == records_c.read_text(encoding="utf-8")


def test_fail_closed_when_no_eligible_parcel(tmp_path):
    empty_land = tmp_path / "empty_public_land.json"
    empty_land.write_text(json.dumps({"crs": "fixture-local-grid-v1", "polygons": []}),
                           encoding="utf-8")
    cfg = _base_cfg(tmp_path, seed=SEED_A, layer="real-nonresidential",
                     public_land_path=empty_land)
    with pytest.raises(ZeeError):
        run(cfg)


def test_email_user_domain_requires_domain(tmp_path):
    cfg = _base_cfg(tmp_path, seed=SEED_A, email_mode="user-domain", email_domain=None)
    with pytest.raises(ZeeError):
        run(cfg)


def test_email_user_domain_produces_addressable_email(tmp_path):
    records_path, _ = run(_base_cfg(
        tmp_path, seed=SEED_A, email_mode="user-domain", email_domain="example-operator.test",
    ))
    with records_path.open(encoding="utf-8", newline="") as f:
        rows = list(csv.DictReader(f))
    assert all(row["email"].endswith("@example-operator.test") for row in rows)


def test_email_ledger_leak_alone_does_not_identify_row(tmp_path):
    """Regression: the email token must not reuse any id that also lives
    in the ledger — otherwise a leaked ledger alone (no seed needed)
    could match an email straight back to its row."""
    records_path, ledger_path = run(_base_cfg(
        tmp_path, seed=SEED_A, email_mode="user-domain", email_domain="example-operator.test",
    ))
    with records_path.open(encoding="utf-8", newline="") as f:
        rows = list(csv.DictReader(f))
    ledger_lines = ledger_path.read_text(encoding="utf-8").splitlines()
    ledger_hmacs = {json.loads(line)["record_hmac"] for line in ledger_lines}
    for row in rows:
        local_part = row["email"].split("@")[0]
        assert local_part not in ledger_hmacs
        assert "record_hmac" not in local_part


def test_weak_seed_rejected(tmp_path):
    with pytest.raises(ZeeError):
        run(_base_cfg(tmp_path, seed="short"))


def test_invalid_count_rejected(tmp_path):
    with pytest.raises(ZeeError):
        run(_base_cfg(tmp_path, seed=SEED_A, count=0))
    with pytest.raises(ZeeError):
        run(_base_cfg(tmp_path, seed=SEED_A, count=-5))


def test_address_pool_exhaustion_fails_closed_instead_of_duplicating(tmp_path):
    """Only 2 eligible parcels + a handful of building/room combos — asking
    for far more unique layer-2 addresses than the pool can produce must
    fail rather than silently write two different people at one address."""
    cfg = _base_cfg(tmp_path, seed=SEED_A, layer="real-nonresidential", count=5000)
    with pytest.raises(ZeeError):
        run(cfg)


def test_refuses_to_overwrite_existing_output(tmp_path):
    cfg = _base_cfg(tmp_path, seed=SEED_A)
    run(cfg)
    with pytest.raises(ZeeError):
        run(cfg)  # same out_dir, already has records.csv/ledger.jsonl
