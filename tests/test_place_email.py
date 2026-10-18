"""End-to-end with fake data only: issue -> table -> simulated breach
result -> leaked place. No network, no real domain (example.test)."""

import json
import stat

import pytest

from zee.decoy.canary_token import CanaryTokenRegistry
from zee.decoy.place_email import FREE_TIER_MAX_ADDRESSES, issue_place_email, locate

DOMAIN = "mailbox-sample.example.test"
PLACES = ["prod-db-dump", "nightly-backup", "partner-share", "support-export"]


def _reg(tmp_path):
    return CanaryTokenRegistry(
        base_url="https://canary.example.test", registry_path=tmp_path / "map" / "t.jsonl"
    )


def test_issue_locate_roundtrip(tmp_path):
    reg = _reg(tmp_path)
    addrs = {p: issue_place_email(reg, DOMAIN, p) for p in PLACES}
    assert len(set(addrs.values())) == len(PLACES)  # unique per place
    assert all(a.endswith("@" + DOMAIN) for a in addrs.values())
    assert issue_place_email(reg, DOMAIN, "prod-db-dump") == addrs["prod-db-dump"]  # idempotent
    # the place name never appears in the address itself
    assert not any(p in a for p, a in addrs.items())

    # simulated breach-index result: backup leaked + one stray alias
    alias = addrs["nightly-backup"].split("@")[0]
    # a fresh registry object (restart) must still resolve it
    hits, unknown = locate(_reg(tmp_path), {alias.upper(): ["FakeBreach2026"], "alice": ["Other"]})
    assert [(h.place, h.breaches) for h in hits] == [("nightly-backup", ("FakeBreach2026",))]
    assert unknown == ["alice"]


def test_no_hit_and_table_is_private(tmp_path):
    reg = _reg(tmp_path)
    issue_place_email(reg, DOMAIN, "prod-db-dump")
    assert locate(reg, {}) == ([], [])
    f = reg.registry_path
    assert stat.S_IMODE(f.stat().st_mode) == 0o600
    assert "place:prod-db-dump" in json.loads(f.read_text().splitlines()[0])["purpose"]


def test_guards(tmp_path):
    reg = _reg(tmp_path)
    with pytest.raises(ValueError):
        issue_place_email(reg, "hdr-mail.example.test", "a")  # origin-revealing domain word
    with pytest.raises(ValueError):
        issue_place_email(reg, DOMAIN, "Bad Name!")
    for i in range(FREE_TIER_MAX_ADDRESSES):
        issue_place_email(reg, DOMAIN, f"p{i}")
    with pytest.raises(ValueError):
        issue_place_email(reg, DOMAIN, "one-too-many")
