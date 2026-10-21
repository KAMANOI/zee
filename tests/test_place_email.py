"""End-to-end with fake data only: issue -> table -> simulated breach
result -> leaked place. No network, no real domain (example.test)."""

import json
import stat
import sys

import pytest

from zee.decoy.canary_token import CanaryTokenRegistry
from zee.decoy.place_email import FREE_TIER_MAX_ADDRESSES, issue_place_email, locate

posix_only = pytest.mark.skipif(sys.platform == "win32", reason="POSIX modes")

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
    hits, unknown = locate(_reg(tmp_path), DOMAIN, {alias.upper(): ["FakeBreach2026"], "alice": ["Other"]})
    assert [(h.place, h.breaches) for h in hits] == [("nightly-backup", ("FakeBreach2026",))]
    assert unknown == ["alice"]


@posix_only
def test_no_hit_and_table_is_private(tmp_path):
    reg = _reg(tmp_path)
    issue_place_email(reg, DOMAIN, "prod-db-dump")
    assert locate(reg, DOMAIN, {}) == ([], [])
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


def test_domain_is_bound_and_checked(tmp_path):
    reg = _reg(tmp_path)
    a = issue_place_email(reg, DOMAIN, "prod-db-dump")
    with pytest.raises(ValueError):
        issue_place_email(reg, "other.example.test", "prod-db-dump")
    with pytest.raises(ValueError):
        issue_place_email(reg, "hdr-mail.example.test", "prod-db-dump")  # checked even if issued
    alias = a.split("@")[0]
    assert locate(reg, "other.example.test", {alias: ["X"]}) == ([], [alias])


def test_concurrent_issue_keeps_cap_and_idempotence(tmp_path):
    import threading

    errs, got = [], []

    def run(i):
        try:
            got.append(issue_place_email(_reg(tmp_path), DOMAIN, f"p{i % 12}"))
        except ValueError as e:
            errs.append(e)

    ts = [threading.Thread(target=run, args=(i,)) for i in range(24)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    assert len(set(got)) == FREE_TIER_MAX_ADDRESSES  # exactly 10 places, one address each
    assert len(errs) == 4  # the 2 places beyond the cap, asked twice each


@posix_only
def test_corrupt_or_loose_table_stops(tmp_path):
    reg = _reg(tmp_path)
    issue_place_email(reg, DOMAIN, "prod-db-dump")
    f = reg.registry_path
    f.chmod(0o644)
    with pytest.raises(PermissionError):
        locate(reg, DOMAIN, {})
    f.chmod(0o600)
    f.write_text(f.read_text() + "[]\n")
    with pytest.raises(ValueError):
        locate(reg, DOMAIN, {})


def test_module_imports_without_fcntl():
    # finding 1: Windows has no fcntl; the module must import (and lock) without it
    import builtins
    import importlib

    import zee.decoy.place_email as pe
    import zee.responder.permission as perm

    real = builtins.__import__

    def no_fcntl(name, *a, **k):
        if name == "fcntl":
            raise ImportError("no fcntl")
        return real(name, *a, **k)

    builtins.__import__ = no_fcntl
    try:
        importlib.reload(pe)
    finally:
        builtins.__import__ = real
        importlib.reload(pe)
    assert "fcntl" not in pe.__dict__ and pe.HostLock is perm.HostLock


@pytest.mark.parametrize(
    "bad", ["", "   ", "a@example.test", "localhost", "-x.example.test", "a..example.test",
            "x" * 64 + ".test", ".".join(["a" * 63] * 4) + ".test", "ex ample.test"],
)
def test_invalid_domain_is_rejected_before_persisting(tmp_path, bad):
    reg = _reg(tmp_path)
    with pytest.raises(ValueError):
        issue_place_email(reg, bad, "prod-db-dump")
    assert not reg.registry_path.exists()


def _append(reg, alias, purpose):
    with reg.registry_path.open("a") as f:
        f.write(json.dumps({"purpose": purpose, "decoy_path": alias}) + "\n")


@pytest.mark.parametrize("dup", ["alias", "place", "bad-alias", "bad-domain"])
def test_conflicting_or_malformed_mapping_stops(tmp_path, dup):
    reg = _reg(tmp_path)
    a = issue_place_email(reg, DOMAIN, "prod-db-dump").split("@")[0]
    alias, purpose = {
        "alias": (a, f"place:nightly-backup|{DOMAIN}"),     # same alias, other place
        "place": ("f" * 32, f"place:prod-db-dump|{DOMAIN}"),  # second alias for one place
        "bad-alias": ("NOT-A-TOKEN", f"place:other|{DOMAIN}"),
        "bad-domain": ("e" * 32, "place:other|a@b"),
    }[dup]
    _append(reg, alias, purpose)
    with pytest.raises(ValueError):
        locate(reg, DOMAIN, {a: ["X"]})
    with pytest.raises(ValueError):
        issue_place_email(reg, DOMAIN, "support-export")
