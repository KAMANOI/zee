"""responder/permission.py — auto-containment permission state + host locks.

The module is landed unwired: nothing in sequence.py / cli.py reads it yet.
These tests pin the state contract (fail-closed decoding, private files,
instance binding) and the lock primitives that egress approval reuses.
"""
from __future__ import annotations

import os
import stat
import sys
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path

import pytest

from zee.config.schema import AssetProfile, Config
from zee.events import TrapEvent
from zee.responder import permission as P

posix_only = pytest.mark.skipif(sys.platform == "win32", reason="POSIX mode bits")


def _asset(mode="auto", method="egress", aid="a1"):
    return AssetProfile(id=aid, type="workstation", overnight_active=False,
                        decoy_paths=("/tmp/d",), response_mode=mode, cut_method=method)


def _event(confidence="high", op_class="change"):
    return TrapEvent.make(source="behavior_anomaly" if confidence != "high" else "decoy_touch",
                          confidence=confidence, asset_id="a1", decoy_path=None,
                          detail="t", op_class=op_class)


def _perm(d: Path, config: Config, enabled=True, revision=1) -> P.Permission:
    return P.Permission(schema_version=1, enabled=enabled, revision=revision,
                        instance_id=P.instance_id(d), policy_hash=P.policy_hash(config),
                        disclosure_version=P.DISCLOSURE_VERSION, changed_by="test",
                        changed_at=datetime.now(timezone.utc))


@pytest.fixture
def state(tmp_path):
    d = (tmp_path / "zee").resolve()
    return d, d / "auto_containment.json"


def test_missing_state_is_none_not_permission(state):
    _, f = state
    assert P.load(f) is None


def test_save_load_roundtrip_and_private_modes(state):
    d, f = state
    cfg = Config(assets=(_asset(),), dry_run=False)
    perm = _perm(d, cfg)
    P.save(perm, f)
    assert P.load(f) == perm
    assert not list(d.glob(".*.tmp"))  # temp file published, not left behind
    if sys.platform != "win32":
        assert stat.S_IMODE(f.stat().st_mode) == 0o600
        assert stat.S_IMODE(d.stat().st_mode) == 0o700


@pytest.mark.parametrize("field,value", [
    ("enabled", "true"), ("enabled", 1), ("revision", 0), ("revision", True),
    ("schema_version", 2), ("policy_hash", "x" * 64), ("disclosure_version", "0"),
    ("changed_at", "2026-10-11T00:00:00"),  # naive timestamp
])
def test_malformed_state_is_invalid_never_permission(state, field, value):
    d, f = state
    cfg = Config(assets=(_asset(),), dry_run=False)
    P.save(_perm(d, cfg), f)
    import json
    raw = json.loads(f.read_text())
    raw[field] = value
    f.write_text(json.dumps(raw))
    os.chmod(f, 0o600)
    assert isinstance(P.load(f), P.Invalid)


def test_garbage_json_is_invalid(state):
    d, f = state
    P.private_directory(d)
    f.write_text("{not json")
    os.chmod(f, 0o600)
    assert isinstance(P.load(f), P.Invalid)


@posix_only
def test_loose_file_mode_is_invalid(state):
    d, f = state
    P.save(_perm(d, Config(assets=(_asset(),), dry_run=False)), f)
    os.chmod(f, 0o644)
    assert isinstance(P.load(f), P.Invalid)


def test_state_copied_to_another_directory_is_invalid(tmp_path, state):
    d, f = state
    P.save(_perm(d, Config(assets=(_asset(),), dry_run=False)), f)
    other = (tmp_path / "other").resolve()
    P.private_directory(other)
    (other / f.name).write_bytes(f.read_bytes())
    os.chmod(other / f.name, 0o600)
    assert P.load(other / f.name) == P.Invalid("instance_id / state directory mismatch")


def test_save_refuses_foreign_instance(tmp_path, state):
    d, f = state
    perm = _perm((tmp_path / "elsewhere").resolve(), Config(assets=(_asset(),), dry_run=False))
    with pytest.raises(ValueError):
        P.save(perm, f)
    assert not f.exists()


@posix_only
def test_symlinked_state_file_refused(tmp_path, state):
    d, f = state
    P.private_directory(d)
    target = tmp_path / "victim"
    target.write_text("keep")
    f.symlink_to(target)
    assert isinstance(P.load(f), P.Invalid)
    with pytest.raises(ValueError):
        P.save(_perm(d, Config(assets=(_asset(),), dry_run=False)), f)
    assert target.read_text() == "keep"


def test_policy_hash_tracks_auto_assets_only():
    base = Config(assets=(_asset(), _asset(mode="notify", aid="n1")), dry_run=False)
    assert P.policy_hash(base) == P.policy_hash(replace(base, dry_run=True))  # dry_run excluded
    assert P.policy_hash(base) == P.policy_hash(Config(assets=(_asset(),), dry_run=False))
    assert P.policy_hash(base) != P.policy_hash(Config(assets=(_asset(method="full"),), dry_run=False))
    assert P.policy_hash(base) != P.policy_hash(
        Config(assets=(_asset(), _asset(aid="a2")), dry_run=False))


def test_decide_truth_table(state):
    d, _ = state
    cfg = Config(assets=(_asset(),), dry_run=False)
    ok = _perm(d, cfg)
    a = _asset()
    assert P.decide(_event(), a, cfg, ok) == (True, None)
    assert P.decide(_event(), _asset(mode="notify"), cfg, ok) == (False, "mode_not_contain")
    assert P.decide(_event(), _asset(mode="staged"), cfg, ok) == (False, "mode_not_contain")
    assert P.decide(_event(confidence="medium"), a, cfg, ok) == (False, "confidence_not_high")
    assert P.decide(_event(op_class="read"), a, cfg, ok) == (False, "op_class_not_change")
    assert P.decide(_event(), a, replace(cfg, dry_run=True), ok) == (False, "dry_run")
    assert P.decide(_event(), a, cfg, None) == (False, "no_permission")
    assert P.decide(_event(), a, cfg, P.Invalid("x")) == (False, "state_invalid")
    assert P.decide(_event(), a, cfg, replace(ok, enabled=False)) == (False, "auto_off")
    changed = Config(assets=(_asset(method="full"),), dry_run=False)
    assert P.decide(_event(), a, changed, ok) == (False, "policy_mismatch")


def test_host_lock_is_exclusive_and_reusable(tmp_path):
    lock = tmp_path / "s" / "host.lock"
    with P.HostLock(lock):
        with pytest.raises(TimeoutError):
            with P.HostLock(lock, timeout=0.05):
                pass
    with P.HostLock(lock, timeout=0.05):  # released after exit
        pass
    assert lock.exists()  # never unlinked


def test_watch_running_three_states(tmp_path):
    d = tmp_path / "s"
    assert P.watch_running(d) is False and not d.exists()  # probe creates nothing
    with P.HostLock(d / "watch.lock"):
        assert P.watch_running(d) is True
    assert P.watch_running(d) is False


def test_deeply_nested_json_is_invalid_not_raised(state):
    d, f = state
    P.private_directory(d)
    f.write_text("[" * 100_000)
    os.chmod(f, 0o600)
    assert isinstance(P.load(f), P.Invalid)


def test_policy_hash_includes_firing_condition():
    a = Config(assets=(_asset(),), dry_run=False)
    b = Config(assets=(replace(_asset(), decoy_paths=("/tmp/other",)),), dry_run=False)
    assert P.policy_hash(a) != P.policy_hash(b)


@posix_only
def test_symlinked_parent_layout_is_followed(tmp_path):
    real = tmp_path / "real"
    real.mkdir()
    (tmp_path / "link").symlink_to(real)  # e.g. /tmp -> /private/tmp
    d = tmp_path / "link" / "zee"         # not resolved on purpose
    cfg = Config(assets=(_asset(),), dry_run=False)
    perm = _perm(d, cfg)
    P.save(perm, d / "auto_containment.json")
    assert P.load(d / "auto_containment.json") == perm
    with P.HostLock(d / "host.lock"):
        pass


@posix_only
def test_symlinked_state_directory_refused(tmp_path):
    real = tmp_path / "real"
    real.mkdir()
    (tmp_path / "zee").symlink_to(real)
    with pytest.raises(ValueError):
        P.save(_perm(tmp_path / "zee", Config(assets=(_asset(),), dry_run=False)),
               tmp_path / "zee" / "auto_containment.json")
    assert isinstance(P.load(tmp_path / "zee" / "auto_containment.json"), P.Invalid)


@posix_only
def test_watch_running_unknown_when_lock_unreadable(tmp_path):
    d = tmp_path / "s"
    with P.HostLock(d / "watch.lock"):
        pass
    os.chmod(d / "watch.lock", 0)
    try:
        assert P.watch_running(d) is None
    finally:
        os.chmod(d / "watch.lock", 0o600)
