"""Restore-token authentication (spec L3, v0.3)."""

from __future__ import annotations

import os
import stat

from zee.recovery.auth import init_token, load_token, verify_token


def test_init_creates_owner_only_file(tmp_path):
    p = tmp_path / "restore_token"
    token = init_token(path=p)
    assert isinstance(token, str) and len(token) >= 32
    assert p.exists()
    mode = stat.S_IMODE(os.stat(p).st_mode)
    assert mode & (stat.S_IRGRP | stat.S_IWGRP | stat.S_IROTH | stat.S_IWOTH) == 0


def test_load_token_returns_what_was_written(tmp_path):
    p = tmp_path / "restore_token"
    token = init_token(path=p)
    assert load_token(path=p) == token


def test_load_token_missing_returns_none(tmp_path):
    assert load_token(path=tmp_path / "absent") is None


def test_load_token_refuses_loose_permissions(tmp_path):
    p = tmp_path / "restore_token"
    init_token(path=p)
    # Loosen perms to mimic an attacker / sloppy operator.
    os.chmod(p, 0o644)
    assert load_token(path=p) is None


def test_verify_token_matches_correct(tmp_path):
    p = tmp_path / "restore_token"
    token = init_token(path=p)
    assert verify_token(token, path=p) is True


def test_verify_token_rejects_wrong(tmp_path):
    p = tmp_path / "restore_token"
    init_token(path=p)
    assert verify_token("wrong-token", path=p) is False


def test_verify_token_when_not_initialised(tmp_path):
    assert verify_token("anything", path=tmp_path / "absent") is False


def test_token_is_high_entropy(tmp_path):
    """Generated tokens must be at least 32 url-safe chars (≈ 192 bits)."""
    p = tmp_path / "restore_token"
    token = init_token(path=p)
    # secrets.token_urlsafe(32) gives ~43 chars
    assert len(token) >= 32


def test_init_rotates_existing_token(tmp_path):
    p = tmp_path / "restore_token"
    t1 = init_token(path=p)
    t2 = init_token(path=p)
    assert t1 != t2
    assert load_token(path=p) == t2
