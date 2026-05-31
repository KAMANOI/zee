"""Canary token registry behavior (spec §9 fallback)."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from zee.decoy.canary_token import CanaryTokenRegistry


def test_unconfigured_registry_raises_on_issue():
    """v0.2: the about:zee fallback was removed. Unconfigured registries
    must refuse to mint tokens rather than silently emit a fake URL."""
    reg = CanaryTokenRegistry()
    assert reg.is_configured is False
    with pytest.raises(RuntimeError) as exc:
        reg.issue("decoy_env")
    assert "base_url" in str(exc.value)


def test_unconfigured_registry_raises_on_issue_for_decoy():
    reg = CanaryTokenRegistry()
    with pytest.raises(RuntimeError):
        reg.issue_for_decoy("/tmp/decoy", "decoy_env")


def test_configured_registry_emits_real_url(tmp_path):
    reg = CanaryTokenRegistry(
        base_url="https://canary.example.com",
        registry_path=tmp_path / "canary_tokens.jsonl",
    )
    assert reg.is_configured is True
    tok = reg.issue("decoy_aws_key")
    # No "/c/" prefix in v0.2 — operator's base_url path is used verbatim.
    assert tok.full_url == f"https://canary.example.com/{tok.token_id}"
    assert tok.purpose == "decoy_aws_key"
    assert reg.lookup(tok.token_id) is tok


def test_configured_registry_rejects_http(tmp_path):
    with pytest.raises(ValueError) as exc:
        CanaryTokenRegistry(
            base_url="http://insecure.example.com",
            registry_path=tmp_path / "canary_tokens.jsonl",
        )
    assert "https://" in str(exc.value)


def test_all_tokens_returns_registry_snapshot(tmp_path):
    reg = CanaryTokenRegistry(
        base_url="https://canary.example.com/",
        registry_path=tmp_path / "canary_tokens.jsonl",
    )
    t1 = reg.issue("decoy_env")
    t2 = reg.issue("decoy_ssh")
    assert {t.token_id for t in reg.all_tokens()} == {t1.token_id, t2.token_id}


def test_issue_for_decoy_is_idempotent(tmp_path):
    """Reseeding the same decoy_path must return the same token."""
    reg = CanaryTokenRegistry(
        base_url="https://canary.example.com",
        registry_path=tmp_path / "canary_tokens.jsonl",
    )
    decoy = "/tmp/decoy.env"
    t1 = reg.issue_for_decoy(decoy, "decoy_env")
    t2 = reg.issue_for_decoy(decoy, "decoy_env")
    assert t1.token_id == t2.token_id
    assert t1.full_url == t2.full_url


def test_persist_then_rehydrate(tmp_path):
    """Tokens issued via issue_for_decoy persist; a new registry instance
    with the same base_url reloads the (decoy_path -> token) map."""
    registry_path = tmp_path / "canary_tokens.jsonl"
    reg1 = CanaryTokenRegistry(
        base_url="https://canary.example.com",
        registry_path=registry_path,
    )
    decoy = "/tmp/decoy.env"
    t1 = reg1.issue_for_decoy(decoy, "decoy_env")
    assert registry_path.exists()
    # File contains a single JSONL record.
    lines = registry_path.read_text().strip().split("\n")
    assert len(lines) == 1
    rec = json.loads(lines[0])
    assert rec["token_id"] == t1.token_id
    assert rec["decoy_path"] == decoy

    # New registry with the SAME base_url rehydrates the binding.
    reg2 = CanaryTokenRegistry(
        base_url="https://canary.example.com",
        registry_path=registry_path,
    )
    rehydrated = reg2.lookup_for_decoy(decoy)
    assert rehydrated is not None
    assert rehydrated.token_id == t1.token_id
    # Idempotent issue returns the same one.
    t2 = reg2.issue_for_decoy(decoy, "decoy_env")
    assert t2.token_id == t1.token_id


def test_rehydrate_skips_records_with_different_base_url(tmp_path):
    """Records for a previously-used base_url are not loaded under a new one."""
    registry_path = tmp_path / "canary_tokens.jsonl"
    reg_old = CanaryTokenRegistry(
        base_url="https://old.example.com",
        registry_path=registry_path,
    )
    reg_old.issue_for_decoy("/tmp/decoy.env", "decoy_env")

    reg_new = CanaryTokenRegistry(
        base_url="https://new.example.com",
        registry_path=registry_path,
    )
    # The decoy was bound under old.example.com; under new.example.com
    # the registry treats it as not yet bound.
    assert reg_new.lookup_for_decoy("/tmp/decoy.env") is None


def test_registry_file_is_owner_only(tmp_path):
    """canary_tokens.jsonl must be 0600 like events.jsonl / metrics.jsonl."""
    import os
    import stat
    registry_path = tmp_path / "state" / "canary_tokens.jsonl"
    reg = CanaryTokenRegistry(
        base_url="https://canary.example.com",
        registry_path=registry_path,
    )
    reg.issue_for_decoy("/tmp/decoy.env", "decoy_env")
    assert registry_path.exists()
    mode = stat.S_IMODE(os.stat(registry_path).st_mode)
    # Only the owner should have read/write; group/other should have nothing.
    assert mode & (stat.S_IRGRP | stat.S_IWGRP | stat.S_IROTH | stat.S_IWOTH) == 0
