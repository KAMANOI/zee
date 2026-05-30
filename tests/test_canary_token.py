"""Canary token registry behavior (spec §9 fallback)."""

from __future__ import annotations

from zee.decoy.canary_token import CanaryTokenRegistry


def test_unconfigured_registry_emits_safe_placeholder_url():
    reg = CanaryTokenRegistry()
    assert reg.is_configured is False
    tok = reg.issue("decoy_env")
    assert tok.full_url.startswith("about:zee/c/")
    assert tok.token_id and len(tok.token_id) >= 16


def test_configured_registry_emits_real_url():
    reg = CanaryTokenRegistry(base_url="https://canary.example.com")
    assert reg.is_configured is True
    tok = reg.issue("decoy_aws_key")
    assert tok.full_url.startswith("https://canary.example.com/c/")
    assert tok.purpose == "decoy_aws_key"
    assert reg.lookup(tok.token_id) is tok


def test_all_tokens_returns_registry_snapshot():
    reg = CanaryTokenRegistry(base_url="https://canary.example.com/")
    t1 = reg.issue("decoy_env")
    t2 = reg.issue("decoy_ssh")
    assert {t.token_id for t in reg.all_tokens()} == {t1.token_id, t2.token_id}
