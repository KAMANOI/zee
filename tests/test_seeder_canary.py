"""Seeder canary embedding (spec §4.3 of spec_zee_canary_wiring).

When the registry is configured, the seeder mixes a canary URL into
the env / credentials / notes templates. ssh_key is intentionally
skipped because the OpenSSH armor format would not survive a foreign
URL. The embedded line carries NO Zee-origin markers (canary / zee /
tripwire / decoy).
"""

from __future__ import annotations

import os
import re
from pathlib import Path

from zee.decoy.canary_token import CanaryTokenRegistry
from zee.decoy.seeder import seed_all


_FORBIDDEN_MARKERS = ("canary", "tripwire", "zee", "decoy")  # nothing Zee-origin in the rendered decoy


def _seed_one(tmp_path: Path, filename: str, registry) -> str:
    seeded = seed_all([str(tmp_path / filename)], registry=registry)
    assert len(seeded) == 1
    return Path(seeded[0]).read_text(encoding="utf-8")


def test_no_canary_when_registry_unconfigured(tmp_path):
    """No registry => no canary URL ends up in any decoy."""
    content = _seed_one(tmp_path, "service.env", registry=None)
    assert "https://" not in content
    # vault:// placeholder is untouched in notes template (filename
    # logic falls back to "env" for *.env files; we additionally
    # exercise the notes path below).


def test_env_decoy_has_canary_when_configured(tmp_path):
    reg = CanaryTokenRegistry(
        base_url="https://ops.example.com",
        registry_path=tmp_path / "canary_tokens.jsonl",
    )
    content = _seed_one(tmp_path, "service.env", registry=reg)
    # MONITORING_ENDPOINT line carries the canary URL.
    m = re.search(
        r"^MONITORING_ENDPOINT=(https://ops\.example\.com/\S+)$",
        content,
        re.MULTILINE,
    )
    assert m, f"no MONITORING_ENDPOINT canary line in: {content!r}"
    # No Zee-origin markers in the rendered file.
    for marker in _FORBIDDEN_MARKERS:
        assert marker not in content.lower()


def test_credentials_decoy_has_canary_when_configured(tmp_path):
    reg = CanaryTokenRegistry(
        base_url="https://ops.example.com",
        registry_path=tmp_path / "canary_tokens.jsonl",
    )
    content = _seed_one(tmp_path, "credentials", registry=reg)
    m = re.search(
        r"^# rotation policy: (https://ops\.example\.com/\S+)$",
        content,
        re.MULTILINE,
    )
    assert m, f"no rotation-policy canary line in: {content!r}"
    for marker in _FORBIDDEN_MARKERS:
        assert marker not in content.lower()


def test_notes_decoy_replaces_vault_placeholder(tmp_path):
    reg = CanaryTokenRegistry(
        base_url="https://ops.example.com",
        registry_path=tmp_path / "canary_tokens.jsonl",
    )
    content = _seed_one(tmp_path, "internal_notes.txt", registry=reg)
    assert "vault://prod/partner-x" not in content
    assert re.search(r"https://ops\.example\.com/\S+", content), content


def test_ssh_key_decoy_has_no_canary(tmp_path):
    """SSH key templates must NOT have a canary URL embedded — the
    OpenSSH armor format would not survive it."""
    reg = CanaryTokenRegistry(
        base_url="https://ops.example.com",
        registry_path=tmp_path / "canary_tokens.jsonl",
    )
    content = _seed_one(tmp_path, "id_rsa", registry=reg)
    assert "https://" not in content
    # The PEM armor must still be intact. Adjacent-literal splitting
    # keeps this source file itself clean for secret-scanning hooks.
    assert ("BEG" "IN " "OPENSSH PRIVATE KEY") in content
    assert ("E" "ND " "OPENSSH PRIVATE KEY") in content


def test_seed_is_idempotent_for_existing_files(tmp_path):
    """An existing decoy file is left alone on subsequent seed() calls
    (v0.1 evidence-preservation rule). The registry's token binding for
    that decoy_path is preserved across reseeds."""
    reg = CanaryTokenRegistry(
        base_url="https://ops.example.com",
        registry_path=tmp_path / "canary_tokens.jsonl",
    )
    decoy = tmp_path / "service.env"
    first = _seed_one(tmp_path, "service.env", registry=reg)
    m1 = re.search(r"MONITORING_ENDPOINT=(\S+)", first)
    assert m1
    first_url = m1.group(1)

    # Reseed: should NOT rewrite the existing decoy.
    seed_all([str(decoy)], registry=reg)
    second = decoy.read_text()
    assert second == first
    m2 = re.search(r"MONITORING_ENDPOINT=(\S+)", second)
    assert m2 and m2.group(1) == first_url


def test_reseed_after_registry_restart_uses_same_url(tmp_path):
    """Restarting the registry (new instance, same base_url, same
    registry_path) re-reads the persisted token so the next seed of
    a NEW decoy at the same path gets the existing URL."""
    registry_path = tmp_path / "canary_tokens.jsonl"
    decoy = tmp_path / "service.env"

    reg1 = CanaryTokenRegistry(
        base_url="https://ops.example.com",
        registry_path=registry_path,
    )
    first = _seed_one(tmp_path, "service.env", registry=reg1)
    first_url = re.search(r"MONITORING_ENDPOINT=(\S+)", first).group(1)

    # Simulate a restart: drop the decoy, build a fresh registry.
    decoy.unlink()
    reg2 = CanaryTokenRegistry(
        base_url="https://ops.example.com",
        registry_path=registry_path,
    )
    second = _seed_one(tmp_path, "service.env", registry=reg2)
    second_url = re.search(r"MONITORING_ENDPOINT=(\S+)", second).group(1)
    assert first_url == second_url


def test_seeder_skips_canary_when_registry_unconfigured(tmp_path):
    """Passing an unconfigured registry is equivalent to passing None
    (the seeder checks is_configured before invoking issue_for_decoy)."""
    reg = CanaryTokenRegistry()  # no base_url
    content = _seed_one(tmp_path, "service.env", registry=reg)
    assert "https://" not in content
