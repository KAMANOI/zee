"""assets.toml loading and validation (spec §6)."""

from __future__ import annotations

from pathlib import Path

import pytest

from zee.config.schema import Config
from zee.errors import (
    ZeeError,
    Z101_INVALID_ASSET_CONFIG,
    Z103_INVALID_RESPONSE_MODE,
    Z104_INVALID_CUT_METHOD,
)


def _write(tmp_path: Path, content: str) -> Path:
    p = tmp_path / "assets.toml"
    p.write_text(content)
    return p


def test_load_valid(tmp_path):
    cfg_path = _write(tmp_path, """
dry_run = true

[[assets]]
id = "host-a"
type = "workstation"
overnight_active = false
decoy_paths = ["/tmp/decoy1"]
response_mode = "notify"
cut_method = "full"
""")
    cfg = Config.load(cfg_path)
    assert cfg.dry_run is True
    assert len(cfg.assets) == 1
    asset = cfg.assets[0]
    assert asset.id == "host-a"
    assert asset.decoy_paths == ("/tmp/decoy1",)


def test_invalid_response_mode(tmp_path):
    cfg_path = _write(tmp_path, """
[[assets]]
id = "host-a"
type = "workstation"
response_mode = "nuke"
""")
    with pytest.raises(ZeeError) as exc:
        Config.load(cfg_path)
    assert exc.value.code == Z103_INVALID_RESPONSE_MODE[0]


def test_invalid_cut_method(tmp_path):
    cfg_path = _write(tmp_path, """
[[assets]]
id = "host-a"
type = "workstation"
response_mode = "auto"
cut_method = "nuke"
""")
    with pytest.raises(ZeeError) as exc:
        Config.load(cfg_path)
    assert exc.value.code == Z104_INVALID_CUT_METHOD[0]


def test_malformed_toml(tmp_path):
    cfg_path = _write(tmp_path, "this is = not = valid = toml")
    with pytest.raises(ZeeError) as exc:
        Config.load(cfg_path)
    assert exc.value.code == Z101_INVALID_ASSET_CONFIG[0]


def test_dry_run_defaults_true(tmp_path):
    cfg_path = _write(tmp_path, """
[[assets]]
id = "host-a"
type = "workstation"
response_mode = "notify"
""")
    cfg = Config.load(cfg_path)
    assert cfg.dry_run is True


def test_find_returns_asset_or_none(tmp_path):
    cfg_path = _write(tmp_path, """
[[assets]]
id = "host-a"
type = "workstation"
response_mode = "notify"
""")
    cfg = Config.load(cfg_path)
    assert cfg.find("host-a").id == "host-a"
    assert cfg.find("nope") is None
