"""assets.yaml schema and loader (spec §6)."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Literal, Optional

import yaml

from ..errors import (
    ZeeError,
    Z101_INVALID_ASSET_YAML,
    Z103_INVALID_RESPONSE_MODE,
    Z104_INVALID_CUT_METHOD,
)

AssetType = Literal["workstation", "server", "ot"]
ResponseMode = Literal["auto", "staged", "notify"]
CutMethod = Literal["full", "egress"]

_VALID_RESPONSE_MODES = ("auto", "staged", "notify")
_VALID_CUT_METHODS = ("full", "egress")
_VALID_ASSET_TYPES = ("workstation", "server", "ot")


@dataclass(frozen=True)
class AssetProfile:
    id: str
    type: AssetType
    overnight_active: bool
    decoy_paths: tuple[str, ...]
    response_mode: ResponseMode
    cut_method: CutMethod


@dataclass(frozen=True)
class Config:
    assets: tuple[AssetProfile, ...]
    dry_run: bool = True  # spec §2: 既定は dry_run

    @classmethod
    def load(cls, path: Path) -> "Config":
        try:
            with path.open("r", encoding="utf-8") as f:
                raw = yaml.safe_load(f) or {}
        except (OSError, yaml.YAMLError) as e:
            raise ZeeError(Z101_INVALID_ASSET_YAML, str(e)) from e

        if not isinstance(raw, dict):
            raise ZeeError(Z101_INVALID_ASSET_YAML, "top level must be a mapping")

        raw_assets = raw.get("assets", [])
        if not isinstance(raw_assets, list):
            raise ZeeError(Z101_INVALID_ASSET_YAML, "'assets' must be a list")

        assets: list[AssetProfile] = []
        for i, a in enumerate(raw_assets):
            if not isinstance(a, dict):
                raise ZeeError(Z101_INVALID_ASSET_YAML, f"assets[{i}] must be a mapping")
            try:
                asset = _parse_asset(a)
            except ZeeError:
                raise
            except (KeyError, TypeError) as e:
                raise ZeeError(Z101_INVALID_ASSET_YAML, f"assets[{i}]: {e}") from e
            assets.append(asset)

        dry_run = bool(raw.get("dry_run", True))
        return cls(assets=tuple(assets), dry_run=dry_run)

    def find(self, asset_id: str) -> Optional[AssetProfile]:
        for a in self.assets:
            if a.id == asset_id:
                return a
        return None


def _parse_asset(raw: dict) -> AssetProfile:
    asset_id = raw["id"]
    asset_type = raw.get("type", "workstation")
    if asset_type not in _VALID_ASSET_TYPES:
        raise ZeeError(
            Z101_INVALID_ASSET_YAML,
            f"asset '{asset_id}': type must be one of {_VALID_ASSET_TYPES}, got '{asset_type}'",
        )

    response_mode = raw.get("response_mode", "notify")
    if response_mode not in _VALID_RESPONSE_MODES:
        raise ZeeError(
            Z103_INVALID_RESPONSE_MODE,
            f"asset '{asset_id}': response_mode='{response_mode}'",
        )

    cut_method = raw.get("cut_method", "full")
    if cut_method not in _VALID_CUT_METHODS:
        raise ZeeError(
            Z104_INVALID_CUT_METHOD,
            f"asset '{asset_id}': cut_method='{cut_method}'",
        )

    return AssetProfile(
        id=asset_id,
        type=asset_type,
        overnight_active=bool(raw.get("overnight_active", False)),
        decoy_paths=tuple(raw.get("decoy_paths", [])),
        response_mode=response_mode,
        cut_method=cut_method,
    )
