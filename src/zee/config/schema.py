"""assets.toml schema and loader (spec §6).

TOML is parsed with the standard library (tomllib, Python 3.11+).
Zee has no runtime third-party dependency.
"""

from __future__ import annotations

import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Literal, Optional

from ..errors import (
    ZeeError,
    Z101_INVALID_ASSET_CONFIG,
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
    # [privsep] socket = "/run/zee/cutd.sock" (Linux) / "/private/var/db/zee/cutd.sock" (macOS): send cuts to the root cut
    # daemon instead of cutting in-process (docs/design/privsep.md). None = as before.
    privsep_socket: Optional[str] = None

    @classmethod
    def load(cls, path: Path) -> "Config":
        try:
            with path.open("rb") as f:  # tomllib requires binary mode
                return cls.load_file(f)
        except OSError as e:
            raise ZeeError(Z101_INVALID_ASSET_CONFIG, str(e)) from e

    @classmethod
    def load_file(cls, f: BinaryIO) -> "Config":
        """Parse an already-open binary file (`zee doctor` checks the fd first)."""
        try:
            raw = tomllib.load(f)
        except (OSError, ValueError) as e:  # TOMLDecodeError / UnicodeDecodeError are ValueErrors
            raise ZeeError(Z101_INVALID_ASSET_CONFIG, str(e)) from e

        if not isinstance(raw, dict):
            raise ZeeError(Z101_INVALID_ASSET_CONFIG, "top level must be a table")

        raw_assets = raw.get("assets", [])
        if not isinstance(raw_assets, list):
            raise ZeeError(Z101_INVALID_ASSET_CONFIG, "'assets' must be an array of tables")

        assets: list[AssetProfile] = []
        for i, a in enumerate(raw_assets):
            if not isinstance(a, dict):
                raise ZeeError(Z101_INVALID_ASSET_CONFIG, f"assets[{i}] must be a table")
            try:
                asset = _parse_asset(a)
            except ZeeError:
                raise
            except (KeyError, TypeError) as e:
                raise ZeeError(Z101_INVALID_ASSET_CONFIG, f"assets[{i}]: {e}") from e
            assets.append(asset)

        dry_run = bool(raw.get("dry_run", True))
        privsep = raw.get("privsep")
        privsep_socket = None
        if privsep is not None:
            sock = privsep.get("socket") if isinstance(privsep, dict) else None
            if not isinstance(sock, str) or not sock.startswith("/") or "\x00" in sock:
                raise ZeeError(Z101_INVALID_ASSET_CONFIG, "[privsep] socket must be an absolute path")
            privsep_socket = sock
        return cls(
            assets=tuple(assets),
            dry_run=dry_run,
            privsep_socket=privsep_socket,
        )

    def find(self, asset_id: str) -> Optional[AssetProfile]:
        for a in self.assets:
            if a.id == asset_id:
                return a
        return None


def duplicate_decoys(config: Config) -> list[tuple[str, str, str]]:
    """(path, first_asset, other_asset) for decoys listed under two assets.

    `zee watch` refuses to start on any; `zee doctor` reports them."""
    seen: dict[str, str] = {}
    dups: list[tuple[str, str, str]] = []
    for asset in config.assets:
        for raw in asset.decoy_paths:
            key = str(Path(raw).expanduser())
            if key in seen and seen[key] != asset.id:
                dups.append((raw, seen[key], asset.id))
            seen.setdefault(key, asset.id)
    return dups


def _parse_asset(raw: dict) -> AssetProfile:
    asset_id = raw["id"]
    if not isinstance(asset_id, str):
        raise ZeeError(Z101_INVALID_ASSET_CONFIG, f"asset id must be a string, got {asset_id!r}")
    decoys = raw.get("decoy_paths", [])
    if not isinstance(decoys, list) or not all(isinstance(d, str) for d in decoys):
        raise ZeeError(Z101_INVALID_ASSET_CONFIG, f"asset '{asset_id}': decoy_paths must be a list of strings")
    for d in decoys:
        try:
            if "\x00" in d:
                raise ValueError("contains a NUL character")
            Path(d).expanduser()
        except (RuntimeError, ValueError) as e:  # RuntimeError: ~unknown_user
            raise ZeeError(Z101_INVALID_ASSET_CONFIG, f"asset '{asset_id}': decoy path {d!r}: {e}") from e
    asset_type = raw.get("type", "workstation")
    if asset_type not in _VALID_ASSET_TYPES:
        raise ZeeError(
            Z101_INVALID_ASSET_CONFIG,
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
        decoy_paths=tuple(decoys),
        response_mode=response_mode,
        cut_method=cut_method,
    )
