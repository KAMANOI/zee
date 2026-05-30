"""Resolve an asset profile to a runtime response mode (spec §6).

The asset profile's response_mode field is authoritative. The defaults
listed in spec §6 (workstation/overnight_active/server/ot) are
recommendations for what to write into the profile, not implicit overrides
applied at runtime.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, Optional

from ..config.schema import AssetProfile, CutMethod

ResolvedMode = Literal["contain", "staged", "notify"]


@dataclass(frozen=True)
class Resolution:
    asset_id: str
    mode: ResolvedMode
    cut_method: Optional[CutMethod]  # None when mode == "notify"
    rationale: str  # human-readable, for the event log


def resolve(asset: AssetProfile) -> Resolution:
    """Return how Zee should respond for this asset, based on its profile.

    response_mode mapping:
        auto    → contain (with cut_method from profile)
        staged  → staged  (operator confirms before cut)
        notify  → notify  (no cut; alerts only)
    """
    if asset.response_mode == "auto":
        return Resolution(
            asset_id=asset.id,
            mode="contain",
            cut_method=asset.cut_method,
            rationale="response_mode=auto",
        )
    if asset.response_mode == "staged":
        return Resolution(
            asset_id=asset.id,
            mode="staged",
            cut_method=asset.cut_method,
            rationale="response_mode=staged",
        )
    # notify — including any unexpected value (defensive default)
    return Resolution(
        asset_id=asset.id,
        mode="notify",
        cut_method=None,
        rationale=f"response_mode={asset.response_mode}",
    )
