"""Cut boundary — the narrow request an automatic cut must pass.

Stage 1 of docs/design/self-defense.md. Today this runs in the same
process (and as the same user) as the watcher, so it adds no privilege
separation by itself. It fixes the contract a later, separately
privileged cut service will enforce:

* the requester supplies only event facts (asset, op_class, confidence);
  it cannot choose the cut method or any target — the boundary takes those
  from the asset policy it holds;
* anything outside the one allowed shape is refused, including dry_run.

It never relaxes the gate in ``sequence.handle``: it re-checks the same
conditions so a bypassed or broken caller-side gate still cannot cut.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from ..config.schema import AssetProfile
from ..policy.asset_profile import resolve


@dataclass(frozen=True)
class CutRequest:
    asset_id: str
    op_class: str
    confidence: str


def refusal(req: CutRequest, asset: AssetProfile, *, dry_run: bool) -> Optional[str]:
    """Return why ``req`` must not cut, or None if it may."""
    if dry_run is not False:
        return "dry_run"
    if not isinstance(req.asset_id, str) or not req.asset_id or req.asset_id != asset.id:
        return "asset_mismatch"
    if resolve(asset).mode != "contain":
        return "mode_not_contain"
    if req.confidence != "high":
        return "confidence_not_high"
    if req.op_class != "change":
        return "op_class_not_change"
    return None
