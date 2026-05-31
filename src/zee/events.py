"""TrapEvent — the single contract between watcher and policy/responder.

decoy_touch events must carry confidence='high' (spec §4).
Only confidence='high' is allowed to trigger automatic containment.

op_class distinguishes "read-like" touches (open, read, attribute
inspection — what bulk readers such as backup tools, AV scanners and
file indexers also do) from "change-like" touches (write, delete,
rename, extend — which legitimate bulk readers do not perform on a
decoy in normal operation). Spec block C: automatic containment is
gated on op_class=="change". Read-like touches are notified with a
hint and the operator decides whether to cut manually (`zee cut`).

The judgement is made on this structured field, NOT by parsing
the `detail` string.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Literal, Optional

Source = Literal["decoy_touch", "behavior_anomaly", "manual"]
Confidence = Literal["high", "medium", "low"]
OpClass = Literal["read", "change"]


@dataclass(frozen=True)
class TrapEvent:
    source: Source
    confidence: Confidence
    asset_id: str
    decoy_path: Optional[str]
    detected_at: datetime
    detail: str
    op_class: OpClass
    # v0.3 (spec L4): `decoy_ref` is the value persisted in events.jsonl
    # in place of the absolute `decoy_path`, so a root attacker reading
    # the log cannot enumerate every decoy's location in one file.
    # Format: "<asset_id>#<index>" where <index> is the 0-based offset
    # in the asset's decoy_paths list. Operators correlate back to the
    # full path via assets.toml. `decoy_path` is kept as an internal
    # field used by the watcher and responder, but is never written to
    # the event log.
    decoy_ref: Optional[str] = None

    def __post_init__(self) -> None:
        if self.source == "decoy_touch" and self.confidence != "high":
            raise ValueError(
                f"decoy_touch events must have confidence='high', got '{self.confidence}'"
            )

    @classmethod
    def make(
        cls,
        source: Source,
        confidence: Confidence,
        asset_id: str,
        decoy_path: Optional[str],
        detail: str,
        op_class: OpClass,
        detected_at: Optional[datetime] = None,
        decoy_ref: Optional[str] = None,
    ) -> "TrapEvent":
        return cls(
            source=source,
            confidence=confidence,
            asset_id=asset_id,
            decoy_path=decoy_path,
            detected_at=detected_at or datetime.now(timezone.utc),
            detail=detail,
            op_class=op_class,
            decoy_ref=decoy_ref,
        )
