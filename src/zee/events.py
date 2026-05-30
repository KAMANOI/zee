"""TrapEvent — the single contract between watcher and policy/responder.

decoy_touch events must carry confidence='high' (spec §4).
Only confidence='high' is allowed to trigger automatic containment.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Literal, Optional

Source = Literal["decoy_touch", "behavior_anomaly", "manual"]
Confidence = Literal["high", "medium", "low"]


@dataclass(frozen=True)
class TrapEvent:
    source: Source
    confidence: Confidence
    asset_id: str
    decoy_path: Optional[str]
    detected_at: datetime
    detail: str

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
        detected_at: Optional[datetime] = None,
    ) -> "TrapEvent":
        return cls(
            source=source,
            confidence=confidence,
            asset_id=asset_id,
            decoy_path=decoy_path,
            detected_at=detected_at or datetime.now(timezone.utc),
            detail=detail,
        )
