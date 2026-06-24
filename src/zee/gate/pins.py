"""Pin registry — the anchor for Rug Pull detection (Phase 3).

When the gate promotes a LOW artifact into its real install location, we
record (pin) its content hash. A "Rug Pull" is an artifact that was
benign at install time and turns malicious later — by self-updating or
silently rewriting its own files on disk. Pinning the hash gives Zee a
fixed reference to compare against, so ``zee gate audit`` can later prove
whether what's installed is still the bytes that passed the gate.

Persistence mirrors the rest of Zee's state (``canary_tokens.jsonl`` /
``cut_state.jsonl``): append-only JSON Lines under the state directory,
parent 0700 / file 0600. stdlib only.
"""

from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from ..telemetry.events_log import default_log_dir

logger = logging.getLogger(__name__)


def default_pins_path() -> Path:
    return default_log_dir() / "gate" / "pins.jsonl"


@dataclass(frozen=True)
class Pin:
    name: str
    kind: str
    source: str
    content_hash: str
    install_dir: str   # where the artifact was promoted to (what we re-hash)
    pinned_at: datetime

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "kind": self.kind,
            "source": self.source,
            "content_hash": self.content_hash,
            "install_dir": self.install_dir,
            "pinned_at": self.pinned_at.isoformat(),
        }

    @staticmethod
    def from_dict(d: dict) -> "Pin":
        return Pin(
            name=d["name"],
            kind=d.get("kind", "package"),
            source=d.get("source", ""),
            content_hash=d["content_hash"],
            install_dir=d["install_dir"],
            pinned_at=datetime.fromisoformat(d["pinned_at"]),
        )


class PinRegistry:
    """Append-only registry of pinned (promoted) artifacts.

    The on-disk JSON Lines file is the source of truth. ``all()`` returns
    the most recent pin per ``install_dir`` so a re-pin (a legitimate
    update promoted to the same place) supersedes the older record.
    """

    def __init__(self, path: Optional[Path] = None) -> None:
        self.path = path or default_pins_path()

    def pin(
        self,
        *,
        name: str,
        kind: str,
        source: str,
        content_hash: str,
        install_dir: str,
        now: Optional[datetime] = None,
    ) -> Pin:
        record = Pin(
            name=name,
            kind=kind,
            source=source,
            content_hash=content_hash,
            install_dir=str(Path(install_dir)),
            pinned_at=now or datetime.now(timezone.utc),
        )
        self._append(record)
        return record

    def all(self) -> list[Pin]:
        latest: dict[str, Pin] = {}
        for rec in self._read_all():
            latest[rec.install_dir] = rec  # later lines win
        return sorted(latest.values(), key=lambda p: p.install_dir)

    # ── persistence ────────────────────────────────────────────────────

    def _read_all(self) -> list[Pin]:
        if not self.path.exists():
            return []
        out: list[Pin] = []
        try:
            content = self.path.read_text(encoding="utf-8")
        except OSError as e:
            logger.warning("pin registry read failed (%s); starting empty", e)
            return []
        for line_no, raw in enumerate(content.splitlines(), start=1):
            line = raw.strip()
            if not line:
                continue
            try:
                out.append(Pin.from_dict(json.loads(line)))
            except (json.JSONDecodeError, KeyError, ValueError, TypeError) as e:
                logger.warning("pin registry %s:%d malformed, skipping (%s)",
                               self.path, line_no, e)
        return out

    def _append(self, record: Pin) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(self.path.parent, 0o700)
        except (OSError, NotImplementedError):
            pass
        existed = self.path.exists()
        with self.path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(record.to_dict(), ensure_ascii=False) + "\n")
        if not existed:
            try:
                os.chmod(self.path, 0o600)
            except (OSError, NotImplementedError):
                pass
