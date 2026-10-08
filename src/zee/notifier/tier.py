"""Notification impact tier — display layer only (docs/design/notification-tier.md).

Classifies "how bad would this be if real" into 4 levels for a non-expert
reader. This module must never influence containment decisions: it is
read by `notifier`/`responder.sequence` for notification text only, never
by `policy.asset_profile.resolve` or the cut gate in `responder.sequence`.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from ..config.schema import AssetProfile
from ..decoy.seeder import _TEMPLATES, _pick_template
from ..events import TrapEvent

logger = logging.getLogger(__name__)

LEVEL_LABELS = {1: "情報", 2: "注意", 3: "警戒", 4: "重大"}

_CREDENTIAL_TEMPLATES = {"credentials", "env", "ssh_key"}
_PII_KEYWORDS = ("顧客", "customer", "personal", "患者", "名簿", "member")

_SENSITIVITY_LABELS = {
    "unknown": "パス種別不明",
    "credential": "認証情報・鍵",
    "personal_data": "個人情報を含みうるデータ",
    "general": "一般ファイル",
}


@dataclass(frozen=True)
class TierResult:
    level: int  # 1..4
    label: str  # LEVEL_LABELS[level]
    sensitivity_category: str  # _SENSITIVITY_LABELS value
    confirmed_axes: tuple[str, ...]  # short human-readable notes, for the reason line


def _sensitivity(decoy_path: Optional[str]) -> tuple[int, str]:
    if decoy_path is None:
        return 0, "unknown"
    name = Path(decoy_path).name.lower()
    if _pick_template(Path(decoy_path)) in _CREDENTIAL_TEMPLATES:
        return 2, "credential"
    if any(kw in name for kw in _PII_KEYWORDS):
        return 1, "personal_data"
    return 0, "general"


def _authority(sensitivity_level: int, asset_type: str) -> int:
    shared = asset_type != "workstation"
    if sensitivity_level == 2:
        return 2 if shared else 1
    return 1 if shared else 0


def _business_reach(asset: AssetProfile) -> int:
    signals = (
        len(asset.decoy_paths) >= 3,
        asset.type != "workstation",
        asset.overnight_active,
    )
    true_count = sum(signals)
    if true_count >= 3:
        return 2
    if true_count == 2:
        return 1
    return 0


def classify(event: TrapEvent, asset: AssetProfile) -> TierResult:
    """Pure function: event + asset -> display tier. Never raises on
    expected inputs; callers should still wrap this (see sequence.py)
    so an unexpected error degrades to the lowest tier instead of
    blocking the notification or the containment path."""
    sens_level, sens_key = _sensitivity(event.decoy_path)
    auth_level = _authority(sens_level, asset.type)
    biz_level = _business_reach(asset)

    max_level = max(sens_level, auth_level, biz_level)
    high_count = sum(1 for lv in (sens_level, auth_level, biz_level) if lv == 2)
    if high_count >= 2:
        level = 4
    elif max_level == 2:
        level = 3
    elif max_level == 1:
        level = 2
    else:
        level = 1

    # Display-only floor: a "change" touch reads as high-suspicion in the
    # existing hint text (_hint_for); don't show a contradicting low tier.
    if event.op_class == "change" and level < 2:
        level = 2

    confirmed: list[str] = []
    if sens_key == "unknown":
        confirmed.append("パス種別は未確認")
    else:
        confirmed.append(f"種別: {_SENSITIVITY_LABELS[sens_key]}")
    confirmed.append(
        "資産は共有/常時稼働領域" if asset.type != "workstation" else "資産は単一ワークステーション"
    )

    return TierResult(
        level=level,
        label=LEVEL_LABELS[level],
        sensitivity_category=_SENSITIVITY_LABELS[sens_key],
        confirmed_axes=tuple(confirmed),
    )


def safe_classify(event: TrapEvent, asset: AssetProfile) -> TierResult:
    """classify() wrapped so a bug here can never block notification or
    containment (design doc: フェイルクローズ). Degrades to the lowest
    tier with a reason noting nothing was confirmed."""
    try:
        return classify(event, asset)
    except Exception:
        logger.exception("tier classify() raised; degrading to lowest tier")
        return TierResult(
            level=1,
            label=LEVEL_LABELS[1],
            sensitivity_category=_SENSITIVITY_LABELS["unknown"],
            confirmed_axes=("種別を確認できず最低段階で表示",),
        )


def reason_line(result: TierResult, *, action: str) -> str:
    """action: one of 'detect' / 'contain' / 'contain_failed' / 'dry_run'."""
    verb = {
        "detect": "検知",
        "contain": "封じ込め",
        "contain_failed": "遮断を試行(失敗、手動確認が必要)",
        "dry_run": "検知(dry_run、手動確認可)",
    }[action]
    axes = "、".join(result.confirmed_axes)
    return f"{result.sensitivity_category}のパスへの接触を{verb}。{axes}。"
