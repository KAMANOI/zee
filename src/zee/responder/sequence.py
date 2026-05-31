"""Fixed notify→cut sequence (spec §5, v4 trigger-limited).

Order is load-bearing:
    1. local notification (must happen first; network is not required).
       The notification carries a hint that depends on op_class:
       - read  : a legitimate bulk reader (backup / AV / indexer) might
                 plausibly explain this. Verify and `zee cut` manually
                 if you have no such explanation.
       - change: a legitimate bulk reader does not normally do this.
                 Treat with higher suspicion.
    2. remote alert (webhook, best-effort, fire-and-forget)
    3. resolve asset profile into a mode
    4. cut gate (spec v4 block C):
         mode == "contain"
       AND confidence == "high"
       AND op_class == "change"     ← NEW in v4
       AND not dry_run
    5. record latency / completion

read-class events never reach step 4 — even with mode=contain and no
dry_run, they go through notification only and the operator decides
whether to invoke `zee cut`. The judgement is on the structured
op_class field, NOT on a substring of detail.
"""

from __future__ import annotations

import logging
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable, Optional

from ..config.schema import AssetProfile
from ..errors import ZeeError, Z403_INVALID_CONFIDENCE_FOR_CONTAIN
from ..events import TrapEvent
from ..notifier.local import notify_local
from ..policy.asset_profile import resolve
from ..telemetry.events_log import EventLog
from .cut_egress import cut_egress
from .cut_full import cut_full

logger = logging.getLogger(__name__)

# A callable that posts to a remote alert channel and returns
# (success, detail). Injected so tests don't actually hit the network.
WebhookSender = Callable[[str, dict], tuple[bool, str]]


@dataclass
class ResponderResult:
    asset_id: str
    mode: str  # contain / staged / notify
    cut_executed: bool
    cut_would_have_been_executed: bool  # for dry_run with op_class=change
    cut_detail: str
    notified_locally: bool
    notified_remote: Optional[bool]  # None == dispatched async or no webhook
    cut_skipped_reason: Optional[str] = None  # e.g. "op_class=read"


def _hint_for(op_class: str, asset_id: str) -> str:
    """Return an operator-facing hint that does NOT tell them to ignore."""
    if op_class == "read":
        return (
            "操作種別: 読み取り。"
            "正規ソフト（バックアップ / AV / OS ファイルインデクサ等）の"
            "読み取りの可能性があります。心当たりがなければ確認し、"
            f"`zee cut {asset_id}` で手動遮断してください。"
        )
    return (
        "操作種別: 変更（書込/削除/改名等）。"
        "正規ソフトは通常この操作をデコイに対して行いません。"
        "危険度が高い可能性があります。"
        f"自動遮断対象（auto + dry_run=false の場合のみ実行）。"
        f"必要なら `zee cut {asset_id}` で手動遮断、"
        f"復旧は `zee restore {asset_id}`。"
    )


def handle(
    event: TrapEvent,
    asset: AssetProfile,
    *,
    dry_run: bool,
    event_log: EventLog,
    webhook_sender: Optional[WebhookSender] = None,
) -> ResponderResult:
    """Run the fixed sequence for one trap event."""
    event_log.record_event(event)

    # Step 1 — local notification (always, must happen before any cut).
    hint = _hint_for(event.op_class, event.asset_id)
    title = f"Zee tripwire ({event.op_class}): {event.asset_id}"
    body = (
        f"{event.detail} | decoy={event.decoy_path or '-'}\n"
        f"{hint}"
    )
    notified_locally = notify_local(title, body)
    alert_sent_at = datetime.now(timezone.utc)

    # Step 2 — remote alert, fire-and-forget.
    notified_remote: Optional[bool] = None
    if webhook_sender is not None:
        payload = {
            "asset_id": event.asset_id,
            "source": event.source,
            "confidence": event.confidence,
            "op_class": event.op_class,
            "decoy_path": event.decoy_path,
            "detected_at": event.detected_at.isoformat(),
            "detail": event.detail,
            "hint": hint,
        }

        def _dispatch() -> None:
            try:
                ok, detail = webhook_sender(title, payload)
                event_log.record_webhook_result(event.asset_id, ok, detail)
            except Exception as e:
                logger.exception("webhook send raised")
                event_log.record_webhook_result(event.asset_id, False, str(e))

        threading.Thread(
            target=_dispatch,
            name=f"zee-webhook:{event.asset_id}",
            daemon=True,
        ).start()
        notified_remote = None  # dispatched; result is in metrics.jsonl

    # Step 3 — resolve mode.
    resolution = resolve(asset)
    mode = resolution.mode

    # Step 4 — gated cut (v4: also requires op_class=change).
    cut_executed = False
    cut_would = False
    cut_detail = ""
    cut_done_at: Optional[datetime] = None
    cut_would_have_done_at: Optional[datetime] = None
    cut_skipped_reason: Optional[str] = None

    if mode == "contain":
        # confidence=high gate (spec §2, §4)
        if event.confidence != "high":
            raise ZeeError(
                Z403_INVALID_CONFIDENCE_FOR_CONTAIN,
                f"asset={event.asset_id} got confidence={event.confidence}",
            )
        # v4 trigger-limit gate: read events never auto-cut.
        if event.op_class != "change":
            cut_skipped_reason = f"op_class={event.op_class}"
            # Already notified in step 1 with read-hint; nothing else to do.
        else:
            cut_fn = cut_egress if resolution.cut_method == "egress" else cut_full
            if dry_run:
                cut_would = True
                cut_would_have_done_at = datetime.now(timezone.utc)
                cut_detail = f"dry_run: would have called {cut_fn.__name__}"
                notify_local(
                    f"Zee dry_run: would cut {event.asset_id}",
                    f"cut_method={resolution.cut_method} (no real cut performed)",
                )
            else:
                ok, detail = cut_fn()
                cut_executed = ok
                cut_done_at = datetime.now(timezone.utc)
                cut_detail = detail
                # Post-cut notification (network may be down for remote channels).
                notify_local(
                    f"Zee cut applied: {event.asset_id}",
                    (
                        f"reason: {event.detail}\n"
                        f"decoy: {event.decoy_path or '-'}\n"
                        f"recover with: zee restore {event.asset_id}"
                    ),
                )

    # Step 5 — record latency.
    event_log.record_latency(
        asset_id=event.asset_id,
        detected_at=event.detected_at,
        alert_sent_at=alert_sent_at,
        cut_done_at=cut_done_at,
        cut_would_have_done_at=cut_would_have_done_at,
        dry_run=dry_run,
        mode=mode,
    )

    return ResponderResult(
        asset_id=event.asset_id,
        mode=mode,
        cut_executed=cut_executed,
        cut_would_have_been_executed=cut_would,
        cut_detail=cut_detail,
        notified_locally=notified_locally,
        notified_remote=notified_remote,
        cut_skipped_reason=cut_skipped_reason,
    )
