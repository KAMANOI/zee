"""Generic webhook poster — optional remote alert channel (spec §5, §10).

Standard library only (urllib). Short timeout, best-effort. The responder
proceeds even when this fails so a broken webhook never blocks a cut.
"""

from __future__ import annotations

import json
import logging
import os
import urllib.error
import urllib.request
from typing import Any, Callable, Optional

logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT_SEC = 3.0

WebhookSender = Callable[[str, dict[str, Any]], tuple[bool, str]]


def post(
    url: str,
    payload: dict[str, Any],
    *,
    timeout: float = DEFAULT_TIMEOUT_SEC,
) -> tuple[bool, str]:
    """POST a JSON payload to `url`. Never raises."""
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=body,
        headers={"Content-Type": "application/json", "User-Agent": "zee/0.1"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            status = getattr(resp, "status", None) or resp.getcode()
            if 200 <= status < 300:
                return True, f"HTTP {status}"
            return False, f"HTTP {status}"
    except urllib.error.HTTPError as e:
        return False, f"HTTPError {e.code}"
    except urllib.error.URLError as e:
        return False, f"URLError: {e.reason}"
    except (OSError, ValueError) as e:
        return False, f"{type(e).__name__}: {e}"


def from_env() -> Optional[WebhookSender]:
    """Return a webhook sender bound to ZEE_WEBHOOK_URL, or None.

    A single environment variable enables remote alerts; no config file
    edit is required.
    """
    url = os.environ.get("ZEE_WEBHOOK_URL", "").strip()
    if not url:
        return None

    def sender(title: str, body: dict[str, Any]) -> tuple[bool, str]:
        payload = {"title": title, **body}
        return post(url, payload)

    return sender
