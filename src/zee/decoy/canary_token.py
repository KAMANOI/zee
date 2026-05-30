"""Canary tokens — out-of-band detection signals embedded in decoys.

When the OS-level watcher cannot reliably observe a read (macOS without
Endpoint Security entitlement, Windows without object-access auditing),
Zee embeds an out-of-band signal into the decoy content: an HTTPS URL
that points at a webhook the operator controls. If the attacker
dereferences the URL — by curl, browser, or automated triage — the
webhook fires and Zee learns the decoy was used.

This module **generates and registers** tokens. It does not run an HTTP
listener. The operator points the URL at any endpoint they trust:
their own webhook receiver, Canarytokens.org, an AWS Lambda, etc.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional


@dataclass(frozen=True)
class CanaryToken:
    token_id: str
    base_url: str
    full_url: str
    purpose: str  # e.g. "decoy_env" / "decoy_aws_key" / "decoy_ssh_key"
    created_at: datetime


class CanaryTokenRegistry:
    """In-memory registry of canary tokens issued by this Zee instance.

    The registry is intentionally simple: it pairs token IDs with the
    decoys they live in. Persistence is out of scope; on restart the
    operator regenerates the decoys.
    """

    def __init__(self, base_url: Optional[str] = None) -> None:
        self._base_url = (base_url or "").rstrip("/")
        self._tokens: dict[str, CanaryToken] = {}

    @property
    def is_configured(self) -> bool:
        """True only when an operator-controlled base URL is configured."""
        return bool(self._base_url)

    def issue(self, purpose: str) -> CanaryToken:
        """Issue a new canary token. The caller embeds full_url in a decoy."""
        token_id = secrets.token_urlsafe(16)
        full_url = f"{self._base_url}/c/{token_id}" if self._base_url else f"about:zee/c/{token_id}"
        token = CanaryToken(
            token_id=token_id,
            base_url=self._base_url,
            full_url=full_url,
            purpose=purpose,
            created_at=datetime.now(timezone.utc),
        )
        self._tokens[token_id] = token
        return token

    def lookup(self, token_id: str) -> Optional[CanaryToken]:
        return self._tokens.get(token_id)

    def all_tokens(self) -> tuple[CanaryToken, ...]:
        return tuple(self._tokens.values())
