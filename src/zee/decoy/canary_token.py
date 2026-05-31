"""Canary tokens — out-of-band detection signals embedded in decoys.

When the OS-level watcher cannot reliably observe a read (macOS without
Endpoint Security entitlement, Windows without object-access auditing),
Zee embeds an out-of-band signal into the decoy content: an HTTPS URL
that points at a webhook the operator controls. If the attacker
dereferences the URL — by curl, browser, or automated triage — the
webhook fires and Zee learns the decoy was used.

This module **generates, registers, and persists** tokens. It does not
run an HTTP listener. The operator points the base URL at any endpoint
they trust: their own webhook receiver, Canarytokens.org, an AWS
Lambda, etc.

Persistence (v0.2):
    Tokens issued for a specific decoy_path are appended to
    ``canary_tokens.jsonl`` in the Zee state directory (0700 / 0600).
    On startup the registry rehydrates the (decoy_path -> token) map
    for the currently-configured base_url, so re-running ``zee watch``
    reuses the same URL for the same decoy. The decoy file itself is
    NOT rewritten on subsequent runs (the v0.1 "leave existing decoy
    alone" rule is preserved); the persisted map therefore acts as
    the authoritative record of which URL is in which decoy.

base_url policy:
    - When base_url is set, it must be an https:// URL (rejected at
      construction otherwise — see ValueError below).
    - When base_url is unset (None or empty), every method that would
      have minted a token raises RuntimeError. The pre-0.2 ``about:zee``
      fallback was removed because emitting a clearly Zee-origin URL
      into a decoy made the deception trivially detectable.
"""

from __future__ import annotations

import json
import logging
import os
import secrets
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class CanaryToken:
    token_id: str
    base_url: str
    full_url: str
    purpose: str  # e.g. "decoy_env" / "decoy_credentials" / "decoy_notes"
    created_at: datetime


def default_registry_path() -> Path:
    """Default location of canary_tokens.jsonl.

    Mirrors telemetry.events_log.default_log_dir() so the canary
    registry lives alongside events.jsonl / metrics.jsonl.
    """
    env = os.environ.get("XDG_STATE_HOME")
    if env:
        return Path(env) / "zee" / "canary_tokens.jsonl"
    home = Path.home()
    local_state_parent = home / ".local" / "state"
    if local_state_parent.exists():
        return local_state_parent / "zee" / "canary_tokens.jsonl"
    return home / ".zee" / "canary_tokens.jsonl"


class CanaryTokenRegistry:
    """Persisted registry of canary tokens issued by this Zee instance.

    The registry pairs token IDs with the decoys they live in. The
    on-disk JSON Lines file (0600) is the source of truth across
    restarts; in-memory state mirrors it.
    """

    def __init__(
        self,
        base_url: Optional[str] = None,
        *,
        registry_path: Optional[Path] = None,
    ) -> None:
        cleaned = (base_url or "").strip().rstrip("/")
        # URL schemes are case-insensitive per RFC 3986; accept HTTPS://
        # / Https:// etc. but require the scheme to resolve to "https".
        scheme = cleaned.split("://", 1)[0].lower() if "://" in cleaned else ""
        if cleaned and scheme != "https":
            raise ValueError(
                "CanaryTokenRegistry base_url must use https:// — canary URLs "
                "are embedded in decoys and dereferenced by attackers; their "
                "destination must not be observable in plaintext on the wire. "
                f"Got: {base_url!r}"
            )
        self._base_url = cleaned
        self._registry_path = registry_path or default_registry_path()
        self._tokens: dict[str, CanaryToken] = {}
        self._decoy_to_token: dict[str, CanaryToken] = {}
        if self._base_url:
            self._load_from_file()

    @property
    def is_configured(self) -> bool:
        """True only when an operator-controlled base URL is configured."""
        return bool(self._base_url)

    @property
    def registry_path(self) -> Path:
        return self._registry_path

    # ── token issuance ────────────────────────────────────────────────

    def issue(self, purpose: str) -> CanaryToken:
        """Issue a token NOT bound to a decoy_path.

        Raises RuntimeError if base_url is unset. The pre-0.2
        ``about:zee/c/...`` fallback was removed deliberately.
        """
        if not self._base_url:
            raise RuntimeError(
                "CanaryTokenRegistry.issue requires base_url to be set "
                "(via ZEE_CANARY_BASE_URL or the constructor). The legacy "
                "'about:zee' fallback was removed in v0.2 because emitting "
                "a clearly Zee-origin URL into a decoy would make the "
                "deception trivially detectable."
            )
        return self._mint_token(purpose)

    def issue_for_decoy(self, decoy_path: str, purpose: str) -> CanaryToken:
        """Return the token bound to ``decoy_path``, minting one if needed.

        Idempotent: a second call with the same decoy_path returns the
        previously-issued token. Mints + persists on first call.
        """
        if not self._base_url:
            raise RuntimeError(
                "CanaryTokenRegistry.issue_for_decoy requires base_url to "
                "be set (via ZEE_CANARY_BASE_URL or the constructor)."
            )
        decoy_key = str(Path(decoy_path).expanduser())
        existing = self._decoy_to_token.get(decoy_key)
        if existing is not None:
            return existing
        token = self._mint_token(purpose)
        self._decoy_to_token[decoy_key] = token
        self._persist(decoy_key, token, purpose)
        return token

    def lookup(self, token_id: str) -> Optional[CanaryToken]:
        return self._tokens.get(token_id)

    def lookup_for_decoy(self, decoy_path: str) -> Optional[CanaryToken]:
        return self._decoy_to_token.get(str(Path(decoy_path).expanduser()))

    def all_tokens(self) -> tuple[CanaryToken, ...]:
        return tuple(self._tokens.values())

    # ── persistence ────────────────────────────────────────────────────

    def _mint_token(self, purpose: str) -> CanaryToken:
        token_id = secrets.token_urlsafe(16)
        # No "/c/" prefix: the URL is just base_url/<token_id>. Operator
        # picks the base_url freely so the path shape is theirs, not
        # Zee's, and there is no Zee-specific marker for an attacker to
        # grep for in the decoy.
        full_url = f"{self._base_url}/{token_id}"
        token = CanaryToken(
            token_id=token_id,
            base_url=self._base_url,
            full_url=full_url,
            purpose=purpose,
            created_at=datetime.now(timezone.utc),
        )
        self._tokens[token_id] = token
        return token

    def _load_from_file(self) -> None:
        if not self._registry_path.exists():
            return
        try:
            content = self._registry_path.read_text(encoding="utf-8")
        except OSError as e:
            logger.warning("canary registry read failed (%s); starting empty", e)
            return
        for line_no, raw_line in enumerate(content.splitlines(), start=1):
            line = raw_line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError as e:
                logger.warning(
                    "canary registry %s:%d: malformed line, skipping (%s)",
                    self._registry_path, line_no, e,
                )
                continue
            # Only rehydrate tokens that match the currently-configured
            # base_url. A different base_url means the operator changed
            # endpoints; previously-embedded URLs are now stale (the
            # decoy still carries the old URL on disk, but Zee no longer
            # tracks it as a live canary).
            rec_base = rec.get("base_url")
            if rec_base != self._base_url:
                continue
            try:
                token_id = rec["token_id"]
                purpose = rec.get("purpose", "")
                created_raw = rec.get("created_at")
                created_at = (
                    datetime.fromisoformat(created_raw)
                    if created_raw
                    else datetime.now(timezone.utc)
                )
                token = CanaryToken(
                    token_id=token_id,
                    base_url=self._base_url,
                    full_url=f"{self._base_url}/{token_id}",
                    purpose=purpose,
                    created_at=created_at,
                )
                self._tokens[token_id] = token
                decoy_path = rec.get("decoy_path")
                if decoy_path:
                    self._decoy_to_token[str(decoy_path)] = token
            except (KeyError, ValueError, TypeError) as e:
                logger.warning(
                    "canary registry %s:%d: malformed record, skipping (%s)",
                    self._registry_path, line_no, e,
                )
                continue

    def _persist(self, decoy_path: str, token: CanaryToken, purpose: str) -> None:
        path = self._registry_path
        path.parent.mkdir(parents=True, exist_ok=True)
        # The state directory is Zee-managed (mirrors telemetry.events_log)
        # so we tighten it on every write rather than seeder's "only if I
        # created it" rule. If an operator shares ~/.local/state/zee with
        # another tool, that's an explicit configuration we don't expect.
        try:
            os.chmod(path.parent, 0o700)
        except (OSError, NotImplementedError):
            pass
        rec = {
            "token_id": token.token_id,
            "base_url": token.base_url,
            "decoy_path": decoy_path,
            "purpose": purpose,
            "created_at": token.created_at.isoformat(),
        }
        existed = path.exists()
        with path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
        if not existed:
            try:
                os.chmod(path, 0o600)
            except (OSError, NotImplementedError):
                pass
