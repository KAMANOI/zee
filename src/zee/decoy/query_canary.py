"""Query-triggered canary values — decoys that fire when *processed*.

``canary_token.py`` fires when a human (or a human-driven tool) reads a
decoy and dereferences the URL inside it. This module targets a
different trigger: an automated data-cleaning pipeline (deduplication,
reachability/MX validation, link-checking) running over stolen data,
which touches the decoy value without anyone "reading" it in the
traditional sense.

Three value shapes a cleaning pipeline is likely to touch on its own:

- ``email``    — ``<token>@<domain>``   fires on an MX/SMTP deliverability check
- ``hostname`` — ``<token>.<domain>``   fires on bare DNS resolution (no HTTP needed)
- ``url``      — ``<base_url>/<token>`` fires on an HTTP fetch (link-checker, preview)

``hostname`` is the recommended default: DNS resolution is usually the
first and cheapest step any of the above pipelines perform, so it fires
regardless of whether the pipeline goes on to open a TCP connection.
See docs/design/query-canary.md for the full design and open questions.

This module only formats values and checks exclusion; it mints tokens
through the existing ``CanaryTokenRegistry`` (same https-only base_url
rule, same persisted jsonl, same no-origin-marker token policy) rather
than building a parallel registry.
"""

from __future__ import annotations

import json
import re
import secrets
from dataclasses import dataclass
from typing import Literal

from .canary_token import CanaryToken, CanaryTokenRegistry, _ORIGIN_WORDS

QueryCanaryKind = Literal["email", "hostname", "url"]

# Words that would tell a curious attacker "this domain exists to catch
# me" if they showed up in the operator's canary domain name. _ORIGIN_WORDS
# guards the *token*; this guards the *domain* the operator picks.
_DOMAIN_ORIGIN_WORDS = (*_ORIGIN_WORDS, "hdr", "honeypot", "trap")


@dataclass(frozen=True)
class QueryCanaryValue:
    kind: QueryCanaryKind
    value: str
    token: CanaryToken


def _check_domain(domain: str) -> None:
    # Whole-word match on labels split at '.'/'-', not substring: a naive
    # substring check on "sting"/"trap" would reject legitimate domains
    # like "myhostingco.test" or "bootstrap-corp.test" (found in review).
    words = re.split(r"[^a-z0-9]+", domain.lower())
    for word in _DOMAIN_ORIGIN_WORDS:
        if word in words:
            raise ValueError(
                f"canary domain must not contain an origin-revealing word "
                f"({word!r} found in {domain!r}); pick an unrelated domain."
            )


def _generate_safe_token() -> str:
    """32 lowercase-hex chars: a valid DNS label (<=63 chars, alnum,
    never starts with '-'), a valid email local-part, and never a CSV
    formula-injection trigger (never starts with = + - @ since the
    alphabet is only 0-9a-f).

    This is deliberately NOT ``CanaryTokenRegistry``'s own token_id:
    that one comes from ``secrets.token_urlsafe`` (mixed case, '-', '_'),
    which breaks all three guarantees above — caught by
    tests/test_query_canary.py::test_hostname_value_shape during
    self-review of this module, which is why the two are kept separate
    here rather than reusing ``token.token_id`` as the embedded value.
    """
    return secrets.token_hex(16)


def issue_query_canary(
    registry: CanaryTokenRegistry,
    kind: QueryCanaryKind,
    purpose: str,
    *,
    domain: str | None = None,
) -> QueryCanaryValue:
    """Mint a decoy value of ``kind`` via ``registry``.

    ``domain`` is required for "email" and "hostname" — it is the
    operator's own domain with MX/NS records pointed at their receiver,
    independent of ``registry``'s https base_url (which only matters
    for "url"). See docs/design/query-canary.md §2.

    For "email"/"hostname" the embedded value is our own safe token
    (see ``_generate_safe_token``), stored as the ``decoy_path`` key via
    ``issue_for_decoy`` — not the registry's own ``token.token_id``,
    which is unsafe to embed directly (see above). For "url" the
    registry's token_id is fine as-is: it never leaves the URL path, so
    DNS-label/email/CSV constraints don't apply, and ``full_url`` already
    uses it.
    """
    if kind == "url":
        token = registry.issue_for_decoy(f"query:url:{secrets.token_hex(8)}", purpose)
        return QueryCanaryValue(kind=kind, value=token.full_url, token=token)
    if domain is None:
        raise ValueError(f"domain is required for kind={kind!r}")
    _check_domain(domain)
    safe_token = _generate_safe_token()
    token = registry.issue_for_decoy(safe_token, purpose)
    if kind == "email":
        value = f"{safe_token}@{domain}"
    elif kind == "hostname":
        value = f"{safe_token}.{domain}"
    else:
        raise ValueError(f"unknown kind: {kind!r}")
    return QueryCanaryValue(kind=kind, value=value, token=token)


def extract_label(value: str, kind: QueryCanaryKind) -> str:
    """Pull the embedded token/label back out of a formatted decoy value."""
    if kind == "email":
        return value.split("@", 1)[0]
    if kind == "hostname":
        return value.split(".", 1)[0]
    if kind == "url":
        return value.rsplit("/", 1)[-1]
    raise ValueError(f"unknown kind: {kind!r}")


def is_known_value(registry: CanaryTokenRegistry, value: str, kind: QueryCanaryKind) -> bool:
    """Exclusion check for an operator's own pipelines.

    Every value this module issues is persisted to the registry's
    canary_tokens.jsonl exactly like a file-decoy token — that file
    already *is* the exclusion ledger: an operator's own dedup/validation
    job can call this before touching a value to skip known decoys
    instead of firing on its own canaries. No second ledger file.

    "url" values key on the registry's own token_id (``lookup``), which
    IS base_url-scoped by design (a stale URL under a rotated base_url
    is correctly treated as dead — see
    test_rehydrate_skips_records_with_different_base_url in
    test_canary_token.py).

    "email"/"hostname" key on our safe token, stored as decoy_path. These
    must NOT be base_url-scoped: an email/hostname canary doesn't point
    at base_url at all (only "url" kind does), so rotating
    ZEE_CANARY_BASE_URL for the webhook receiver must not strand
    previously-issued email/hostname canaries out of the exclusion check
    (found in independent review 2026-10-09 — registry.lookup_for_decoy
    only sees records loaded for the *current* base_url, via
    CanaryTokenRegistry._load_from_file's base_url filter). We read
    canary_tokens.jsonl directly for decoy_path matches instead of going
    through the registry's in-memory, base_url-filtered map.
    """
    label = extract_label(value, kind)
    if kind == "url":
        return registry.lookup(label) is not None
    return _decoy_path_ever_persisted(registry.registry_path, label)


def _decoy_path_ever_persisted(registry_path, decoy_path: str) -> bool:
    if not registry_path.exists():
        return False
    for raw_line in registry_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        if rec.get("decoy_path") == decoy_path:
            return True
    return False
