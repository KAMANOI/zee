"""One decoy e-mail address per storage place, and offline lookup of a
breach-notification result back to the place that leaked.

Idea: put a unique address (``<token>@<watched domain>``) into each place
data is kept (DB dump, backup, shared export...). If a third-party breach
index later reports that address, the address tells you *which* place
leaked. Zee never calls that index: the operator pastes the result
(``{alias: [breach names]}``, the shape of Have I Been Pwned's
``/breachedDomain`` response) into :func:`locate`. See
docs/design/hibp-decoy-mapping.md.

Reuses ``issue_query_canary`` (token shape, origin-word domain check) and
the registry's 0600 jsonl as the mapping table; ``purpose`` carries the
place name. Keep that jsonl apart from the places it describes.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass

from .canary_token import CanaryTokenRegistry
from .query_canary import issue_query_canary

PLACE_PREFIX = "place:"
# HIBP's free domain monitoring covers a domain with <=10 breached addresses
# (https://haveibeenpwned.com/Subscription). One address per place means at
# most len(places) addresses can ever be breached on this domain.
FREE_TIER_MAX_ADDRESSES = 10
_PLACE_RE = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,62}$")


@dataclass(frozen=True)
class Hit:
    place: str
    alias: str
    breaches: tuple[str, ...]


def _place_by_alias(registry: CanaryTokenRegistry) -> dict[str, str]:
    out: dict[str, str] = {}
    path = registry.registry_path
    if not path.exists():
        return out
    for raw in path.read_text(encoding="utf-8").splitlines():
        try:
            rec = json.loads(raw)
        except json.JSONDecodeError:
            continue
        purpose = rec.get("purpose", "")
        if purpose.startswith(PLACE_PREFIX) and rec.get("decoy_path"):
            out[rec["decoy_path"].rsplit("/", 1)[-1]] = purpose[len(PLACE_PREFIX):]
    return out


def issue_place_email(registry: CanaryTokenRegistry, domain: str, place: str) -> str:
    """Return the address for ``place`` (one per place; idempotent)."""
    if not _PLACE_RE.match(place):
        raise ValueError(f"place name must match {_PLACE_RE.pattern!r}: {place!r}")
    existing = {p: a for a, p in _place_by_alias(registry).items()}
    if place in existing:
        return f"{existing[place]}@{domain}"
    if len(existing) >= FREE_TIER_MAX_ADDRESSES:
        raise ValueError(
            f"{len(existing)} places already hold an address; more than "
            f"{FREE_TIER_MAX_ADDRESSES} could exceed the free domain-monitoring tier"
        )
    return issue_query_canary(registry, "email", PLACE_PREFIX + place, domain=domain).value


def locate(
    registry: CanaryTokenRegistry, breached: dict[str, list[str]]
) -> tuple[list[Hit], list[str]]:
    """Map ``{alias: [breach names]}`` to (hits on our decoys, unknown aliases).

    Unknown aliases are addresses on the watched domain that are not in
    the table (a real user or an address leaked from somewhere we did
    not seed); report them, do not drop them.
    """
    table = _place_by_alias(registry)
    hits = [
        Hit(table[a.lower()], a.lower(), tuple(b))
        for a, b in breached.items()
        if a.lower() in table
    ]
    unknown = sorted(a for a in breached if a.lower() not in table)
    return hits, unknown
