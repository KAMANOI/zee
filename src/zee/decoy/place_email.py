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
import sys
from dataclasses import dataclass
from pathlib import Path

from ..responder.permission import HostLock  # fcntl on POSIX, msvcrt on Windows
from .canary_token import CanaryTokenRegistry
from .query_canary import _check_domain as check_domain
from .query_canary import issue_query_canary

PLACE_PREFIX = "place:"
# HIBP's free domain monitoring covers a domain with <=10 breached addresses
# (https://haveibeenpwned.com/Subscription). One address per place means at
# most len(places) addresses can ever be breached on this domain.
FREE_TIER_MAX_ADDRESSES = 10
_PLACE_RE = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,62}$")
_ALIAS_RE = re.compile(r"^[0-9a-f]{32}$")  # issue_query_canary's token shape
_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


def check_domain_syntax(domain: str) -> None:
    """Lowercase hostname, >=2 labels of 1-63 chars, <=253 total."""
    labels = domain.split(".")
    if len(domain) > 253 or len(labels) < 2 or not all(_LABEL_RE.match(x) for x in labels):
        raise ValueError(f"not a valid mail domain: {domain!r}")


@dataclass(frozen=True)
class Hit:
    place: str
    alias: str
    breaches: tuple[str, ...]


def _records(registry: CanaryTokenRegistry) -> list[tuple[str, str, str]]:
    """(alias, place, domain) for every place record. A corrupt table stops
    the run (raises) instead of being read as "no such decoy"."""
    out: list[tuple[str, str, str]] = []
    path = registry.registry_path
    if not path.exists():
        return out
    # Windows: POSIX bits are not the ACL; not checked (as recovery/auth.py).
    if sys.platform != "win32" and path.stat().st_mode & 0o077:
        raise PermissionError(f"{path} must be owner-only (0600)")
    aliases: set[str] = set()
    places: set[str] = set()
    for n, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not raw.strip():
            continue
        try:
            rec = json.loads(raw)
            purpose, alias = rec["purpose"], rec["decoy_path"]
        except (json.JSONDecodeError, KeyError, TypeError) as e:
            raise ValueError(f"{path}:{n} is not a valid mapping record") from e
        if not isinstance(purpose, str) or not purpose.startswith(PLACE_PREFIX):
            continue
        place, _, domain = purpose[len(PLACE_PREFIX):].partition("|")
        alias = alias.rsplit("/", 1)[-1] if isinstance(alias, str) else ""
        try:
            if not _ALIAS_RE.match(alias) or not _PLACE_RE.match(place):
                raise ValueError("bad alias or place")
            check_domain_syntax(domain)
        except ValueError as e:
            raise ValueError(f"{path}:{n} is not a valid mapping record") from e
        if alias in aliases or place in places:  # would mis-attribute a hit
            raise ValueError(f"{path}:{n} duplicates alias or place {place!r}; table is corrupt")
        aliases.add(alias)
        places.add(place)
        out.append((alias, place, domain))
    return out


def issue_place_email(registry: CanaryTokenRegistry, domain: str, place: str) -> str:
    """Return the address for ``place`` (one per place; idempotent).

    Serialised by a lock file next to the table so two runs cannot both
    pass the cap or mint two addresses for one place.
    """
    domain = domain.strip().lower()
    if not _PLACE_RE.match(place):
        raise ValueError(f"place name must match {_PLACE_RE.pattern!r}: {place!r}")
    check_domain_syntax(domain)
    check_domain(domain)  # also for an already-issued place
    with HostLock(Path(str(registry.registry_path) + ".lock")):
        recs = _records(registry)
        for alias, p, d in recs:
            if p == place:
                if d != domain:
                    raise ValueError(f"{place!r} already has an address on another domain")
                return f"{alias}@{domain}"
        if len({p for _, p, _ in recs}) >= FREE_TIER_MAX_ADDRESSES:
            raise ValueError(
                f"{FREE_TIER_MAX_ADDRESSES} places already hold an address; more could "
                "exceed the free domain-monitoring tier"
            )
        value = issue_query_canary(
            registry, "email", f"{PLACE_PREFIX}{place}|{domain}", domain=domain
        ).value
        _records(registry)  # re-validate: a token collision raises here
        return value


def locate(
    registry: CanaryTokenRegistry, domain: str, breached: dict[str, list[str]]
) -> tuple[list[Hit], list[str]]:
    """Map ``{alias: [breach names]}`` for ``domain`` to (candidate places, unknown aliases).

    A hit means "this decoy was in the leaked data", i.e. the place is a
    *candidate* (a dump copied elsewhere carries its decoy along). Unknown
    aliases are addresses on the domain that are not in the table; report
    them, do not drop them.
    """
    domain = domain.strip().lower()
    table = {a: p for a, p, d in _records(registry) if d == domain}
    hits = [
        Hit(table[a.lower()], a.lower(), tuple(b))
        for a, b in breached.items()
        if a.lower() in table
    ]
    unknown = sorted(a for a in breached if a.lower() not in table)
    return hits, unknown
