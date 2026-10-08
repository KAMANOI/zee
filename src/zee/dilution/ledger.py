"""Holder-only ledger: lets the operator tell their own dummies apart
without putting any marker on the dummy record itself (design doc §5).

record_hmac is HMAC-SHA256 keyed on the operator's secret seed, over a
canonical join of the record's fields. Leaking the ledger alone (without
the seed) does not let anyone recompute which real-looking rows are
dummies, and the public generator source code alone doesn't either.
"""

from __future__ import annotations

import hmac
import json
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path


def canonical_record(fields: dict[str, str]) -> str:
    """Fixed field order so the same record always hashes the same way."""
    order = ("surname", "given_name", "gender", "age", "postal_code",
             "address", "phone", "email")
    return "\x1f".join(str(fields.get(k, "")) for k in order)


def record_hmac(fields: dict[str, str], seed: str) -> str:
    key = seed.encode("utf-8")
    msg = canonical_record(fields).encode("utf-8")
    return hmac.new(key, msg, sha256).hexdigest()


@dataclass(frozen=True)
class LedgerEntry:
    dummy_id: str
    record_hmac: str


def write_ledger(path: Path, entries: list[LedgerEntry]) -> None:
    with Path(path).open("w", encoding="utf-8") as f:
        for e in entries:
            f.write(json.dumps({"dummy_id": e.dummy_id, "record_hmac": e.record_hmac},
                                ensure_ascii=False) + "\n")


def is_dummy(fields: dict[str, str], seed: str, ledger_hmacs: frozenset[str]) -> bool:
    """What the operator runs per real-data row to recognize their own dummies."""
    return record_hmac(fields, seed) in ledger_hmacs
