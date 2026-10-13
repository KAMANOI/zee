"""Holder-only ledger: lets the operator tell their own dummies apart
without putting any marker on the dummy record itself (design doc §5).

record_hmac is HMAC-SHA256 keyed on the operator's secret seed, over a
canonical join of the record's fields. Leaking the ledger alone (without
the seed) does not let anyone recompute which real-looking rows are
dummies, and the public generator source code alone doesn't either.

The ledger carries nothing but the HMAC list — no separate id that
could itself correlate back to a record (e.g. if that id were ever also
embedded in the record, as an earlier draft of this module's caller
mistakenly did for the user-domain email option; see generate.py).
"""

from __future__ import annotations

import hmac
import json
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


def write_ledger(path: Path, hmacs: list[str]) -> None:
    with Path(path).open("w", encoding="utf-8") as f:
        for h in hmacs:
            f.write(json.dumps({"record_hmac": h}, ensure_ascii=False) + "\n")


def load_ledger_hmacs(path: Path) -> frozenset[str]:
    with Path(path).open(encoding="utf-8") as f:
        return frozenset(json.loads(line)["record_hmac"] for line in f if line.strip())


def is_dummy(fields: dict[str, str], seed: str, ledger_hmacs: frozenset[str]) -> bool:
    """What the operator runs per real-data row to recognize their own dummies."""
    return record_hmac(fields, seed) in ledger_hmacs
