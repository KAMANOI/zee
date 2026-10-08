"""郵便番号 lookup — day one usable against Japan Post's KEN_ALL.CSV /
utf_all.csv as-is (confirmed public-domain by Japan Post: "郵便番号データ
に限っては日本郵便株式会社は著作権を主張しません。自由に配布していただい
て結構です。" — see design doc §3). v1 only needs columns 郵便番号/町域名,
so this loader works unmodified against the real file's layout; the
fixture used in tests mirrors just those columns.
"""

from __future__ import annotations

import csv
from pathlib import Path

# KEN_ALL.CSV / utf_all.csv column indices for 郵便番号 (2) and 町域名 (8).
_ZIP_COL = 2
_TOWN_COL = 8


def load_zip_by_town(path: Path) -> dict[str, str]:
    """town name -> zipcode, last match wins (town names aren't 1:1 with
    zipcodes in the real file; good enough for a plausible-looking fill-in,
    not an authoritative reverse lookup)."""
    out: dict[str, str] = {}
    with Path(path).open(encoding="utf-8", newline="") as f:
        for row in csv.reader(f):
            if len(row) <= max(_ZIP_COL, _TOWN_COL):
                continue
            out[row[_TOWN_COL].strip()] = row[_ZIP_COL].strip()
    return out


def zip_for_town(rng, town: str, zip_by_town: dict[str, str], fallback: str) -> str:
    """A zip for ``town``, or — if unmatched (always true for a Layer-1
    fictional town) — a real zip drawn from the same dataset rather than
    a fixed placeholder. A constant fallback (e.g. "0000000") would be a
    value-level tell: every Layer-1 row would carry an identical,
    obviously-fake zip, greppable without even needing the ledger."""
    if town in zip_by_town:
        return zip_by_town[town]
    if zip_by_town:
        return rng.choice(sorted(set(zip_by_town.values())))
    return fallback
