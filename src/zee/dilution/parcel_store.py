"""Seed-encrypted side file recording which real chiban each Layer-2 dummy
used, so `refresh` can re-check them later (design doc §8) without putting
any chiban in the ledger (§5: the ledger stays HMAC-only).

Stdlib only (core is dependency-free): PBKDF2 key from the seed, HMAC-SHA256
in counter mode as the keystream, encrypt-then-MAC. Without the seed the
file reveals nothing; a wrong seed or any tampering fails the tag check.
# ponytail: homemade stream construction — swap for AES-GCM if a
# cryptography dependency is ever accepted.
"""

from __future__ import annotations

import hmac
import json
import os
from hashlib import pbkdf2_hmac, sha256
from pathlib import Path

from ..errors import Z810_PARCEL_STORE_UNREADABLE, ZeeError

_MAGIC = b"ZEEPS1"
_ITER = 200_000


def _keys(seed: str, salt: bytes) -> tuple[bytes, bytes]:
    k = pbkdf2_hmac("sha256", seed.encode("utf-8"), salt, _ITER, dklen=64)
    return k[:32], k[32:]


def _stream(key: bytes, nonce: bytes, n: int) -> bytes:
    out = bytearray()
    i = 0
    while len(out) < n:
        out += hmac.new(key, nonce + i.to_bytes(8, "big"), sha256).digest()
        i += 1
    return bytes(out[:n])


def write_store(path: Path, seed: str, entries: list[dict]) -> None:
    """entries: [{"chiban": str, "town": str, "hmacs": [record_hmac, ...]}]"""
    salt, nonce = os.urandom(16), os.urandom(16)
    ek, mk = _keys(seed, salt)
    pt = json.dumps(entries, ensure_ascii=False).encode("utf-8")
    ct = bytes(a ^ b for a, b in zip(pt, _stream(ek, nonce, len(pt))))
    body = _MAGIC + salt + nonce + ct
    Path(path).write_bytes(body + hmac.new(mk, body, sha256).digest())


def read_store(path: Path, seed: str) -> list[dict]:
    raw = Path(path).read_bytes()
    hdr = len(_MAGIC) + 32
    if len(raw) < hdr + 32 or not raw.startswith(_MAGIC):
        raise ZeeError(Z810_PARCEL_STORE_UNREADABLE)
    body, tag = raw[:-32], raw[-32:]
    salt, nonce = body[len(_MAGIC):len(_MAGIC) + 16], body[len(_MAGIC) + 16:hdr]
    ek, mk = _keys(seed, salt)
    if not hmac.compare_digest(tag, hmac.new(mk, body, sha256).digest()):
        raise ZeeError(Z810_PARCEL_STORE_UNREADABLE)
    ct = body[hdr:]
    return json.loads(bytes(a ^ b for a, b in zip(ct, _stream(ek, nonce, len(ct)))))
