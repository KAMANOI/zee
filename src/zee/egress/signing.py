"""What the approver signs, and how a signature is checked.

The signed bytes are a domain-separated digest of the *whole* request
payload (destination, volume cap, data ids, expiry, nonce, match code…).
Zee compares the submitted payload to the request it actually issued, so
what the phone showed, what was signed and what is let through cannot differ.

Signature checking sits behind `Verifier` because the standard library has
no ECDSA. `OpensslVerifier` shells out to the openssl CLI (the same style as
Zee's pfctl/nft/netsh calls); an optional `cryptography` backend is a
drop-in alternative (see the design doc).
"""
from __future__ import annotations

import hashlib
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Protocol

from ..telemetry.events_log import _canonical_json

DOMAIN = b"zee-egress-approval-v1\x00"


def payload_digest(payload: dict) -> bytes:
    """Digest the approver signs (the WebAuthn challenge / Enclave message)."""
    return hashlib.sha256(DOMAIN + _canonical_json(payload).encode("utf-8")).digest()


class Verifier(Protocol):
    def verify(self, public_key: str, digest: bytes, signature: bytes) -> bool: ...


class OpensslVerifier:
    """ES256 (P-256, SHA-256, DER signature) via `openssl pkeyutl -verify`.

    `public_key` is a PEM public key. `digest` is the pre-hashed message, so
    the raw-digest verify is used and nothing is hashed twice.
    Any failure — missing openssl, bad PEM, bad signature — is "not verified".
    """

    def __init__(self, openssl: str | None = None) -> None:
        self.openssl = openssl or shutil.which("openssl")

    def verify(self, public_key: str, digest: bytes, signature: bytes) -> bool:
        if not self.openssl or len(digest) != 32 or not signature:
            return False
        with tempfile.TemporaryDirectory(prefix="zee-verify-") as d:
            key, sig, dig = (Path(d) / n for n in ("k.pem", "s.der", "d.bin"))
            key.write_text(public_key)
            sig.write_bytes(signature)
            dig.write_bytes(digest)
            try:
                cp = subprocess.run(
                    [self.openssl, "pkeyutl", "-verify", "-pubin", "-inkey", str(key),
                     "-in", str(dig), "-sigfile", str(sig)],
                    capture_output=True, timeout=10,
                )
            except (subprocess.SubprocessError, OSError):
                return False
        return cp.returncode == 0
