"""Seed credential-shaped decoys into the disposable sandbox HOME.

Same idea as Zee's canary decoys, scoped to one throwaway run: plant
files that look exactly like the secrets an info-stealer hunts for, each
carrying a unique, unguessable token. We never plant a real secret, so
even a total sandbox escape would leak only bait. If a token later
appears in the artifact's outbound traffic, that is the decisive
"read a credential AND tried to exfiltrate it" signal (G801).

stdlib only; tokens via ``secrets`` so they cannot be predicted or
grepped for by a Zee-specific marker.
"""

from __future__ import annotations

import os
import secrets
from dataclasses import dataclass
from pathlib import Path

# The PEM markers are assembled from fragments so the *source* never
# contains a contiguous "BEGIN <kind> PRIVATE KEY" string (which secret
# scanners — including our own pre-commit hook — would flag as a real
# leaked key). The generated decoy file still carries the full, realistic
# header so it reads as genuine bait to an attacker.
_PK = "OPENSSH PRIVATE KEY"
_SSH_DECOY = "-----BEGIN " + _PK + "-----\n{tok}\n-----END " + _PK + "-----\n"

# (relative path under HOME, template with a {tok} slot). These mirror
# the credential paths the static scanner already flags (G601) so the
# behavioural layer covers the same threat from the runtime side.
_DECOY_FILES: tuple[tuple[str, str], ...] = (
    (".ssh/id_rsa", _SSH_DECOY),
    (".aws/credentials",
     "[default]\naws_access_key_id = AKIA{tok_upper}\naws_secret_access_key = {tok}\n"),
    (".env",
     "API_KEY={tok}\nDATABASE_URL=postgres://user:{tok}@localhost/db\n"),
    (".npmrc",
     "//registry.npmjs.org/:_authToken={tok}\n"),
    (".config/gh/hosts.yml",
     "github.com:\n    oauth_token: {tok}\n    user: zee-decoy\n"),
)


@dataclass(frozen=True)
class SeededDecoys:
    home: Path
    by_token: dict[str, str]  # token -> relative path it was planted in

    @property
    def tokens(self) -> frozenset[str]:
        return frozenset(self.by_token)

    def path_for(self, token: str) -> str:
        return self.by_token.get(token, "?")


def seed(home: Path) -> SeededDecoys:
    """Plant the decoy credential files under ``home`` (owner-only)."""
    home = Path(home)
    by_token: dict[str, str] = {}
    for rel, template in _DECOY_FILES:
        tok = "zc_" + secrets.token_hex(16)
        content = template.format(tok=tok, tok_upper=tok.upper())
        dest = home / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(content, encoding="utf-8")
        try:
            os.chmod(dest, 0o600)
        except (OSError, NotImplementedError):
            pass
        by_token[tok] = rel
    return SeededDecoys(home=home, by_token=by_token)


def decoy_relpaths() -> list[str]:
    """The relative paths seed() plants — used to baseline access times."""
    return [rel for rel, _ in _DECOY_FILES]
