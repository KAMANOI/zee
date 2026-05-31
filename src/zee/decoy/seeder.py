"""Decoy seeder — places plausible-looking decoy files on disk (spec §1, §6).

Decoy contents are intentionally non-secret. Anyone who reads them learns
nothing real about the host. Their only purpose is to be touched by an
intruder, generating a high-confidence TrapEvent.
"""

from __future__ import annotations

import os
from datetime import datetime, timezone
from pathlib import Path

from ..errors import ZeeError, Z201_DECOY_PATH_NOT_WRITABLE

# Plausible-looking, intentionally non-secret content. The credentials,
# keys, and hostnames below are fabricated and do not authenticate to
# anything real. They exist solely to bait reads.
#
# Marker strings deliberately include underscores so they do NOT match
# the actual production regular expressions used by Stripe/AWS/GitHub
# secret scanners:
#   - AWS access keys:   AKIA[0-9A-Z]{16}            (no underscores)
#   - Stripe live keys:  sk_live_[A-Za-z0-9]{24,}    (no underscores after prefix)
# An attacker doing surface inspection still sees credential-shaped strings,
# but no real scanner will fire a false positive on the decoy contents
# (which would cascade into the operator's own AWS / Stripe / GitHub).
# Adjacent-literal splitting is kept to also keep this source file itself
# scanner-clean for pre-commit hooks.
_AWS_KEY_PREFIX = "A" "KIA"  # split so this source isn't itself flagged
_AWS_KEY = _AWS_KEY_PREFIX + "_DECOY_NOT_REAL"          # has _, breaks AWS regex
_AWS_SECRET = "zee_decoy_not_real_aws_secret_xxxxxxxxxx"
_STRIPE_KEY = "s" "k_" "live_" + "ZEE_DECOY_NOT_REAL_dummy_value"  # has _, breaks Stripe regex
_PEM_BEGIN = "-----" "BEGIN " "OPENSSH PRIVATE KEY" "-----"
_PEM_END = "-----" "END " "OPENSSH PRIVATE KEY" "-----"

_TEMPLATES: dict[str, str] = {
    "credentials": (
        "# DO NOT COMMIT — zee decoy file, not real credentials\n"
        "# rotated quarterly, last touched {ts}\n"
        "[default]\n"
        f"aws_access_key_id = {_AWS_KEY}\n"
        f"aws_secret_access_key = {_AWS_SECRET}\n"
    ),
    "env": (
        "# local overrides, do not check in — zee decoy file\n"
        "DATABASE_URL=postgres://decoy:decoy@db.internal:5432/app\n"
        "JWT_SECRET=zee_decoy_not_a_real_secret\n"
        f"STRIPE_SECRET_KEY={_STRIPE_KEY}\n"
    ),
    "ssh_key": (
        f"{_PEM_BEGIN}\n"
        + "DECOY" * 11 + "\n"
        + "DECOY" * 11 + "\n"
        + f"{_PEM_END}\n"
    ),
    "notes": (
        "internal notes — DO NOT SHARE\n"
        "- Q3 roadmap (draft)\n"
        "- customer pricing model v2\n"
        "- partner integration credentials in vault://prod/partner-x\n"
    ),
}


def _pick_template(path: Path) -> str:
    name = path.name.lower()
    if "credential" in name:
        return "credentials"
    if name.endswith(".env") or "env" in name:
        return "env"
    if "id_rsa" in name or "ssh" in name or name.endswith(".pem"):
        return "ssh_key"
    return "notes"


def seed(path: Path) -> Path:
    """Create a decoy file at `path` if it does not already exist.

    Existing files are left alone (an attacker may already have touched them;
    overwriting would corrupt the evidence).
    """
    path = path.expanduser().resolve()
    parent = path.parent
    parent_existed = parent.exists()
    parent.mkdir(parents=True, exist_ok=True)
    # Tighten the parent directory only when Zee created it: a 0755 default
    # would let other local users enumerate decoy filenames. We do not
    # narrow an existing dir's mode (the operator may have placed decoys
    # under a path with its own policy). Best-effort: Windows ignores
    # POSIX mode; some filesystems reject chmod.
    if not parent_existed:
        try:
            os.chmod(parent, 0o700)
        except (OSError, NotImplementedError):
            pass
    if path.exists():
        return path
    template = _TEMPLATES[_pick_template(path)]
    content = template.format(ts=datetime.now(timezone.utc).isoformat())
    try:
        path.write_text(content, encoding="utf-8")
        # 0600 so the decoy looks like a real secret file
        os.chmod(path, 0o600)
    except OSError as e:
        raise ZeeError(Z201_DECOY_PATH_NOT_WRITABLE, f"{path}: {e}") from e
    return path


def seed_all(paths: list[str]) -> list[Path]:
    return [seed(Path(p)) for p in paths]
