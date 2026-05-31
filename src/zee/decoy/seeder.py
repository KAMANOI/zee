"""Decoy seeder — places plausible-looking decoy files on disk (spec §1, §6).

Decoy contents are intentionally non-secret. Anyone who reads them learns
nothing real about the host. Their only purpose is to be touched by an
intruder, generating a high-confidence TrapEvent.

Canary URL embedding (v0.2):
    When a configured CanaryTokenRegistry is passed, the env /
    credentials / notes templates have one extra line / value swapped
    for a canary URL pointing at the operator's external endpoint.
    The ssh_key template is left alone (an OpenSSH-formatted block
    cannot host an URL without breaking the format).

    The embedded canary line contains NO Zee-origin tokens
    (``canary``, ``zee``, ``tripwire``, ``decoy``). The URL itself is
    ``base_url/<token_id>`` — whatever shape the operator chose for
    base_url is what an attacker sees.

    Existing decoy files are NOT rewritten on subsequent seed runs
    (the v0.1 evidence-preservation rule). The registry's persisted
    map remains the authoritative record of which URL is in which
    decoy across restarts.
"""

from __future__ import annotations

import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from ..errors import ZeeError, Z201_DECOY_PATH_NOT_WRITABLE
from .canary_token import CanaryTokenRegistry

# Plausible-looking, intentionally non-secret content. The credentials,
# keys, and hostnames below are fabricated and do not authenticate to
# anything real. They exist solely to bait reads.
#
# Crucial: the file contents must look like ordinary internal secrets
# to an attacker reading them. The strings ``zee`` / ``decoy`` /
# ``tripwire`` / ``canary`` MUST NOT appear in the rendered output —
# an attacker who `grep`s for those words would otherwise spot every
# decoy at once and avoid them. This is enforced by tests
# (see tests/test_seeder_canary.py _FORBIDDEN_MARKERS).
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
_AWS_KEY = _AWS_KEY_PREFIX + "_PLACEHOLDER_NOT_REAL"     # has _, breaks AWS regex
_AWS_SECRET = "placeholder_not_real_aws_secret_xxxxxxxx"
_STRIPE_KEY = "s" "k_" "live_" + "INTERNAL_NOT_REAL_dummy_value"  # has _, breaks Stripe regex
_PEM_BEGIN = "-----" "BEGIN " "OPENSSH PRIVATE KEY" "-----"
_PEM_END = "-----" "END " "OPENSSH PRIVATE KEY" "-----"
# Random-looking armor body (no Zee-origin tokens). 11 groups × 5 chars
# preserves the original block length so an attacker comparing widths
# does not get a hint.
_PEM_BODY_LINE = "XK7HD" "QM3FP" "VB2RS" "JT9YA" "WC4LE" "ZN6UI" "GO8HX" "MK1PQ" "DF5VR" "BS7TY" "CL3WA"

# Placeholder URL in the notes template; replaced by a canary URL when
# the registry is configured. Kept as a vault:// scheme so the no-canary
# behaviour still produces a plausible-looking line.
_NOTES_PLACEHOLDER = "vault://prod/partner-x"

_TEMPLATES: dict[str, str] = {
    "credentials": (
        "# DO NOT COMMIT — internal credentials, not for VCS\n"
        "# rotated quarterly, last touched {ts}\n"
        "[default]\n"
        f"aws_access_key_id = {_AWS_KEY}\n"
        f"aws_secret_access_key = {_AWS_SECRET}\n"
    ),
    "env": (
        "# local overrides, do not check in\n"
        "DATABASE_URL=postgres://app:placeholder@db.internal:5432/app\n"
        "JWT_SECRET=internal_dev_only_xxxxxxxxxxxxxxxx\n"
        f"STRIPE_SECRET_KEY={_STRIPE_KEY}\n"
    ),
    "ssh_key": (
        f"{_PEM_BEGIN}\n"
        + _PEM_BODY_LINE + "\n"
        + _PEM_BODY_LINE + "\n"
        + f"{_PEM_END}\n"
    ),
    "notes": (
        "internal notes — DO NOT SHARE\n"
        "- Q3 roadmap (draft)\n"
        "- customer pricing model v2\n"
        f"- partner integration credentials in {_NOTES_PLACEHOLDER}\n"
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


def _embed_canary(template_key: str, base_content: str, canary_url: str) -> str:
    """Mix a canary URL into the rendered template body.

    The choice of phrasing is deliberate: nothing in the inserted line
    references Zee. An attacker grepping for ``canary`` / ``tripwire``
    / ``zee`` in the file finds nothing.

    ssh_key is intentionally skipped: the OpenSSH armor format does
    not survive a foreign URL embedded inside it.
    """
    if template_key == "credentials":
        return (
            base_content.rstrip()
            + f"\n# rotation policy: {canary_url}\n"
        )
    if template_key == "env":
        return (
            base_content.rstrip()
            + f"\nMONITORING_ENDPOINT={canary_url}\n"
        )
    if template_key == "notes":
        return base_content.replace(_NOTES_PLACEHOLDER, canary_url)
    # ssh_key: do not embed.
    return base_content


def seed(path: Path, registry: Optional[CanaryTokenRegistry] = None) -> Path:
    """Create a decoy file at `path` if it does not already exist.

    Existing files are left alone (an attacker may already have touched them;
    overwriting would corrupt the evidence).

    When ``registry`` is supplied AND configured, the rendered content
    has a canary URL mixed in (env / credentials / notes templates).
    The registry's idempotent ``issue_for_decoy`` is used so reseeding
    the same decoy_path yields the same URL across restarts.
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
    template_key = _pick_template(path)
    base = _TEMPLATES[template_key].format(ts=datetime.now(timezone.utc).isoformat())
    content = base
    if (
        registry is not None
        and registry.is_configured
        and template_key in ("credentials", "env", "notes")
    ):
        token = registry.issue_for_decoy(
            decoy_path=str(path),
            purpose=f"decoy_{template_key}",
        )
        content = _embed_canary(template_key, base, token.full_url)
    try:
        path.write_text(content, encoding="utf-8")
        # 0600 so the decoy looks like a real secret file
        os.chmod(path, 0o600)
    except OSError as e:
        raise ZeeError(Z201_DECOY_PATH_NOT_WRITABLE, f"{path}: {e}") from e
    return path


def seed_all(
    paths: list[str],
    registry: Optional[CanaryTokenRegistry] = None,
) -> list[Path]:
    return [seed(Path(p), registry=registry) for p in paths]
