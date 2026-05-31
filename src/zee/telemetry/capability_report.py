"""Capability matrix — single source of truth (spec §9, v0.2).

Describes what each OS backend can / cannot detect, regardless of which
OS this code currently runs on. Used by `zee capability` and the README.

The macOS / Windows columns depend on whether the operator has wired
a canary URL receiver (ZEE_CANARY_BASE_URL). Call ``render_text()`` or
``get_matrix()`` with ``canary_configured`` so the rendered output
matches the live configuration.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class StaticCapability:
    os: str
    backend: str
    detects_open: Optional[bool]
    detects_read: Optional[bool]
    detects_modify: Optional[bool]
    uses_canary_fallback: bool
    status: str  # "implemented" / "planned" / "limited"
    notes: str


def get_matrix(*, canary_configured: bool = False) -> tuple[StaticCapability, ...]:
    """Return the per-OS capability rows for the current configuration.

    Linux is unaffected by canary configuration (inotify observes reads
    directly). macOS / Windows toggle based on whether the seeder is
    wired to embed canary URLs.
    """
    if canary_configured:
        macos_backend = "kqueue/EVFILT_VNODE + canary URL (out-of-band)"
        macos_status = "implemented (change-direct + read-via-canary)"
        macos_notes = (
            "kqueue/EVFILT_VNODE for change detection. Read detection is "
            "delegated to canary URLs embedded in decoys by the seeder; "
            "the operator's external endpoint fires when an attacker "
            "dereferences the URL. The fire never re-enters Zee's local "
            "responder."
        )
        windows_backend = "ReadDirectoryChangesW + canary URL (out-of-band)"
        windows_status = "implemented (change-direct + read-via-canary; untested on Windows hardware)"
        windows_notes = (
            "ReadDirectoryChangesW for change detection on the parent "
            "directory. Read detection is delegated to canary URLs "
            "embedded in decoys by the seeder; the operator's external "
            "endpoint fires when an attacker dereferences the URL."
        )
    else:
        macos_backend = "kqueue/EVFILT_VNODE"
        macos_status = "implemented (change-only; set ZEE_CANARY_BASE_URL for read)"
        macos_notes = (
            "kqueue/EVFILT_VNODE for change detection. Set "
            "ZEE_CANARY_BASE_URL to wire the canary URL path; without "
            "it, read-only attacker activity against a macOS decoy is "
            "not observed."
        )
        windows_backend = "ReadDirectoryChangesW"
        windows_status = "implemented (change-only; set ZEE_CANARY_BASE_URL for read; untested on Windows hardware)"
        windows_notes = (
            "ReadDirectoryChangesW for change detection on the parent "
            "directory. Set ZEE_CANARY_BASE_URL to wire the canary URL "
            "path; without it, read-only attacker activity against a "
            "Windows decoy is not observed."
        )
    return (
        StaticCapability(
            os="Linux",
            backend="inotify (kernel)",
            detects_open=True,
            detects_read=True,
            detects_modify=True,
            uses_canary_fallback=False,
            status="implemented",
            notes=(
                "IN_ACCESS / IN_OPEN / IN_MODIFY. Standard library only "
                "(ctypes). No extra package needed."
            ),
        ),
        StaticCapability(
            os="macOS",
            backend=macos_backend,
            detects_open=False,
            detects_read=False,
            detects_modify=True,
            uses_canary_fallback=canary_configured,
            status=macos_status,
            notes=macos_notes,
        ),
        StaticCapability(
            os="Windows",
            backend=windows_backend,
            detects_open=False,
            detects_read=False,
            detects_modify=True,
            uses_canary_fallback=canary_configured,
            status=windows_status,
            notes=windows_notes,
        ),
    )


# Backwards-compatible static MATRIX (assumes canary is not configured).
# Prefer ``get_matrix(canary_configured=...)`` in new code.
MATRIX: tuple[StaticCapability, ...] = get_matrix(canary_configured=False)


def render_markdown(*, canary_configured: bool = False) -> str:
    """Markdown matrix suitable for inclusion in README."""
    matrix = get_matrix(canary_configured=canary_configured)
    header = "| OS | Backend | open | read | modify | canary fallback | status |"
    sep = "|---|---|---|---|---|---|---|"
    rows = [
        f"| {c.os} | {c.backend} | "
        f"{_yn(c.detects_open)} | {_yn(c.detects_read)} | {_yn(c.detects_modify)} | "
        f"{'yes' if c.uses_canary_fallback else 'no'} | {c.status} |"
        for c in matrix
    ]
    notes = "\n\n".join(f"- **{c.os}** — {c.notes}" for c in matrix)
    return "\n".join([header, sep, *rows, "", notes])


def render_text(*, canary_configured: bool = False) -> str:
    """Plain-text matrix for `zee capability`."""
    lines: list[str] = []
    for c in get_matrix(canary_configured=canary_configured):
        lines.append(f"{c.os}  [{c.status}]")
        lines.append(f"  backend             : {c.backend}")
        lines.append(f"  detects_open        : {_yn(c.detects_open)}")
        lines.append(f"  detects_read        : {_yn(c.detects_read)}")
        lines.append(f"  detects_modify      : {_yn(c.detects_modify)}")
        lines.append(f"  uses_canary_fallback: {'yes' if c.uses_canary_fallback else 'no'}")
        lines.append(f"  notes               : {c.notes}")
        lines.append("")
    return "\n".join(lines)


def _yn(b: Optional[bool]) -> str:
    if b is None:
        return "—"
    return "yes" if b else "no"
