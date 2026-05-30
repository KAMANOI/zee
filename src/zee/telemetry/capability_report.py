"""Capability matrix — static, single source of truth (spec §9).

Describes what each OS backend can / cannot detect, regardless of which
OS this code currently runs on. Used by `zee capability` and pasted into
the README so what we claim and what we deliver stay aligned.
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


MATRIX: tuple[StaticCapability, ...] = (
    StaticCapability(
        os="Linux",
        backend="inotify (kernel)",
        detects_open=True,
        detects_read=True,
        detects_modify=True,
        uses_canary_fallback=False,
        status="implemented",
        notes=(
            "IN_ACCESS / IN_OPEN / IN_MODIFY. Standard library only (ctypes). "
            "No extra package needed."
        ),
    ),
    StaticCapability(
        os="macOS",
        backend="kqueue/EVFILT_VNODE + canary token fallback",
        detects_open=False,
        detects_read=False,
        detects_modify=True,
        uses_canary_fallback=True,
        status="implemented",
        notes=(
            "kqueue for change detection only. Reliable read detection requires "
            "the Endpoint Security framework (entitlement); v1 relies on "
            "canary URLs embedded in decoys for read signals."
        ),
    ),
    StaticCapability(
        os="Windows",
        backend="ReadDirectoryChangesW + canary token fallback",
        detects_open=False,
        detects_read=False,
        detects_modify=True,
        uses_canary_fallback=True,
        status="implemented (untested on Windows hardware)",
        notes=(
            "ReadDirectoryChangesW for change detection on the parent directory. "
            "Reliable read auditing requires Object Access auditing (SACL + Event "
            "Log); v1 relies on canary URLs embedded in decoys for read signals."
        ),
    ),
)


def render_markdown() -> str:
    """Markdown matrix suitable for inclusion in README."""
    header = "| OS | Backend | open | read | modify | canary fallback | status |"
    sep = "|---|---|---|---|---|---|---|"
    rows = [
        f"| {c.os} | {c.backend} | "
        f"{_yn(c.detects_open)} | {_yn(c.detects_read)} | {_yn(c.detects_modify)} | "
        f"{'yes' if c.uses_canary_fallback else 'no'} | {c.status} |"
        for c in MATRIX
    ]
    notes = "\n\n".join(f"- **{c.os}** — {c.notes}" for c in MATRIX)
    return "\n".join([header, sep, *rows, "", notes])


def render_text() -> str:
    """Plain-text matrix for `zee capability`."""
    lines: list[str] = []
    for c in MATRIX:
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
