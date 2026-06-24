"""Ingest existing scanners' output (interoperability, invariant I4).

Zee does not re-implement Semgrep / Snyk / Socket — it folds their
findings into the same verdict so a team runs one gate instead of
reconciling several reports. Supported inputs:

  * Semgrep JSON   (``semgrep --json``)            -> results[].check_id
  * SARIF 2.1.0    (Snyk, CodeQL, many CI scanners) -> runs[].results[]

Each imported finding becomes a ``G901`` flag carrying the source tool,
rule id and location, at a severity mapped from the tool's own. An
imported ``error`` / ``HIGH`` therefore drives the verdict to HIGH just
like a native finding. A file we cannot parse becomes a single ``G909``
notice rather than a crash, so a bad path never aborts an inspection.
stdlib only.
"""

from __future__ import annotations

import json
from pathlib import Path

from .model import Flag, Severity

# Map external severities (lowercased) onto Zee's three levels.
_SEVERITY = {
    "error": Severity.HIGH, "high": Severity.HIGH, "critical": Severity.HIGH,
    "warning": Severity.MEDIUM, "medium": Severity.MEDIUM, "moderate": Severity.MEDIUM,
    "note": Severity.LOW, "info": Severity.LOW, "low": Severity.LOW,
    "none": Severity.LOW,
}


def _sev(raw: object) -> Severity:
    return _SEVERITY.get(str(raw).strip().lower(), Severity.MEDIUM)


def _sanitize(s: str) -> str:
    # An imported report is attacker-influenced text; strip control chars
    # (ANSI escapes / CR / BEL) so it can't spoof or corrupt the terminal
    # when the verdict is rendered. Keep spaces, drop the rest non-printable.
    return "".join(c for c in s if c == " " or c.isprintable())


def _flag(tool: str, rule: str, sev: Severity, message: str, loc: str) -> Flag:
    where = f"{_sanitize(loc)}: " if loc else ""
    first_line = message.strip().splitlines()[0] if message else rule
    msg = _sanitize(first_line)
    return Flag(
        sev, "G901",
        f"imported from {_sanitize(tool)}: {_sanitize(rule)}",
        evidence=f"{where}{msg}"[:200],
    )


def _parse_semgrep(data: dict) -> list[Flag]:
    flags: list[Flag] = []
    for r in data.get("results", []):
        if not isinstance(r, dict):
            continue
        extra = r.get("extra", {}) if isinstance(r.get("extra"), dict) else {}
        rule = str(r.get("check_id", "rule"))
        sev = _sev(extra.get("severity", "warning"))
        message = str(extra.get("message", ""))
        start = r.get("start", {}) if isinstance(r.get("start"), dict) else {}
        loc = str(r.get("path", ""))
        if start.get("line"):
            loc = f"{loc}:{start['line']}"
        flags.append(_flag("semgrep", rule, sev, message, loc))
    return flags


def _parse_sarif(data: dict) -> list[Flag]:
    flags: list[Flag] = []
    for run in data.get("runs", []):
        if not isinstance(run, dict):
            continue
        tool = "sarif"
        driver = (run.get("tool", {}) or {}).get("driver", {})
        if isinstance(driver, dict) and driver.get("name"):
            tool = str(driver["name"])
        for r in run.get("results", []):
            if not isinstance(r, dict):
                continue
            rule = str(r.get("ruleId", "rule"))
            sev = _sev(r.get("level", "warning"))
            msg_obj = r.get("message", {})
            message = str(msg_obj.get("text", "")) if isinstance(msg_obj, dict) else ""
            loc = ""
            locs = r.get("locations", [])
            if isinstance(locs, list) and locs:
                phys = locs[0].get("physicalLocation", {}) if isinstance(locs[0], dict) else {}
                art = phys.get("artifactLocation", {}) if isinstance(phys, dict) else {}
                region = phys.get("region", {}) if isinstance(phys, dict) else {}
                loc = str(art.get("uri", ""))
                if region.get("startLine"):
                    loc = f"{loc}:{region['startLine']}"
            flags.append(_flag(tool, rule, sev, message, loc))
    return flags


def import_scan_file(path: str | Path) -> list[Flag]:
    """Parse one scanner report into flags (auto-detecting the format)."""
    p = Path(path)
    try:
        data = json.loads(p.read_text(encoding="utf-8", errors="ignore"))
    except (OSError, json.JSONDecodeError) as e:
        return [Flag(Severity.LOW, "G909",
                     "could not parse imported scan file",
                     evidence=f"{p}: {e}")]
    if not isinstance(data, dict):
        return [Flag(Severity.LOW, "G909",
                     "imported scan file is not a JSON object",
                     evidence=str(p))]
    # SARIF has "runs" (+ usually a sarif "version"); Semgrep has "results"
    # with check_id entries.
    if "runs" in data:
        return _parse_sarif(data)
    if "results" in data:
        return _parse_semgrep(data)
    return [Flag(Severity.LOW, "G909",
                 "unrecognised scan format (expected Semgrep JSON or SARIF)",
                 evidence=str(p))]


def import_scans(paths) -> list[Flag]:
    flags: list[Flag] = []
    for path in paths:
        flags += import_scan_file(path)
    return flags
