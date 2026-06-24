"""Phase 4 — ecosystem adapters + external scanner ingestion (interop)."""

from __future__ import annotations

import json

import pytest

from zee.gate.adapters import pick_adapter
from zee.gate.imports import import_scan_file, import_scans
from zee.gate.inspector import inspect_source
from zee.gate.model import ArtifactKind, RiskLevel


def _write(d, files):
    for rel, content in files.items():
        p = d / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content if isinstance(content, str) else json.dumps(content))
    return d


# ── adapters ────────────────────────────────────────────────────────────

def test_npm_adapter_detects_name_and_version(tmp_path):
    d = _write(tmp_path / "n", {"package.json": {
        "name": "left-pad", "version": "1.3.0",
        "scripts": {"postinstall": "node x.js"}}})
    art = pick_adapter(d).build(str(d), d)
    assert art.kind is ArtifactKind.NPM
    assert art.name == "left-pad" and art.version == "1.3.0"
    assert any("postinstall" in h for h in art.install_hooks)


def test_pypi_adapter_reads_pyproject(tmp_path):
    d = _write(tmp_path / "p", {
        "pyproject.toml": '[project]\nname = "reqs"\nversion = "2.1.0"\n',
        "setup.py": "from setuptools import setup\nsetup()\n"})
    art = pick_adapter(d).build(str(d), d)
    assert art.kind is ArtifactKind.PYPI
    assert art.name == "reqs" and art.version == "2.1.0"


def test_vscode_adapter_wins_over_npm_for_extensions(tmp_path):
    d = _write(tmp_path / "v", {"package.json": {
        "name": "theme", "version": "0.0.1",
        "engines": {"vscode": "^1.80.0"}, "contributes": {}}})
    art = pick_adapter(d).build(str(d), d)
    assert art.kind is ArtifactKind.VSCODE  # not misread as plain npm


def test_explicit_kind_overrides_autodetect(tmp_path):
    d = _write(tmp_path / "x", {"package.json": {"name": "p"}})
    assert pick_adapter(d, "pypi").kind is ArtifactKind.PYPI


def test_unknown_kind_raises(tmp_path):
    with pytest.raises(ValueError):
        pick_adapter(tmp_path, "nonsense")


# ── scanner ingestion (interop / I4) ────────────────────────────────────

def test_import_semgrep_maps_severity(tmp_path):
    f = tmp_path / "sg.json"
    f.write_text(json.dumps({"results": [
        {"check_id": "py.eval", "path": "a.py", "start": {"line": 7},
         "extra": {"severity": "ERROR", "message": "eval is bad"}}]}))
    flags = import_scan_file(f)
    assert len(flags) == 1
    assert flags[0].code == "G901" and flags[0].severity.value == "high"
    assert "semgrep" in flags[0].message and "a.py:7" in flags[0].evidence


def test_import_sarif_uses_driver_name_and_level(tmp_path):
    f = tmp_path / "snyk.sarif"
    f.write_text(json.dumps({"runs": [{
        "tool": {"driver": {"name": "Snyk"}},
        "results": [{"ruleId": "S1", "level": "warning",
                     "message": {"text": "vuln"},
                     "locations": [{"physicalLocation": {
                         "artifactLocation": {"uri": "i.js"},
                         "region": {"startLine": 3}}}]}]}]}))
    flags = import_scan_file(f)
    assert flags[0].code == "G901" and flags[0].severity.value == "medium"
    assert "Snyk" in flags[0].message and "i.js:3" in flags[0].evidence


def test_import_bad_file_is_a_notice_not_a_crash(tmp_path):
    f = tmp_path / "broken.json"
    f.write_text("{ this is not json")
    flags = import_scan_file(f)
    assert len(flags) == 1 and flags[0].code == "G909"


def test_import_unrecognised_format_is_notice(tmp_path):
    f = tmp_path / "weird.json"
    f.write_text(json.dumps({"hello": "world"}))
    assert import_scan_file(f)[0].code == "G909"


def test_imported_high_drives_verdict_high(tmp_path):
    pkg = _write(tmp_path / "pkg", {"package.json": {"name": "p"}})
    sg = tmp_path / "sg.json"
    sg.write_text(json.dumps({"results": [
        {"check_id": "r", "path": "a", "extra": {"severity": "ERROR", "message": "m"}}]}))
    v = inspect_source(str(pkg), import_scans=(str(sg),))
    assert v.risk_level is RiskLevel.HIGH
    assert "G901" in {f.code for f in v.flags}


def test_imported_evidence_strips_control_chars(tmp_path):
    """Regression (review 低): an attacker-authored report must not be able
    to inject terminal escape sequences into the rendered verdict."""
    f = tmp_path / "sg.json"
    f.write_text(json.dumps({"results": [
        {"check_id": "r\x1b[31m", "path": "a.py", "start": {"line": 1},
         "extra": {"severity": "ERROR", "message": "boom\x1b[2Jwiped\x07"}}]}))
    flags = import_scan_file(f)
    rendered = flags[0].message + " " + flags[0].evidence
    assert "\x1b" not in rendered and "\x07" not in rendered


def test_action_yml_passes_inputs_via_env_not_interpolation():
    """Regression (review HIGH): the gate's own GitHub Action must not
    splice ${{ inputs.* }} into a run: body (command injection)."""
    import pathlib
    import re

    repo_root = pathlib.Path(__file__).resolve().parents[1]
    action = (repo_root / "action.yml").read_text()
    # In every step that uses inputs, the reference must be an env mapping
    # (`  NAME: ${{ inputs.x }}`), never spliced into a `run:` script line.
    env_mapping = re.compile(r'^\s*[A-Za-z_][A-Za-z0-9_]*:\s*\$\{\{\s*inputs\.')
    for line in action.splitlines():
        if "${{ inputs." in line:
            assert env_mapping.match(line), (
                f"input interpolated outside an env mapping: {line!r}"
            )


def test_import_scans_aggregates_multiple(tmp_path):
    a = tmp_path / "a.json"
    a.write_text(json.dumps({"results": [
        {"check_id": "r1", "path": "x", "extra": {"severity": "INFO", "message": "m"}}]}))
    b = tmp_path / "b.sarif"
    b.write_text(json.dumps({"runs": [{"results": [
        {"ruleId": "r2", "level": "error", "message": {"text": "m"}}]}]}))
    flags = import_scans([str(a), str(b)])
    assert len(flags) == 2
    assert {fl.severity.value for fl in flags} == {"low", "high"}
