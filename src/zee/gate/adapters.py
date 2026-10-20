"""Ecosystem adapters: resolve a fetched tree into an Artifact.

Each adapter knows how to read one ecosystem's manifest to extract the
name, version, declared capabilities and install hooks (the parts a
static scan needs to reason about). Ships Claude Code skill + MCP server
(Phase 1) plus npm / PyPI / VS Code extension (Phase 4), with a generic
package fallback. Adding another ecosystem is a new adapter, not a
rewrite.
"""

from __future__ import annotations

import json
import sys
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Optional

from .fetch import sha256_tree
from .model import Artifact, ArtifactKind, Flag, Severity

if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover - zee requires 3.11+, this branch is unreachable
    tomllib = None

_HOOK_FILENAMES = {
    "setup.py": "setup.py",
    "install.sh": "install.sh",
    "postinstall.js": "postinstall.js",
    "postinstall.sh": "postinstall.sh",
    "preinstall.js": "preinstall.js",
    "preinstall.sh": "preinstall.sh",
}


_MANIFEST_CAP = 8 * 1024 * 1024


def _text(p: Path) -> str:
    """A manifest, capped: a multi-GB file named package.json must not be slurped (OSError = unreadable)."""
    with p.open("rb") as f:
        raw = f.read(_MANIFEST_CAP + 1)
    if len(raw) > _MANIFEST_CAP:
        raise OSError(f"manifest over {_MANIFEST_CAP} bytes")
    return raw.decode("utf-8", errors="ignore")


def manifest_flags(root: Path) -> list[Flag]:
    """G912: a manifest that cannot be parsed or has an unexpected shape
    means the hook / capability facts below it are unknown, not absent."""
    flags: list[Flag] = []
    for pattern in ("package.json", "manifest.json", "mcp.json"):
        for p in sorted(root.rglob(pattern)):
            rel = str(p.relative_to(root))
            try:
                data = json.loads(_text(p))
            except (OSError, json.JSONDecodeError) as e:
                flags.append(_bad_manifest(rel, str(e)))
                continue
            if not isinstance(data, dict):
                flags.append(_bad_manifest(rel, "top level is not an object"))
                continue
            if pattern == "package.json" and not isinstance(
                data.get("scripts", {}), dict
            ):
                flags.append(_bad_manifest(rel, "'scripts' is not an object"))
    for p in sorted(root.rglob("pyproject.toml")):
        rel = str(p.relative_to(root))
        if tomllib is None:  # pragma: no cover
            continue
        try:
            tomllib.loads(_text(p))
        except (OSError, tomllib.TOMLDecodeError) as e:
            flags.append(_bad_manifest(rel, str(e)))
    return flags


def _bad_manifest(rel: str, why: str) -> Flag:
    return Flag(
        Severity.LOW, "G912",
        "manifest could not be read; install hooks and capabilities unknown",
        evidence=f"{rel}: {why}"[:200],
    )


def _detect_install_hooks(root: Path) -> list[str]:
    hooks: list[str] = []
    for pj in root.rglob("package.json"):
        try:
            data = json.loads(_text(pj))
        except (OSError, json.JSONDecodeError):
            continue  # unreadable manifest is reported by manifest_flags()
        scripts = data.get("scripts", {}) if isinstance(data, dict) else {}
        if not isinstance(scripts, dict):
            continue  # e.g. "scripts": 1 used to raise TypeError here
        for k in ("preinstall", "install", "postinstall"):
            if k in scripts:
                hooks.append(f"{pj.name}:scripts.{k}")
    for p in root.rglob("*"):
        if p.is_file() and p.name in _HOOK_FILENAMES:
            hooks.append(p.name)
    return sorted(set(hooks))


def _read_capabilities(root: Path) -> list[str]:
    """Best-effort: capabilities/permissions declared in a manifest."""
    caps: list[str] = []
    for mani in list(root.rglob("manifest.json")) + list(root.rglob("mcp.json")):
        try:
            data = json.loads(_text(mani))
        except (OSError, json.JSONDecodeError):
            continue
        if not isinstance(data, dict):
            continue
        for key in ("capabilities", "permissions"):
            val = data.get(key)
            if isinstance(val, list):
                caps.extend(str(v) for v in val)
            elif isinstance(val, dict):
                caps.extend(val.keys())
    return sorted(set(caps))


def _first_json(root: Path, filename: str) -> Optional[dict]:
    for p in root.rglob(filename):
        try:
            data = json.loads(_text(p))
        except (OSError, json.JSONDecodeError):
            continue
        if isinstance(data, dict):
            return data
    return None


def _first_toml(root: Path, filename: str) -> Optional[dict]:
    if tomllib is None:  # pragma: no cover
        return None
    for p in root.rglob(filename):
        try:
            return tomllib.loads(_text(p))
        except (OSError, tomllib.TOMLDecodeError):
            continue
    return None


class Adapter(ABC):
    kind: ArtifactKind

    @abstractmethod
    def matches(self, root: Path) -> bool:
        ...

    def _name(self, source: str | Path, root: Path) -> str:
        return Path(source).name

    def _version(self, root: Path) -> Optional[str]:
        return None

    def build(self, source: str | Path, root: Path) -> Artifact:
        return Artifact(
            kind=self.kind,
            source=str(source),
            name=self._name(source, root),
            content_hash=sha256_tree(root),
            declared_capabilities=tuple(_read_capabilities(root)),
            install_hooks=tuple(_detect_install_hooks(root)),
            root=str(root),
            version=self._version(root),
        )


class SkillAdapter(Adapter):
    kind = ArtifactKind.SKILL

    def matches(self, root: Path) -> bool:
        return any(root.rglob("SKILL.md")) or any(root.rglob("skill.json"))


class McpAdapter(Adapter):
    kind = ArtifactKind.MCP

    def matches(self, root: Path) -> bool:
        if any(root.rglob("mcp.json")):
            return True
        # an MCP server often declares an "mcpServers" block or a server entry
        for pj in root.rglob("package.json"):
            try:
                txt = _text(pj)
            except OSError:
                continue
            if "mcpServers" in txt or "modelcontextprotocol" in txt:
                return True
        return False


class VscodeAdapter(Adapter):
    kind = ArtifactKind.VSCODE

    def matches(self, root: Path) -> bool:
        data = _first_json(root, "package.json")
        if not data:
            return False
        engines = data.get("engines")
        has_vscode_engine = isinstance(engines, dict) and "vscode" in engines
        return has_vscode_engine or "contributes" in data

    def _name(self, source: str | Path, root: Path) -> str:
        data = _first_json(root, "package.json") or {}
        return str(data.get("name") or Path(source).name)

    def _version(self, root: Path) -> Optional[str]:
        data = _first_json(root, "package.json") or {}
        v = data.get("version")
        return str(v) if v else None


class NpmAdapter(Adapter):
    kind = ArtifactKind.NPM

    def matches(self, root: Path) -> bool:
        return _first_json(root, "package.json") is not None

    def _name(self, source: str | Path, root: Path) -> str:
        data = _first_json(root, "package.json") or {}
        return str(data.get("name") or Path(source).name)

    def _version(self, root: Path) -> Optional[str]:
        data = _first_json(root, "package.json") or {}
        v = data.get("version")
        return str(v) if v else None


class PypiAdapter(Adapter):
    kind = ArtifactKind.PYPI

    def matches(self, root: Path) -> bool:
        return (
            any(root.rglob("pyproject.toml"))
            or any(root.rglob("setup.py"))
            or any(root.rglob("setup.cfg"))
            or any(root.rglob("PKG-INFO"))
        )

    def _name(self, source: str | Path, root: Path) -> str:
        data = _first_toml(root, "pyproject.toml")
        if isinstance(data, dict):
            proj = data.get("project")
            if isinstance(proj, dict) and proj.get("name"):
                return str(proj["name"])
        return Path(source).name

    def _version(self, root: Path) -> Optional[str]:
        data = _first_toml(root, "pyproject.toml")
        if isinstance(data, dict):
            proj = data.get("project")
            if isinstance(proj, dict) and proj.get("version"):
                return str(proj["version"])
        return None


class PackageAdapter(Adapter):
    kind = ArtifactKind.PACKAGE

    def matches(self, root: Path) -> bool:
        return True  # fallback


_BY_NAME = {
    "skill": SkillAdapter,
    "mcp": McpAdapter,
    "vscode": VscodeAdapter,
    "npm": NpmAdapter,
    "pypi": PypiAdapter,
    "package": PackageAdapter,
}

# Most specific first; VS Code before npm (both read package.json) and
# skill/mcp before either, so a Claude artifact is never misread as npm.
_AUTODETECT = (
    SkillAdapter, McpAdapter, VscodeAdapter, NpmAdapter, PypiAdapter,
)


def pick_adapter(root: Path, kind: str | None = None) -> Adapter:
    if kind:
        cls = _BY_NAME.get(kind)
        if cls is None:
            raise ValueError(f"unknown kind: {kind}")
        return cls()
    for cls in _AUTODETECT:  # specific before fallback
        a = cls()
        if a.matches(root):
            return a
    return PackageAdapter()
