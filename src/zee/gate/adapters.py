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
from .model import Artifact, ArtifactKind

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


def _detect_install_hooks(root: Path) -> list[str]:
    hooks: list[str] = []
    for pj in root.rglob("package.json"):
        try:
            data = json.loads(pj.read_text(encoding="utf-8", errors="ignore"))
        except (OSError, json.JSONDecodeError):
            continue
        scripts = data.get("scripts", {}) if isinstance(data, dict) else {}
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
            data = json.loads(mani.read_text(encoding="utf-8", errors="ignore"))
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
            data = json.loads(p.read_text(encoding="utf-8", errors="ignore"))
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
            return tomllib.loads(p.read_text(encoding="utf-8", errors="ignore"))
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
                txt = pj.read_text(encoding="utf-8", errors="ignore")
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
