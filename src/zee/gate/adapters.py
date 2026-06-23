"""Ecosystem adapters: resolve a fetched tree into an Artifact.

Each adapter knows how to read one ecosystem's manifest to extract the
declared capabilities and the install hooks (the parts a static scan
needs to reason about). MVP ships Claude Code skill + MCP server + a
generic package fallback (handover Q5: skill + MCP both). Adding npm /
PyPI / VS Code later is a new adapter, not a rewrite.
"""

from __future__ import annotations

import json
from abc import ABC, abstractmethod
from pathlib import Path

from .fetch import sha256_tree
from .model import Artifact, ArtifactKind

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


class Adapter(ABC):
    kind: ArtifactKind

    @abstractmethod
    def matches(self, root: Path) -> bool:
        ...

    def build(self, source: str | Path, root: Path) -> Artifact:
        return Artifact(
            kind=self.kind,
            source=str(source),
            name=Path(source).name,
            content_hash=sha256_tree(root),
            declared_capabilities=tuple(_read_capabilities(root)),
            install_hooks=tuple(_detect_install_hooks(root)),
            root=str(root),
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


class PackageAdapter(Adapter):
    kind = ArtifactKind.PACKAGE

    def matches(self, root: Path) -> bool:
        return True  # fallback


_BY_NAME = {
    "skill": SkillAdapter,
    "mcp": McpAdapter,
    "package": PackageAdapter,
}


def pick_adapter(root: Path, kind: str | None = None) -> Adapter:
    if kind:
        cls = _BY_NAME.get(kind)
        if cls is None:
            raise ValueError(f"unknown kind: {kind}")
        return cls()
    for cls in (SkillAdapter, McpAdapter):  # specific before fallback
        a = cls()
        if a.matches(root):
            return a
    return PackageAdapter()
