"""Render (never run) the macOS pf rules for held / approved destinations.

Prototype limit: this only produces text. Loading it needs root and changes
the network configuration, which the prototype deliberately does not do.
Destinations must be IPs/CIDRs; resolving a hostname is the caller's job.
"""
from __future__ import annotations

import ipaddress


def _addr(dest: str) -> str:
    host = dest
    if "/" not in dest:
        if dest.startswith("["):
            host = dest[1:].split("]")[0]
        elif dest.count(":") == 1:
            host = dest.split(":")[0]
    return str(ipaddress.ip_network(host, strict=False))  # ValueError for hostnames


def render(held: list[str], allowed: list[str], *, default_deny: bool = False) -> str:
    """`default_deny` is the server form (allow-list primary); the PC form blocks only held peers."""
    rules = ["pass out quick on lo0 all"]
    rules += [f"pass out quick to {_addr(d)}" for d in sorted(allowed)]
    if default_deny:
        rules.append("block drop out quick all")
    else:
        rules += [f"block drop out quick to {_addr(d)}" for d in sorted(held)]
    return "\n".join(rules) + "\n"
