"""Render (never run) the macOS pf rules for held / approved destinations.

Prototype limit: this only produces text. Loading it needs root and changes
the network configuration, which the prototype deliberately does not do.
Destinations must be IPs/CIDRs; resolving a hostname is the caller's job.
"""
from __future__ import annotations

import ipaddress


def _to(dest: str, *, keep_port: bool = True) -> str:
    """pf target for one destination. Passes keep the port (approving :8443 must not open :443);
    blocks drop it, so a held peer is closed on every port (no port hopping; fails closed)."""
    host, port = dest, None
    if "/" not in dest:
        if dest.startswith("["):
            host, _, rest = dest[1:].partition("]")
            if rest and not rest.startswith(":"):
                raise ValueError(f"bad destination: {dest}")
            port = rest[1:] or None
        elif dest.count(":") == 1:
            host, port = dest.split(":")
    to = str(ipaddress.ip_network(host, strict=False))  # ValueError for hostnames
    if port is None or not keep_port:
        return f"to {to}"
    if not (port.isdigit() and 0 < int(port) < 65536):
        raise ValueError(f"bad port: {dest}")
    return f"proto {{ tcp udp }} to {to} port {int(port)}"  # pf: "port" needs a tcp/udp proto


def render(held: list[str], allowed: list[str], *, default_deny: bool = False) -> str:
    """`default_deny` is the server form (allow-list primary); the PC form blocks only held peers."""
    rules = ["pass out quick on lo0 all"]
    rules += [f"pass out quick {_to(d)}" for d in sorted(allowed)]
    if default_deny:
        rules.append("block drop out quick all")
    else:
        rules += [f"block drop out quick {_to(d, keep_port=False)}" for d in sorted(held)]
    return "\n".join(rules) + "\n"
