"""Business-side client of the cut daemon (docs/design/privsep.md)."""
from __future__ import annotations

import json
import socket
from pathlib import Path

from ..responder.blocker import CutRequest

DEFAULT_SOCKET = Path("/var/run/zee/cutd.sock")


def call(socket_path: Path, request: dict, *, timeout: float = 60) -> dict:
    """One request line, one reply line. Raises OSError / ValueError if the daemon can't answer."""
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)  # a full cut reads interfaces back: allow it time
        s.connect(str(socket_path))
        s.sendall(json.dumps(request).encode() + b"\n")
        buf = b""
        while not buf.endswith(b"\n"):
            chunk = s.recv(65536)
            if not chunk:
                break
            buf += chunk
    reply = json.loads(buf)
    if not isinstance(reply, dict):
        raise ValueError("reply is not an object")
    return reply


def privsep_cut(socket_path: Path):
    """A cut function for responder.sequence.handle: sends only the three facts."""
    def cut(req: CutRequest) -> tuple[bool, str]:
        try:
            r = call(socket_path, {"op": "cut", "asset_id": req.asset_id,
                                   "op_class": req.op_class, "confidence": req.confidence})
        except (OSError, ValueError) as e:
            return False, f"cut daemon unreachable ({e}); nothing was cut by Zee"
        if r.get("ok") is True:
            return True, f"cut daemon: {r.get('detail', '')}"
        return False, f"cut daemon: {r.get('refused') or r.get('error') or r.get('detail')}"
    return cut
