"""Business-side client of the cut daemon (docs/design/privsep.md)."""
from __future__ import annotations

import json
import socket
import struct
import sys
from pathlib import Path

from ..responder.blocker import CutRequest

# macOS: /var/db (root:wheel 0755 all the way up). Not /var/run: it is root:daemon 0775,
# so a non-root service account could replace the socket (Codex review 8).
DEFAULT_SOCKET = Path("/var/db/zee/cutd.sock" if sys.platform == "darwin" else "/run/zee/cutd.sock")


class NotSent(OSError):
    """Nothing reached the daemon (no socket, refused, wrong server): the request had no effect."""


def peer_uid(sock: socket.socket) -> int:
    """Effective uid of the connected peer, as recorded by the kernel at connect().

    Linux: SO_PEERCRED returns struct ucred {pid, uid, gid} (unix(7)).
    macOS: LOCAL_PEERCRED at level SOL_LOCAL (0, sys/un.h) returns struct xucred
    {u_int cr_version; uid_t cr_uid; ...} with cr_version == XUCRED_VERSION (0)
    (unix(4), sys/ucred.h). Anything else is refused, never guessed.
    """
    if hasattr(socket, "SO_PEERCRED"):
        _pid, uid, _gid = struct.unpack(
            "3i", sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")))
        return uid
    if hasattr(socket, "LOCAL_PEERCRED"):
        raw = sock.getsockopt(0, socket.LOCAL_PEERCRED, struct.calcsize("IIh16I"))
        version, uid = struct.unpack_from("II", raw)
        if version != 0:
            raise OSError(f"unknown xucred version {version}")
        return uid
    raise OSError("no peer credentials on this platform")


def call(socket_path: Path, request: dict, *, timeout: float = 60, server_uid: int = 0) -> dict:
    """One request line, one reply line.

    Raises NotSent if nothing was delivered (including a socket not served by
    ``server_uid`` — root for the real daemon: a swapped socket can't fake
    "cut applied"), and OSError / ValueError when the request was sent but no
    usable answer came back (its effect is then unknown)."""
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)  # a full cut reads interfaces back: allow it time
        try:
            s.connect(str(socket_path))
            uid = peer_uid(s)
        except OSError as e:
            raise NotSent(str(e)) from e
        if uid != server_uid:
            raise NotSent(f"{socket_path} is served by uid {uid}, not {server_uid}: not the cut daemon")
        try:
            s.sendall(json.dumps(request).encode() + b"\n")
        except OSError as e:
            raise NotSent(str(e)) from e
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


def privsep_cut(socket_path: Path, *, server_uid: int = 0):
    """A cut function for responder.sequence.handle: sends only the three facts."""
    def cut(req: CutRequest) -> tuple[bool, str]:
        try:
            r = call(socket_path, {"op": "cut", "asset_id": req.asset_id, "op_class": req.op_class,
                                   "confidence": req.confidence}, server_uid=server_uid)
        except NotSent as e:
            return False, f"Z710 cut daemon unreachable ({e}); nothing was sent, so Zee cut nothing"
        except (OSError, ValueError) as e:
            return False, (f"Z720 cut result UNKNOWN ({e}): the daemon got the request and may have cut; "
                           "check `zee privsep status` (unresolved) before assuming anything")
        if r.get("ok") is True:
            return True, f"cut daemon: {r.get('detail', '')}"
        return False, (f"cut daemon: {r.get('refused') or r.get('error') or r.get('detail')}"
                       f" ({r.get('code', '-')})")
    return cut
