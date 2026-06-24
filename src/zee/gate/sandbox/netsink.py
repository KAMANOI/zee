"""Local FakeNet sink — the only network destination the sandbox can reach.

The sandbox profile denies all network except one loopback port; the
runner points the sandboxed process's proxy env vars at this sink. So
any HTTP(S) the artifact attempts during install rides into here, where
we log the destination and (for plaintext HTTP) the full payload. That
payload is searched for the decoy tokens — a token landing here means
the artifact read a planted credential and tried to send it out.

Containment vs observation (honest limits, invariant I5):
  * plaintext HTTP proxy request → we see destination + body (token-visible)
  * HTTPS via CONNECT → we see destination only; the TLS body is opaque,
    so token exfil over direct-CONNECT TLS is contained but not decoded.
  * outbound that ignores the proxy and dials a real host → denied by the
    kernel sandbox (contained), and usually invisible to us.
So a destination we log is an outbound *attempt*; a missing token does not
prove nothing was exfiltrated, only that we could not decode it.
We answer the proxy with a canned 200 so the artifact doesn't hang.
stdlib only (socketserver / threading).
"""

from __future__ import annotations

import socketserver
import threading
from dataclasses import dataclass, field


@dataclass
class Capture:
    raw: str           # bytes seen, decoded latin-1 (lossless for search)
    destination: str   # host:port the request targeted, "?" if unknown


class _Handler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        try:
            self.request.settimeout(3.0)
            data = self.request.recv(65536)
        except OSError:
            return
        text = data.decode("latin-1", errors="replace")
        dest = _parse_destination(text)
        self.server.captures.append(Capture(raw=text, destination=dest))  # type: ignore[attr-defined]
        try:
            if text.upper().startswith("CONNECT"):
                # HTTPS tunnel: acknowledge so the client proceeds (we
                # still only see the destination, never the TLS body).
                self.request.sendall(
                    b"HTTP/1.1 200 Connection established\r\n\r\n"
                )
            else:
                self.request.sendall(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"
                )
        except OSError:
            pass


def _parse_destination(text: str) -> str:
    """Best-effort host:port from a proxied request's first line / Host."""
    first = text.split("\r\n", 1)[0]
    parts = first.split()
    if len(parts) >= 2:
        target = parts[1]
        if parts[0].upper() == "CONNECT":
            return target  # already host:port
        if "://" in target:
            rest = target.split("://", 1)[1]
            return rest.split("/", 1)[0]
    for line in text.split("\r\n"):
        if line.lower().startswith("host:"):
            return line.split(":", 1)[1].strip()
    return "?"


class _Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, *args, **kwargs):
        self.captures: list[Capture] = []
        super().__init__(*args, **kwargs)


@dataclass
class NetSink:
    """Loopback HTTP sink. Use as a context manager around a sandbox run."""

    _server: _Server | None = field(default=None, init=False)
    _thread: threading.Thread | None = field(default=None, init=False)

    def __enter__(self) -> "NetSink":
        self._server = _Server(("127.0.0.1", 0), _Handler)
        self._thread = threading.Thread(
            target=self._server.serve_forever, daemon=True
        )
        self._thread.start()
        return self

    def __exit__(self, *exc) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
        if self._thread is not None:
            self._thread.join(timeout=2.0)

    @property
    def port(self) -> int:
        if self._server is None:
            raise RuntimeError("NetSink not started")
        return self._server.server_address[1]

    @property
    def captures(self) -> list[Capture]:
        return self._server.captures if self._server else []

    def exfiltrated_tokens(self, tokens) -> dict[str, str]:
        """token -> destination, for every decoy token seen in any payload."""
        found: dict[str, str] = {}
        for cap in self.captures:
            for tok in tokens:
                if tok in cap.raw:
                    found[tok] = cap.destination
        return found

    def outbound_destinations(self) -> list[str]:
        """Distinct non-empty destinations the sandbox tried to reach."""
        seen: list[str] = []
        for cap in self.captures:
            d = cap.destination
            if d and d != "?" and d not in seen:
                seen.append(d)
        return seen
