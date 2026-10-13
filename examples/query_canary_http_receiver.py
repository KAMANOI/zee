"""Reference receiver for "url"-kind query canaries (HTTP fetch trigger).

Zee itself does not run a listener (see canary_token.py's docstring) —
this is an example an operator deploys on infrastructure they control
and point their own https:// base_url at. It does three things and
nothing else:

1. Logs {ts, remote_ip, token, method, user_agent} as one JSON line per
   hit to --log (default ./query_canary_hits.jsonl).
2. Replies 204 with an empty body, no Set-Cookie, no Location, no
   caching headers — nothing that causes the client to do anything
   beyond "the request completed".
3. Never writes to the filesystem/network outside that log file. It
   does not retry, redirect, or probe the requester.

Usage:
    python examples/query_canary_http_receiver.py [--port 8787] [--log PATH]
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


class _Handler(BaseHTTPRequestHandler):
    log_path: Path  # set via make_handler_class

    def _record_hit(self) -> None:
        token = self.path.lstrip("/").split("/", 1)[0]
        rec = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "remote_ip": self.client_address[0],
            "token": token,
            "method": self.command,
            "user_agent": self.headers.get("User-Agent", ""),
        }
        with self.log_path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
        self.send_response(204)
        self.end_headers()

    def do_GET(self) -> None:  # noqa: N802 (stdlib naming)
        self._record_hit()

    def do_POST(self) -> None:  # noqa: N802
        self._record_hit()

    def do_HEAD(self) -> None:  # noqa: N802
        self._record_hit()

    def do_OPTIONS(self) -> None:  # noqa: N802
        self._record_hit()

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002
        pass  # suppress default stderr access log; our JSONL is the record


def make_handler_class(log_path: Path) -> type[_Handler]:
    return type("_BoundHandler", (_Handler,), {"log_path": log_path})


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--port", type=int, default=8787)
    ap.add_argument("--log", type=Path, default=Path("query_canary_hits.jsonl"))
    ap.add_argument("--bind", default="127.0.0.1")
    args = ap.parse_args()

    server = ThreadingHTTPServer((args.bind, args.port), make_handler_class(args.log))
    print(f"# listening on http://{args.bind}:{args.port} — Ctrl-C to stop")
    print(f"# hits logged to {args.log}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
