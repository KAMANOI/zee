"""Reference receiver for "hostname"-kind query canaries (DNS trigger).

DNS resolution is the lowest-friction thing a cleaning pipeline can do
to a URL/hostname-shaped value — most link validators, mail-deliverability
checkers, and even "is this domain still alive" dedup heuristics resolve
the name before (or instead of) opening a TCP connection. Pointing the
canary domain's NS records at this receiver (or a real nameserver with
query logging, e.g. PowerDNS/BIND — see docs/design/query-canary.md §5)
catches that first step.

This is a minimal authoritative-enough stub, not a real nameserver: it
answers every query with NXDOMAIN after logging it. It does not resolve
anything, does not forward, does not cache, and sends nothing but the
protocol-minimum NXDOMAIN reply — no A/AAAA record that could cause the
resolver to connect anywhere next.

Usage:
    python examples/query_canary_dns_receiver.py [--port 53] [--log PATH]

Binding to UDP port 53 needs root/CAP_NET_BIND_SERVICE on most OSes;
use --port 15353 + a local test for the prototype in tests/test_query_canary.py.
"""

from __future__ import annotations

import argparse
import json
import socket
from datetime import datetime, timezone
from pathlib import Path


def parse_qname(data: bytes, offset: int = 12) -> tuple[str, int]:
    """Return (dotted qname, offset just past the QTYPE/QCLASS fields)."""
    labels: list[str] = []
    while True:
        length = data[offset]
        offset += 1
        if length == 0:
            break
        labels.append(data[offset : offset + length].decode("ascii", errors="replace"))
        offset += length
    return ".".join(labels), offset + 4  # skip QTYPE(2) + QCLASS(2)


def build_nxdomain_response(query: bytes, question_end: int) -> bytes:
    """Echo the query id/question, flip to a response, RCODE=NXDOMAIN(3)."""
    txid = query[0:2]
    flags = (0x8000 | (query[2] & 0x01) << 8 | 0x0003).to_bytes(2, "big")  # QR=1, RD echoed, RCODE=3
    qdcount = (1).to_bytes(2, "big")
    zero = (0).to_bytes(2, "big")
    header = txid + flags + qdcount + zero + zero + zero
    question = query[12:question_end]
    return header + question


def serve(bind: str, port: int, log_path: Path) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((bind, port))
    print(f"# listening on udp://{bind}:{port} — Ctrl-C to stop")
    print(f"# hits logged to {log_path}")
    try:
        while True:
            data, addr = sock.recvfrom(512)
            try:
                qname, question_end = parse_qname(data)
            except IndexError:
                continue  # malformed packet, drop silently
            rec = {
                "ts": datetime.now(timezone.utc).isoformat(),
                "remote_ip": addr[0],
                "qname": qname,
                "token": qname.split(".", 1)[0],
            }
            with log_path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(rec, ensure_ascii=False) + "\n")
            sock.sendto(build_nxdomain_response(data, question_end), addr)
    except KeyboardInterrupt:
        pass
    finally:
        sock.close()


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--port", type=int, default=53)
    ap.add_argument("--bind", default="127.0.0.1")
    ap.add_argument("--log", type=Path, default=Path("query_canary_dns_hits.jsonl"))
    args = ap.parse_args()
    serve(args.bind, args.port, args.log)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
