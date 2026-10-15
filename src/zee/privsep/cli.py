"""`zee privsep ...` subcommands (prototype, docs/design/privsep.md)."""
from __future__ import annotations

import argparse
import base64
import json
import os
import sys
from pathlib import Path

from ..egress.signing import payload_digest
from .client import DEFAULT_SOCKET, call

DEFAULT_STATE = Path("/Library/Application Support/Zee/cutd" if sys.platform == "darwin"
                     else "/var/lib/zee-cutd")


def _print(reply: dict) -> int:
    print(json.dumps(reply, ensure_ascii=False, indent=1))
    return 0 if reply.get("ok") is True else 1


def _daemon(a: argparse.Namespace) -> int:
    from .daemon import CutDaemon, serve
    if os.geteuid() != 0:
        print("[zee cutd] warning: not running as root (cuts and restores will fail)", file=sys.stderr)
    import grp  # POSIX only: imported here so Windows can load the CLI
    group = None
    if a.group is not None:
        group = int(a.group) if a.group.isdigit() else grp.getgrnam(a.group).gr_gid
    d = CutDaemon(a.state_dir, set(a.allow_uid), watch_config=a.watch_config,
                  tamper_grace=a.tamper_grace)
    return serve(d, a.socket, group=group, check_every=a.check_every)


def _status(a: argparse.Namespace) -> int:
    return _print(call(a.socket, {"op": "status"}))


def _challenge(a: argparse.Namespace) -> int:
    args = {}
    for kv in a.args:
        k, sep, v = kv.partition("=")
        if not sep:
            print(f"expected key=value, got {kv!r}", file=sys.stderr)
            return 2
        args[k] = v
    r = call(a.socket, {"op": "challenge", "admin_op": a.admin_op, "args": args})
    if r.get("ok") is True:
        print(f"match code (type it on the approver device, never copy it there by other means): "
              f"{r['code']}", file=sys.stderr)
        r = {"ok": True, "payload": r["payload"]}  # the code stays on this host's screen
    return _print(r)


def _load_payload(path: Path) -> dict:
    raw = json.loads(path.read_text())
    return raw["payload"] if isinstance(raw, dict) and "payload" in raw else raw


def _digest(a: argparse.Namespace) -> int:
    a.out.write_bytes(payload_digest({**_load_payload(a.request), "entered": a.entered}))
    return 0


def _submit(a: argparse.Namespace) -> int:
    return _print(call(a.socket, {
        "op": "submit", "payload": _load_payload(a.request), "entered": a.entered,
        "key_id": a.key_id, "signature": base64.b64encode(a.signature.read_bytes()).decode()}))


def _bootstrap(a: argparse.Namespace) -> int:
    return _print(call(a.socket, {"op": "bootstrap_key", "key_id": a.key_id,
                                  "public_key": a.public_key.read_text()}))


def add_parser(sub) -> None:
    p = sub.add_parser("privsep", help="root cut daemon and its signed admin path "
                       "(prototype, off unless [privsep] is set; docs/design/privsep.md)")
    ps = p.add_subparsers(dest="privsep_command", required=True)

    def sock(x):
        x.add_argument("--socket", type=Path, default=DEFAULT_SOCKET)

    d = ps.add_parser("daemon", help="run the cut daemon (as root, from launchd/systemd)")
    sock(d)
    d.add_argument("--state-dir", type=Path, default=DEFAULT_STATE)
    d.add_argument("--allow-uid", type=int, action="append", required=True,
                   help="uid allowed to send cut/status (the user running zee watch); repeatable")
    d.add_argument("--group", default=None, help="group given rw on the socket (name or gid)")
    d.add_argument("--watch-config", type=Path, default=None,
                   help="the watch user's assets.toml: compared with the approved copy")
    d.add_argument("--tamper-grace", type=float, default=300)
    d.add_argument("--check-every", type=float, default=30)
    d.set_defaults(func=_daemon)

    s = ps.add_parser("status", help="ask the daemon for its state")
    sock(s)
    s.set_defaults(func=_status)

    c = ps.add_parser("challenge", help="ask for a signed admin request "
                      "(restore, config_set, auto_set, tamper_set, stop, key_add, key_remove)")
    sock(c)
    c.add_argument("admin_op")
    c.add_argument("args", nargs="*", help="key=value")
    c.set_defaults(func=_challenge)

    g = ps.add_parser("digest", help="write the 32-byte digest an ES256 signer signs")
    g.add_argument("--request", type=Path, required=True)
    g.add_argument("--entered", required=True)
    g.add_argument("--out", type=Path, required=True)
    g.set_defaults(func=_digest)

    m = ps.add_parser("submit", help="send a signed admin request")
    sock(m)
    m.add_argument("--request", type=Path, required=True)
    m.add_argument("--entered", required=True)
    m.add_argument("--key-id", required=True)
    m.add_argument("--signature", type=Path, required=True, help="DER ECDSA signature file")
    m.set_defaults(func=_submit)

    b = ps.add_parser("bootstrap-key", help="register the first approver key (root only)")
    sock(b)
    b.add_argument("--key-id", required=True)
    b.add_argument("--public-key", type=Path, required=True, help="PEM public key (P-256)")
    b.set_defaults(func=_bootstrap)
