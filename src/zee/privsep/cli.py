"""`zee privsep ...` subcommands (prototype, docs/design/privsep.md)."""
from __future__ import annotations

import argparse
import base64
import json
import os
import sys
from pathlib import Path

from .. import errors
from ..egress.signing import payload_digest
from ..errors import ZeeError, Z710_CUTD_UNREACHABLE, Z719_PRIVSEP_REQUEST_FILE, Z720_CUTD_RESULT_UNKNOWN
from .client import DEFAULT_SOCKET, NotSent, call as _raw_call

DEFAULT_STATE = Path("/Library/Application Support/Zee/cutd" if sys.platform == "darwin"
                     else "/var/lib/zee-cutd")


_MEANING = {v[0]: v[1] for k, v in vars(errors).items() if k.startswith(("Z71", "Z72"))}


def call(sock: Path, req: dict) -> dict:
    try:
        return _raw_call(sock, req)
    except NotSent as e:  # no daemon, refused, no permission, not served by root
        raise ZeeError(Z710_CUTD_UNREACHABLE, f"{sock}: {e}") from e
    except (OSError, ValueError) as e:  # sent, but no usable answer: it may have been carried out
        raise ZeeError(Z720_CUTD_RESULT_UNKNOWN, f"{req.get('op')}: {e}") from e


def _read(path: Path, kind: str = "text"):
    try:
        if kind == "bytes":
            return path.read_bytes()
        if kind == "json":
            raw = json.loads(path.read_text())
            raw = raw["payload"] if isinstance(raw, dict) and "payload" in raw else raw
            if not isinstance(raw, dict):
                raise ValueError("not a JSON object")
            return raw
        return path.read_text()
    except (OSError, ValueError, UnicodeDecodeError) as e:
        raise ZeeError(Z719_PRIVSEP_REQUEST_FILE, f"{path}: {e}") from e


def _print(reply: dict) -> int:
    print(json.dumps(reply, ensure_ascii=False, indent=1))
    if reply.get("ok") is not True and reply.get("code") in _MEANING:
        print(f"error: [{reply['code']}] {_MEANING[reply['code']]}", file=sys.stderr)
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
    return _read(path, "json")


def _digest(a: argparse.Namespace) -> int:
    """Shows what is being approved and asks for "yes" before writing the digest to sign."""
    p = _load_payload(a.request)
    print("You are about to approve this request to the Zee cut daemon:", file=sys.stderr)
    for k in ("aud", "host", "op", "args", "exp"):
        v = p.get(k)
        if k == "exp" and isinstance(v, int):
            import datetime
            v = f"{v} ({datetime.datetime.fromtimestamp(v).isoformat(timespec='seconds')})"
        print(f"  {k:5}: {json.dumps(v, ensure_ascii=False) if not isinstance(v, str) else v}", file=sys.stderr)
    if p.get("aud") != "zee-cutd-admin-v1":
        print("  WARNING: this is not a cut daemon admin request", file=sys.stderr)
    print('Type "yes" to approve: ', end="", file=sys.stderr, flush=True)
    if sys.stdin.readline().strip() != "yes":
        print("not approved; nothing written", file=sys.stderr)
        return 1
    a.out.write_bytes(payload_digest({**p, "entered": a.entered}))
    return 0


def _submit(a: argparse.Namespace) -> int:
    return _print(call(a.socket, {
        "op": "submit", "payload": _load_payload(a.request), "entered": a.entered,
        "key_id": a.key_id, "signature": base64.b64encode(_read(a.signature, "bytes")).decode()}))


def _bootstrap(a: argparse.Namespace) -> int:
    return _print(call(a.socket, {"op": "bootstrap_key", "key_id": a.key_id,
                                  "public_key": _read(a.public_key)}))


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
