"""Cut daemon: the small root part of Zee (docs/design/privsep.md).

Runs as root (LaunchDaemon / systemd). The business user's ``zee watch``
talks to it over a Unix socket. Unsigned requests are only ``cut`` and
``status``, and only from the uids given with ``--allow-uid`` (the uid comes
from the kernel: SO_PEERCRED / LOCAL_PEERCRED, never from the request).
Restore, configuration changes, the auto-cut switch, the tamper response and
stopping the daemon need an approver signature, checked by the same engine
as egress approval (src/zee/egress/engine.py): request issued here, single
use, expiry, number matching, ES256 key registry, persisted replay ledger.

The requester never chooses how or what to cut: the daemon decides from its
own root-owned copy of assets.toml, the auto-containment permission and the
cut boundary (responder/blocker.py).
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import logging
import os
import re
import socket
import socketserver
import stat
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Optional

from .. import __version__
from ..config.schema import Config
from ..egress.engine import Engine
from ..egress.signing import OpensslVerifier, Verifier
from ..errors import ZeeError
from ..policy.asset_profile import resolve
from ..recovery.restore import restore
from ..responder import blocker, permission
from ..responder.cut_egress import cut_egress
from ..responder.cut_full import cut_full
from ..telemetry.cut_state import CutStateLog
from .client import peer_uid

logger = logging.getLogger(__name__)

AUD = "zee-cutd-admin-v1"  # in every signed admin payload: never mistaken for an egress approval
TAMPER_ASSET = "zee-tamper"  # ledger id of a cut made by the tamper response
MAX_LINE = 16 * 1024
MAX_CONFIG = 256 * 1024
PENDING_PER_UID = 4  # unanswered admin requests per uid (only allowed uids and root may ask)
CHALLENGES_PER_MIN = 10
CONN_SLOTS = 16  # concurrent connections per pool (allowed uids / everyone else)
READ_DEADLINE = 5.0  # seconds for the whole request line
_ASSET_ID = re.compile(r"[A-Za-z0-9._-]{1,64}")
# Bound fields: filled in by the daemon when it issues the request (never by the
# requester) and re-checked right before applying, so an old, unused signature can't
# act on a later state. "gen" counts applied admin operations (persisted): any newer
# approval voids every older pending one (e.g. an old "auto on" after a newer "off").
# A restore also binds the whole cut ledger (egress rules are host-wide, so a newer
# cut of any asset voids it); auto_set binds the approved config.
BOUND = ("gen", "config_sha256", "ledger_sha256")
ADMIN_OPS = {"restore": ("asset_id", "scope", "ledger_sha256", "gen"),
             "config_set": ("path", "sha256", "gen"), "auto_set": ("state", "config_sha256", "gen"),
             "tamper_set": ("action", "gen"), "stop": ("gen",),
             "key_add": ("key_id", "public_key", "gen"), "key_remove": ("key_id", "gen")}
_CHOICES = {"scope": ("recorded", "all"), "state": ("on", "off"),
            "action": ("off", "egress", "full")}


def read_bounded(path: Path, limit: int = MAX_CONFIG) -> bytes:
    """A regular file, not through a final symlink, at most ``limit`` bytes; else OSError.
    Never blocks on a FIFO and never reads a device."""
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    with os.fdopen(fd, "rb") as f:
        if not stat.S_ISREG(os.fstat(f.fileno()).st_mode):
            raise OSError(f"not a regular file: {path}")
        data = f.read(limit + 1)
    if len(data) > limit:
        raise OSError(f"too large: {path}")
    return data


def file_sha256(path: Path) -> str:
    """Streaming hash of a regular file (no size limit: the ledger only grows); "absent" if missing."""
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    except FileNotFoundError:
        return "absent"
    h = hashlib.sha256()
    with os.fdopen(fd, "rb") as f:
        if not stat.S_ISREG(os.fstat(f.fileno()).st_mode):
            raise OSError(f"not a regular file: {path}")
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


# Reply codes (src/zee/errors.py Z71x; docs/maintenance/privsep_install.md lists them).
def reply_code(reply: dict) -> str:
    err, refused = reply.get("error"), reply.get("refused")
    if err == "malformed":
        return "Z711"
    if err in ("peer_not_allowed", "root_only", "peer_unknown"):
        return "Z712"
    if err == "unknown_op":
        return "Z713"
    if refused in ("unknown_request", "expired", "payload_mismatch", "code_mismatch", "unknown_key",
                   "replay", "bad_signature", "would_leave_one_key", "malformed"):
        return "Z714"
    if refused == "rate_limited":
        return "Z717"
    if refused is not None:
        return "Z715"  # cut or request refused by the daemon's policy / argument checks
    if err is not None:
        return "Z716"  # internal error or a ZeeError from the cut / restore code
    return "Z718"  # the signature was accepted but the operation itself failed (see detail)


class AdminEngine(Engine):
    """The egress approval engine with the daemon's admin operations instead of egress config.

    No egress flows ever reach it; only request_config / submit / bootstrap_key are used.
    ``recovery_start`` (unsigned) is never exposed: losing every approver key is
    recovered by root at the console (docs/design/privsep.md).
    """
    OPS = ADMIN_OPS
    STATE_FILE, LOG_FILE = "admin_keys.json", "admin.jsonl"

    def __init__(self, state_dir: Path, verifier: Verifier, daemon: "CutDaemon", **kw) -> None:
        self.daemon = daemon
        self.outcome: tuple[bool, str] = (False, "")
        super().__init__(state_dir, verifier, **kw)

    def _new_request(self, kind: str, body: dict, ttl: Optional[float] = None):
        return super()._new_request(kind, {"aud": AUD, "host": socket.gethostname(), **body}, ttl)

    def _apply(self, req, key_id: str) -> list[str]:
        op, args = req.payload["op"], req.payload["args"]
        stale = [k for k, v in self.daemon.bindings(op).items() if args.get(k) != v]
        if stale:
            self.outcome = (False, f"refused: state changed since this request was issued ({', '.join(stale)}); "
                                   "ask for a new one")
            self._log("denied", req=req.id, op=op, key_id=key_id, reason="stale:" + ",".join(stale))
            return []
        self.daemon.bump_gen()  # before acting: a crash mid-way still voids older approvals
        if op in ("key_add", "key_remove"):
            self.outcome = (True, op)
            return super()._apply(req, key_id)
        self.outcome = self.daemon._apply_admin(op, args)
        self._log("config_applied", req=req.id, op=op, key_id=key_id, args=args,
                  ok=self.outcome[0], detail=self.outcome[1][:500])
        return []


class CutDaemon:
    def __init__(self, state_dir: Path, allow_uids: set[int], *, watch_config: Optional[Path] = None,
                 verifier: Optional[Verifier] = None, tamper_grace: float = 300,
                 clock: Callable[[], float] = time.time,
                 cut_fns: Optional[dict[str, Callable]] = None, restore_fn: Callable = restore) -> None:
        self.dir = check_state_dir(Path(state_dir))  # before reading keys / config / ledger
        self.allow = set(allow_uids)
        self.watch_config = watch_config
        self.grace, self.clock = tamper_grace, clock
        self.cut_fns = cut_fns or {"full": cut_full, "egress": cut_egress}
        self.restore_fn = restore_fn
        self.cut_state = CutStateLog(self.dir / "cut_state.jsonl")
        self.lock = threading.Lock()  # ponytail: one lock for everything; cuts are rare and serial
        self.engine = AdminEngine(self.dir, verifier or OpensslVerifier(), self, clock=clock)
        self.stopping = False
        self.last_seen: Optional[float] = None
        self.findings: list[str] = []
        self._strikes = 0
        self._asked: dict[tuple[int, str], list[float]] = {}  # (uid, op) -> request times (last minute)
        self._owner: dict[str, int] = {}  # pending request id -> uid that asked for it
        self._tamper_acted = False

    # ---- files the daemon owns (all inside its 0700 state directory)
    @property
    def config_path(self) -> Path:
        return self.dir / "assets.toml"

    def bindings(self, op: str) -> dict[str, str]:
        b = {"gen": str(self._gen())}
        if op == "auto_set":
            b["config_sha256"] = file_sha256(self.config_path)
        if op == "restore":
            b["ledger_sha256"] = file_sha256(self.ledger_path)
        return b

    def _gen(self) -> int:
        try:
            return int((self.dir / "admin_gen").read_text())
        except FileNotFoundError:
            return 0
        # anything else (unreadable, not a number) raises: no request is issued or applied

    def bump_gen(self) -> None:
        tmp = permission.private_temp(self.dir / "admin_gen", str(self._gen() + 1))
        os.replace(tmp, self.dir / "admin_gen")

    @property
    def ledger_path(self) -> Path:
        return self.cut_state.path

    @property
    def perm_path(self) -> Path:
        return self.dir / "auto_containment.json"

    def config(self) -> Optional[Config]:
        if not self.config_path.exists():
            return None
        return Config.load(self.config_path)

    def tamper_action(self) -> str:
        try:
            a = json.loads((self.dir / "tamper.json").read_text())["action"]
            return a if a in _CHOICES["action"] else "off"
        except (OSError, ValueError, KeyError, TypeError):
            return "off"  # default OFF (approved 2026-10-15): only a signed tamper_set turns it on

    # ---- one request line -> one reply (the whole trust boundary)
    def handle_line(self, line: bytes, uid: int) -> dict:
        reply = self._handle(line, uid)
        if reply.get("ok") is not True:
            reply["code"] = reply_code(reply)
        return reply

    def _handle(self, line: bytes, uid: int) -> dict:
        try:
            req = json.loads(line)
        except (ValueError, RecursionError):
            return {"ok": False, "error": "malformed"}
        if not isinstance(req, dict) or not isinstance(req.get("op"), str):
            return {"ok": False, "error": "malformed"}
        op = req["op"]
        if op == "bootstrap_key":
            if uid != 0:
                return {"ok": False, "error": "root_only"}
        elif op in ("cut", "status", "challenge", "submit"):
            if uid not in self.allow and uid != 0:
                return {"ok": False, "error": "peer_not_allowed"}
        else:
            return {"ok": False, "error": "unknown_op"}
        try:
            if op == "status":  # never waits behind a slow cut / restore (files are replaced atomically)
                return self._status(uid)
            with self.lock:
                if op == "cut":
                    return self._cut(req)
                if op == "challenge":
                    return self._challenge(req, uid)
                if op == "submit":
                    return self._submit(req, uid)
                return self._bootstrap(req, uid)
        except ZeeError as e:
            return {"ok": False, "error": str(e)}
        except Exception as e:  # noqa: BLE001 - a bad request must never kill the daemon
            logger.exception("cutd: request failed")
            return {"ok": False, "error": f"internal: {type(e).__name__}"}

    def _cut(self, req: dict) -> dict:
        if set(req) != {"op", "asset_id", "op_class", "confidence"} or not all(
                type(req[k]) is str and 0 < len(req[k]) <= 128 for k in ("asset_id", "op_class", "confidence")):
            return {"ok": False, "error": "malformed"}
        cr = blocker.CutRequest(req["asset_id"], req["op_class"], req["confidence"])
        cfg = self.config()
        asset = cfg.find(cr.asset_id) if cfg else None
        if asset is None:
            return {"ok": False, "refused": "unknown_asset"}
        allowed, why = permission.decide(cr, asset, cfg, permission.load(self.perm_path))
        why = why or blocker.refusal(cr, asset, dry_run=cfg.dry_run)
        if not allowed or why:
            return {"ok": False, "refused": why}
        ok, detail = self.cut_fns[resolve(asset).cut_method](asset_id=asset.id, cut_state=self.cut_state)
        return {"ok": ok, "detail": detail}

    def _status(self, uid: int) -> dict:
        if uid in self.allow:
            self.last_seen = self.clock()  # the watch's status call is its heartbeat
        try:
            cfg, cfg_error = self.config(), None
        except ZeeError as e:
            cfg, cfg_error = None, str(e)
        perm = permission.load(self.perm_path)
        if perm is None:
            auto = "off (never set)"
        elif isinstance(perm, permission.Invalid):
            auto = f"invalid: {perm.reason}"
        elif not perm.enabled:
            auto = "off"
        elif cfg is None or perm.policy_hash != permission.policy_hash(cfg):
            auto = "policy_mismatch"  # on, but for another config: refuses every cut
        else:
            auto = "on"
        unresolved = sorted(a for a in self._restorable() if self.cut_state.unresolved_for(a)[0] is not None)
        return {"ok": True, "version": __version__, "config_error": cfg_error,
                "dry_run": cfg.dry_run if cfg else None, "auto": auto,
                "tamper_action": self.tamper_action(), "findings": list(self.findings),
                "unresolved": unresolved, "keys": len(self.engine.state["keys"]),
                "watch_seen_s_ago": None if self.last_seen is None else round(self.clock() - self.last_seen)}

    def _challenge(self, req: dict, uid: int) -> dict:
        args = req.get("args", {})
        if set(req) - {"op", "admin_op", "args"} or not isinstance(req.get("admin_op"), str) \
                or not isinstance(args, dict):
            return {"ok": False, "error": "malformed"}
        why = self._check_args(req["admin_op"], args)
        if why:
            return {"ok": False, "refused": why}
        args = {**args, **self.bindings(req["admin_op"])}
        if self._rate_limited(uid, "challenge"):
            return {"ok": False, "refused": "rate_limited"}
        mine = [r for r, u in self._owner.items() if u == uid and r in self.engine.pending]
        self._owner = {r: u for r, u in self._owner.items() if r in self.engine.pending}
        while len(mine) >= PENDING_PER_UID:  # a uid only ever displaces its own requests
            self.engine.pending.pop(mine.pop(0), None)
        try:
            r = self.engine.request_config(req["admin_op"], **args)
        except (ValueError, PermissionError, TypeError) as e:
            return {"ok": False, "refused": f"bad_request: {e}"}
        self._owner[r.id] = uid
        return {"ok": True, "payload": r.payload, "code": r.code}

    def _check_args(self, op: str, args: dict) -> Optional[str]:
        if op not in ADMIN_OPS or set(args) != set(ADMIN_OPS[op]) - set(BOUND) \
                or not all(type(v) is str and 0 < len(v) <= 4096 for v in args.values()):
            return "bad_args"
        for k, choices in _CHOICES.items():
            if k in args and args[k] not in choices:
                return f"bad_{k}"
        if op == "restore":
            if args["asset_id"] not in self._restorable():
                return "unknown_asset"
        if op == "config_set":
            if not os.path.isabs(args["path"]):
                return "path_not_absolute"
            if len(args["sha256"]) != 64 or any(c not in "0123456789abcdef" for c in args["sha256"]):
                return "bad_sha256"
        return None

    def _rate_limited(self, uid: int, op: str) -> bool:
        """At most CHALLENGES_PER_MIN per uid and op: bounds root's admin.jsonl growth too."""
        now = self.clock()
        recent = [t for t in self._asked.get((uid, op), []) if t > now - 60]
        if len(recent) >= CHALLENGES_PER_MIN:
            return True
        self._asked[(uid, op)] = recent + [now]
        return False

    def _submit(self, req: dict, uid: int) -> dict:
        if self._rate_limited(uid, "submit"):
            return {"ok": False, "refused": "rate_limited"}
        if set(req) != {"op", "payload", "entered", "key_id", "signature"} \
                or not isinstance(req["signature"], str):
            return {"ok": False, "error": "malformed"}
        try:
            sig = base64.b64decode(req["signature"], validate=True)
        except (binascii.Error, ValueError):
            return {"ok": False, "error": "malformed"}
        res = self.engine.submit(req["payload"], req["entered"], req["key_id"], sig)
        if not res.ok:
            return {"ok": False, "refused": res.reason}
        ok, detail = self.engine.outcome  # the signature was good; this is the operation's own result
        return {"ok": ok, "detail": detail}

    def _bootstrap(self, req: dict, uid: int) -> dict:
        if set(req) != {"op", "key_id", "public_key"} or not all(
                type(req[k]) is str and req[k] for k in ("key_id", "public_key")):
            return {"ok": False, "error": "malformed"}
        try:
            self.engine.bootstrap_key(req["key_id"], req["public_key"])
        except PermissionError as e:
            return {"ok": False, "refused": str(e)}
        return {"ok": True}

    # ---- signed operations (called by the engine only after every check passed)
    def _restorable(self) -> set[str]:
        """Assets in the approved config, the tamper id, and any asset with an
        unresolved cut (one removed from the config by config_set stays restorable)."""
        ids = {TAMPER_ASSET}
        try:
            cfg = self.config()
        except ZeeError:
            cfg = None
        ids |= {a.id for a in cfg.assets} if cfg else set()
        try:
            for line in self.ledger_path.read_text(encoding="utf-8").splitlines():
                rec = json.loads(line) if line.strip() else None
                if isinstance(rec, dict) and isinstance(rec.get("asset_id"), str):
                    ids.add(rec["asset_id"])
        except (OSError, ValueError, RecursionError):
            pass  # unreadable ledger: restore itself refuses (Z605) or goes by --all
        return ids

    def _apply_admin(self, op: str, a: dict) -> tuple[bool, str]:
        if op == "restore":
            try:
                return self.restore_fn(a["asset_id"], cut_state=self.cut_state,
                                       all_interfaces=a["scope"] == "all")
            except ZeeError as e:
                return False, str(e)
        if op == "config_set":
            return self._config_set(a["path"], a["sha256"])
        if op == "auto_set":
            return self._auto_set(a["state"] == "on")
        if op == "tamper_set":
            tmp = permission.private_temp(self.dir / "tamper.json", json.dumps({"action": a["action"]}))
            os.replace(tmp, self.dir / "tamper.json")
            self._tamper_acted = False
            return True, f"tamper response: {a['action']}"
        if op == "stop":
            self.stopping = True
            return True, "stopping"
        return False, f"unknown op {op}"

    def _config_set(self, path: str, sha256: str) -> tuple[bool, str]:
        try:
            data = read_bounded(Path(path))
        except OSError as e:
            return False, f"unreadable or not a regular file of at most {MAX_CONFIG} bytes: {e}"
        if hashlib.sha256(data).hexdigest() != sha256:
            return False, "sha256 differs from the signed value"
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            return False, "not UTF-8"
        tmp = permission.private_temp(self.config_path, text)
        try:
            bad = [a.id for a in Config.load(tmp).assets if not _ASSET_ID.fullmatch(str(a.id))]
        except ZeeError as e:
            tmp.unlink(missing_ok=True)
            return False, f"invalid config: {e}"
        if bad:  # ids reach notifications and ledgers run by root: keep them plain
            tmp.unlink(missing_ok=True)
            return False, f"asset ids must match {_ASSET_ID.pattern}: {bad[:3]}"
        os.replace(tmp, self.config_path)
        self._auto_set(False)  # a new config is never covered by the old switch
        return True, "config replaced; auto-cut is now OFF until a new signed auto_set on"

    def _auto_set(self, on: bool) -> tuple[bool, str]:
        cfg = self.config()
        if on and cfg is None:
            return False, "no config"
        prev = permission.load(self.perm_path)
        rev = prev.revision + 1 if isinstance(prev, permission.Permission) else 1
        permission.save(permission.Permission(
            schema_version=1, enabled=on, revision=rev, instance_id=permission.instance_id(self.dir),
            policy_hash=permission.policy_hash(cfg or Config(assets=())),
            disclosure_version=permission.DISCLOSURE_VERSION, changed_by="signed",
            changed_at=datetime.now(timezone.utc)), self.perm_path)
        return True, f"auto-cut {'on' if on else 'off'} (revision {rev})"

    # ---- condition (2): unapproved config change / protection destroyed (default OFF)
    def check_tamper(self) -> None:
        theirs = None
        if self.watch_config is not None:  # user-controlled file: bounded read, outside the lock
            try:
                theirs = hashlib.sha256(read_bounded(self.watch_config)).hexdigest()
            except OSError:
                theirs = "unreadable"
        with self.lock:
            found = []
            if theirs == "unreadable":
                found.append("watch_config_unreadable")
            elif theirs is not None and theirs != file_sha256(self.config_path):
                found.append("watch_config_unapproved")
            if self.last_seen is not None and self.clock() - self.last_seen > self.grace:
                found.append("watch_silent")
            self.findings = found
            if not found:
                self._strikes, self._tamper_acted = 0, False
                return
            self._strikes += 1
            self.engine._log("tamper", findings=found, strikes=self._strikes)
            action = self.tamper_action()
            # One gap is never enough (self-defense.md §4.2): act on the second check in a row, once.
            if action == "off" or self._strikes < 2 or self._tamper_acted:
                return
            self._tamper_acted = True
            try:
                cfg = self.config()
            except ZeeError:
                cfg = None
            if cfg is None or cfg.dry_run:
                self.engine._log("tamper_cut", result="dry_run: would cut", method=action)
                return
            ok, detail = self.cut_fns[action](asset_id=TAMPER_ASSET, cut_state=self.cut_state)
            self.engine._log("tamper_cut", ok=ok, method=action, detail=detail[:500])


def _read_line(sock: socket.socket) -> Optional[bytes]:
    """One request line within an overall deadline (a trickling client can't hold a slot)."""
    end, buf = time.monotonic() + READ_DEADLINE, b""
    while b"\n" not in buf and len(buf) <= MAX_LINE:
        left = end - time.monotonic()
        if left <= 0:
            return None
        sock.settimeout(left)
        try:
            chunk = sock.recv(4096)
        except OSError:  # includes the timeout
            return None
        if not chunk:
            break
        buf += chunk
    line, nl, _ = buf.partition(b"\n")
    return line + nl if nl and len(line) < MAX_LINE else None


def _replaceable_by_others(st: os.stat_result, *, sticky_ok: bool) -> bool:
    """Writable by anyone but the owner: group- or other-writable, whatever the group (gid 0
    included: a non-root member of it could swap entries). Only sticky directories on the way
    (like /tmp) are tolerated: others can't rename what root owns there."""
    w = bool(st.st_mode & (stat.S_IWOTH | stat.S_IWGRP))
    return w and not (sticky_ok and st.st_mode & stat.S_ISVTX)


def _resolve_checked(d: Path) -> Path:
    """Resolve ``d`` one component at a time. Every directory entered must be owned by root
    or us and not replaceable by others; every symlink followed (including hops in the
    middle of a chain) must be owned by root or us, and it lives in a directory already
    checked. Returns the resolved path; callers use it, never a second realpath()."""
    me = os.geteuid()

    def bad(p: Path) -> ValueError:
        return ValueError(f"socket directory must be owned by uid {me}, not a symlink and not "
                          f"writable by others, and no directory or link on the way may be "
                          f"replaceable by others: {p}")
    todo, cur, hops = list(Path(os.path.abspath(d)).parts[1:]), Path("/"), 0
    st = os.lstat(cur)
    if st.st_uid not in (0, me) or _replaceable_by_others(st, sticky_ok=True):
        raise bad(cur)
    while todo:
        name = todo.pop(0)
        if name in ("", "."):
            continue
        if name == "..":
            cur = cur.parent
            continue
        nxt = cur / name
        st = os.lstat(nxt)
        if stat.S_ISLNK(st.st_mode):
            hops += 1
            if st.st_uid not in (0, me) or hops > 40:
                raise bad(nxt)
            target = Path(os.readlink(nxt))
            if target.is_absolute():
                cur = Path("/")
            todo = [*target.parts[1 if target.is_absolute() else 0:], *todo]
            continue
        if not stat.S_ISDIR(st.st_mode) or st.st_uid not in (0, me) \
                or _replaceable_by_others(st, sticky_ok=True):
            raise bad(nxt)
        cur = nxt
    return cur


def _runtime_targets() -> dict[str, tuple[Path, str]]:
    """What a root daemon actually executes: (path, depth) with depth "tree" (every file),
    "top" (the directory and its entries: site-packages, where .pth files run at start-up)."""
    import site
    import sysconfig
    t = {"python": (Path(sys.executable), "tree"),
         "zee package": (Path(__file__).resolve().parent.parent, "tree")}
    for k in ("stdlib", "platstdlib"):
        t[k] = (Path(sysconfig.get_paths()[k]), "tree")
    for n, sp in enumerate(site.getsitepackages()):
        if os.path.isdir(sp):
            t[f"site-packages {n}"] = (Path(sp), "top")
    return t


_THIRD_PARTY = {"site-packages", "dist-packages"}  # checked at the top level as their own targets


def check_runtime(targets: Optional[dict[str, tuple[Path, str]]] = None) -> None:
    """Refuse to run as root from code that anyone but root could change: the Python
    executable, the standard library, the site-packages directories (top level: .pth files
    run at start-up) and the zee package. Each is reached through directories and links
    nobody else can replace, owned by us, writable by no one else (no group, gid 0 included).
    (macOS /usr/bin/python3 is 3.9; a Homebrew Python belongs to the user who installed it.)"""
    me = os.geteuid()
    for what, (t, depth) in (targets or _runtime_targets()).items():
        try:
            real = _resolve_checked(t.parent) / t.name
            st = os.lstat(real)
            while stat.S_ISLNK(st.st_mode):  # e.g. bin/python3 -> python3.12, in a checked directory
                if st.st_uid not in (0, me):
                    raise ValueError(f"link not owned by root: {real}")
                link = Path(os.readlink(real))
                real = _resolve_checked((real.parent / link).parent) / link.name
                st = os.lstat(real)
        except (OSError, ValueError) as e:
            raise ValueError(f"{what} ({t}) is not root-controlled: {e}") from e
        if st.st_uid != me or _replaceable_by_others(st, sticky_ok=False):
            raise ValueError(f"{what} ({real}) must be owned by uid {me} and writable by no one else")
        if not stat.S_ISDIR(st.st_mode):
            continue
        _check_tree(what, real, depth, me, set())


def _check_tree(what: str, top: Path, depth: str, me: int, seen: set) -> None:
    """Every entry under ``top``: ours and writable by no one else. A symlink is judged by its
    owner (its mode means nothing) and by its target: the path to the target must not be
    replaceable, the target must pass the same test, and a linked directory is walked too."""
    if str(top) in seen:  # link cycles
        return
    seen.add(str(top))
    for root, dirs, files in os.walk(top):
        if depth == "tree":
            dirs[:] = [d for d in dirs if d not in _THIRD_PARTY]
        for n in dirs + files:
            path = os.path.join(root, n)
            sub = os.lstat(path)
            if stat.S_ISLNK(sub.st_mode):
                target = Path(os.path.normpath(os.path.join(root, os.readlink(path))))
                try:
                    if sub.st_uid not in (0, me):
                        raise ValueError("link not owned by root")
                    resolved = _resolve_checked(target.parent) / target.name
                    tst = os.lstat(resolved)
                    while stat.S_ISLNK(tst.st_mode):
                        if tst.st_uid not in (0, me):
                            raise ValueError("link not owned by root")
                        nxt = Path(os.path.normpath(os.path.join(resolved.parent, os.readlink(resolved))))
                        resolved = _resolve_checked(nxt.parent) / nxt.name
                        tst = os.lstat(resolved)
                except (OSError, ValueError) as e:
                    raise ValueError(f"{what}: link {path} -> {target} is not root-controlled: {e}") from e
                if tst.st_uid != me or _replaceable_by_others(tst, sticky_ok=False):
                    raise ValueError(f"{what}: {path} -> {resolved} must be owned by uid {me} "
                                     "and writable by no one else")
                if stat.S_ISDIR(tst.st_mode) and depth == "tree":
                    _check_tree(what, resolved, depth, me, seen)
                continue
            if sub.st_uid != me or _replaceable_by_others(sub, sticky_ok=False):
                raise ValueError(f"{what}: {path} must be owned by uid {me} and writable by no one else")
        if depth == "top":
            break


def check_state_dir(d: Path) -> Path:
    """The state directory holds the approver key registry: if anyone but root could put a
    file there (or swap the directory), they could register their own key. Reached through
    nothing others can replace; ours, 0700; every entry ours, a regular file or directory
    (no links), writable by no one else. Created 0700 when missing. Returns the checked path."""
    d = Path(os.path.abspath(d))
    if os.path.islink(d):
        raise ValueError(f"state directory is a symlink: {d}")
    parent = _resolve_checked(d.parent)
    real = parent / d.name
    if not os.path.lexists(real):
        real.mkdir(mode=0o700)
    me = os.geteuid()
    st = os.lstat(real)
    if not stat.S_ISDIR(st.st_mode) or st.st_uid != me or stat.S_IMODE(st.st_mode) & 0o077:
        raise ValueError(f"state directory must be a directory owned by uid {me}, mode 0700: {real}")
    for root, dirs, files in os.walk(real):
        for n in dirs + files:
            sub = os.lstat(os.path.join(root, n))
            if stat.S_ISLNK(sub.st_mode) or sub.st_uid != me or _replaceable_by_others(sub, sticky_ok=False):
                raise ValueError(f"state entry must be ours, not a link, writable by no one else: "
                                 f"{os.path.join(root, n)}")
    return real


def check_socket_dir(d: Path) -> Path:
    """The socket directory: not a symlink itself, ours, writable by no one else, reached
    only through what others can't replace. Returns the checked, resolved path."""
    if os.path.islink(os.path.abspath(d)):
        raise ValueError(f"socket directory is a symlink: {d}")
    real = _resolve_checked(d)
    st = os.lstat(real)
    if st.st_uid != os.geteuid() or _replaceable_by_others(st, sticky_ok=False):
        raise ValueError(f"socket directory must be owned by uid {os.geteuid()} and not "
                         f"writable by others: {real}")
    return real


def serve(daemon: CutDaemon, socket_path: Path, *, group: Optional[int] = None,
          check_every: float = 30) -> int:
    """Bind, then serve until a signed ``stop``. Exit 0 so `KeepAlive.SuccessfulExit=false`
    (launchd) / `Restart=on-failure` (systemd) leave it stopped."""
    check_runtime()
    socket_path = Path(os.path.abspath(socket_path))
    if not os.path.lexists(socket_path.parent):  # e.g. /var/db/zee on macOS (RuntimeDirectory on Linux)
        made = _resolve_checked(socket_path.parent.parent) / socket_path.parent.name
        made.mkdir()
        os.chmod(made, 0o755)  # the daemon's umask (077) would make it untraversable
    socket_path = check_socket_dir(socket_path.parent) / socket_path.name  # fixed, checked path
    if socket_path.is_symlink():
        raise ValueError(f"symlink refused: {socket_path}")
    if socket_path.exists():
        if not stat.S_ISSOCK(socket_path.lstat().st_mode):
            raise ValueError(f"not a socket: {socket_path}")
        socket_path.unlink()  # our own stale socket from a previous run

    # Bounded concurrency: allowed uids (the watch, root) and everyone else get
    # separate pools, so other socket users can't crowd out a cut. Over the cap a
    # connection is closed before any thread starts.
    pools = {True: threading.BoundedSemaphore(CONN_SLOTS), False: threading.BoundedSemaphore(CONN_SLOTS)}

    class Handler(socketserver.BaseRequestHandler):
        def handle(self) -> None:
            uid = self.server.peer_of[id(self.request)][0]
            if uid is None:
                self.request.sendall(b'{"ok": false, "error": "peer_unknown", "code": "Z712"}\n')
                return
            line = _read_line(self.request)
            if line is None:
                reply = {"ok": False, "error": "malformed", "code": "Z711"}
            else:
                reply = daemon.handle_line(line, uid)
            try:
                self.request.sendall(json.dumps(reply).encode() + b"\n")
            finally:  # an approved stop completes even if the requester hung up
                if daemon.stopping:
                    threading.Thread(target=self.server.shutdown, daemon=True).start()

    class Server(socketserver.ThreadingUnixStreamServer):
        daemon_threads = True
        peer_of: dict = {}

        def process_request(self, request, client_address):
            try:
                uid = peer_uid(request)
            except OSError:
                uid = None
            pool = pools[uid is not None and (uid in daemon.allow or uid == 0)]
            if not pool.acquire(blocking=False):
                self.shutdown_request(request)  # too many at once: refuse, don't queue
                return
            self.peer_of[id(request)] = (uid, pool)  # sockets take no attributes (__slots__)
            try:
                super().process_request(request, client_address)
            except BaseException:
                self.peer_of.pop(id(request), None)
                pool.release()
                raise

        def process_request_thread(self, request, client_address):
            try:
                super().process_request_thread(request, client_address)
            finally:
                self.peer_of.pop(id(request))[1].release()

    old = os.umask(0o177)  # the socket never exists with wider modes than 0600
    try:
        server = Server(str(socket_path), Handler)
    finally:
        os.umask(old)
    if group is not None:
        os.chown(socket_path, -1, group)
        os.chmod(socket_path, 0o660)  # BSD may ignore socket modes (unix(7)): the uid check is the gate

    def tamper_loop() -> None:
        while not daemon.stopping:
            time.sleep(check_every)
            try:
                daemon.check_tamper()
            except Exception:  # noqa: BLE001
                logger.exception("cutd: tamper check failed")

    threading.Thread(target=tamper_loop, daemon=True).start()
    print(f"[zee cutd] {__version__} listening on {socket_path} uid={os.geteuid()} "
          f"allow={sorted(daemon.allow)}", file=sys.stderr, flush=True)
    with server:
        server.serve_forever()
    print("[zee cutd] stopped by a signed request", file=sys.stderr, flush=True)
    return 0
