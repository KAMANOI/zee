"""Control core of egress approval: shape judgement, hold, signed release.

Pure policy + state. It never touches the network itself: holding and
releasing go through an `Enforcer` (a mock in tests, a pf renderer in
`pf.py`). Time is injected so every deadline is testable.

Fail-closed rule: a held (exfiltration-shaped) send is never passed without a verified signature that
matches a request Zee itself issued. Observation/notification is computed
BEFORE the on/off switch is consulted, so switching approval off (or a broken
state file) can never silence detection.
"""
from __future__ import annotations

import fnmatch
import ipaddress
import math
import json
import os
import secrets
import socket
import time
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Optional, Protocol

from ..responder.permission import HostLock, private_directory, private_temp
from ..telemetry.events_log import EventLog
from .signing import Verifier, payload_digest

logger = logging.getLogger(__name__)

CONFIG_OPS = {"allow_add": ("dest",), "allow_remove": ("dest",), "protect_add": ("id",),
              "protect_remove": ("id",), "key_add": ("key_id", "public_key"),
              "key_remove": ("key_id",), "disable": ()}  # op -> required (non-empty str) args


class Enforcer(Protocol):
    def hold(self, dest: str) -> None: ...
    def allow(self, dest: str, until: float) -> None: ...
    def release(self, dest: str) -> None: ...


@dataclass(frozen=True)
class Flow:
    proc: str
    dest: str  # "host:port"
    bytes_out: int  # bytes since the previous sample


@dataclass(frozen=True)
class Verdict:
    action: str  # "pass" | "notify" | "hold"
    reason: str


@dataclass
class Request:
    id: str
    kind: str  # "egress" | "config"
    payload: dict  # exactly what is shown to, and signed by, the approver
    code: str  # number-matching code: shown on this host only, typed on the phone
    exp: float


@dataclass
class Grant:
    until: float
    remaining: int


@dataclass
class Result:
    ok: bool
    reason: str = ""


def _host(dest: str) -> str:
    h = dest.rsplit(":", 1)[0] if dest.count(":") == 1 or dest.startswith("[") else dest
    return h.strip("[]")


def _match(dest: str, entries: list[str]) -> bool:
    host = _host(dest)
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        ip = None
    if ip is not None and ip.is_loopback:
        return True
    for e in entries:
        if e == dest or e == host or (e.startswith("*.") and fnmatch.fnmatch(host, e)):
            return True
        if ip is not None and "/" in e:
            try:
                if ip in ipaddress.ip_network(e, strict=False):
                    return True
            except ValueError:
                pass
    return False


class Engine:
    BUNDLE_WINDOW = 20  # s: flows within this window share one request
    MIN_BATCH_INTERVAL = 60  # s: at most one new request per minute (approval-fatigue guard)
    RESPONSE_TTL = 300  # s: no answer by then = denied
    GRANT_TTL = 900  # s: how long an approved destination stays open
    BYTES_THRESHOLD = 1_000_000  # un-allowlisted egress at/above this is exfil-shaped
    TAINT_WINDOW = 600  # s: after a protected-data touch, any new destination is exfil-shaped
    RECOVERY_WAIT = 72 * 3600
    RECOVERY_NOTICE_EVERY = 6 * 3600

    def __init__(self, state_dir: Path, verifier: Verifier, *, enforcer: Optional[Enforcer] = None,
                 notify: Optional[Callable[[str, dict], None]] = None,
                 clock: Callable[[], float] = time.time, server_form: bool = False) -> None:
        self.dir, self.verifier, self.enforcer = Path(state_dir), verifier, enforcer
        self._notify, self.clock, self.server_form = notify, clock, server_form
        self.path = self.dir / "egress_approval.json"
        self.log_path = self.dir / "egress.jsonl"
        self.pending: dict[str, Request] = {}
        self.grants: dict[str, Grant] = {}
        self.held: set[str] = set()
        self.taint: dict[str, float] = {}
        self.batch: Optional[dict] = None
        self.last_batch = -1e18
        self.last_recovery_notice = 0.0
        self.state_invalid = False
        self.state = self._load()

    # ---- state (writes share responder/permission.py's 0700/0600 atomic replace;
    # reads are a plain read — single-process prototype, same-user tampering out of scope)
    def _fresh(self) -> dict:
        return {"enabled": False, "keys": {}, "allow": [], "protect": [], "used": {},
                "single_key_ack": False, "recovery_start": None}

    def _load(self) -> dict:
        try:
            raw = json.loads(self.path.read_text())
            if not isinstance(raw, dict) or set(raw) != set(self._fresh()):
                raise ValueError("bad shape")
            for k, v in self._fresh().items():
                got = raw[k]
                if k == "recovery_start":  # NaN would skip the 72h wait
                    ok = got is None or (type(got) in (int, float) and math.isfinite(got))
                else:
                    ok = type(got) is type(v)  # exact: "false"/1 never pass as bool
                if ok and k in ("allow", "protect"):
                    ok = all(type(x) is str for x in got)
                elif ok and k == "keys":
                    ok = all(type(x) is str for x in got.values())
                elif ok and k == "used":
                    ok = all(type(x) in (int, float) for x in got.values())
                if not ok:
                    raise ValueError(f"bad type: {k}")
            return raw
        except FileNotFoundError:
            return self._fresh()
        except (OSError, ValueError, RecursionError):
            # Present but unreadable: treat as ON with no authority (fail closed).
            self.state_invalid = True
            return {**self._fresh(), "enabled": True}

    def _save(self) -> None:
        private_directory(self.dir)
        with HostLock(self.dir / "egress.lock"):
            tmp = private_temp(self.path, json.dumps(self.state, sort_keys=True) + "\n")
            os.replace(tmp, self.path)
        self.state_invalid = False

    def _log(self, type_: str, **rec) -> None:
        rec = {"type": type_, "ts": datetime.fromtimestamp(self.clock(), timezone.utc).isoformat(), **rec}
        if self._notify:
            try:
                self._notify(type_, rec)
            except Exception:  # noqa: BLE001 - a failed notification must never stop the hold
                logger.exception("zee: egress notification failed")
        try:
            private_directory(self.dir)
            EventLog._append(self.log_path, rec)
        except Exception:  # noqa: BLE001 - evidence must never stop detection or the hold
            logger.exception("zee: egress evidence write failed")

    @property
    def enabled(self) -> bool:
        return bool(self.state["enabled"])

    # ---- local (unsigned) setup: only while approval is OFF
    def _setup_only(self) -> None:
        if self.enabled:
            raise PermissionError("approval is ON: change this with a signed request")

    def setup_allow(self, dest: str) -> None:
        self._setup_only()
        self.state["allow"].append(dest)
        self._save()

    def setup_protect(self, data_id: str) -> None:
        self._setup_only()
        self.state["protect"].append(data_id)
        self._save()

    def bootstrap_key(self, key_id: str, public_key: str) -> None:
        """First approver device, entered at the host console. Later keys need a signature."""
        if self.state["keys"] or self.state_invalid:
            raise PermissionError("registry not empty or state invalid: no unsigned registration")
        self.state["keys"][key_id] = public_key
        self._save()
        self._log("config_applied", op="key_add", key_id=key_id, via="bootstrap")

    def ack_single_key(self) -> None:
        self._setup_only()
        self.state["single_key_ack"] = True
        self._save()

    def enable(self) -> None:
        """Explicit user operation. Needs a spare approver key (or a recorded acknowledgement)."""
        n = len(self.state["keys"])
        if n == 0 or (n < 2 and not self.state["single_key_ack"]):
            raise PermissionError("register a spare approver key first")
        self.state["enabled"] = True
        self._save()
        self._log("enabled")

    # ---- requests and signed submissions
    def _new_request(self, kind: str, body: dict, ttl: Optional[float] = None) -> Request:
        now = self.clock()
        rid = secrets.token_hex(8)
        payload = {"v": 1, "kind": kind, "req": rid, "nonce": secrets.token_hex(16),
                   "exp": int(now + (ttl or self.RESPONSE_TTL)), **body}
        req = Request(rid, kind, payload, f"{secrets.randbelow(100):02d}", payload["exp"])
        self.pending[rid] = req
        return req

    def _key_floor(self) -> bool:
        """True if removing a key now would leave fewer than two while ON without the ack."""
        return self.enabled and not self.state["single_key_ack"] and len(self.state["keys"]) <= 2

    def request_config(self, op: str, **args) -> Request:
        # Validated before issuing: a bad arg must never consume an approval or reach _match().
        if op not in CONFIG_OPS or set(args) != set(CONFIG_OPS[op]) \
                or not all(type(v) is str and v for v in args.values()):
            raise ValueError(op)
        if op == "key_remove" and self._key_floor():
            raise PermissionError("would leave fewer than two approver keys")
        req = self._new_request("config", {"op": op, "args": args})
        self._log("request", req=req.id, kind="config", op=op, code_shown_on="host",
                  args={k: v for k, v in args.items() if k != "public_key"})
        return req

    def submit(self, payload: dict, entered: str, key_id: str, signature: bytes) -> Result:
        """`payload` is what the approver's device showed and signed (plus `entered`)."""
        now = self.clock()
        if not (isinstance(payload, dict) and isinstance(payload.get("req"), str)
                and isinstance(entered, str) and isinstance(key_id, str)
                and isinstance(signature, (bytes, bytearray))):
            self._log("denied", reason="malformed")
            return Result(False, "malformed")
        req = self.pending.get(payload["req"])

        def deny(reason: str) -> Result:
            self._log("denied", req=payload["req"][:32], key_id=key_id[:64], reason=reason)
            return Result(False, reason)

        if req is None:
            return deny("unknown_request")
        if now > req.exp:
            self.pending.pop(req.id, None)
            return deny("expired")
        if payload != req.payload:
            return deny("payload_mismatch")  # shown/signed content differs from what Zee asked
        pub = self.state["keys"].get(key_id)
        if pub is None:
            return deny("unknown_key")
        digest = payload_digest({**payload, "entered": entered})
        if digest.hex() in self.state["used"]:
            return deny("replay")
        if not self.verifier.verify(pub, digest, bytes(signature)):
            return deny("bad_signature")
        # Checked only AFTER the signature: the code can't be brute-forced without a registered key.
        if entered != req.code:
            return deny("code_mismatch")
        # Re-checked against the CURRENT keys: two removals issued at 3 keys must not both apply.
        if req.kind == "config" and payload["op"] == "key_remove" and self._key_floor():
            return deny("would_leave_one_key")
        self.pending.pop(req.id, None)
        self.state["used"] = {d: e for d, e in self.state["used"].items() if e >= now}
        self.state["used"][digest.hex()] = payload["exp"]
        self._save()  # persist the replay ledger BEFORE acting on the approval
        self._apply(req, key_id)
        return Result(True)

    def _apply(self, req: Request, key_id: str) -> None:
        p = req.payload
        if req.kind == "egress":
            for d in p["dests"]:
                self.grants[d] = Grant(float(p["until"]), int(p["max_bytes"]))
                if self.enforcer:
                    self.enforcer.allow(d, float(p["until"]))
                self.held.discard(d)
            self._log("approved", req=req.id, key_id=key_id, dests=p["dests"],
                      max_bytes=p["max_bytes"], until=p["until"])
            return
        op, a, s = p["op"], p["args"], self.state
        if op == "allow_add" and a["dest"] not in s["allow"]:
            s["allow"].append(a["dest"])
            self._release({d for d in self.held | set(self.grants) if _match(d, [a["dest"]])})
        elif op == "allow_remove" and a["dest"] in s["allow"]:
            s["allow"].remove(a["dest"])
        elif op == "protect_add" and a["id"] not in s["protect"]:
            s["protect"].append(a["id"])
        elif op == "protect_remove" and a["id"] in s["protect"]:
            s["protect"].remove(a["id"])
        elif op == "key_add":
            s["keys"][a["key_id"]] = a["public_key"]
        elif op == "key_remove" and len(s["keys"]) > 1:
            s["keys"].pop(a["key_id"], None)
        elif op == "disable":
            s["enabled"] = False
            self._release(self.held | set(self.grants))
        s["recovery_start"] = None
        self._save()
        self._log("config_applied", req=req.id, op=op, key_id=key_id,
                  args={k: v for k, v in a.items() if k != "public_key"})

    def _release(self, dests: set[str]) -> None:
        for d in sorted(dests):
            try:
                if self.enforcer:
                    self.enforcer.release(d)
            except Exception:  # noqa: BLE001 - stays recorded as held (fail closed); config still saved
                logger.exception("zee: egress release failed")
                continue
            self.held.discard(d)
            self.grants.pop(d, None)

    # ---- recovery when every approver key is lost: time-locked, loud, cancellable
    def recovery_start(self) -> None:
        self.state["recovery_start"] = self.clock()
        self._save()
        self.last_recovery_notice = self.clock()
        self._log("recovery_started", wait_s=self.RECOVERY_WAIT)

    def recovery_complete(self) -> Result:
        t = self.state["recovery_start"]
        if t is None or self.clock() < t + self.RECOVERY_WAIT:
            return Result(False, "waiting")
        self._release(self.held | set(self.grants))  # OFF must actually reopen, as with disable
        self.state.update(keys={}, enabled=False, recovery_start=None, single_key_ack=False)
        self._save()
        self._log("recovery_completed")
        return Result(True)

    # ---- shape judgement and hold
    def note_protected_touch(self, data_id: str) -> None:
        if data_id in self.state["protect"]:
            self.taint[data_id] = self.clock() + self.TAINT_WINDOW

    def _tainted(self) -> list[str]:
        now = self.clock()
        self.taint = {k: v for k, v in self.taint.items() if v > now}
        return sorted(self.taint)

    def _classify(self, f: Flow) -> Optional[str]:
        """Reason this flow is exfil-shaped, or None. Pure: ignores the on/off switch."""
        if _match(f.dest, self.state["allow"]):
            return None
        if self.server_form:
            return "server_not_allowlisted"
        if self._tainted():
            return "protected_touch_then_new_destination"
        if f.bytes_out >= self.BYTES_THRESHOLD:
            return "large_unlisted_send"
        if f.dest in self.grants:  # the signed volume/deadline is metered on every send
            return "approved_destination"
        if f.dest in self.held:  # still held: small/untainted sends don't make it pass
            return "held_destination"
        return None

    def observe(self, f: Flow) -> Verdict:
        reason = self._classify(f)
        if reason is None:
            return Verdict("pass", "ok")
        # Detection + notification happen here, before the switch is read.
        self._log("egress_shape", proc=f.proc, dest=f.dest, bytes_out=f.bytes_out, reason=reason,
                  data=self._tainted())
        if not self.enabled:
            return Verdict("notify", "approval_off")
        g = self.grants.get(f.dest)
        now = self.clock()
        if g and g.until > now and g.remaining >= f.bytes_out:
            g.remaining -= f.bytes_out
            return Verdict("pass", "approved")
        self._hold(f)  # expired or over the signed volume: close again
        self.grants.pop(f.dest, None)  # only once held, so a failed hold is retried
        return Verdict("hold", "no_valid_approval")

    def _hold(self, f: Flow) -> None:
        if f.dest not in self.held:
            if self.enforcer:
                self.enforcer.hold(f.dest)  # may raise: then not marked held, next flow retries
            self.held.add(f.dest)
            self._log("hold", dest=f.dest, proc=f.proc)
        b = self.batch
        if b is None:
            b = self.batch = {"opened": self.clock(), "dests": {}, "procs": set(), "data": set()}
        b["dests"][f.dest] = max(b["dests"].get(f.dest, 0), f.bytes_out)
        b["procs"].add(f.proc)
        b["data"].update(self._tainted())

    def tick(self) -> None:
        """Seal batches into ONE request, expire unanswered ones, close expired grants."""
        now = self.clock()
        b = self.batch
        if b and now - b["opened"] >= self.BUNDLE_WINDOW and now - self.last_batch >= self.MIN_BATCH_INTERVAL:
            self.batch, self.last_batch = None, now
            req = self._new_request("egress", {
                "host": socket.gethostname(), "dests": sorted(b["dests"]), "procs": sorted(b["procs"]),
                "max_bytes": max(self.BYTES_THRESHOLD, *b["dests"].values()),
                "data": sorted(b["data"]), "until": int(now + self.GRANT_TTL)})
            self._log("request", req=req.id, kind="egress", dests=req.payload["dests"],
                      procs=req.payload["procs"], data=req.payload["data"],
                      max_bytes=req.payload["max_bytes"], code_shown_on="host")
        for rid, r in list(self.pending.items()):
            if now > r.exp:
                self.pending.pop(rid)
                self._log("timeout", req=rid, result="not_passed")  # no answer = stays held
        for d, g in list(self.grants.items()):
            if g.until <= now:
                try:
                    if self.enforcer:
                        self.enforcer.hold(d)
                except Exception:  # noqa: BLE001 - keep the expired grant: next tick/flow retries
                    logger.exception("zee: egress hold failed")
                    continue
                self.grants.pop(d)
                self.held.add(d)
        t = self.state["recovery_start"]
        if t is not None and now - self.last_recovery_notice >= self.RECOVERY_NOTICE_EVERY:
            self.last_recovery_notice = now
            self._log("recovery_pending", completes_at=t + self.RECOVERY_WAIT)
