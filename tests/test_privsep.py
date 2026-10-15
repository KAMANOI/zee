"""Privsep prototype: the cut daemon's trust boundary (docs/design/privsep.md).

OS effects are stubbed here; the real root/second-user run is
.github/workflows/privsep.yml.
"""
import base64
import hashlib
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

import pytest

from zee.config.schema import Config
from zee.egress.engine import Engine
from zee.errors import ZeeError, Z601_RESTORE_FAILED
from zee.events import TrapEvent
from zee.responder import sequence
from zee.telemetry.events_log import EventLog

from .test_egress_approval import Clock, HmacVerifier, sign

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="Unix sockets / POSIX modes")

WATCH, OTHER = 1001, 1002


@pytest.fixture(autouse=True)
def _dev_runtime(request, monkeypatch):
    """serve() refuses a Python / zee tree others can write (the dev venv is one):
    tested on its own below and on the CI runners; skipped for the socket tests."""
    if "check_runtime" not in request.node.name:
        from zee.privsep import daemon
        monkeypatch.setattr(daemon, "check_runtime", lambda *a, **k: None)
CFG = '''dry_run = false
[[assets]]
id = "ws"
response_mode = "auto"
cut_method = "egress"
decoy_paths = ["/tmp/zee-decoy"]
'''


class Cuts:
    def __init__(self):
        self.calls = []

    def fns(self):
        return {m: (lambda m=m, **kw: self.calls.append((m, kw["asset_id"])) or (True, f"{m} ok"))
                for m in ("full", "egress")}


@pytest.fixture
def env(tmp_path):
    from zee.privsep.daemon import CutDaemon
    state = tmp_path / "cutd"
    state.mkdir(mode=0o700)
    (state / "assets.toml").write_text(CFG)
    cuts, restores, clock = Cuts(), [], Clock()

    def fake_restore(asset_id, *, cut_state, all_interfaces):
        restores.append((asset_id, all_interfaces))
        return True, "restored"

    d = CutDaemon(state, {WATCH}, verifier=HmacVerifier(), clock=clock,
                  cut_fns=cuts.fns(), restore_fn=fake_restore, tamper_grace=100)
    assert d.handle_line(json.dumps({"op": "bootstrap_key", "key_id": "k1", "public_key": "s1"}).encode(), 0)["ok"]
    return d, cuts, restores, clock


def req(d, uid=WATCH, **r):
    return d.handle_line(json.dumps(r).encode(), uid)


def signed(d, admin_op, uid=WATCH, secret="s1", key="k1", tamper=None, **args):
    ch = req(d, uid, op="challenge", admin_op=admin_op, args=args)
    assert ch["ok"], ch
    payload, code = ch["payload"], ch["code"]
    if tamper:
        payload, code = tamper(payload, code)
    sig = base64.b64encode(sign(secret, payload, code)).decode()
    return req(d, uid, op="submit", payload=payload, entered=code, key_id=key, signature=sig)


def cut(d, uid=WATCH, **over):
    r = {"op": "cut", "asset_id": "ws", "op_class": "change", "confidence": "high", **over}
    return req(d, uid, **r)


# ---- peer credentials (kernel-reported, not self-declared)
def test_peer_uid_is_the_kernel_reported_uid():
    from zee.privsep.daemon import peer_uid
    a, b = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    with a, b:
        assert peer_uid(a) == os.geteuid()


# ---- unsigned surface: cut and status only, only from allowed uids
def test_cut_and_status_need_an_allowed_peer(env):
    d, cuts, _, _ = env
    for op in ("cut", "status", "challenge", "submit"):
        assert req(d, OTHER, op=op) == {"ok": False, "error": "peer_not_allowed", "code": "Z712"}
    assert req(d, WATCH, op="status")["ok"] is True
    assert cuts.calls == []


@pytest.mark.parametrize("op", ["restore", "config_set", "auto_set", "stop", "tamper_set", "disable"])
def test_management_ops_are_not_unsigned_requests(env, op):
    d, cuts, restores, _ = env
    assert req(d, 0, op=op, asset_id="ws") == {"ok": False, "error": "unknown_op", "code": "Z713"}
    assert restores == [] and not d.stopping


def test_cut_needs_the_signed_auto_permission(env):
    d, cuts, _, _ = env
    assert cut(d) == {"ok": False, "refused": "no_permission", "code": "Z715"}
    assert signed(d, "auto_set", state="on")["ok"]
    assert cut(d)["ok"] is True
    assert cuts.calls == [("egress", "ws")]  # the method comes from the daemon's own config
    assert signed(d, "auto_set", state="off")["ok"]
    assert cut(d) == {"ok": False, "refused": "auto_off", "code": "Z715"}


@pytest.mark.parametrize("over,why", [
    ({"op_class": "read"}, "op_class_not_change"),
    ({"confidence": "medium"}, "confidence_not_high"),
    ({"asset_id": "nope"}, "unknown_asset"),
])
def test_cut_facts_are_checked_by_the_daemon(env, over, why):
    d, cuts, _, _ = env
    signed(d, "auto_set", state="on")
    assert cut(d, **over)["refused"] == why
    assert cuts.calls == []


@pytest.mark.parametrize("extra", [{"method": "full"}, {"target": "en0"}, {"asset_id": 1}, {"asset_id": "x" * 129}])
def test_requester_cannot_choose_method_or_target(env, extra):
    d, cuts, _, _ = env
    signed(d, "auto_set", state="on")
    assert cut(d, **extra) == {"ok": False, "error": "malformed", "code": "Z711"}
    assert cuts.calls == []


def test_dry_run_in_the_daemon_config_never_cuts(env):
    d, cuts, _, _ = env
    signed(d, "auto_set", state="on")
    (d.dir / "assets.toml").write_text(CFG.replace("dry_run = false", "dry_run = true"))
    assert cut(d)["ok"] is False
    assert cuts.calls == []


def test_malformed_lines_never_raise(env):
    d, _, _, _ = env
    for line in (b"", b"[]", b"{", b'{"op": 1}', b"\xff", b"[" * 100000):
        assert d.handle_line(line, WATCH)["ok"] is False


# ---- signed path: the egress approval engine, reused
def test_signed_restore_maps_scope(env):
    d, _, restores, _ = env
    assert signed(d, "restore", asset_id="ws", scope="recorded")["ok"]
    assert signed(d, "restore", asset_id="zee-tamper", scope="all")["ok"]
    assert restores == [("ws", False), ("zee-tamper", True)]


def test_restore_of_unknown_asset_is_not_even_issued(env):
    d, _, _, _ = env
    assert req(d, WATCH, op="challenge", admin_op="restore",
               args={"asset_id": "nope", "scope": "recorded"})["refused"] == "unknown_asset"


def test_failed_restore_is_reported_and_daemon_keeps_serving(env):
    d, _, _, _ = env

    def boom(*a, **k):
        raise ZeeError(Z601_RESTORE_FAILED, "x")
    d.restore_fn = boom
    r = signed(d, "restore", asset_id="ws", scope="recorded")
    assert r["ok"] is False and "Z601" in r["detail"]
    assert req(d, op="status")["ok"]


def test_old_auto_on_signature_cannot_approve_a_newer_config(env, tmp_path):
    d, cuts, _, _ = env
    ch = req(d, WATCH, op="challenge", admin_op="auto_set", args={"state": "on"})
    assert len(ch["payload"]["args"]["config_sha256"]) == 64  # bound by the daemon
    new = tmp_path / "full.toml"
    new.write_text(CFG.replace('"egress"', '"full"'))
    assert signed(d, "config_set", path=str(new), sha256=hashlib.sha256(new.read_bytes()).hexdigest())["ok"]
    sig = base64.b64encode(sign("s1", ch["payload"], ch["code"])).decode()
    r = req(d, WATCH, op="submit", payload=ch["payload"], entered=ch["code"], key_id="k1", signature=sig)
    assert r["ok"] is False and "config_sha256" in r["detail"]
    assert cut(d)["refused"] == "auto_off" and cuts.calls == []


def test_old_restore_signature_cannot_undo_a_newer_cut(env):
    d, cuts, restores, _ = env
    ch = req(d, WATCH, op="challenge", admin_op="restore", args={"asset_id": "ws", "scope": "recorded"})
    d.cut_state.record_cut(asset_id="ws", method="egress", platform=sys.platform, modified=["x"])
    sig = base64.b64encode(sign("s1", ch["payload"], ch["code"])).decode()
    r = req(d, WATCH, op="submit", payload=ch["payload"], entered=ch["code"], key_id="k1", signature=sig)
    assert r["ok"] is False and "ledger_sha256" in r["detail"] and restores == []


def test_bound_fields_cannot_be_supplied_by_the_requester(env):
    d, _, _, _ = env
    for op, args in (("auto_set", {"state": "on", "config_sha256": "0" * 64}), ("stop", {"gen": "0"}),
                     ("restore", {"asset_id": "ws", "scope": "all", "ledger_sha256": "absent"})):
        assert req(d, WATCH, op="challenge", admin_op=op, args=args)["refused"] == "bad_args"


def test_old_auto_on_signature_cannot_undo_a_newer_off(env):
    """Codex 2: hold an 'on' signature, let a newer 'off' apply, then replay the old 'on'."""
    d, cuts, _, _ = env
    old = req(d, WATCH, op="challenge", admin_op="auto_set", args={"state": "on"})
    assert signed(d, "auto_set", state="off")["ok"]
    sig = base64.b64encode(sign("s1", old["payload"], old["code"])).decode()
    r = req(d, WATCH, op="submit", payload=old["payload"], entered=old["code"], key_id="k1", signature=sig)
    assert r["ok"] is False and "gen" in r["detail"]
    assert cut(d)["refused"] == "auto_off" and cuts.calls == []


def test_old_tamper_off_cannot_undo_a_newer_on(env):
    d, _, _, _ = env
    old = req(d, WATCH, op="challenge", admin_op="tamper_set", args={"action": "off"})
    assert signed(d, "tamper_set", action="full")["ok"]
    sig = base64.b64encode(sign("s1", old["payload"], old["code"])).decode()
    assert req(d, WATCH, op="submit", payload=old["payload"], entered=old["code"],
               key_id="k1", signature=sig)["ok"] is False
    assert d.tamper_action() == "full"


def test_config_set_rejects_odd_asset_ids(env, tmp_path):
    d, _, _, _ = env
    new = tmp_path / "q.toml"
    new.write_text(CFG.replace('"ws"', '"w\\"s"'))
    r = signed(d, "config_set", path=str(new), sha256=hashlib.sha256(new.read_bytes()).hexdigest())
    assert r["ok"] is False and "asset ids" in r["detail"]


def test_large_ledger_still_hashes(env):
    from zee.privsep.daemon import file_sha256
    d, _, _, _ = env
    d.ledger_path.write_bytes(b"x" * (3 * 1024 * 1024))
    assert len(file_sha256(d.ledger_path)) == 64


def test_cut_asset_removed_from_config_stays_restorable_and_visible(env, tmp_path):
    d, _, restores, _ = env
    d.cut_state.record_cut(asset_id="old", method="egress", platform=sys.platform, modified=["x"])
    assert "old" in req(d, op="status")["unresolved"]
    assert signed(d, "restore", asset_id="old", scope="recorded")["ok"]
    assert restores == [("old", False)]


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="needs mkfifo")
def test_watch_config_fifo_or_huge_file_never_blocks(env, tmp_path):
    d, _, _, _ = env
    fifo = tmp_path / "fifo"
    os.mkfifo(fifo)
    d.watch_config = fifo
    d.check_tamper()  # returns at once (O_NONBLOCK + regular-file check)
    assert d.findings == ["watch_config_unreadable"]
    big = tmp_path / "big.toml"
    big.write_bytes(b"#" * (300 * 1024))
    d.watch_config = big
    d.check_tamper()
    assert d.findings == ["watch_config_unreadable"]


@pytest.mark.parametrize("tamper,why", [
    (lambda p, c: (p, "xx" if c != "xx" else "yy"), "code_mismatch"),
    (lambda p, c: ({**p, "args": {"asset_id": "ws", "scope": "all"}}, c), "payload_mismatch"),
    (lambda p, c: ({**p, "req": "0" * 16}, c), "unknown_request"),
])
def test_signature_must_match_what_the_daemon_issued(env, tamper, why):
    d, _, restores, _ = env
    assert signed(d, "restore", asset_id="ws", scope="recorded", tamper=tamper)["refused"] == why
    assert restores == []


def test_bad_signature_and_unknown_key(env):
    d, _, restores, _ = env
    assert signed(d, "restore", secret="wrong", asset_id="ws", scope="recorded")["refused"] == "bad_signature"
    assert signed(d, "restore", key="k9", asset_id="ws", scope="recorded")["refused"] == "unknown_key"
    assert restores == []


def test_signature_is_single_use(env):
    d, _, restores, _ = env
    ch = req(d, WATCH, op="challenge", admin_op="restore", args={"asset_id": "ws", "scope": "recorded"})
    sub = {"op": "submit", "payload": ch["payload"], "entered": ch["code"], "key_id": "k1",
           "signature": base64.b64encode(sign("s1", ch["payload"], ch["code"])).decode()}
    assert req(d, WATCH, **sub)["ok"]
    assert req(d, WATCH, **sub)["refused"] == "unknown_request"
    assert len(restores) == 1


def test_signed_payload_is_bound_to_the_daemon(env, tmp_path):
    """An egress approval signature (same key, same digest function) can't be used here."""
    d, _, restores, _ = env
    ch = req(d, WATCH, op="challenge", admin_op="restore", args={"asset_id": "ws", "scope": "recorded"})
    assert ch["payload"]["aud"] == "zee-cutd-admin-v1"
    eg = Engine(tmp_path / "eg", HmacVerifier())
    eg.bootstrap_key("k1", "s1")
    ereq = eg.request_config("allow_add", dest="1.2.3.4")
    sig = base64.b64encode(sign("s1", ereq.payload, ereq.code)).decode()
    r = req(d, WATCH, op="submit", payload=ereq.payload, entered=ereq.code, key_id="k1", signature=sig)
    assert r["refused"] == "unknown_request" and restores == []


def test_pending_challenges_are_capped(env):
    d, _, _, _ = env
    for _ in range(50):
        req(d, WATCH, op="challenge", admin_op="stop", args={})
    assert len(d.engine.pending) <= 16


def test_bootstrap_is_root_only_and_only_once(env):
    d, _, _, _ = env
    assert req(d, WATCH, op="bootstrap_key", key_id="k2", public_key="s2")["error"] == "root_only"
    assert req(d, 0, op="bootstrap_key", key_id="k2", public_key="s2")["ok"] is False


def test_signed_key_add_then_use(env):
    d, _, restores, _ = env
    assert signed(d, "key_add", key_id="k2", public_key="s2")["ok"]
    assert signed(d, "restore", key="k2", secret="s2", asset_id="ws", scope="recorded")["ok"]


def test_signed_stop(env):
    d, _, _, _ = env
    assert not d.stopping
    assert signed(d, "stop")["ok"] and d.stopping


# ---- config_set
def test_config_set_needs_matching_sha_and_regular_file(env, tmp_path):
    d, _, _, _ = env
    signed(d, "auto_set", state="on")
    new = tmp_path / "new.toml"
    new.write_text(CFG.replace('"ws"', '"ws2"'))
    sha = hashlib.sha256(new.read_bytes()).hexdigest()
    assert signed(d, "config_set", path=str(new), sha256="0" * 64)["ok"] is False
    link = tmp_path / "link.toml"
    link.symlink_to(new)
    assert signed(d, "config_set", path=str(link), sha256=sha)["ok"] is False
    assert signed(d, "config_set", path=str(new), sha256=sha)["ok"] is True
    assert Config.load(d.config_path).find("ws2") is not None
    assert req(d, op="status")["auto"] == "off"  # a new config is never covered by the old switch
    assert cut(d, asset_id="ws2")["refused"] == "auto_off"


def test_config_set_rejects_invalid_config_and_keeps_the_old(env, tmp_path):
    d, _, _, _ = env
    bad = tmp_path / "bad.toml"
    bad.write_text('[[assets]]\nid = "x"\ncut_method = "nuke"\n')
    r = signed(d, "config_set", path=str(bad), sha256=hashlib.sha256(bad.read_bytes()).hexdigest())
    assert r["ok"] is False
    assert Config.load(d.config_path).find("ws") is not None


def test_config_set_relative_path_not_issued(env):
    d, _, _, _ = env
    r = req(d, WATCH, op="challenge", admin_op="config_set", args={"path": "x.toml", "sha256": "0" * 64})
    assert r["refused"] == "path_not_absolute"


# ---- condition (2): default OFF, needs two checks in a row, acts once
def test_tamper_is_reported_but_not_acted_on_by_default(env, tmp_path):
    d, cuts, _, clock = env
    watch_cfg = tmp_path / "watch.toml"
    watch_cfg.write_text(CFG.replace("dry_run = false", "dry_run = true"))  # protection weakened
    d.watch_config = watch_cfg
    for _ in range(3):
        d.check_tamper()
    assert d.findings == ["watch_config_unapproved"]
    assert req(d, op="status")["findings"] == ["watch_config_unapproved"]
    assert cuts.calls == []


def test_tamper_cut_when_signed_on(env, tmp_path):
    d, cuts, _, clock = env
    watch_cfg = tmp_path / "watch.toml"
    watch_cfg.write_text(CFG)
    d.watch_config = watch_cfg
    assert signed(d, "tamper_set", action="full")["ok"]
    d.check_tamper()
    assert d.findings == []
    watch_cfg.write_text(CFG + "\n# edited\n")
    d.check_tamper()
    assert cuts.calls == []  # one observation is not enough
    d.check_tamper()
    d.check_tamper()
    assert cuts.calls == [("full", "zee-tamper")]  # once per incident


def test_watch_silence_only_after_the_watch_was_seen(env):
    d, cuts, _, clock = env
    clock.t += 10_000
    d.check_tamper()
    assert d.findings == []
    req(d, op="status")  # heartbeat
    clock.t += 101
    d.check_tamper()
    assert d.findings == ["watch_silent"]
    req(d, op="status")
    d.check_tamper()
    assert d.findings == []


def test_tamper_respects_daemon_dry_run(env, tmp_path):
    d, cuts, _, clock = env
    (d.dir / "assets.toml").write_text(CFG.replace("dry_run = false", "dry_run = true"))
    signed(d, "tamper_set", action="egress")
    req(d, op="status")
    clock.t += 101
    d.check_tamper()
    d.check_tamper()
    assert cuts.calls == []


# ---- the default path is unchanged
def test_config_without_privsep_table(tmp_path):
    p = tmp_path / "a.toml"
    p.write_text(CFG)
    assert Config.load(p).privsep_socket is None
    p.write_text(CFG + '[privsep]\nsocket = "/var/run/zee/cutd.sock"\n')
    assert Config.load(p).privsep_socket == "/var/run/zee/cutd.sock"
    p.write_text(CFG + '[privsep]\nsocket = "rel.sock"\n')
    with pytest.raises(ZeeError):
        Config.load(p)


def _event():
    from datetime import datetime, timezone
    return TrapEvent(asset_id="ws", source="test", confidence="high", op_class="change",
                     detected_at=datetime.now(timezone.utc), detail="d", decoy_path="/tmp/x")


def test_handle_uses_privsep_only_when_given(tmp_path, monkeypatch):
    monkeypatch.setattr(sequence, "notify_local", lambda *a: True)
    direct, sent = [], []
    monkeypatch.setattr(sequence, "cut_egress", lambda **kw: direct.append(kw) or (True, "direct"))
    asset = Config.load(_write(tmp_path, CFG)).find("ws")
    log = EventLog(log_dir=tmp_path / "logs")
    r = sequence.handle(_event(), asset, dry_run=False, event_log=log)
    assert r.cut_executed and len(direct) == 1 and sent == []
    r = sequence.handle(_event(), asset, dry_run=False, event_log=log,
                        privsep_cut=lambda cr: sent.append(cr) or (False, "cut daemon: no_permission"))
    assert r.cut_failed and len(direct) == 1
    assert sent[0].asset_id == "ws" and sent[0].op_class == "change"


def _write(tmp_path, text):
    p = tmp_path / "c.toml"
    p.write_text(text)
    return p


# ---- over a real socket (non-root: the uid check uses this user's uid)
def test_serve_end_to_end(tmp_path):
    from zee.privsep.client import call, privsep_cut
    from zee.privsep.daemon import CutDaemon, serve
    from zee.responder.blocker import CutRequest
    state = tmp_path / "cutd"
    state.mkdir(mode=0o700)
    (state / "assets.toml").write_text(CFG)
    cuts = Cuts()
    d = CutDaemon(state, {os.geteuid()}, verifier=HmacVerifier(), cut_fns=cuts.fns())
    sockdir = Path(tempfile.mkdtemp(prefix="zt", dir="/tmp"))  # AF_UNIX paths are short
    sock = sockdir / "s"
    t = threading.Thread(target=serve, args=(d, sock), kwargs={"check_every": 0.05}, daemon=True)
    t.start()
    for _ in range(100):
        if sock.exists():
            break
        time.sleep(0.02)
    assert oct(sock.stat().st_mode & 0o777) == "0o600"
    me = os.geteuid()
    assert call(sock, {"op": "status"}, server_uid=me)["ok"]
    r = privsep_cut(sock)(CutRequest("ws", "change", "high"))  # expects root: refuses this server
    assert r[0] is False and "not the cut daemon" in r[1] and "nothing was sent" in r[1]
    assert privsep_cut(sock, server_uid=me)(CutRequest("ws", "change", "high")) == (
        False, "cut daemon: no_permission (Z715)")
    d.engine.state["keys"]["k1"] = "s1"
    ch = call(sock, {"op": "challenge", "admin_op": "stop", "args": {}}, server_uid=me)
    sig = base64.b64encode(sign("s1", ch["payload"], ch["code"])).decode()
    assert call(sock, {"op": "submit", "payload": ch["payload"], "entered": ch["code"],
                       "key_id": "k1", "signature": sig}, server_uid=me)["ok"]
    t.join(5)
    assert not t.is_alive()
    assert privsep_cut(sock, server_uid=me)(CutRequest("ws", "change", "high"))[0] is False  # gone


@pytest.mark.skipif(not shutil.which("openssl"), reason="openssl not available")
def test_real_p256_admin_signature(env, tmp_path):
    """Same ES256 check as egress approval (openssl), now on an admin request."""
    from zee.egress.signing import OpensslVerifier, payload_digest
    d, _, restores, _ = env
    k, pub = tmp_path / "k.pem", tmp_path / "pub.pem"
    subprocess.run(["openssl", "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", str(k)],
                   check=True, capture_output=True)
    subprocess.run(["openssl", "ec", "-in", str(k), "-pubout", "-out", str(pub)], check=True, capture_output=True)
    assert signed(d, "key_add", key_id="p256", public_key=pub.read_text())["ok"]
    d.engine.verifier = OpensslVerifier()
    ch = req(d, WATCH, op="challenge", admin_op="restore", args={"asset_id": "ws", "scope": "recorded"})
    (tmp_path / "d.bin").write_bytes(payload_digest({**ch["payload"], "entered": ch["code"]}))
    der = subprocess.run(["openssl", "pkeyutl", "-sign", "-inkey", str(k), "-in", str(tmp_path / "d.bin")],
                         check=True, capture_output=True).stdout
    r = req(d, WATCH, op="submit", payload=ch["payload"], entered=ch["code"], key_id="p256",
            signature=base64.b64encode(der).decode())
    assert r["ok"] and restores == [("ws", False)]


def test_slow_and_excess_connections_cannot_block_the_daemon(tmp_path, monkeypatch):
    """Codex 3: a trickling client is cut off by the overall deadline; past the cap,
    other uids are refused while the allowed uid still gets through."""
    from zee.privsep import daemon as dm
    from zee.privsep.client import call
    monkeypatch.setattr(dm, "READ_DEADLINE", 0.5)
    monkeypatch.setattr(dm, "CONN_SLOTS", 2)
    state = tmp_path / "cutd"
    state.mkdir(mode=0o700)
    (state / "assets.toml").write_text(CFG)
    d = dm.CutDaemon(state, {os.geteuid()}, verifier=HmacVerifier(), cut_fns=Cuts().fns())
    sock = Path(tempfile.mkdtemp(prefix="zt", dir="/tmp")) / "s"
    threading.Thread(target=dm.serve, args=(d, sock), kwargs={"check_every": 60}, daemon=True).start()
    for _ in range(100):
        if sock.exists():
            break
        time.sleep(0.02)
    slow = []
    for _ in range(2):  # fill this uid's pool with clients that trickle bytes
        c = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        c.connect(str(sock))
        c.sendall(b"{")
        slow.append(c)
    time.sleep(0.1)
    extra = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    extra.connect(str(sock))
    extra.settimeout(2)
    assert extra.recv(100) == b""  # over the cap: closed at once, no thread
    t0 = time.monotonic()
    for c in slow:
        c.sendall(b" ")  # keep trickling: the overall deadline still ends it
    time.sleep(0.6)
    for c in slow:
        c.settimeout(2)
        assert b"malformed" in c.recv(200)
    assert time.monotonic() - t0 < 2
    assert call(sock, {"op": "status"}, server_uid=os.geteuid())["ok"]  # slots were released


# ---- 4-persona review (2026-10-16)
def test_status_does_not_wait_behind_a_slow_cut(env):
    d, _, _, _ = env
    with d.lock:  # a cut / restore in progress
        r = []
        t = threading.Thread(target=lambda: r.append(req(d, op="status")))
        t.start()
        t.join(2)
        assert r and r[0]["ok"] is True


def test_failed_operation_has_its_own_code(env):
    d, _, _, _ = env
    d.restore_fn = lambda *a, **k: (False, "Z601 x")
    r = signed(d, "restore", asset_id="ws", scope="recorded")
    assert r["ok"] is False and r["code"] == "Z718"


def test_socket_directory_must_not_be_writable_by_others(tmp_path):
    from zee.privsep.daemon import CutDaemon, serve
    state = tmp_path / "cutd"
    state.mkdir(mode=0o700)
    d = CutDaemon(state, {os.geteuid()}, verifier=HmacVerifier())
    loose = Path(tempfile.mkdtemp(prefix="zt", dir="/tmp"))
    os.chmod(loose, 0o777)
    with pytest.raises(ValueError, match="writable by others"):
        serve(d, loose / "s")
    real = Path(tempfile.mkdtemp(prefix="zt", dir="/tmp"))
    link = Path(tempfile.mkdtemp(prefix="zt", dir="/tmp")) / "l"
    link.symlink_to(real)
    with pytest.raises(ValueError):
        serve(d, link / "s")


def test_cli_without_daemon_gives_z710_not_a_traceback(tmp_path, capsys):
    from zee.cli import main
    sock = Path(tempfile.mkdtemp(prefix="zt", dir="/tmp")) / "none"
    assert main(["privsep", "status", "--socket", str(sock)]) == 1
    assert "Z710" in capsys.readouterr().err
    assert main(["privsep", "submit", "--socket", str(sock), "--request", str(tmp_path / "missing.json"),
                 "--entered", "00", "--key-id", "k", "--signature", str(tmp_path / "s")]) == 1
    assert "Z719" in capsys.readouterr().err


def test_digest_shows_the_request_and_needs_yes(tmp_path, monkeypatch, capsys):
    import io
    from zee.cli import main
    reqf, out = tmp_path / "req.json", tmp_path / "d.bin"
    reqf.write_text(json.dumps({"payload": {"aud": "zee-cutd-admin-v1", "host": "h", "op": "restore",
                                            "args": {"asset_id": "ws", "scope": "all"}, "exp": 2000000000}}))
    monkeypatch.setattr(sys, "stdin", io.StringIO("y\n"))
    assert main(["privsep", "digest", "--request", str(reqf), "--entered", "12", "--out", str(out)]) == 1
    err = capsys.readouterr().err
    assert "restore" in err and '"scope": "all"' in err and not out.exists()
    monkeypatch.setattr(sys, "stdin", io.StringIO("yes\n"))
    assert main(["privsep", "digest", "--request", str(reqf), "--entered", "12", "--out", str(out)]) == 0
    assert len(out.read_bytes()) == 32


def test_heartbeat_announces_loss_and_return_once_each(monkeypatch):
    from zee import cli
    answers = [OSError("refused"), OSError("refused"), {"ok": True}, {"ok": True}, OSError("x")]
    notes, hooks, done = [], [], threading.Event()

    def call(sock, req, timeout):
        if not answers:
            done.set()
            threading.Event().wait()  # park the daemon thread for the rest of the run
        a = answers.pop(0)
        if isinstance(a, Exception):
            raise a
        return a
    cli._start_privsep_heartbeat(Path("/nonexistent"), call, lambda t, p: hooks.append(t), every=0,
                                 notify=lambda t, b: notes.append(t))
    assert done.wait(5)
    assert notes == ["Zee cut daemon UNREACHABLE (Z710)", "Zee cut daemon reachable again",
                     "Zee cut daemon UNREACHABLE (Z710)"]
    assert hooks == notes


# ---- Codex 6
def test_submit_is_rate_limited_per_uid(env):
    d, _, _, _ = env
    bogus = {"op": "submit", "payload": {"req": "x"}, "entered": "00", "key_id": "k1", "signature": ""}
    for _ in range(10):
        assert req(d, **bogus)["refused"] == "unknown_request"
    assert req(d, **bogus)["refused"] == "rate_limited"


def test_socket_dir_under_a_replaceable_parent_is_refused():
    from zee.privsep.daemon import check_socket_dir
    parent = Path(tempfile.mkdtemp(prefix="zt", dir="/tmp"))
    child = parent / "run"
    child.mkdir(mode=0o755)
    check_socket_dir(child)
    os.chmod(parent, 0o777)  # others could rename "run" and plant their own socket
    with pytest.raises(ValueError, match="replaceable"):
        check_socket_dir(child)
    os.chmod(parent, 0o1777)  # sticky (like /tmp): others can't rename our directory
    check_socket_dir(child)


def test_cut_result_unknown_after_the_request_was_sent():
    from zee.privsep.client import privsep_cut
    from zee.responder.blocker import CutRequest
    sock = Path(tempfile.mkdtemp(prefix="zt", dir="/tmp")) / "s"
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(str(sock))
    srv.listen(1)

    def accept_and_hang_up():
        c, _ = srv.accept()
        c.recv(1000)
        c.close()  # took the request, never answered
    threading.Thread(target=accept_and_hang_up, daemon=True).start()
    ok, detail = privsep_cut(sock, server_uid=os.geteuid())(CutRequest("ws", "change", "high"))
    assert ok is False and "UNKNOWN" in detail and "nothing was sent" not in detail


# ---- Codex 7
def test_socket_path_through_a_replaceable_link_is_refused():
    from zee.privsep.daemon import check_socket_dir
    safe = Path(tempfile.mkdtemp(prefix="zt", dir="/tmp"))
    (safe / "run").mkdir(mode=0o755)
    open_dir = Path(tempfile.mkdtemp(prefix="zt", dir="/tmp"))
    os.chmod(open_dir, 0o777)  # anyone may swap entries here (not sticky)
    (open_dir / "link").symlink_to(safe)
    assert (open_dir / "link" / "run").is_dir()
    with pytest.raises(ValueError, match="replaceable"):
        check_socket_dir(open_dir / "link" / "run")  # the resolved path alone would pass
    assert check_socket_dir(safe / "run") == Path(os.path.realpath(safe / "run"))


def test_approved_stop_completes_even_if_the_requester_hangs_up(tmp_path):
    from zee.privsep.daemon import CutDaemon, serve
    state = tmp_path / "cutd"
    state.mkdir(mode=0o700)
    (state / "assets.toml").write_text(CFG)
    d = CutDaemon(state, {os.geteuid()}, verifier=HmacVerifier(), cut_fns=Cuts().fns())
    d.engine.state["keys"]["k1"] = "s1"
    sock = Path(tempfile.mkdtemp(prefix="zt", dir="/tmp")) / "s"
    t = threading.Thread(target=serve, args=(d, sock), kwargs={"check_every": 60}, daemon=True)
    t.start()
    for _ in range(100):
        if sock.exists():
            break
        time.sleep(0.02)
    ch = d.handle_line(json.dumps({"op": "challenge", "admin_op": "stop", "args": {}}).encode(), os.geteuid())
    sig = base64.b64encode(sign("s1", ch["payload"], ch["code"])).decode()
    c = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    c.connect(str(sock))
    c.sendall(json.dumps({"op": "submit", "payload": ch["payload"], "entered": ch["code"],
                          "key_id": "k1", "signature": sig}).encode() + b"\n")
    c.close()  # gone before the reply
    t.join(5)
    assert not t.is_alive() and d.stopping


def test_cli_reports_unknown_result_after_sending(monkeypatch, capsys):
    from zee.cli import main
    from zee.privsep import cli as pcli

    def sent_but_no_answer(sock, req):
        raise TimeoutError("timed out")
    monkeypatch.setattr(pcli, "_raw_call", sent_but_no_answer)
    assert main(["privsep", "status", "--socket", "/nonexistent"]) == 1
    assert "Z720" in capsys.readouterr().err


# ---- Codex 8
def test_group_writable_parent_is_refused_whatever_the_group():
    from zee.privsep.daemon import check_socket_dir
    parent = Path(tempfile.mkdtemp(prefix="zt", dir="/tmp"))
    (parent / "run").mkdir(mode=0o755)
    if os.getgid() == 0:
        pytest.skip("running with gid 0")
    os.chown(parent, -1, os.getgid())  # a group other than gid 0 (BSD /tmp gives wheel)
    os.chmod(parent, 0o775)
    with pytest.raises(ValueError, match="replaceable"):
        check_socket_dir(parent / "run")


def test_link_hop_in_the_middle_of_a_chain_is_checked():
    from zee.privsep.daemon import check_socket_dir
    safe = Path(tempfile.mkdtemp(prefix="zt", dir="/tmp"))
    (safe / "run").mkdir(mode=0o755)
    untrusted = Path(tempfile.mkdtemp(prefix="zt", dir="/tmp"))
    os.chmod(untrusted, 0o777)
    (untrusted / "hop").symlink_to(safe)
    trusted = Path(tempfile.mkdtemp(prefix="zt", dir="/tmp"))
    (trusted / "link").symlink_to(untrusted / "hop")
    with pytest.raises(ValueError, match="replaceable"):
        check_socket_dir(trusted / "link" / "run")
    (trusted / "direct").symlink_to(safe)
    assert check_socket_dir(trusted / "direct" / "run") == Path(os.path.realpath(safe / "run"))


# ---- final review (Codex 09 / re-review)
def test_gid0_group_writable_socket_dir_is_refused(monkeypatch):
    """No group gets write access, gid 0 included (st_gid is faked: chgrp 0 needs root)."""
    from zee.privsep import daemon
    d = Path(tempfile.mkdtemp(prefix="zt", dir="/tmp"))
    os.chmod(d, 0o775)
    real_lstat, target = os.lstat, str(os.path.realpath(d))

    def lstat(p):
        st = real_lstat(p)
        if str(p) == target:
            return os.stat_result((st.st_mode, st.st_ino, st.st_dev, st.st_nlink, st.st_uid, 0,
                                   st.st_size, int(st.st_atime), int(st.st_mtime), int(st.st_ctime)))
        return st
    monkeypatch.setattr(daemon.os, "lstat", lstat)
    with pytest.raises(ValueError, match="writable by others"):
        daemon.check_socket_dir(d)


def test_check_runtime_refuses_code_others_can_write():
    from zee.privsep.daemon import check_runtime
    root = Path(tempfile.mkdtemp(prefix="zt", dir="/tmp"))
    (root / "bin").mkdir(mode=0o755)
    exe = root / "bin" / "python3.12"
    exe.write_text("")
    os.chmod(exe, 0o755)
    (root / "bin" / "python3").symlink_to("python3.12")
    pkg = root / "zee"
    pkg.mkdir(mode=0o755)
    (pkg / "a.py").write_text("")
    os.chmod(pkg / "a.py", 0o644)
    t = {"python": root / "bin" / "python3", "prefix": root, "zee package": pkg}
    check_runtime(t)
    os.chmod(pkg / "a.py", 0o666)  # a module anyone can rewrite
    with pytest.raises(ValueError, match="zee package"):
        check_runtime(t)
    os.chmod(pkg / "a.py", 0o644)
    os.chmod(exe, 0o775)  # the interpreter itself group-writable
    with pytest.raises(ValueError, match="python"):
        check_runtime(t)


def test_check_runtime_refuses_this_dev_venv():
    """The real default targets: a dev checkout is not root-controlled, so a daemon refuses it."""
    from zee.privsep.daemon import check_runtime
    if os.geteuid() == 0:
        pytest.skip("as root the tree may legitimately pass")
    try:
        check_runtime()
    except ValueError:
        return
    pytest.skip("this tree happens to be owned and unwritable (e.g. CI copy)")


def test_daemon_start_refusal_is_a_zee_error(tmp_path, capsys):
    from zee.cli import main
    loose = Path(tempfile.mkdtemp(prefix="zt", dir="/tmp"))
    os.chmod(loose, 0o777)
    assert main(["privsep", "daemon", "--state-dir", str(tmp_path / "s"), "--allow-uid", "1",
                 "--socket", str(loose / "s")]) == 1
    assert "Z721" in capsys.readouterr().err
    assert main(["privsep", "daemon", "--state-dir", str(tmp_path / "s"), "--allow-uid", "1",
                 "--group", "no-such-group-zee", "--socket", str(loose / "s")]) == 1
    assert "Z721" in capsys.readouterr().err


def test_heartbeat_names_a_refusal_by_its_code():
    from zee import cli
    notes, done = [], threading.Event()
    answers = [{"ok": False, "error": "peer_not_allowed", "code": "Z712"}]

    def call(sock, req, timeout):
        if not answers:
            done.set()
            threading.Event().wait()
        return answers.pop(0)
    cli._start_privsep_heartbeat(Path("/x"), call, None, every=0, notify=lambda t, b: notes.append(t))
    assert done.wait(5)
    assert notes == ["Zee cut daemon REFUSED this watch (Z712)"]
