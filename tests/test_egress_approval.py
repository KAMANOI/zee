"""Egress approval prototype: protocol logic against a mock (HMAC) signature backend."""
import hashlib
import hmac
import shutil
import subprocess

import pytest

from zee.egress.engine import Engine, Flow
from zee.egress.pf import render
from zee.egress.signing import OpensslVerifier, payload_digest
from zee.telemetry.events_log import verify_chain


class HmacVerifier:
    """Mock backend: 'public key' is a shared secret. Tests protocol, not the curve."""
    def verify(self, public_key, digest, signature):
        return hmac.compare_digest(hmac.new(public_key.encode(), digest, hashlib.sha256).digest(), signature)


def sign(secret, payload, entered):
    return hmac.new(secret.encode(), payload_digest({**payload, "entered": entered}), hashlib.sha256).digest()


class Clock:
    t = 1_000_000.0
    def __call__(self):
        return self.t


class Rec:
    def __init__(self):
        self.held, self.allowed = [], []
    def hold(self, d): self.held.append(d)
    def allow(self, d, until): self.allowed.append(d)
    def release(self, d): self.released = getattr(self, 'released', []) + [d]


def approve(eng, req, key="k1", secret="s1", entered=None, payload=None):
    entered = req.code if entered is None else entered
    payload = payload or req.payload
    return eng.submit(payload, entered, key, sign(secret, payload, entered))


@pytest.fixture
def env(tmp_path):
    clock, enf, notes = Clock(), Rec(), []
    eng = Engine(tmp_path / "zee", HmacVerifier(), enforcer=enf, clock=clock,
                 notify=lambda k, r: notes.append(k))
    eng.setup_allow("api.example.com:443")
    eng.setup_protect("env:prod")
    eng.bootstrap_key("k1", "s1")
    eng.ack_single_key()
    eng.enable()
    return eng, clock, enf, notes


def seal(eng, clock):
    clock.t += eng.BUNDLE_WINDOW + 1
    eng.tick()
    return next(iter(eng.pending.values()))


def hold_one(eng, clock, dest="203.0.113.5:443", n=2_000_000):
    eng.note_protected_touch("env:prod")
    assert eng.observe(Flow("curl", dest, n)).action == "hold"
    return seal(eng, clock)


def test_approved_send_passes_within_signed_dest_and_volume(env):
    eng, clock, enf, _ = env
    req = hold_one(eng, clock)
    assert approve(eng, req).ok
    assert eng.observe(Flow("curl", "203.0.113.5:443", 1_500_000)).action == "pass"
    assert enf.allowed == ["203.0.113.5:443"]


def test_reused_signature_rejected(env):
    eng, clock, _, _ = env
    req = hold_one(eng, clock)
    payload, code = req.payload, req.code
    sig = sign("s1", payload, code)
    assert eng.submit(payload, code, "k1", sig).ok
    assert eng.submit(payload, code, "k1", sig).reason == "unknown_request"
    # restart: pending is gone, but the replay ledger on disk still refuses the digest
    eng2 = Engine(eng.dir, HmacVerifier(), clock=clock)
    eng2.pending[payload["req"]] = req
    assert eng2.submit(payload, code, "k1", sig).reason == "replay"


def test_expired_signature_rejected(env):
    eng, clock, _, _ = env
    req = hold_one(eng, clock)
    clock.t = req.exp + 1
    assert approve(eng, req).reason == "expired"
    assert "203.0.113.5:443" not in eng.grants
    assert eng.observe(Flow("curl", "203.0.113.5:443", 2_000_000)).action == "hold"


def test_traffic_differing_from_what_was_shown_is_refused(env):
    eng, clock, _, _ = env
    req = hold_one(eng, clock)
    # attacker swaps the destination / volume after the phone displayed the request
    forged = {**req.payload, "dests": ["198.51.100.9:443"]}
    assert approve(eng, req, payload=forged).reason == "payload_mismatch"
    forged = {**req.payload, "max_bytes": 10**12}
    assert approve(eng, req, payload=forged).reason == "payload_mismatch"
    assert approve(eng, req).ok
    # still only the signed destination and volume
    assert eng.observe(Flow("curl", "198.51.100.9:443", 10)).action == "hold"
    assert eng.observe(Flow("curl", "203.0.113.5:443", req.payload["max_bytes"] + 1)).action == "hold"


def test_number_matching_wrong_code_rejected(env):
    eng, clock, _, _ = env
    req = hold_one(eng, clock)
    wrong = f"{(int(req.code) + 1) % 100:02d}"
    assert approve(eng, req, entered=wrong).reason == "code_mismatch"


def test_unsigned_or_forged_config_changes_rejected(env):
    eng, _, _, _ = env
    with pytest.raises(PermissionError):
        eng.setup_allow("evil.example:443")  # ON: no local back door
    with pytest.raises(PermissionError):
        eng.bootstrap_key("k9", "s9")
    req = eng.request_config("allow_add", dest="evil.example:443")
    assert approve(eng, req, key="k1", secret="wrong").reason == "bad_signature"
    assert approve(eng, req, key="unknown").reason == "unknown_key"
    assert "evil.example:443" not in eng.state["allow"]
    req = eng.request_config("key_add", key_id="k2", public_key="s2")
    assert approve(eng, req).ok and "k2" in eng.state["keys"]
    # signature of the right key but over a different payload
    req = eng.request_config("disable")
    other = eng.request_config("allow_add", dest="x:1")
    sig = sign("s1", other.payload, other.code)
    assert eng.submit(req.payload, req.code, "k1", sig).reason == "bad_signature"
    assert eng.enabled


def test_no_answer_means_not_passed(env):
    eng, clock, enf, notes = env
    req = hold_one(eng, clock)
    clock.t = req.exp + 1
    eng.tick()
    assert "timeout" in notes and not eng.pending
    assert eng.observe(Flow("curl", "203.0.113.5:443", 10)).action == "hold"
    assert "203.0.113.5:443" in enf.held


def test_requests_in_a_burst_are_bundled_into_one(env):
    eng, clock, _, notes = env
    eng.note_protected_touch("env:prod")
    for i in range(5):
        clock.t += 2
        assert eng.observe(Flow("p", f"203.0.113.{i}:443", 10)).action == "hold"
    clock.t += eng.BUNDLE_WINDOW
    eng.tick()
    assert notes.count("request") == 1 and len(eng.pending) == 1
    assert len(next(iter(eng.pending.values())).payload["dests"]) == 5
    # more flows right after: held, but no second request inside the minimum interval
    eng.observe(Flow("p", "203.0.113.99:443", 10))
    clock.t += eng.BUNDLE_WINDOW + 1
    eng.tick()
    assert notes.count("request") == 1
    clock.t += eng.MIN_BATCH_INTERVAL
    eng.tick()
    assert notes.count("request") == 2


def test_switching_approval_off_keeps_detection_and_notification(env):
    eng, clock, enf, notes = env
    hold_one(eng, clock)  # something is held when approval is switched off
    assert eng.held
    req = eng.request_config("disable")
    assert approve(eng, req).ok and not eng.enabled
    assert not eng.held and enf.released == ["203.0.113.5:443"]  # OFF really releases the block
    notes.clear()
    eng.note_protected_touch("env:prod")  # taint is still tracked
    v = eng.observe(Flow("curl", "203.0.113.7:443", 10))
    assert v.action == "notify" and "egress_shape" in notes
    assert enf.held == ["203.0.113.5:443"]  # nothing NEW is held while OFF


def test_corrupt_state_fails_closed(tmp_path):
    d = tmp_path / "zee"
    d.mkdir()
    (d / "egress_approval.json").write_text("{not json")
    eng = Engine(d, HmacVerifier(), clock=Clock())
    assert eng.state_invalid and eng.enabled and not eng.state["keys"]
    assert eng.observe(Flow("p", "203.0.113.5:443", 5_000_000)).action == "hold"


def test_enable_needs_spare_key(tmp_path):
    eng = Engine(tmp_path / "zee", HmacVerifier(), clock=Clock())
    eng.bootstrap_key("k1", "s1")
    with pytest.raises(PermissionError):
        eng.enable()


def test_recovery_is_time_locked_and_cancellable(env):
    eng, clock, _, notes = env
    eng.recovery_start()
    clock.t += eng.RECOVERY_WAIT - 1
    assert eng.recovery_complete().reason == "waiting"
    clock.t += eng.RECOVERY_NOTICE_EVERY
    eng.tick()
    assert "recovery_pending" in notes
    # a registered device cancels it
    req = eng.request_config("allow_add", dest="a.example:443")
    assert approve(eng, req).ok and eng.state["recovery_start"] is None
    eng.recovery_start()
    clock.t += eng.RECOVERY_WAIT
    assert eng.recovery_complete().ok and not eng.state["keys"] and not eng.enabled


def test_server_form_allowlist_primary(tmp_path):
    eng = Engine(tmp_path / "zee", HmacVerifier(), clock=Clock(), server_form=True)
    eng.setup_allow("10.0.0.0/8")
    eng.bootstrap_key("k1", "s1")
    eng.ack_single_key()
    eng.enable()
    assert eng.observe(Flow("svc", "10.1.2.3:5432", 1)).action == "pass"
    assert eng.observe(Flow("svc", "203.0.113.5:443", 1)).action == "hold"
    assert eng.observe(Flow("svc", "127.0.0.1:80", 1)).action == "pass"


def test_evidence_chain_is_valid_and_has_no_signature_material(env):
    eng, clock, _, _ = env
    approve(eng, hold_one(eng, clock))
    res = verify_chain(eng.log_path)
    assert res["results"] and all(r["status"] == "ok" for r in res["results"])
    text = eng.log_path.read_text()
    assert '"approved"' in text and "s1" not in text.replace("shape", "")


def test_pf_render_includes_ipv6_and_never_names_hosts():
    out = render(["203.0.113.5:443", "[2001:db8::1]:443"], ["198.51.100.0/24"])
    assert "block drop out quick to 2001:db8::1/128" in out
    assert out.index("pass out quick to 198.51.100.0/24") < out.index("block drop")
    with pytest.raises(ValueError):
        render(["evil.example:443"], [])
    assert render([], ["10.0.0.0/8"], default_deny=True).endswith("block drop out quick all\n")


@pytest.mark.skipif(not shutil.which("openssl"), reason="openssl not available")
def test_real_p256_signature_via_openssl(tmp_path):
    k, pub = tmp_path / "k.pem", tmp_path / "p.pem"
    subprocess.run(["openssl", "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", str(k)],
                   check=True, capture_output=True)
    subprocess.run(["openssl", "ec", "-in", str(k), "-pubout", "-out", str(pub)], check=True, capture_output=True)
    digest = payload_digest({"a": 1})
    (tmp_path / "d.bin").write_bytes(digest)
    sig = subprocess.run(["openssl", "pkeyutl", "-sign", "-inkey", str(k), "-in", str(tmp_path / "d.bin")],
                         check=True, capture_output=True).stdout
    v = OpensslVerifier()
    assert v.verify(pub.read_text(), digest, sig)
    assert not v.verify(pub.read_text(), payload_digest({"a": 2}), sig)
    assert not v.verify(pub.read_text(), digest, sig[:-1] + bytes([sig[-1] ^ 1]))
    assert not v.verify("not a key", digest, sig)


def test_code_cannot_be_guessed_without_a_registered_key(env):
    eng, clock, _, _ = env
    req = hold_one(eng, clock)
    reasons = {eng.submit(req.payload, f"{i:02d}", "nokey", b"x").reason for i in range(100)}
    assert reasons == {"unknown_key"}


def test_malformed_submissions_do_not_raise(env):
    eng, _, _, _ = env
    for args in (({"req": [1]}, "00", "k1", b"x"), ("nope", "00", "k1", b"x"), ({"req": "a"}, 5, "k1", b"x")):
        assert eng.submit(*args).reason == "malformed"


def test_broken_state_allows_no_unsigned_registration(tmp_path):
    d = tmp_path / "zee"
    d.mkdir()
    (d / "egress_approval.json").write_text("{not json")
    with pytest.raises(PermissionError):
        Engine(d, HmacVerifier(), clock=Clock()).bootstrap_key("evil", "e")


def test_cumulative_volume_closes_the_destination(env):
    eng, clock, _, _ = env
    req = hold_one(eng, clock)
    assert approve(eng, req).ok
    cap = req.payload["max_bytes"]
    assert eng.observe(Flow("curl", "203.0.113.5:443", cap - 1_000_000)).action == "pass"
    assert eng.observe(Flow("curl", "203.0.113.5:443", 1_000_001)).action == "hold"  # sum exceeds the cap


def test_grant_expiry_closes_the_destination_again(env):
    eng, clock, enf, _ = env
    req = hold_one(eng, clock)
    assert approve(eng, req).ok and "203.0.113.5:443" in eng.grants
    clock.t = req.payload["until"] + 1
    eng.tick()
    assert not eng.grants and "203.0.113.5:443" in eng.held
    assert enf.held.count("203.0.113.5:443") == 2  # held, released by approval, held again
    assert eng.observe(Flow("curl", "203.0.113.5:443", 2_000_000)).action == "hold"


def test_log_failure_does_not_stop_detection_or_hold(env, monkeypatch):
    eng, _, enf, notes = env
    monkeypatch.setattr("zee.egress.engine.EventLog._append", staticmethod(lambda *a: 1 / 0))
    eng.note_protected_touch("env:prod")
    assert eng.observe(Flow("curl", "203.0.113.5:443", 10)).action == "hold"
    assert enf.held and "egress_shape" in notes


def test_public_key_never_reaches_the_evidence_log(env):
    eng, _, _, _ = env
    req = eng.request_config("key_add", key_id="k2", public_key="PUBKEYXYZ")
    assert approve(eng, req).ok
    assert "PUBKEYXYZ" not in eng.log_path.read_text()


def test_cannot_drop_below_two_keys_without_ack(tmp_path):
    clock = Clock()
    eng = Engine(tmp_path / "zee", HmacVerifier(), clock=clock)
    eng.bootstrap_key("k1", "s1")
    eng.state["keys"]["k2"] = "s2"
    eng.state["single_key_ack"] = False
    eng.enable()
    with pytest.raises(PermissionError):
        eng.request_config("key_remove", key_id="k2")


def test_server_form_hold_then_signed_release(tmp_path):
    clock = Clock()
    eng = Engine(tmp_path / "zee", HmacVerifier(), clock=clock, server_form=True)
    eng.bootstrap_key("k1", "s1")
    eng.ack_single_key()
    eng.enable()
    assert eng.observe(Flow("svc", "203.0.113.5:443", 1)).action == "hold"
    req = seal(eng, clock)
    assert approve(eng, req).ok
    assert eng.observe(Flow("svc", "203.0.113.5:443", 1)).action == "pass"


@pytest.mark.skipif(not shutil.which("openssl"), reason="openssl not available")
def test_engine_end_to_end_with_real_p256(tmp_path):
    k, pub = tmp_path / "k.pem", tmp_path / "p.pem"
    subprocess.run(["openssl", "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", str(k)],
                   check=True, capture_output=True)
    subprocess.run(["openssl", "ec", "-in", str(k), "-pubout", "-out", str(pub)], check=True, capture_output=True)
    clock = Clock()
    eng = Engine(tmp_path / "zee", OpensslVerifier(), clock=clock, server_form=True)
    eng.bootstrap_key("phone", pub.read_text())
    eng.ack_single_key()
    eng.enable()
    eng.observe(Flow("svc", "203.0.113.5:443", 1))
    req = seal(eng, clock)

    def sig(payload, entered):
        (tmp_path / "d.bin").write_bytes(payload_digest({**payload, "entered": entered}))
        return subprocess.run(["openssl", "pkeyutl", "-sign", "-inkey", str(k), "-in", str(tmp_path / "d.bin")],
                              check=True, capture_output=True).stdout
    forged = {**req.payload, "dests": ["198.51.100.9:443"]}
    assert eng.submit(forged, req.code, "phone", sig(req.payload, req.code)).reason == "payload_mismatch"
    assert eng.submit(req.payload, req.code, "phone", sig(forged, req.code)).reason == "bad_signature"
    assert eng.submit(req.payload, req.code, "phone", sig(req.payload, req.code)).ok
    assert eng.observe(Flow("svc", "203.0.113.5:443", 1)).action == "pass"
