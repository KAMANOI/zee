"""Query-triggered canary: value shapes, exclusion ledger, and the two
reference receivers (HTTP for "url", UDP/DNS for "hostname").

Covers exactly the 完成の定義 items from the 20261009 query-canary
instruction: processing a value reaches the receiver; the hit carries a
timestamp and source address; a value already in the registry can be
excluded by an operator's own pipeline; the receiver sends nothing back
that causes behavior (no body / no redirect / no cookie for HTTP, plain
NXDOMAIN for DNS).
"""

from __future__ import annotations

import importlib.util
import json
import socket
import struct
import sys
import threading
import time
import urllib.request
from pathlib import Path

import pytest

from zee.decoy.canary_token import CanaryTokenRegistry
from zee.decoy.query_canary import extract_label, is_known_value, issue_query_canary

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


http_receiver = _load("query_canary_http_receiver", EXAMPLES / "query_canary_http_receiver.py")
dns_receiver = _load("query_canary_dns_receiver", EXAMPLES / "query_canary_dns_receiver.py")


def _registry(tmp_path: Path) -> CanaryTokenRegistry:
    return CanaryTokenRegistry(
        base_url="https://canary.example.com",
        registry_path=tmp_path / "canary_tokens.jsonl",
    )


# ── value shapes ──────────────────────────────────────────────────────


def test_email_value_shape(tmp_path):
    val = issue_query_canary(_registry(tmp_path), "email", "dilution_row", domain="example-corp.test")
    local, domain = val.value.split("@", 1)
    assert domain == "example-corp.test"
    assert local[0].isalnum()
    assert all(c in "0123456789abcdef" for c in local)
    assert extract_label(val.value, "email") == local


def test_hostname_value_shape(tmp_path):
    val = issue_query_canary(_registry(tmp_path), "hostname", "dilution_row", domain="example-corp.test")
    label, domain = val.value.split(".", 1)
    assert domain == "example-corp.test"
    assert label[0].isalnum()
    # DNS labels: lowercase alnum only (token_hex output), <=63 chars
    assert len(label) <= 63
    assert all(c.isalnum() for c in label)


def test_url_value_shape(tmp_path):
    val = issue_query_canary(_registry(tmp_path), "url", "decoy_notes")
    assert val.value == val.token.full_url
    assert val.value.startswith("https://canary.example.com/")


def test_email_and_hostname_require_domain(tmp_path):
    reg = _registry(tmp_path)
    with pytest.raises(ValueError):
        issue_query_canary(reg, "email", "p")
    with pytest.raises(ValueError):
        issue_query_canary(reg, "hostname", "p")


@pytest.mark.parametrize("word", ["zee", "canary", "decoy", "hdr", "honeypot", "trap"])
def test_domain_origin_words_rejected(tmp_path, word):
    reg = _registry(tmp_path)
    with pytest.raises(ValueError):
        issue_query_canary(reg, "hostname", "p", domain=f"my-{word}-domain.test")


@pytest.mark.parametrize(
    "domain",
    ["myhostingco.test", "bootstrap-corp.test", "existing-client.test", "testing-vendor.test"],
)
def test_domain_check_is_whole_word_not_substring(tmp_path, domain):
    """'trap' is a substring of "bootstrap"; a naive substring check on
    _DOMAIN_ORIGIN_WORDS would wrongly reject ordinary domains like these
    (independent review finding) — the check must split on '.'/'-' and
    match whole labels only."""
    reg = _registry(tmp_path)
    issue_query_canary(reg, "hostname", "p", domain=domain)  # must not raise


# ── exclusion ledger (reuses canary_tokens.jsonl, no second file) ──────


def test_issued_value_is_known(tmp_path):
    reg = _registry(tmp_path)
    val = issue_query_canary(reg, "email", "p", domain="example-corp.test")
    assert is_known_value(reg, val.value, "email") is True


def test_unissued_value_is_not_known(tmp_path):
    reg = _registry(tmp_path)
    assert is_known_value(reg, "deadbeef@example-corp.test", "email") is False


def test_exclusion_survives_reload(tmp_path):
    """A second process (operator's own pipeline) loading the same
    registry file must still recognise the value as a known decoy."""
    registry_path = tmp_path / "canary_tokens.jsonl"
    reg1 = CanaryTokenRegistry(base_url="https://canary.example.com", registry_path=registry_path)
    val = issue_query_canary(reg1, "hostname", "p", domain="example-corp.test")

    reg2 = CanaryTokenRegistry(base_url="https://canary.example.com", registry_path=registry_path)
    assert is_known_value(reg2, val.value, "hostname") is True


def test_email_exclusion_survives_base_url_rotation(tmp_path):
    """Independent review (2026-10-09): email/hostname canaries don't
    point at base_url at all, so rotating the webhook's base_url (e.g.
    after an incident) must not strand already-issued email/hostname
    canaries out of the operator's own exclusion check — only "url"
    kind is allowed to go stale when base_url changes."""
    registry_path = tmp_path / "canary_tokens.jsonl"
    reg_old = CanaryTokenRegistry(base_url="https://old.canary.example.com", registry_path=registry_path)
    val = issue_query_canary(reg_old, "email", "p", domain="example-corp.test")

    reg_new = CanaryTokenRegistry(base_url="https://new.canary.example.com", registry_path=registry_path)
    assert is_known_value(reg_new, val.value, "email") is True


# ── HTTP receiver (url kind) ────────────────────────────────────────────


@pytest.fixture
def running_http_receiver(tmp_path):
    log_path = tmp_path / "hits.jsonl"
    handler_cls = http_receiver.make_handler_class(log_path)
    server = http_receiver.ThreadingHTTPServer(("127.0.0.1", 0), handler_cls)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server, log_path
    finally:
        server.shutdown()
        server.server_close()


def test_http_hit_is_logged_with_ts_and_ip(running_http_receiver, tmp_path):
    server, log_path = running_http_receiver
    port = server.server_address[1]
    # registry_path is isolated under tmp_path; the receiver's own base_url
    # (https://canary.example.com, never actually dialed) only needs to be
    # a valid https:// string to satisfy the registry's construction check.
    reg = _registry(tmp_path / "registry")
    token = reg.issue("decoy_notes")

    resp = urllib.request.urlopen(f"http://127.0.0.1:{port}/{token.token_id}", timeout=5)
    assert resp.status == 204
    assert resp.read() == b""
    assert resp.headers.get("Set-Cookie") is None
    assert resp.headers.get("Location") is None

    lines = log_path.read_text().strip().splitlines()
    assert len(lines) == 1
    rec = json.loads(lines[0])
    assert rec["token"] == token.token_id
    assert rec["remote_ip"] == "127.0.0.1"
    assert "ts" in rec and rec["ts"]


def test_http_receiver_returns_no_payload_on_post_too(running_http_receiver):
    server, log_path = running_http_receiver
    port = server.server_address[1]
    req = urllib.request.Request(f"http://127.0.0.1:{port}/sometoken", method="POST", data=b"")
    resp = urllib.request.urlopen(req, timeout=5)
    assert resp.status == 204
    assert resp.read() == b""


def test_http_receiver_logs_options_too(running_http_receiver):
    """A link-checker that probes with OPTIONS before GET must still be
    logged — stdlib's default OPTIONS handler (501) would otherwise
    silently drop the hit (independent review, low-severity finding)."""
    server, log_path = running_http_receiver
    port = server.server_address[1]
    req = urllib.request.Request(f"http://127.0.0.1:{port}/opts-token", method="OPTIONS")
    resp = urllib.request.urlopen(req, timeout=5)
    assert resp.status == 204
    rec = json.loads(log_path.read_text().strip().splitlines()[-1])
    assert rec["token"] == "opts-token"
    assert rec["method"] == "OPTIONS"


# ── DNS receiver (hostname kind) ────────────────────────────────────────


def _dns_query_packet(qname: str) -> bytes:
    txid = struct.pack(">H", 0x1234)
    flags = struct.pack(">H", 0x0100)  # standard query, RD=1
    counts = struct.pack(">HHHH", 1, 0, 0, 0)
    question = b"".join(bytes([len(label)]) + label.encode("ascii") for label in qname.split(".")) + b"\x00"
    question += struct.pack(">HH", 1, 1)  # QTYPE=A, QCLASS=IN
    return txid + flags + counts + question


@pytest.fixture
def running_dns_receiver(tmp_path):
    log_path = tmp_path / "dns_hits.jsonl"
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()  # free the port; serve() re-binds it in the server thread

    def run():
        dns_receiver.serve("127.0.0.1", port, log_path)

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    time.sleep(0.2)  # let the bind land before the test sends a packet
    try:
        yield port, log_path
    finally:
        pass  # daemon thread; process teardown reclaims the socket


def test_dns_query_is_logged_and_gets_nxdomain(running_dns_receiver):
    port, log_path = running_dns_receiver
    qname = "abc123def456.example-corp.test"
    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client.settimeout(5)
    client.sendto(_dns_query_packet(qname), ("127.0.0.1", port))
    response, _ = client.recvfrom(512)
    client.close()

    rcode = response[3] & 0x0F
    assert rcode == 3  # NXDOMAIN
    assert response[0:2] == struct.pack(">H", 0x1234)  # echoes query id
    ancount, nscount, arcount = struct.unpack(">HHH", response[6:12])
    assert (ancount, nscount, arcount) == (0, 0, 0)  # no A/AAAA or any other record attached
    # response is exactly header(12) + the echoed question, nothing appended
    assert len(response) == 12 + (len(_dns_query_packet(qname)) - 12)

    deadline = time.time() + 2
    while time.time() < deadline and not log_path.exists():
        time.sleep(0.05)
    rec = json.loads(log_path.read_text().strip().splitlines()[-1])
    assert rec["qname"] == qname
    assert rec["token"] == "abc123def456"
    assert rec["remote_ip"] == "127.0.0.1"
    assert "ts" in rec and rec["ts"]


def test_parse_qname_roundtrip():
    packet = _dns_query_packet("tok.example-corp.test")
    qname, end = dns_receiver.parse_qname(packet)
    assert qname == "tok.example-corp.test"
    assert end == len(packet)


def test_parse_qname_rejects_truncated_packet():
    """A label length byte claiming more bytes than the packet has left
    (truncated packet, or a DNS compression pointer 0xC0.. which this
    minimal parser does not implement) must fail loudly, not hang or
    silently decode garbage. The caller (serve()) already catches
    IndexError and drops the packet — this pins that contract."""
    truncated = struct.pack(">H", 1) + b"\x00" * 10 + bytes([200])  # claims a 200-byte label, 0 bytes follow
    with pytest.raises(IndexError):
        dns_receiver.parse_qname(truncated)


def test_malformed_dns_packet_is_dropped_not_crashed(running_dns_receiver):
    """serve()'s IndexError guard (query_canary_dns_receiver.py) must
    keep the receiver alive after a garbage packet, so a legitimate
    query sent right after is still answered."""
    port, log_path = running_dns_receiver
    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client.settimeout(5)
    client.sendto(b"\x00\x01garbage, too short", ("127.0.0.1", port))

    qname = "stillalive.example-corp.test"
    client.sendto(_dns_query_packet(qname), ("127.0.0.1", port))
    response, _ = client.recvfrom(512)
    client.close()
    assert response[3] & 0x0F == 3
