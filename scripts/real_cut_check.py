"""Real cut -> measure -> restore -> measure, for one cut method.

IPv6 (--url6, an IPv6-only URL so nothing falls back to IPv4) is measured
the same way. Measured and failed always fails the run. A host with no
IPv6 path before the cut records IPv6 as "unmeasured" (never as passed):
that fails with --require-ipv6, otherwise the verdict is the IPv4 one.

Used by .github/workflows/real-cut.yml (virtual runners) and by
scripts/verify-real-macos.sh (a real Mac). Needs root (the cut changes the
OS firewall / interfaces). Writes one JSON result and exits 0 only if Zee's
cut and its normal restore both reported success AND the traffic stopped
during the cut AND came back after the restore (see passed()).

Safety: a timer restores (Zee's normal restore for this cut) after
--safety-seconds even if this process is stuck, and `finally` restores on
any exception. The caller adds its own outer safety net as well.

Not part of the zee package; stdlib only.
"""
from __future__ import annotations

import argparse
import http.client
import json
import os
import platform
import socket
import ssl
import sys
import tempfile
import threading
import time
import urllib.parse
from datetime import datetime, timezone
from pathlib import Path

ASSET = "verify-real-cut"


def _port(u) -> int:
    return u.port or (443 if u.scheme == "https" else 80)


def resolve(url: str, family: int) -> tuple[object, str]:
    """The destination address, resolved once before the cut and then
    reused: a name lookup failing during the cut (the DNS server is outside
    too) must not count as the traffic being stopped. IPv4-mapped IPv6 is
    IPv4 on the wire, so it is refused for the IPv6 probe."""
    u = urllib.parse.urlsplit(url)
    try:
        addr = socket.getaddrinfo(u.hostname, _port(u), family, socket.SOCK_STREAM)[0][4]
    except Exception as e:  # noqa: BLE001
        return None, f"resolve failed: {type(e).__name__}: {e}"
    if family == socket.AF_INET6 and addr[0].lower().startswith("::ffff:"):
        return None, f"not an IPv6 destination: {addr[0]}"
    return addr, addr[0]


def reachable(url: str, timeout: float, family: int = socket.AF_INET,
              addr: object = None) -> tuple[bool, str]:
    """HTTP GET over a socket of ``family`` to ``addr`` (resolved now if not
    given): no proxy, no fallback to the other family, no redirect. Any
    HTTP answer means the network path works."""
    if addr is None:
        addr, why = resolve(url, family)
        if addr is None:
            return False, why
    u = urllib.parse.urlsplit(url)
    try:
        sock = socket.socket(family, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        conn = http.client.HTTPConnection(u.hostname, _port(u), timeout=timeout)
        try:
            sock.connect(addr)
            # http.client uses an already-set socket as is (TLS for https).
            conn.sock = (ssl.create_default_context().wrap_socket(sock, server_hostname=u.hostname)
                         if u.scheme == "https" else sock)
            conn.request("GET", u.path or "/")
            return True, f"HTTP {conn.getresponse().status} via {addr[0]}"
        finally:
            conn.close()
            sock.close()
    except Exception as e:  # noqa: BLE001 - every failure is "not reachable"
        return False, f"{type(e).__name__}: {e}"


def passed(result: dict, require_ipv6: bool = False) -> bool:
    """Zee's own cut and normal restore must both report success, the restore
    must be the normal one (not the safety timer), and the traffic must have
    stopped and come back. Reachability alone can come from a DNS blip or
    an outer safety net, so it never passes by itself. IPv6 measured and
    failed always fails; require_ipv6 also fails "unmeasured"."""
    restore = result.get("restore") or {}
    ok = bool(
        (result.get("cut") or {}).get("ok") is True
        and restore.get("ok") is True and restore.get("by") == "finally"
        and result.get("stopped") and result.get("came_back"))
    v6 = (result.get("ipv6") or {}).get("status")
    if v6 == "failed" or (require_ipv6 and v6 != "passed"):
        return False
    return ok


def ipv6_status(v6: dict) -> str:
    """"unmeasured" when IPv6 was not reachable before the cut (no IPv6
    path to test), else "passed" / "failed" on stopped and came back."""
    if not v6.get("before", {}).get("reachable"):
        return "unmeasured"
    return "passed" if not v6["during"]["reachable"] and v6["after"]["reachable"] else "failed"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--method", choices=("egress", "full"), required=True)
    ap.add_argument("--url", required=True, help="non-private URL to probe")
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--probe-timeout", type=float, default=4.0)
    ap.add_argument("--safety-seconds", type=float, default=60.0)
    ap.add_argument("--label", default="")
    ap.add_argument("--url6", help="IPv6-only URL to probe as well")
    ap.add_argument("--require-ipv6", action="store_true",
                    help="IPv6 must be measured and pass (needs --url6)")
    args = ap.parse_args()
    if args.require_ipv6 and not args.url6:
        ap.error("--require-ipv6 needs --url6")
    for u in filter(None, (args.url, args.url6)):
        if not u.startswith(("http://", "https://")):
            ap.error(f"{u}: only http:// and https:// URLs are probed")

    from zee.recovery.restore import restore
    from zee.responder.cut_egress import cut_egress
    from zee.responder.cut_full import cut_full
    from zee.telemetry.cut_state import CutStateLog

    state = CutStateLog(Path(tempfile.mkdtemp(prefix="zee-real-cut-")) / "cut_state.jsonl")
    result: dict = {
        "label": args.label, "method": args.method, "url": args.url,
        "host": {"platform": sys.platform, "release": platform.release(),
                 "machine": platform.machine(), "mac_ver": platform.mac_ver()[0]},
        "started_at": datetime.now(timezone.utc).isoformat(),
    }
    restored = threading.Event()
    lock = threading.Lock()

    def do_restore(why: str) -> None:
        with lock:
            if restored.is_set():
                return
            try:
                ok, detail = restore(ASSET, cut_state=state)
                result["restore"] = {"by": why, "ok": ok, "detail": detail}
                restored.set()
            except Exception as e:  # noqa: BLE001 - record; a later call may still restore
                # Not marked done: e.g. the timer fired before the cut wrote its
                # record (Z605), so the `finally` call must still try.
                result.setdefault("restore_attempts", []).append(
                    {"by": why, "error": f"{type(e).__name__}: {e}"})
                result["restore"] = {"by": why, "ok": False, "error": f"{type(e).__name__}: {e}"}

    # Resolved once, before the cut (see resolve()).
    addr4, why4 = resolve(args.url, socket.AF_INET)
    addr6, why6 = resolve(args.url6, socket.AF_INET6) if args.url6 else (None, "")

    def probe(v6_probe: bool = False) -> dict:
        # The family is chosen by the caller, never by the URL (the same URL
        # may be given for both).
        url, family, addr, why = ((args.url6, socket.AF_INET6, addr6, why6) if v6_probe
                                  else (args.url, socket.AF_INET, addr4, why4))
        ok, detail = reachable(url, args.probe_timeout, family, addr) if addr else (False, why)
        return {"reachable": ok, "detail": detail}

    v6: dict = {"url": args.url6} if args.url6 else {}
    result["before"] = probe()
    if args.url6:
        v6["before"] = probe(v6_probe=True)
    safety = threading.Timer(args.safety_seconds, do_restore, args=("safety-timer",))
    safety.daemon = True
    safety.start()
    try:
        cut_fn = cut_egress if args.method == "egress" else cut_full
        t0 = time.monotonic()
        ok, detail = cut_fn(asset_id=ASSET, cut_state=state)
        result["cut"] = {"ok": ok, "detail": detail, "seconds": round(time.monotonic() - t0, 2)}
        time.sleep(1.0)
        result["during"] = probe()
        if args.url6:
            v6["during"] = probe(v6_probe=True)
    finally:
        do_restore("finally")
        safety.cancel()
    time.sleep(2.0)
    after = tuple(probe().values())
    for _ in range(10):  # interfaces (Wi-Fi rejoin) may take a moment to come back
        if after[0]:
            break
        time.sleep(3.0)
        after = tuple(probe().values())
    result["after"] = dict(zip(("reachable", "detail"), after))
    if args.url6:
        after6 = tuple(probe(v6_probe=True).values())
        for _ in range(5):
            if after6[0] or not v6["before"]["reachable"]:
                break
            time.sleep(3.0)
            after6 = tuple(probe(v6_probe=True).values())
        v6["after"] = dict(zip(("reachable", "detail"), after6))
        v6.setdefault("during", {"reachable": None, "detail": "cut raised before the probe"})
        v6["status"] = ipv6_status(v6)
        result["ipv6"] = v6
    else:
        result["ipv6"] = {"status": "unmeasured", "detail": "no --url6"}
    result["stopped"] = result["before"]["reachable"] and not result["during"]["reachable"]
    result["came_back"] = result["after"]["reachable"]
    result["passed"] = passed(result, require_ipv6=args.require_ipv6)
    result["finished_at"] = datetime.now(timezone.utc).isoformat()
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps({**{k: result[k] for k in ("label", "method", "stopped", "came_back", "passed")},
                      "ipv6": result["ipv6"]["status"]}))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
    os.environ.setdefault("PYTHONDONTWRITEBYTECODE", "1")
    sys.exit(main())
