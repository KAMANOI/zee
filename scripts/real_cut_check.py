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
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

ASSET = "verify-real-cut"


# No proxy: a configured proxy would carry the probe over its own path.
_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def reachable(url: str, timeout: float) -> tuple[bool, str]:
    try:
        with _OPENER.open(url, timeout=timeout) as r:  # noqa: S310 - fixed test URL
            return True, f"HTTP {r.status}"
    except urllib.error.HTTPError as e:  # any HTTP answer means the network path works
        return True, f"HTTP {e.code}"
    except Exception as e:  # noqa: BLE001 - every failure is "not reachable"
        return False, f"{type(e).__name__}: {e}"


def reachable6(url: str, timeout: float) -> tuple[bool, str]:
    """HTTP over IPv6 only: the socket is AF_INET6 (no IPv4 fallback, no
    proxy, no redirect). Any HTTP answer means the IPv6 path works."""
    u = urllib.parse.urlsplit(url)
    try:
        port = u.port or 80
        addr = socket.getaddrinfo(u.hostname, port, socket.AF_INET6, socket.SOCK_STREAM)[0][4]
        if addr[0].lower().startswith("::ffff:"):  # IPv4-mapped = IPv4 on the wire
            return False, f"not an IPv6 destination: {addr[0]}"
        sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        conn = http.client.HTTPConnection(u.hostname, port, timeout=timeout)
        try:
            sock.connect(addr)
            conn.sock = sock  # http.client uses an already-set socket as is
            conn.request("GET", u.path or "/")
            return True, f"HTTP {conn.getresponse().status} via [{addr[0]}]"
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
    if args.url6 and not args.url6.startswith("http://"):
        ap.error("--url6 must be http:// (probed over a raw IPv6 socket)")

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

    def probe(url: str) -> dict:
        check = reachable6 if url == args.url6 else reachable
        return dict(zip(("reachable", "detail"), check(url, args.probe_timeout)))

    v6: dict = {"url": args.url6} if args.url6 else {}
    result["before"] = probe(args.url)
    if args.url6:
        v6["before"] = probe(args.url6)
    safety = threading.Timer(args.safety_seconds, do_restore, args=("safety-timer",))
    safety.daemon = True
    safety.start()
    try:
        cut_fn = cut_egress if args.method == "egress" else cut_full
        t0 = time.monotonic()
        ok, detail = cut_fn(asset_id=ASSET, cut_state=state)
        result["cut"] = {"ok": ok, "detail": detail, "seconds": round(time.monotonic() - t0, 2)}
        time.sleep(1.0)
        result["during"] = probe(args.url)
        if args.url6:
            v6["during"] = probe(args.url6)
    finally:
        do_restore("finally")
        safety.cancel()
    time.sleep(2.0)
    after = reachable(args.url, args.probe_timeout)
    for _ in range(10):  # interfaces (Wi-Fi rejoin) may take a moment to come back
        if after[0]:
            break
        time.sleep(3.0)
        after = reachable(args.url, args.probe_timeout)
    result["after"] = dict(zip(("reachable", "detail"), after))
    if args.url6:
        after6 = reachable6(args.url6, args.probe_timeout)
        for _ in range(5):
            if after6[0] or not v6["before"]["reachable"]:
                break
            time.sleep(3.0)
            after6 = reachable6(args.url6, args.probe_timeout)
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
