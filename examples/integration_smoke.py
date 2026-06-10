"""Integration smoke test — real filesystem events via dry_run watcher.

Reproduces the Discussion #3 walkthrough automatically:
  seed → watch → tamper → observe event → (optionally) run zee status

Run manually (not part of CI):
    python examples/integration_smoke.py

Exit code 0: all checks passed.
Exit code 1: a check failed (details printed to stderr).

Requirements:
  - pip install -e .   (zee installed in the current virtualenv)
  - No ZEE_CANARY_BASE_URL needed (change-class detection only).
"""

from __future__ import annotations

import sys
import tempfile
import threading
import time
from pathlib import Path

_TIMEOUT_SEC = 10.0


def _run() -> int:
    try:
        from zee.watcher.backend_macos import MacOSKqueueWatcher  # type: ignore
        watcher_cls = MacOSKqueueWatcher
        platform_name = "macOS kqueue"
    except Exception:
        pass
    else:
        return _smoke(watcher_cls, platform_name)

    try:
        from zee.watcher.backend_linux import LinuxInotifyWatcher  # type: ignore
        watcher_cls = LinuxInotifyWatcher
        platform_name = "Linux inotify"
    except Exception:
        pass
    else:
        return _smoke(watcher_cls, platform_name)

    print("SKIP: no supported watcher backend on this platform", file=sys.stderr)
    return 0


def _smoke(watcher_cls, platform_name: str) -> int:
    print(f"[smoke] using {platform_name}")

    with tempfile.TemporaryDirectory() as td:
        decoy = Path(td) / "fake-credentials.env"
        decoy.write_text("AWS_SECRET=EXAMPLE\n")

        received: list = []
        gate = threading.Event()

        def on_event(evt):
            received.append(evt)
            gate.set()

        w = watcher_cls()
        w.start([str(decoy)], "smoke-asset", on_event)
        time.sleep(0.2)

        print("[smoke] Step 1: modify decoy (simulates attacker write)")
        with decoy.open("a") as f:
            f.write(f"TAMPERED={time.time()}\n")

        if not gate.wait(timeout=_TIMEOUT_SEC):
            print("FAIL: no event received within timeout", file=sys.stderr)
            w.stop()
            return 1

        evt = received[0]
        print(f"[smoke] Event received: asset={evt.asset_id} op={evt.op_class} "
              f"confidence={evt.confidence}")
        assert evt.asset_id == "smoke-asset", f"unexpected asset_id: {evt.asset_id}"
        assert evt.op_class == "change", f"unexpected op_class: {evt.op_class}"
        assert evt.confidence == "high", f"unexpected confidence: {evt.confidence}"

        # Step 2: delete → recreate → tamper (verifies re-registration)
        received.clear()
        gate.clear()
        print("[smoke] Step 2: delete decoy")
        decoy.unlink()
        time.sleep(0.3)

        print("[smoke] Step 2: recreate decoy (simulates zee seed)")
        decoy.write_text("RESEEDED=1\n")
        # Give the re-registration loop time to pick up the new file.
        time.sleep(1.0)

        print("[smoke] Step 2: tamper re-seeded decoy")
        with decoy.open("a") as f:
            f.write(f"SECOND_ATTACK={time.time()}\n")

        if not gate.wait(timeout=_TIMEOUT_SEC):
            print("FAIL: no event on re-seeded decoy within timeout", file=sys.stderr)
            w.stop()
            return 1

        evt2 = received[0]
        print(f"[smoke] Re-seed event: asset={evt2.asset_id} op={evt2.op_class}")
        assert evt2.asset_id == "smoke-asset"

        w.stop()

    print("[smoke] All checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(_run())
