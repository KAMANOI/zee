"""`zee doctor` — read-only self-check of a Zee install.

Looks at the config file, decoys, restore token, state directory, canary
setting, a running `zee watch` and cut privileges, and prints what is
missing with the next step. It only reads: it never seeds decoys, never
reads the token's value (stat only), never talks to the privsep daemon
(its `status` op counts as watch liveness) and never goes to the network.
"""

from __future__ import annotations

import os
import shlex
import stat
import subprocess
import sys
from pathlib import Path
from typing import Callable, Optional

from . import __version__
from .config.schema import Config, duplicate_decoys
from .errors import ZeeError
from .recovery.auth import default_token_path
from .telemetry.events_log import default_log_dir

_LOOSE = stat.S_IWGRP | stat.S_IWOTH
_SYNCED = ("Documents", "Desktop", "OneDrive", "Mobile Documents", "Dropbox", "Google Drive")


def _ps_lines() -> Optional[list[str]]:
    """Command lines of running processes (POSIX), or None if unknown."""
    if sys.platform == "win32":
        return None
    try:
        out = subprocess.run(["ps", "-A", "-o", "args="], capture_output=True,
                             text=True, timeout=5, check=True).stdout
    except (OSError, subprocess.SubprocessError):
        return None
    return out.splitlines()


def _looks_like_watch(line: str) -> bool:
    parts = line.split()
    return "watch" in parts and any(Path(p).name in ("zee", "zee.exe") or p == "zee.cli"
                                    for p in parts)


def _synced(p: Path) -> Optional[str]:
    # ponytail: name-based heuristic; misses custom sync roots, flags any folder with these names.
    home = Path.home()
    try:
        rel = p.relative_to(home)
    except ValueError:
        rel = p
    return next((n for n in _SYNCED if n in rel.parts), None)


def run(config_path: Path, *, ps: Callable[[], Optional[list[str]]] = _ps_lines,
        out=None) -> int:
    out = out or sys.stdout
    counts = {"OK": 0, "WARN": 0, "FAIL": 0, "INFO": 0}
    posix = sys.platform != "win32"

    def say(level: str, topic: str, fact: str, nxt: str = "") -> None:
        counts[level] += 1
        print(f"[{level}] {topic}: {fact}", file=out)
        if nxt:
            print(f"       → next: {nxt}", file=out)

    say("INFO", "version", f"zee {__version__} / Python {sys.version.split()[0]} / "
        f"{sys.platform} (local only; not compared with the latest release)")

    # --- config -----------------------------------------------------------
    cfg: Optional[Config] = None
    if not config_path.exists():
        say("FAIL", "config", f"{config_path} not found",
            "zee init   (or pass the file with -c PATH)")
    else:
        try:
            cfg = Config.load(config_path)
        except ZeeError as e:
            say("FAIL", "config", f"{config_path} does not load: {e}",
                "fix the file (see examples/assets.example.toml)")
        if cfg is not None:
            if not cfg.assets:
                say("FAIL", "config", "no [[assets]] defined; `zee watch` refuses to start",
                    f"add an asset to {config_path}")
            else:
                dups = duplicate_decoys(cfg)
                for path, a, b in dups:
                    say("FAIL", "config", f"decoy {path} is under both {a!r} and {b!r}; "
                        "`zee watch` refuses to start", "keep each decoy under one asset")
                if not dups:
                    say("OK", "config", f"{config_path} loads ({len(cfg.assets)} asset(s))")
            if posix and stat.S_IMODE(config_path.stat().st_mode) & _LOOSE:
                say("WARN", "config", f"{config_path} is writable by other users "
                    "(they could change dry_run / response_mode)", f"chmod 600 {config_path}")

    # --- mode -------------------------------------------------------------
    armed: list[str] = []
    if cfg is not None and cfg.assets:
        armed = [a.id for a in cfg.assets if a.response_mode == "auto"]
        if cfg.dry_run or not armed:
            say("INFO", "mode", "observe only: no automatic network cut "
                f"(dry_run={str(cfg.dry_run).lower()}, auto assets={len(armed)})")
            armed = []
        else:
            say("INFO", "mode", f"automatic cut is ON for {', '.join(armed)} "
                "(dry_run=false, response_mode=auto; change-class decoy touches only)")

    # --- decoys -----------------------------------------------------------
    for asset in (cfg.assets if cfg else ()):
        for raw in asset.decoy_paths:
            p = Path(raw).expanduser()
            where = _synced(p)
            if where:
                say("WARN", "decoy", f"{p} is under a folder named {where!r}, which is "
                    "often synced to the cloud (iCloud / OneDrive / ...): the decoy and any "
                    "canary URL in it may be copied there",
                    "move it to a Zee-only folder such as ~/.local/share/zee-decoys/")
            if os.path.lexists(p):
                say("OK", "decoy", f"{p} present")
            else:
                say("INFO", "decoy", f"{p} not present yet; `zee watch` creates it on start "
                    "(if watch is already running, it may have been removed)")

    # --- restore token (stat only: never read the value) ------------------
    tok = default_token_path()
    try:
        st = tok.stat()
    except FileNotFoundError:
        say("WARN", "restore token", f"{tok} not found; `zee restore` cannot run after a cut",
            "zee init-restore-token   # keep the printed token somewhere safe")
    except OSError as e:
        say("FAIL", "restore token", f"{tok} cannot be checked: {e}")
    else:
        # same bits load_token() refuses on
        if posix and stat.S_IMODE(st.st_mode) & (stat.S_IRGRP | stat.S_IWGRP | stat.S_IROTH | stat.S_IWOTH):
            say("FAIL", "restore token", f"{tok} is readable/writable by other users "
                f"(mode {stat.S_IMODE(st.st_mode):o}); `zee restore` refuses it",
                f"chmod 600 {tok}")
        else:
            say("OK", "restore token", f"{tok} present" +
                (" (owner-only)" if posix else " (Windows: ACL not checked)"))

    # --- state directory --------------------------------------------------
    log_dir = default_log_dir()
    if not log_dir.exists():
        say("INFO", "state dir", f"{log_dir} not created yet (made on the first record)")
    elif not os.access(log_dir, os.W_OK):
        say("FAIL", "state dir", f"{log_dir} is not writable by this user; events cannot be recorded",
            f"check the owner of {log_dir}")
    elif posix and stat.S_IMODE(log_dir.stat().st_mode) & _LOOSE:
        say("WARN", "state dir", f"{log_dir} is writable by other users (records could be altered)",
            f"chmod 700 {log_dir}")
    else:
        say("OK", "state dir", f"{log_dir}")

    # --- canary -----------------------------------------------------------
    url = os.environ.get("ZEE_CANARY_BASE_URL", "").strip()
    if url and url.split("://", 1)[0].lower() != "https":
        say("FAIL", "canary", "ZEE_CANARY_BASE_URL is set but not https://; `zee watch` refuses to start",
            "use an https:// receiver URL or unset it")
    elif url:
        say("OK", "canary", "ZEE_CANARY_BASE_URL set (https)")
    elif sys.platform.startswith("linux"):
        say("INFO", "canary", "not set (Linux observes reads directly with inotify)")
    else:
        say("WARN", "canary", "ZEE_CANARY_BASE_URL not set: on macOS / Windows only changes to "
            "decoys are observed, read-only access is not",
            "optional: set ZEE_CANARY_BASE_URL to an https receiver you control")

    # --- running watch ----------------------------------------------------
    lines = ps()
    if lines is None:
        say("INFO", "watch", "not checked on this platform (no process list)")
    elif found := [line for line in lines if _looks_like_watch(line)]:
        say("OK", "watch", f"{len(found)} process(es) that look like `zee watch` "
            "(process list only: not proof it is healthy or uses this config file)")
        for line in found[:3]:
            print(f"       {line[:160]}", file=out)
    else:
        say("WARN", "watch", "no process that looks like `zee watch` was found; decoys are not watched",
            f"zee -c {shlex.quote(str(config_path))} watch   (or check your launchd / systemd / Task Scheduler entry)")

    # --- privileges for cuts ----------------------------------------------
    if armed and cfg is not None:
        if cfg.privsep_socket:
            if Path(cfg.privsep_socket).exists():
                say("OK", "cut privileges", f"cuts go to the privsep daemon at {cfg.privsep_socket} "
                    "(socket present; not contacted)")
            else:
                say("FAIL", "cut privileges", f"privsep socket {cfg.privsep_socket} not found; "
                    "automatic cuts will fail", "start the cut daemon (docs/maintenance/privsep_install.md)")
        elif not posix:
            say("INFO", "cut privileges", "administrator rights not checked on Windows; cuts need them")
        elif os.geteuid() != 0:
            say("WARN", "cut privileges", "not running as root: automatic cuts will likely fail "
                "(the network commands need admin rights)",
                "run watch as root, or use [privsep] (docs/design/privsep.md)")
        else:
            say("OK", "cut privileges", "running as root")

    print(f"summary: {counts['FAIL']} fail, {counts['WARN']} warn, {counts['OK']} ok, "
          f"{counts['INFO']} info", file=out)
    return 1 if counts["FAIL"] else 0
