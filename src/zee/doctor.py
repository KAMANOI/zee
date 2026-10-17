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
from .decoy.canary_token import normalize_base_url
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
                             text=True, errors="replace", timeout=5, check=True).stdout
    except (OSError, subprocess.SubprocessError, UnicodeError):
        return None
    return out.splitlines()


def _looks_like_watch(line: str) -> bool:
    parts = line.split()
    return "watch" in parts and any(Path(p).name in ("zee", "zee.exe") or p == "zee.cli"
                                    for p in parts)


def _stat(p: Path) -> Optional[os.stat_result]:
    """stat() that follows links; None if missing. Other OSErrors propagate."""
    try:
        return p.stat()
    except FileNotFoundError:
        return None


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

    def emit(text: str) -> None:
        enc = getattr(out, "encoding", None) or "utf-8"  # e.g. cp1252 when redirected on Windows
        print(text.encode(enc, "replace").decode(enc), file=out)

    def say(level: str, topic: str, fact: str, nxt: str = "") -> None:
        counts[level] += 1
        emit(f"[{level}] {topic}: {fact}" + (f"\n       -> next: {nxt}" if nxt else ""))

    say("INFO", "version", f"zee {__version__} / Python {sys.version.split()[0]} / "
        f"{sys.platform} (local only; not compared with the latest release)")

    # --- config -----------------------------------------------------------
    # Open once, check the open file (regular file, not the restore token),
    # then parse that same descriptor: no stat/open race, no FIFO hang, and
    # the token's value is never read.
    cfg: Optional[Config] = None
    cst: Optional[os.stat_result] = None
    tok = default_token_path()
    try:
        fd = os.open(config_path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0))
    except FileNotFoundError:
        say("FAIL", "config", f"{config_path} not found", "zee init   (or point at your file: zee -c PATH doctor)")
    except (OSError, ValueError) as e:
        say("FAIL", "config", f"{config_path} cannot be opened: {e}",
            f"check that {config_path} is a file you can read")
    else:
        with os.fdopen(fd, "rb") as f:
            cst = os.fstat(fd)
            try:
                tst = _stat(tok)
                same = tst is not None and (cst.st_dev, cst.st_ino) == (tst.st_dev, tst.st_ino)
            except OSError:
                same = True  # cannot rule it out: do not read
            if not stat.S_ISREG(cst.st_mode):
                say("FAIL", "config", f"{config_path} is not a regular file; not read",
                    "point at your assets.toml: zee -c PATH doctor")
            elif same:
                say("FAIL", "config", f"{config_path} is (or may be) the restore token file; not read",
                    "point at your assets.toml: zee -c PATH doctor")
            else:
                try:
                    cfg = Config.load_file(f)
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
            if posix and stat.S_IMODE(cst.st_mode) & _LOOSE:
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
            try:
                os.lstat(p)
            except FileNotFoundError:
                say("INFO", "decoy", f"{p} not present yet; `zee watch` creates it on start if it "
                    "can write there (if watch is already running, it may have been removed)")
            except OSError as e:
                say("FAIL", "decoy", f"{p} cannot be checked: {e}",
                    f"check the folder {p.parent} exists and is yours")
            else:
                say("OK", "decoy", f"{p} present")

    # --- restore token (stat only: never read the value) ------------------
    try:
        st = tok.stat()
    except FileNotFoundError:
        say("WARN", "restore token", f"{tok} not found; `zee restore` cannot run after a cut",
            "zee init-restore-token   # keep the printed token somewhere safe")
    except OSError as e:
        say("FAIL", "restore token", f"{tok} cannot be checked: {e}",
            f"check the owner and permissions of {tok.parent}")
    else:
        if not stat.S_ISREG(st.st_mode):
            say("FAIL", "restore token", f"{tok} is not a regular file; `zee restore` cannot read it",
                "move it aside, then zee init-restore-token")
        # same bits load_token() refuses on
        elif posix and stat.S_IMODE(st.st_mode) & (stat.S_IRGRP | stat.S_IWGRP | stat.S_IROTH | stat.S_IWOTH):
            say("FAIL", "restore token", f"{tok} is readable/writable by other users "
                f"(mode {stat.S_IMODE(st.st_mode):o}); `zee restore` refuses it",
                f"chmod 600 {tok}")
        else:
            say("OK", "restore token", f"{tok} present" +
                (" (owner-only)" if posix else " (Windows: ACL not checked)"))

    # --- state directory --------------------------------------------------
    log_dir = Path("~/.zee")  # placeholder for messages if discovery itself fails
    lst, err = None, None
    try:
        log_dir = default_log_dir()
        lst = _stat(log_dir)
    except OSError as e:
        err = e
    if err is not None:
        say("FAIL", "state dir", f"{log_dir} cannot be checked: {err}",
            f"check the owner and permissions of {log_dir.parent}")
    elif lst is None:
        if not os.path.lexists(log_dir):
            say("INFO", "state dir", f"{log_dir} not created yet (`zee watch` creates it on start)")
        else:
            say("FAIL", "state dir", f"{log_dir} is a broken link; `zee watch` cannot record",
                f"move {log_dir} aside")
    elif not stat.S_ISDIR(lst.st_mode):
        say("FAIL", "state dir", f"{log_dir} exists but is not a directory; `zee watch` cannot record",
            f"move {log_dir} aside")
    elif not os.access(log_dir, os.W_OK | os.X_OK):
        say("FAIL", "state dir", f"{log_dir} is not writable by this user; events cannot be recorded",
            f"check the owner of {log_dir}")
    elif posix and stat.S_IMODE(lst.st_mode) & _LOOSE:
        say("WARN", "state dir", f"{log_dir} is writable by other users (records could be altered)",
            f"chmod 700 {log_dir}")
    else:
        say("OK", "state dir", f"{log_dir}")

    # --- canary -----------------------------------------------------------
    try:
        url = normalize_base_url(os.environ.get("ZEE_CANARY_BASE_URL"))
        bad = False
    except ValueError:
        url, bad = "", True
    if bad:
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
            emit(f"       {line[:160]}")
    else:
        say("WARN", "watch", "no process that looks like `zee watch` was found "
            "(process list only: a renamed launcher would be missed)",
            f"zee -c {shlex.quote(str(config_path))} watch   (or check your launchd / systemd / Task Scheduler entry)")

    # --- privileges for cuts ----------------------------------------------
    if armed and cfg is not None:
        if cfg.privsep_socket:
            try:
                is_sock = stat.S_ISSOCK(os.stat(cfg.privsep_socket).st_mode)
            except (OSError, ValueError):
                is_sock = False
            if is_sock:
                say("OK", "cut privileges", f"cuts go to the privsep daemon at {cfg.privsep_socket} "
                    "(socket file present; daemon not contacted, so not known to be up)")
            else:
                say("FAIL", "cut privileges", f"privsep socket {cfg.privsep_socket} missing or not a socket; "
                    "automatic cuts will fail", "start the cut daemon (docs/maintenance/privsep_install.md)")
        elif not posix:
            say("INFO", "cut privileges", "administrator rights not checked on Windows; cuts need them")
        elif os.geteuid() != 0:
            say("WARN", "cut privileges", "not running as root: automatic cuts will likely fail "
                "(the network commands need admin rights)",
                "run watch as root, or use [privsep] (docs/design/privsep.md)")
        else:
            say("OK", "cut privileges", "running as root")

    emit(f"summary: {counts['FAIL']} fail, {counts['WARN']} warn, {counts['OK']} ok, "
          f"{counts['INFO']} info")
    return 1 if counts["FAIL"] else 0
