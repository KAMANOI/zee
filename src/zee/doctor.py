"""`zee doctor` — read-only self-check of a Zee install.

Looks at the config file, decoys, restore token, state directory, canary
setting, a running `zee watch` and cut privileges, and prints what is
missing with the next step. It only reads: it never seeds decoys, never
reads the token's value (stat only), never talks to the privsep daemon
(its `status` op counts as watch liveness) and never goes to the network.
"""

from __future__ import annotations

import os
import re
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
from .responder.cut_egress import (PF_ANCHOR, _ABSENT, _ip6tables_tool, _iptables_chain_structure,
                                   _iptables_jump_first, _lines, _nft_structure, _pf_block_rule)
from .responder.cut_full import (SENTINEL_LINUX_IP6TABLES_EGRESS, SENTINEL_LINUX_IPTABLES_EGRESS,
                                 SENTINEL_LINUX_NFT_EGRESS, SENTINEL_MACOS_PFCTL_EGRESS, _run,
                                 iptables_backend, kernel_ipv6_absent, sbin_which)
from .telemetry.cut_state import CutStateLog
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


# cut record entry -> the backend name `_egress_state` reports it under
_BACKEND = {SENTINEL_LINUX_NFT_EGRESS: "nft", SENTINEL_LINUX_IPTABLES_EGRESS: "iptables",
            SENTINEL_LINUX_IP6TABLES_EGRESS: "ip6tables", SENTINEL_MACOS_PFCTL_EGRESS: "pf"}


def _nft_bare(ln: str) -> str:
    """An nft rule line with its comment and counter (and the counter's values)
    removed, so an unconditional `accept` reads as `accept` whichever it carries."""
    ln = re.sub(r'\bcomment "[^"]*"', "", ln)
    ln = re.sub(r"\bcounter(?: packets \d+ bytes \d+)?", "", ln)
    return re.sub(r"\s+", " ", ln).strip()


def _egress_state() -> dict[str, str]:
    """Read (never write) the egress-cut rules Zee loads, per backend:
    "present" (the shape Zee loads), "absent", "unexpected" (there, but not that shape) or
    "unreadable" (tool missing or needs admin rights). macOS / Linux only."""
    # jump=True: an iptables-family backend whose chain only blocks while OUTPUT
    # still jumps to it -- read OUTPUT back and verify the jump, or a disabled
    # block (chain + DROP present, jump gone) would read as "present".
    if sys.platform == "darwin":
        checks = [("pf", ["pfctl", "-a", PF_ANCHOR, "-s", "rules"], _pf_block_rule, False)]
    elif sys.platform.startswith("linux"):
        checks = [("nft", ["nft", "list", "table", "inet", "zee_egress"], _nft_structure, False),
                  ("iptables", ["iptables", "-S", "ZEE_EGRESS"], _iptables_chain_structure, True)]
        ipt = sbin_which("iptables")
        if ipt is not None and not kernel_ipv6_absent():
            # IPv6 has its own table: read it through the ip6tables of the same kernel backend
            # as iptables, as the cut does (nft's inet table already covers both families)
            ok_v, version = _run([ipt, "--version"])
            v6 = _ip6tables_tool(iptables_backend(version) if ok_v else None) or "ip6tables"
            checks.append(("ip6tables", [v6, "-S", "ZEE_EGRESS"], _iptables_chain_structure, True))
    else:
        return {}
    res: dict[str, str] = {}
    for name, cmd, shape, jump in checks:
        exe = sbin_which(cmd[0])
        if exe is None:
            res[name] = "unreadable"
            continue
        ok, out = _run([exe, *cmd[1:]])
        if ok and not _lines(out):
            res[name] = "absent"
        elif ok:
            # Drop nft comments (`comment "..."`) and `counter` values
            # ("counter packets 3 bytes 180 accept"), or an unconditional accept
            # carrying either still slips past the bypass check below.
            plain = [_nft_bare(ln) for ln in _lines(out)]
            # an unconditional accept in the chain is not the cut Zee loads (the shape check
            # looks only for the hooked drop policy), nor is a chain OUTPUT no longer jumps to
            present = shape(out, set()) == "confirmed" and "accept" not in plain
            if present and jump:
                ok_j, out_j = _run([exe, "-S", "OUTPUT"])
                present = ok_j and _iptables_jump_first(out_j, set()) == "confirmed"
            res[name] = "present" if present else "unexpected"
        elif any(a in out for a in _ABSENT):
            res[name] = "absent"
        else:
            res[name] = "unreadable"
    return res


def run(config_path: Path, *, ps: Callable[[], Optional[list[str]]] = _ps_lines,
        egress: Callable[[], dict[str, str]] = _egress_state, out=None) -> int:
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
                try:
                    dups = duplicate_decoys(cfg)
                except ZeeError as e:  # decoy path watch cannot use
                    say("FAIL", "config", f"{config_path}: {e}; `zee watch` refuses to start",
                        "fix decoy_paths")
                    dups, cfg = [], None
                for path, a, b in dups:
                    say("FAIL", "config", f"decoy {path} is under both {a!r} and {b!r}; "
                        "`zee watch` refuses to start", "keep each decoy under one asset")
                if cfg is not None and not dups:
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
        # Count only: a command line can carry a token (`zee restore watch --token ...`)
        # or a home path with a personal name.
        say("OK", "watch", f"{len(found)} process(es) that look like `zee watch` "
            "(process list only: not proof it is healthy or uses this config file)")
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

    # --- egress rules vs the cut record (read-only; light drift check) ------
    # ponytail: compares what is loaded with the shape Zee itself loads and with the cut record;
    # there is no stored list of approved destinations yet (egress approval is not wired),
    # and rules from other software are not inspected. Windows is not checked.
    states = egress()
    if states:
        bad = sorted(k for k, v in states.items() if v == "unexpected")
        on = sorted(k for k, v in states.items() if v == "present")
        recorded: Optional[set[str]] = None  # None = not comparable (no usable config / damaged record)
        if cfg is not None:
            try:
                res = [CutStateLog().unresolved_for(a.id) for a in cfg.assets]
                if not any(damaged for _r, damaged in res):
                    # every firewall entry of the merged record, not the latest cut's method (an
                    # egress cut followed by a full cut still leaves the egress rules to restore)
                    recorded = {_BACKEND[name] for r, _d in res if r is not None
                                for kind, name in r.entries() if kind == "firewall" and name in _BACKEND}
            except (OSError, ValueError):
                pass
        extra = [k for k in on if recorded is not None and k not in recorded]
        lost = sorted(k for k in (recorded or ()) if states.get(k) == "absent")
        if bad:
            say("WARN", "egress rules", f"{', '.join(bad)}: Zee's cut rules are there but not in the "
                "shape Zee loads (changed by hand or by other software?)",
                "inspect them, then `zee restore` to remove Zee's rules")
        elif extra:
            say("WARN", "egress rules", f"Zee cut rules are in force ({', '.join(extra)}) but the cut "
                "record has no open egress cut for them", "zee restore   (if you did not cut on purpose)")
        elif lost:
            say("WARN", "egress rules", f"the cut record says an egress cut is open but Zee's "
                f"{', '.join(lost)} rules are not loaded", "zee restore   (closes the record)")
        elif "unreadable" in states.values():
            say("INFO", "egress rules", "not checked: reading firewall rules needs admin rights "
                "or the tool is not usable (run `sudo zee doctor` to include it)")
        elif recorded is None:
            say("INFO", "egress rules", "not compared with the cut record (config not usable or "
                f"record damaged); loaded rules: {', '.join(f'{k}={v}' for k, v in sorted(states.items()))}")
        else:
            say("OK", "egress rules", "no drift found between loaded cut rules and the cut record "
                "(shape check only; not a proof of what traffic is allowed)")

    emit(f"summary: {counts['FAIL']} fail, {counts['WARN']} warn, {counts['OK']} ok, "
          f"{counts['INFO']} info")
    return 1 if counts["FAIL"] else 0
