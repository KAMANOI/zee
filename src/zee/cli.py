"""Zee CLI entry point.

By default Zee runs dry_run. `zee watch` starts monitoring; `zee restore`
recovers an asset after containment.
"""

from __future__ import annotations

import argparse
import logging
import os
import sys
import threading
import time
from pathlib import Path
from typing import Optional

from . import __version__
from .config.schema import Config
from .decoy.canary_token import CanaryTokenRegistry
from .decoy.seeder import seed_all
from .errors import (
    ZeeError,
    Z102_UNKNOWN_ASSET_ID,
    Z404_CUT_COMMAND_FAILED,
    Z602_RESTORE_TOKEN_REQUIRED,
    Z603_RESTORE_TOKEN_NOT_INITIALIZED,
    Z604_RESTORE_TOKEN_INVALID,
)
from .notifier.webhook import from_env as webhook_from_env
from .responder.sequence import handle, recover_hint
from .recovery.auth import init_token, load_token, verify_token
from .recovery.restore import restore
from .telemetry.capability_report import render_text as capability_text
from .telemetry.cut_state import CutStateLog
from .telemetry.events_log import EventLog


def _canary_registry_from_env() -> Optional[CanaryTokenRegistry]:
    """Build a CanaryTokenRegistry from ZEE_CANARY_BASE_URL, or None."""
    url = os.environ.get("ZEE_CANARY_BASE_URL", "").strip()
    if not url:
        return None
    return CanaryTokenRegistry(base_url=url)


def _cmd_watch(args: argparse.Namespace) -> int:
    config = Config.load(args.config)
    if not config.assets:
        print("no assets defined in", args.config, file=sys.stderr)
        return 1

    # NOTE: the previous build held a hard block here that refused
    # response_mode=auto with dry_run=false. Spec v4 retires that
    # approach. Auto-cut is now gated by op_class=="change" in
    # responder/sequence.py — a structurally narrower trigger that does
    # not require process attribution. Read-class touches never auto-cut.

    # Detect decoy_paths registered to more than one asset. Same path
    # under multiple assets confuses watcher bookkeeping (duplicate FDs,
    # ambiguous reporting).
    seen: dict[str, str] = {}
    for asset in config.assets:
        for raw in asset.decoy_paths:
            key = str(Path(raw).expanduser())
            if key in seen and seen[key] != asset.id:
                print(
                    f"[error] decoy_path {raw!r} appears under both "
                    f"asset {seen[key]!r} and {asset.id!r}. Each decoy "
                    f"must belong to exactly one asset.",
                    file=sys.stderr,
                )
                return 1
            seen[key] = asset.id

    event_log = EventLog()
    cut_state = CutStateLog()
    privsep_cut = None
    if config.privsep_socket:  # opt-in: cuts go to the root cut daemon (docs/design/privsep.md)
        from .privsep.client import call, privsep_cut as make_privsep_cut
        privsep_cut = make_privsep_cut(Path(config.privsep_socket))
        _start_privsep_heartbeat(Path(config.privsep_socket), call, webhook_from_env())
    log_dir = event_log.log_dir
    sender = webhook_from_env()
    try:
        canary_registry = _canary_registry_from_env()
    except ValueError as e:
        print(f"[error] {e}", file=sys.stderr)
        return 1
    canary_configured = canary_registry is not None and canary_registry.is_configured
    print(
        f"[zee watch] dry_run={config.dry_run} log_dir={log_dir} "
        f"webhook={'configured' if sender else 'none'} "
        f"canary={'configured' if canary_configured else 'not configured'}",
        file=sys.stderr,
    )

    # Lazy import so each platform only loads its own backend module.
    watchers: list[object] = []
    backend_kwargs: dict = {}
    if sys.platform.startswith("linux"):
        from .watcher.backend_linux import LinuxInotifyWatcher
        backend_cls: type = LinuxInotifyWatcher
    elif sys.platform == "darwin":
        from .watcher.backend_macos import MacOSKqueueWatcher
        backend_cls = MacOSKqueueWatcher
        backend_kwargs["canary_configured"] = canary_configured
    elif sys.platform == "win32":
        from .watcher.backend_windows import WindowsWatcher
        backend_cls = WindowsWatcher
        backend_kwargs["canary_configured"] = canary_configured
    else:
        print(f"[zee watch] unsupported platform: {sys.platform}", file=sys.stderr)
        return 2

    for asset in config.assets:
        seeded = seed_all(list(asset.decoy_paths), registry=canary_registry)
        print(f"[seeded] asset={asset.id} paths={[str(p) for p in seeded]}",
              file=sys.stderr)

        watcher = backend_cls(**backend_kwargs)
        cap = watcher.capability()
        print(f"[capability] {cap}", file=sys.stderr)

        def make_handler(asset_=asset):
            def _on_event(event):
                try:
                    result = handle(
                        event, asset_,
                        dry_run=config.dry_run,
                        event_log=event_log,
                        webhook_sender=sender,
                        cut_state=cut_state,
                        privsep_cut=privsep_cut,
                    )
                    print(
                        f"[event] {event.detail} → mode={result.mode} "
                        f"cut={'yes' if result.cut_executed else 'FAILED(Z404)' if result.cut_failed else 'no'} "
                        f"would_cut={'yes' if result.cut_would_have_been_executed else 'no'}",
                        file=sys.stderr,
                    )
                except ZeeError as e:
                    print(f"[error] {e}", file=sys.stderr)
            return _on_event

        watcher.start(asset.decoy_paths, asset.id, make_handler())
        watchers.append(watcher)

    print("[zee watch] running. Ctrl+C to stop.", file=sys.stderr)
    try:
        while True:
            time.sleep(1.0)
    except KeyboardInterrupt:
        print("\n[zee watch] stopping...", file=sys.stderr)
    finally:
        for w in watchers:
            w.stop()  # type: ignore[attr-defined]
    return 0


def _start_privsep_heartbeat(sock: Path, call, sender=None, every: float = 30,
                             notify=None) -> threading.Thread:
    """status every 30 s: the daemon's evidence that this watch is alive.

    Losing the daemon is announced once (local notification + webhook) when it
    becomes unreachable, and once when it is back; stderr gets every failure."""
    from .notifier.local import notify_local
    notify = notify or notify_local

    def announce(title: str, body: str) -> None:
        notify(title, body)
        if sender is not None:
            try:
                sender(title, {"event": "privsep_daemon", "detail": body})
            except Exception:  # noqa: BLE001 - an alert path must never stop the heartbeat
                pass

    def loop() -> None:
        up = None  # unknown until the first answer
        while True:
            try:
                r = call(sock, {"op": "status"}, timeout=30)
                ok = r.get("ok") is True
                if not ok or r.get("findings"):
                    print(f"[zee watch] cut daemon reports: {r}", file=sys.stderr, flush=True)
            except (OSError, ValueError) as e:
                ok, r = False, {"error": str(e)}
                print(f"[zee watch] cut daemon UNREACHABLE ({e}): automatic cuts will fail",
                      file=sys.stderr, flush=True)
            if not ok and up is not False:
                if "code" in r:  # it answered, but refused (e.g. Z712: this uid is not allowed)
                    announce(f"Zee cut daemon REFUSED this watch ({r['code']})",
                             f"automatic cuts will FAIL: {r}")
                else:
                    announce("Zee cut daemon UNREACHABLE (Z710)",
                             f"automatic cuts will FAIL until it answers again: {r}")
            elif ok and up is False:
                announce("Zee cut daemon reachable again", "automatic cuts go to the daemon again")
            up = ok
            time.sleep(every)

    t = threading.Thread(target=loop, name="zee-privsep-heartbeat", daemon=True)
    t.start()
    return t


def _cmd_restore(args: argparse.Namespace) -> int:
    config = Config.load(args.config)
    if config.find(args.asset_id) is None:
        raise ZeeError(Z102_UNKNOWN_ASSET_ID, args.asset_id)

    # v0.3 (spec L3): restore requires an operator-supplied token so a
    # casual same-user attacker cannot revert containment from another
    # shell session. The token file is created with `zee init-restore-token`.
    provided = (args.token or os.environ.get("ZEE_RESTORE_TOKEN", "")).strip()
    if not provided:
        raise ZeeError(
            Z602_RESTORE_TOKEN_REQUIRED,
            "use --token <TOKEN> or set ZEE_RESTORE_TOKEN. "
            "Run `zee init-restore-token` once to generate the token.",
        )
    if not verify_token(provided):
        # Distinguish "not initialised yet" (no file at all) from "file
        # present but unreadable" (loose perms or wrong token). Without
        # this split, a 0644 token file would be reported as Z603 and
        # re-running init-restore-token would silently rotate the token
        # without alerting the operator to the permission problem.
        from .recovery.auth import default_token_path
        token_path = default_token_path()
        if not token_path.exists():
            raise ZeeError(
                Z603_RESTORE_TOKEN_NOT_INITIALIZED,
                "no restore_token file at ~/.zee/restore_token. "
                "Run `zee init-restore-token` first.",
            )
        # File exists. Either perms are loose (load_token returned None)
        # or the operator supplied the wrong token. Both are Z604; the
        # detail string tells them which one to fix.
        if load_token() is None:
            raise ZeeError(
                Z604_RESTORE_TOKEN_INVALID,
                f"restore_token file at {token_path} has loose permissions "
                f"and was refused. `chmod 600 {token_path}` and retry.",
            )
        raise ZeeError(Z604_RESTORE_TOKEN_INVALID, "supplied token does not match")

    ok, detail = restore(args.asset_id, all_interfaces=args.all_interfaces)
    print(detail, file=sys.stderr)
    return 0 if ok else 1


# Starter profile written by `zee init`. Same safe defaults as
# examples/assets.example.toml (tests/test_init_cli.py keeps them in step):
# observe-only, notify, decoys in a Zee-only directory.
_INIT_TEMPLATE = """\
# Zee asset profile — written by `zee init` (Zee {version}).
# Full annotated example: examples/assets.example.toml in the repository.
#
# Observe-only: dry_run = true and response_mode = "notify" never cut the
# network. Promote to "auto" only after watching for false positives.
#
# Decoys live in a Zee-only directory. Keep it out of ~/Documents and
# ~/Desktop (iCloud / OneDrive copy those to the cloud) and add it to your
# backup / antivirus / search-index exclusions to avoid false positives.

dry_run = true

[[assets]]
id = "{asset_id}"
type = "workstation"
overnight_active = false
decoy_paths = [
    "~/.local/share/zee-decoys/aws-credentials.decoy",
    "~/.local/share/zee-decoys/.env",
]
response_mode = "notify"   # auto / staged / notify  (start with notify)
cut_method = "full"        # full / egress  (only used when mode != notify)
"""


def _init_asset_id() -> str:
    import re
    import socket
    name = re.sub(r"[^A-Za-z0-9-]+", "-", socket.gethostname().split(".")[0]).strip("-")
    return name[:63] or "this-machine"


def _cmd_init(args: argparse.Namespace) -> int:
    """Write a starter assets.toml so `uv tool install` users (no clone, no
    examples/) can start. Never overwrites; never touches decoys or tokens."""
    from .errors import Z105_CONFIG_ALREADY_EXISTS, Z106_CONFIG_NOT_WRITABLE

    path: Path = args.config
    if os.path.lexists(path):
        raise ZeeError(Z105_CONFIG_ALREADY_EXISTS, f"{path}（中身を確認して編集するか、別の場所を -c で指定）")
    text = _INIT_TEMPLATE.format(version=__version__, asset_id=_init_asset_id())
    try:
        _write_private_files([(path, text)], force=False)
    except ZeeError as e:  # re-label: the shared writer reports export codes
        if os.path.lexists(path):  # appeared after our check: still never overwritten
            raise ZeeError(Z105_CONFIG_ALREADY_EXISTS, str(path)) from e
        raise ZeeError(Z106_CONFIG_NOT_WRITABLE, e.detail) from e
    Config.load(path)  # self-check: what we wrote must load
    import shlex
    import subprocess
    q = subprocess.list2cmdline([str(path)]) if sys.platform == "win32" else shlex.quote(str(path))
    c = f"-c {q} " if path != Path("assets.toml") else ""
    print(f"[zee init] wrote {path} (observe-only: dry_run=true, notify; "
          f"mode 0600 on macOS/Linux)",
          file=sys.stderr)
    print("next:", file=sys.stderr)
    print(f"  1. review decoy_paths in {path}", file=sys.stderr)
    print("  2. zee init-restore-token   # keep the printed token somewhere safe",
          file=sys.stderr)
    print(f"  3. zee {c}watch", file=sys.stderr)
    return 0


def _cmd_init_restore_token(args: argparse.Namespace) -> int:
    """Generate (or rotate) the restore_token at ~/.zee/restore_token.

    The token is printed to stderr exactly once. Capture it now and
    store it where you keep operational secrets (a password manager,
    sealed envelope, etc.); the file on disk is 0600 owner-only, but
    that is a complement to — not a replacement for — keeping the
    string out of shared chat logs.
    """
    token = init_token()
    print(
        "# Zee restore token (do not paste in shared chats):",
        file=sys.stderr,
    )
    print(token, file=sys.stderr)
    print(
        "# Use it via:  zee restore <asset_id> --token <TOKEN>",
        file=sys.stderr,
    )
    print(
        "# Or:          ZEE_RESTORE_TOKEN=<TOKEN> zee restore <asset_id>",
        file=sys.stderr,
    )
    return 0


def _cmd_cut(args: argparse.Namespace) -> int:
    """Manual containment. Companion to the read-class notification.

    Spec v4 block C: read-class touches never auto-cut. When the
    operator reviews a read-class alert and concludes it is hostile,
    they invoke this. cut_method defaults to the asset profile;
    --method overrides per invocation.
    """
    config = Config.load(args.config)
    asset = config.find(args.asset_id)
    if asset is None:
        raise ZeeError(Z102_UNKNOWN_ASSET_ID, args.asset_id)
    method = args.method or asset.cut_method
    from .responder.cut_egress import cut_egress
    from .responder.cut_full import cut_full
    cut_fn = cut_egress if method == "egress" else cut_full
    cut_state = CutStateLog()
    print(f"[zee cut] asset={args.asset_id} method={method}", file=sys.stderr)
    ok, detail = cut_fn(asset_id=args.asset_id, cut_state=cut_state)
    print(detail, file=sys.stderr)
    if ok:
        print(f"[zee cut] applied. {recover_hint(cut_state, args.asset_id)}", file=sys.stderr)
    else:
        print(f"[zee cut] FAILED ({Z404_CUT_COMMAND_FAILED[0]}) — traffic may NOT be stopped. "
              f"{recover_hint(cut_state, args.asset_id)}", file=sys.stderr)
    return 0 if ok else 1


def _write_private_files(outputs: list[tuple[Path, str]], force: bool) -> None:
    """Write each (path, text) owner-only (0600) without ever following a
    symlink or truncating an existing file in place.

    1. Refuse (Z701) if any target already exists — including a symlink
       or dangling symlink — unless `force`. Nothing is written then.
    2. Write every payload to a sibling temp file created
       O_CREAT|O_EXCL|O_NOFOLLOW at 0600, so partial content is never
       readable by other users and a pre-planted link is never followed.
    3. Only after ALL temps are complete, publish each one.
       Without --force: os.link(temp, target), which fails atomically if
       the target exists by then (a file or link that appeared after step
       1 is never overwritten); the temp name is then released.
       With --force: os.replace (replaces a link itself, never its target).
    On failure, already-written temp files stay behind at 0600 and are
    named in the error.
    """
    from .errors import Z701_EXPORT_OUTPUT_NOT_WRITABLE

    nofollow = getattr(os, "O_NOFOLLOW", 0)
    if not force:
        existing = [str(p) for p, _ in outputs if os.path.lexists(p)]
        if existing:
            raise ZeeError(
                Z701_EXPORT_OUTPUT_NOT_WRITABLE,
                f"既に存在します: {', '.join(existing)}（上書きするなら --force）",
            )
    temps: list[tuple[Path, Path]] = []
    try:
        for final, text in outputs:
            tmp = final.parent / f".{final.name}.{os.getpid()}.tmp"
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | nofollow, 0o600)
            temps.append((tmp, final))
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(text)
        for tmp, final in temps:
            if force:
                os.replace(tmp, final)
            else:
                os.link(tmp, final, follow_symlinks=False)
                # Only drops the temp NAME of the file just published at `final`.
                os.unlink(tmp)
    except FileExistsError as e:
        left = [str(t) for t, _ in temps if os.path.lexists(t)]
        raise ZeeError(
            Z701_EXPORT_OUTPUT_NOT_WRITABLE,
            f"書き込み中に出力先が作られました（上書きしません）: {e.filename}"
            + (f"（一時ファイル・所有者のみ読み取り可: {', '.join(left)}）" if left else ""),
        ) from e
    except OSError as e:
        left = [str(t) for t, _ in temps if os.path.lexists(t)]
        hint = f"（書きかけの一時ファイル・所有者のみ読み取り可: {', '.join(left)}）" if left else ""
        raise ZeeError(Z701_EXPORT_OUTPUT_NOT_WRITABLE, f"{e}{hint}") from e


def _cmd_export(args: argparse.Namespace) -> int:
    """Containment report export — read-only, writes local files only.

    Zee does not access or act on an attacker's machines (the statutory
    power for that — サイバー危害防止措置 — belongs to police / SDF
    officers, see README 法制度との関係). This packages what Zee already
    recorded into files the operator can choose to hand to whoever they
    report to. It never submits anything itself.
    """
    import json as _json

    from .telemetry.events_log import default_log_dir
    from .telemetry.report_export import attach_digest, build_export, render_text

    # Z702 on malformed / reversed --since/--until (raised inside).
    export = build_export(
        log_dir=default_log_dir(),
        since=args.since,
        until=args.until,
        redact_paths=not args.no_redact,
    )
    export, digest = attach_digest(export)

    # Append, never replace, the extension: `--out report.2026` must not
    # collide with `--out report.2025` (Path.with_suffix would).
    out_json = Path(str(args.out) + ".json")
    out_text = Path(str(args.out) + ".txt")
    _write_private_files(
        [
            (out_json, _json.dumps(export, ensure_ascii=False, indent=2)),
            (out_text, render_text(export)),
        ],
        force=args.force,
    )

    print(f"[zee export] wrote {out_json}", file=sys.stderr)
    print(f"[zee export] wrote {out_text}", file=sys.stderr)
    print(f"[zee export] export_sha256: {digest}", file=sys.stderr)
    print(
        "[zee export] record that digest somewhere OTHER than these two "
        "files (e.g. in your submission email). It only shows the export "
        "was not changed after this moment; it says nothing about the log "
        "before export.",
        file=sys.stderr,
    )
    rc = 0
    for name, key in (("events.jsonl", "events_jsonl"), ("metrics.jsonl", "metrics_jsonl")):
        c = export["chain_verification"][key]
        if c["status"] == "unverifiable":
            print(
                f"[zee export] WARNING: {name} could not be read — evidence is "
                f"UNVERIFIABLE ({c['read_error']}).",
                file=sys.stderr,
            )
            rc = 1
        elif c["status"] == "tamper_suspected":
            print(
                f"[zee export] WARNING: hash-chain verification of {name} found "
                "an edited, missing or out-of-place record — see "
                "chain_verification in the JSON output.",
                file=sys.stderr,
            )
            rc = 1
    return rc


def _cmd_incident_report(args: argparse.Namespace) -> int:
    """Bundle a zee export JSON into a document for the operator to hand
    to police or the PPC. Read-only over its input, writes local files
    only, never submits anything (see src/zee/report/incident_report.py).
    """
    import json as _json

    from .errors import Z1005_OUTPUT_COLLIDES_WITH_INPUT
    from .report.incident_report import (
        build_incident_report,
        load_export,
        render_html,
        render_text,
    )

    export_path = Path(args.export_json)
    out_json = Path(str(args.out) + ".json")
    out_text = Path(str(args.out) + ".txt")
    out_html = Path(str(args.out) + ".html")

    # The input file is read-only evidence; never let --force make it an
    # output target.
    for out_p in (out_json, out_text, out_html):
        if out_p.exists() and out_p.resolve() == export_path.resolve():
            raise ZeeError(Z1005_OUTPUT_COLLIDES_WITH_INPUT, str(out_p))

    export = load_export(export_path)
    report = build_incident_report(
        export=export,
        recipient=args.recipient,
        incident_label=args.incident_label,
    )

    _write_private_files(
        [
            (out_json, _json.dumps(report, ensure_ascii=False, indent=2)),
            (out_text, render_text(report)),
            (out_html, render_html(report)),
        ],
        force=args.force,
    )
    print(f"[zee incident-report] wrote {out_json}", file=sys.stderr)
    print(f"[zee incident-report] wrote {out_text}", file=sys.stderr)
    print(f"[zee incident-report] wrote {out_html}", file=sys.stderr)
    if not export["redacted"]:
        print(
            "[zee incident-report] WARNING: the input export was made with "
            "--no-redact; paths are NOT masked in these files. Review them "
            "before you hand them to anyone.",
            file=sys.stderr,
        )
    print(
        "[zee incident-report] this is a document to attach when YOU report "
        "— zee does not submit it anywhere.",
        file=sys.stderr,
    )
    return 0


def _cmd_status(args: argparse.Namespace) -> int:
    from .telemetry.status import compute, render
    report = compute()
    print(render(report))
    return 0


def _cmd_capability(args: argparse.Namespace) -> int:
    canary_url = os.environ.get("ZEE_CANARY_BASE_URL", "").strip()
    canary_configured = bool(canary_url)
    print("# Zee capability matrix")
    print(f"current platform: {sys.platform}")
    print(
        f"canary base_url : {'configured' if canary_configured else 'not configured'}"
        + (" (read-class detection on macOS / Windows is wired)"
           if canary_configured else
           " (set ZEE_CANARY_BASE_URL to wire macOS / Windows read detection)")
    )
    print(
        "auto-cut trigger : change-class touches only "
        "(write / delete / rename / extend)"
    )
    print(
        "                  read-class touches notify only and require "
        "manual `zee cut` if hostile"
    )
    print(
        "                  reason: the watcher cannot identify the "
        "process that touched the decoy, so auto-cut is restricted to "
        "operations that legitimate bulk readers do not perform."
    )
    print()
    print(capability_text(canary_configured=canary_configured))
    return 0


def _cmd_mcp(args: argparse.Namespace) -> int:
    """Run the optional MCP server (read-only + propose-only).

    Needs the `mcp` extra (`pip install 'zee[mcp]'`). It exposes Zee's
    signals over stdio so an agent can read status/events and *propose*
    next steps — it never cuts, restores, or edits policy.
    """
    try:
        from .mcp.server import serve
        from .mcp.config import McpConfig
    except ImportError:
        print(
            "the MCP layer needs the optional extra. Install it with:\n"
            "    pip install 'zee[mcp]'",
            file=sys.stderr,
        )
        return 2
    cfg = McpConfig.load(args.config)
    if not cfg.enabled and not args.force:
        print(
            "MCP is disabled (default). Enable it by adding to assets.toml:\n"
            "    [mcp]\n    enabled = true\n"
            "or pass --force to run anyway (still read-only + propose-only).",
            file=sys.stderr,
        )
        return 2
    print(
        f"[zee mcp] starting stdio server  redact_paths={cfg.redact_paths} "
        f"expose_actions={cfg.expose_actions} (propose-only)",
        file=sys.stderr,
    )
    serve(config_path=str(args.config))
    return 0


def _cmd_gate_add(args: argparse.Namespace) -> int:
    """Entry gate: fetch (no exec) -> inspect -> verdict -> optional promote.

    Exit code is the verdict: LOW=0, MEDIUM=1, HIGH=2 (safeinspect
    heritage). 3 = verdict over an incomplete inspection, 4 = no verdict
    at all. Any failure to inspect exits 4, never a pass.
    """
    import json as _json

    from .gate.inspector import inspect_source, promote_if_low
    from .gate.model import EXIT_ERROR, error_payload

    try:
        verdict = inspect_source(
            args.source,
            kind=args.kind,
            behavioral=args.behavioral,
            behavioral_timeout=args.timeout,
            import_scans=tuple(args.import_scan or ()),
        )
    except Exception as e:  # noqa: BLE001 - every failure here is fail-closed
        detail = f"{type(e).__name__}: {e}"
        print(f"error: inspection did not complete ({detail})", file=sys.stderr)
        if args.json:
            print(_json.dumps(
                error_payload(str(args.source), detail),
                ensure_ascii=False, indent=2,
            ))
        return EXIT_ERROR
    if args.json:
        print(_json.dumps(verdict.to_dict(), ensure_ascii=False, indent=2))
    else:
        print(verdict.to_text())
    if args.promote_to:
        try:
            ok, msg = promote_if_low(verdict, args.promote_to)
        except OSError as e:  # e.g. read-only install dir
            print(f"error: promotion failed ({e})", file=sys.stderr)
            return EXIT_ERROR
        print(msg, file=sys.stderr)
        if ok:
            # Pin the promoted bytes so `zee gate audit` can later detect a
            # Rug Pull (self-update / silent rewrite) of this install.
            from .gate.pins import PinRegistry

            dest = str(Path(args.promote_to).expanduser() / verdict.artifact.name)
            PinRegistry().pin(
                name=verdict.artifact.name,
                kind=verdict.artifact.kind.value,
                source=verdict.artifact.source,
                content_hash=verdict.artifact.content_hash,
                install_dir=dest,
            )
            print(f"pinned for Rug Pull monitoring: {dest}", file=sys.stderr)
    return verdict.exit_code


def _cmd_gate_audit(args: argparse.Namespace) -> int:
    """Re-check pinned artifacts for Rug Pull drift (Phase 3).

    Exit code: 2 if any pinned artifact has drifted (HIGH), 1 if some are
    missing, 0 if all clean — so it composes in cron / pre-run hooks.
    """
    import json as _json

    from .gate.audit import audit_pins
    from .gate.pins import PinRegistry

    report = audit_pins(
        PinRegistry(), rescan=args.rescan, behavioral=args.behavioral
    )
    if args.json:
        print(_json.dumps(report.to_dict(), ensure_ascii=False, indent=2))
    else:
        print(report.to_text())
    return report.exit_code


def _cmd_dilute_generate(args: argparse.Namespace) -> int:
    """Generate dummy PII records + a holder-only ledger (value dilution).

    Writes files only — see docs/design/decoy-pii-dilution.md. Does not
    touch any database, backup, or network; mixing the output into a
    backup/export is the operator's own step.
    """
    import secrets

    from .dilution.generate import DiluteConfig, run

    seed = args.seed or os.environ.get("ZEE_DILUTE_SEED")
    if not seed:
        # design doc §5: unspecified seed is auto-generated and shown
        # once, on stdout only — never written to a file or log.
        seed = secrets.token_hex(32)
        print(f"generated seed (save this — it is the only way to re-run "
              f"identically or recognize these dummies later): {seed}")

    records_path, ledger_path = run(DiluteConfig(
        parcels_path=Path(args.parcels) if args.parcels else None,
        public_land_path=Path(args.public_land) if args.public_land else None,
        abr_towns_path=Path(args.abr_towns),
        zipcode_path=Path(args.zipcode_data),
        seed=seed,
        count=args.count,
        layer=args.layer,
        email_mode=args.email_mode,
        email_domain=args.email_domain,
        fallback_zip=args.fallback_zip,
        out_dir=Path(args.out),
    ))
    print(f"wrote {records_path}")
    print(f"wrote {ledger_path}  (keep separately from records.csv; "
          f"this is how you tell your own dummies apart later)")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="zee",
        description=(
            "Zee — lightweight decoy tripwire and post-intrusion containment layer. "
            "Runs in dry_run by default. Does not actually cut connections unless "
            "an asset profile is explicitly promoted to auto or staged mode."
        ),
    )
    parser.add_argument("--version", action="version", version=f"zee {__version__}")
    parser.add_argument(
        "-c", "--config", type=Path, default=Path("assets.toml"),
        help="path to assets.toml (default: ./assets.toml)",
    )
    parser.add_argument("--verbose", action="store_true", help="enable debug logging")

    sub = parser.add_subparsers(dest="command", required=True)

    p_init = sub.add_parser(
        "init",
        help="write a starter assets.toml (observe-only; refuses to overwrite)",
    )
    p_init.set_defaults(func=_cmd_init)

    p_watch = sub.add_parser("watch", help="start monitoring decoys")
    p_watch.set_defaults(func=_cmd_watch)

    p_restore = sub.add_parser(
        "restore", help="manually restore an asset after containment"
    )
    p_restore.add_argument("asset_id")
    p_restore.add_argument(
        "--token",
        default=None,
        help="restore_token (alternatively set ZEE_RESTORE_TOKEN). "
             "Generate one with `zee init-restore-token`.",
    )
    p_restore.add_argument(
        "--all-interfaces",
        action="store_true",
        help="emergency only: re-enable every interface/service and remove Zee's "
             "egress rules even without a cut record (may re-enable interfaces "
             "disabled by other tools). Without it, restore refuses when no cut "
             "record exists for the asset (Z605).",
    )
    p_restore.set_defaults(func=_cmd_restore)

    p_init_token = sub.add_parser(
        "init-restore-token",
        help="generate (or rotate) the local restore_token at ~/.zee/restore_token",
    )
    p_init_token.set_defaults(func=_cmd_init_restore_token)

    p_cut = sub.add_parser(
        "cut",
        help="manually cut an asset's network (companion to read-class alerts)",
    )
    p_cut.add_argument("asset_id")
    p_cut.add_argument(
        "--method",
        choices=("full", "egress"),
        default=None,
        help="cut method override; defaults to the asset profile's cut_method",
    )
    p_cut.set_defaults(func=_cmd_cut)

    p_status = sub.add_parser(
        "status",
        help="show recent trap activity, cut state, and burst detection summary",
    )
    p_status.set_defaults(func=_cmd_status)

    p_export = sub.add_parser(
        "export",
        help="export recorded containment evidence to local files you can "
        "attach to a report of your choosing (read-only over the logs; "
        "Zee never submits anything itself)",
    )
    p_export.add_argument(
        "--out", required=True,
        help="output path prefix; writes <prefix>.json and <prefix>.txt "
        "(owner-only 0600; refuses to overwrite existing files or links)",
    )
    p_export.add_argument(
        "--force", action="store_true",
        help="replace existing <prefix>.json / <prefix>.txt (a symlink is "
        "replaced itself, never followed)",
    )
    p_export.add_argument(
        "--since", default=None,
        help="ISO8601; only events at or after this instant. No timezone = "
        "UTC; date only (2026-10-01) = 00:00 UTC of that day",
    )
    p_export.add_argument(
        "--until", default=None,
        help="ISO8601; only events at or before this instant. No timezone = "
        "UTC; date only = 00:00 UTC of that day (so it EXCLUDES that day — "
        "use the next day to include it)",
    )
    p_export.add_argument(
        "--no-redact", action="store_true",
        help="include unmasked free-text detail (paths) in the export; "
        "default masks it, matching the MCP layer's default",
    )
    p_export.set_defaults(func=_cmd_export)

    p_incident = sub.add_parser(
        "incident-report",
        help="bundle a zee export into a document to attach when reporting "
        "to police or the PPC; read-only over its input, never submits "
        "anything itself",
    )
    p_incident.add_argument(
        "--export-json", required=True,
        help="path to the <prefix>.json written by `zee export`",
    )
    p_incident.add_argument(
        "--recipient", required=True, choices=("police", "ppc"),
        help="which handoff document to produce",
    )
    p_incident.add_argument(
        "--incident-label", default=None,
        help="free-text label for this incident bundle (operator's own reference)",
    )
    p_incident.add_argument(
        "--out", required=True,
        help="output path prefix; writes <prefix>.json / .txt / .html "
        "(owner-only 0600; refuses to overwrite existing files or links)",
    )
    p_incident.add_argument(
        "--force", action="store_true",
        help="replace existing <prefix>.{json,txt,html} (a symlink is "
        "replaced itself, never followed)",
    )
    p_incident.set_defaults(func=_cmd_incident_report)

    p_cap = sub.add_parser(
        "capability", help="print the detection-capability matrix for this OS"
    )
    p_cap.set_defaults(func=_cmd_capability)

    p_mcp = sub.add_parser(
        "mcp",
        help="run the MCP server (read-only + propose-only; needs zee[mcp])",
    )
    p_mcp.add_argument(
        "--force",
        action="store_true",
        help="run even if [mcp] enabled is not set in assets.toml",
    )
    p_mcp.set_defaults(func=_cmd_mcp)

    p_gate = sub.add_parser(
        "gate",
        help="inspect an AI artifact (skill / MCP / package) before install",
    )
    gate_sub = p_gate.add_subparsers(dest="gate_command", required=True)
    p_gate_add = gate_sub.add_parser(
        "add",
        help="fetch into quarantine (no exec), statically inspect, and "
        "optionally promote if LOW",
    )
    p_gate_add.add_argument(
        "source", help="local path to a skill / MCP server / package"
    )
    p_gate_add.add_argument(
        "--kind",
        choices=("skill", "mcp", "npm", "pypi", "vscode", "package"),
        default=None,
        help="artifact kind (auto-detected if omitted)",
    )
    p_gate_add.add_argument(
        "--import-scan",
        action="append",
        metavar="FILE",
        help="fold an existing scanner's report (Semgrep JSON or SARIF) "
        "into the verdict instead of re-running it (repeatable)",
    )
    p_gate_add.add_argument(
        "--promote-to",
        default=None,
        help="install dir to copy into IF the verdict is LOW",
    )
    p_gate_add.add_argument(
        "--json", action="store_true", help="emit the verdict as JSON"
    )
    p_gate_add.add_argument(
        "--behavioral",
        action="store_true",
        help="ALSO run the artifact's install hook inside an isolation "
        "sandbox and watch for credential exfil / persistence / outbound "
        "traffic (opt-in; needs an isolation backend such as macOS "
        "sandbox-exec — never runs on the bare host)",
    )
    p_gate_add.add_argument(
        "--timeout",
        type=int,
        default=20,
        help="wall-clock seconds for the behavioural run (default: 20)",
    )
    p_gate_add.set_defaults(func=_cmd_gate_add)

    p_gate_audit = gate_sub.add_parser(
        "audit",
        help="re-check pinned (promoted) artifacts for Rug Pull drift — a "
        "silent self-update / rewrite since they passed the gate",
    )
    p_gate_audit.add_argument(
        "--rescan",
        action="store_true",
        help="re-inspect any drifted artifact to show what it became "
        "(static; add --behavioral to also detonate it)",
    )
    p_gate_audit.add_argument(
        "--behavioral",
        action="store_true",
        help="with --rescan, also run the drifted artifact in the sandbox",
    )
    p_gate_audit.add_argument(
        "--json", action="store_true", help="emit the audit report as JSON"
    )
    p_gate_audit.set_defaults(func=_cmd_gate_audit)

    p_dilute = sub.add_parser(
        "dilute-generate",
        help="generate dummy PII records + a holder-only ledger (value "
        "dilution for exfiltrated data); writes files only — see "
        "docs/design/decoy-pii-dilution.md",
    )
    p_dilute.add_argument(
        "--layer", choices=("fictional-town", "real-nonresidential", "both"),
        default="fictional-town",
        help="fictional-town: real-looking but non-existent town name "
        "(no extra inputs needed). real-nonresidential: real town + a "
        "chiban confirmed fully inside park/river public land, requires "
        "--parcels and --public-land. both: mix of the two. "
        "NOT RECOMMENDED: the public-land layer is not guaranteed to stay "
        "non-residential (representative decision 2026-10-13: fictional-town only).",
    )
    p_dilute.add_argument("--parcels", default=None,
                          help="地番 parcel extract (required for real-nonresidential/both)")
    p_dilute.add_argument("--public-land", default=None,
                          help="都市公園・河川区域 extract (required for real-nonresidential/both)")
    p_dilute.add_argument("--abr-towns", required=True,
                          help="町字マスター CSV (real town names, one per line)")
    p_dilute.add_argument("--zipcode-data", required=True,
                          help="日本郵便 KEN_ALL.CSV / utf_all.csv (or a same-shaped subset)")
    p_dilute.add_argument("--seed", default=None,
                          help="your own secret, min 16 chars — reusing the same seed "
                          "reproduces the same output deterministically; do not share "
                          "it, and prefer ZEE_DILUTE_SEED over this flag (shell "
                          "history / process list exposure). Omit both to auto-generate "
                          "one (printed once, to stdout only)")
    p_dilute.add_argument("--count", type=int, default=100)
    p_dilute.add_argument("--email-mode", choices=("omit", "user-domain"), default="omit")
    p_dilute.add_argument("--email-domain", default=None,
                          help="a domain you control; required with --email-mode=user-domain")
    p_dilute.add_argument("--fallback-zip", default="0000000",
                          help="used when a town has no match in --zipcode-data")
    p_dilute.add_argument("--out", required=True, help="output directory")
    p_dilute.set_defaults(func=_cmd_dilute_generate)

    from .privsep.cli import add_parser as add_privsep_parser
    add_privsep_parser(sub)

    return parser


_DISCUSSIONS_URL = (
    "https://github.com/KAMANOI/zee/discussions/categories/q-a"
)

# Error codes that are clearly user-input mistakes, not OS-shift /
# environment-quirk failures. We suppress the seeded-OSS Discussions
# hint on these so the operator isn't pointed at a community board
# for "you typed the wrong token" or "you ran restore on an asset
# that's not in assets.toml". The hint stays on every other code so
# any genuinely environment-shaped error gets pointed at the right
# place by default.
_USER_INPUT_CODES = frozenset({
    "Z102",  # unknown asset_id
    "Z105",  # init: assets.toml already exists
    "Z106",  # init: target folder missing or not writable
    "Z602",  # restore token required
    "Z603",  # restore token not initialised
    "Z604",  # restore token invalid
    "Z702",  # export: invalid --since/--until
    "Z1001",  # incident-report: unknown --recipient
    "Z1004",  # incident-report: unreadable / non-matching --export-json
    "Z1005",  # incident-report: --out collides with the --export-json file
    "Z802",  # dilute-generate: --email-domain required for user-domain mode
    "Z803",  # dilute-generate: --parcels/--public-land required for this --layer
    "Z804",  # dilute-generate: parcels/public-land crs mismatch
    "Z805",  # dilute-generate: empty town master
    "Z806",  # dilute-generate: --seed too short
    "Z807",  # dilute-generate: --count must be positive
    "Z808",  # dilute-generate: --out already has output files
    "Z809",  # dilute-generate: address pool exhausted for requested --count
})


def main(argv: list[str] | None = None) -> int:
    if sys.version_info < (3, 11):
        print(
            "zee requires Python 3.11 or newer (uses the standard library "
            f"tomllib module). Detected: Python {sys.version_info.major}."
            f"{sys.version_info.minor}.",
            file=sys.stderr,
        )
        return 2
    parser = build_parser()
    args = parser.parse_args(argv)
    if getattr(args, "verbose", False):
        logging.basicConfig(level=logging.DEBUG)
    try:
        return args.func(args)
    except ZeeError as e:
        print(f"error: {e}", file=sys.stderr)
        if e.code not in _USER_INPUT_CODES:
            # Seeded-OSS hint (v0.5): nudge the operator toward the
            # community knowledge base for genuinely environment-shaped
            # failures, while staying out of the way for plain
            # user-input mistakes (above list).
            print(
                f"  ↳ hit by an OS update or environment-specific quirk? "
                f"search / share at:\n    {_DISCUSSIONS_URL}",
                file=sys.stderr,
            )
        return 1


if __name__ == "__main__":
    sys.exit(main())
