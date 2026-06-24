"""Zee CLI entry point.

By default Zee runs dry_run. `zee watch` starts monitoring; `zee restore`
recovers an asset after containment.
"""

from __future__ import annotations

import argparse
import logging
import os
import sys
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
    Z602_RESTORE_TOKEN_REQUIRED,
    Z603_RESTORE_TOKEN_NOT_INITIALIZED,
    Z604_RESTORE_TOKEN_INVALID,
)
from .notifier.webhook import from_env as webhook_from_env
from .responder.sequence import handle
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
                    )
                    print(
                        f"[event] {event.detail} → mode={result.mode} "
                        f"cut={'yes' if result.cut_executed else 'no'} "
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

    ok, detail = restore(args.asset_id)
    print(detail, file=sys.stderr)
    return 0 if ok else 1


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
        print(
            f"[zee cut] applied. recover with: zee restore {args.asset_id}",
            file=sys.stderr,
        )
    return 0 if ok else 1


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
    heritage), so the command composes in CI / pre-install hooks.
    """
    import json as _json

    from .gate.inspector import inspect_source, promote_if_low

    try:
        verdict = inspect_source(
            args.source,
            kind=args.kind,
            behavioral=args.behavioral,
            behavioral_timeout=args.timeout,
        )
    except FileNotFoundError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    if args.json:
        print(_json.dumps(verdict.to_dict(), ensure_ascii=False, indent=2))
    else:
        print(verdict.to_text())
    if args.promote_to:
        ok, msg = promote_if_low(verdict, args.promote_to)
        print(msg, file=sys.stderr)
    return verdict.exit_code


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
        choices=("skill", "mcp", "package"),
        default=None,
        help="artifact kind (auto-detected if omitted)",
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
    "Z602",  # restore token required
    "Z603",  # restore token not initialised
    "Z604",  # restore token invalid
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
