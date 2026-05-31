"""Zee CLI entry point.

By default Zee runs dry_run. `zee watch` starts monitoring; `zee restore`
recovers an asset after containment.
"""

from __future__ import annotations

import argparse
import logging
import sys
import time
from pathlib import Path

from . import __version__
from .config.schema import Config
from .decoy.seeder import seed_all
from .errors import ZeeError, Z102_UNKNOWN_ASSET_ID
from .notifier.webhook import from_env as webhook_from_env
from .responder.sequence import handle
from .recovery.restore import restore
from .telemetry.capability_report import render_text as capability_text
from .telemetry.events_log import EventLog


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
            from pathlib import Path as _P
            key = str(_P(raw).expanduser())
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
    log_dir = event_log.log_dir
    sender = webhook_from_env()
    print(
        f"[zee watch] dry_run={config.dry_run} log_dir={log_dir} "
        f"webhook={'configured' if sender else 'none'}",
        file=sys.stderr,
    )

    # Lazy import so each platform only loads its own backend module.
    watchers: list[object] = []
    if sys.platform.startswith("linux"):
        from .watcher.backend_linux import LinuxInotifyWatcher
        backend_cls: type = LinuxInotifyWatcher
    elif sys.platform == "darwin":
        from .watcher.backend_macos import MacOSKqueueWatcher
        backend_cls = MacOSKqueueWatcher
    elif sys.platform == "win32":
        from .watcher.backend_windows import WindowsWatcher
        backend_cls = WindowsWatcher
    else:
        print(f"[zee watch] unsupported platform: {sys.platform}", file=sys.stderr)
        return 2

    for asset in config.assets:
        seeded = seed_all(list(asset.decoy_paths))
        print(f"[seeded] asset={asset.id} paths={[str(p) for p in seeded]}",
              file=sys.stderr)

        watcher = backend_cls()
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
    ok, detail = restore(args.asset_id)
    print(detail, file=sys.stderr)
    return 0 if ok else 1


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
    print(f"[zee cut] asset={args.asset_id} method={method}", file=sys.stderr)
    ok, detail = cut_fn()
    print(detail, file=sys.stderr)
    if ok:
        print(
            f"[zee cut] applied. recover with: zee restore {args.asset_id}",
            file=sys.stderr,
        )
    return 0 if ok else 1


def _cmd_capability(args: argparse.Namespace) -> int:
    print("# Zee capability matrix")
    print(f"current platform: {sys.platform}")
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
    print(capability_text())
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

    p_watch = sub.add_parser("watch", help="start monitoring decoys")
    p_watch.set_defaults(func=_cmd_watch)

    p_restore = sub.add_parser(
        "restore", help="manually restore an asset after containment"
    )
    p_restore.add_argument("asset_id")
    p_restore.set_defaults(func=_cmd_restore)

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

    p_cap = sub.add_parser(
        "capability", help="print the detection-capability matrix for this OS"
    )
    p_cap.set_defaults(func=_cmd_capability)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if getattr(args, "verbose", False):
        logging.basicConfig(level=logging.DEBUG)
    try:
        return args.func(args)
    except ZeeError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
