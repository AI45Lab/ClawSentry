"""Unified CLI entry point for clawsentry."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from .initializers import FRAMEWORK_INITIALIZERS


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="clawsentry",
        description="ClawSentry — AHP unified safety supervision framework.",
    )
    sub = parser.add_subparsers(dest="command")

    # --- init ---
    init_parser = sub.add_parser(
        "init",
        help="Initialize framework integration.",
    )
    init_parser.add_argument(
        "framework",
        choices=sorted(FRAMEWORK_INITIALIZERS.keys()),
        help="Target framework to initialize.",
    )
    init_parser.add_argument(
        "--dir",
        type=Path,
        default=Path("."),
        help="Directory to write config files (default: current dir).",
    )
    init_parser.add_argument(
        "--force",
        action="store_true",
        help="Overwrite existing config files.",
    )
    init_parser.add_argument(
        "--auto-detect",
        action="store_true",
        default=False,
        help="Auto-detect existing framework configuration (e.g. OpenClaw tokens).",
    )
    init_parser.add_argument(
        "--setup",
        action="store_true",
        default=False,
        help="Auto-configure OpenClaw settings for Monitor integration.",
    )
    init_parser.add_argument(
        "--dry-run",
        action="store_true",
        default=False,
        help="Preview OpenClaw config changes without applying (use with --setup).",
    )

    # --- gateway ---
    sub.add_parser(
        "gateway",
        help="Start Supervision Gateway (auto-enables OpenClaw when configured).",
        add_help=False,
    )

    # --- stack ---
    sub.add_parser(
        "stack",
        help="Start full stack (Gateway + OpenClaw). Alias for gateway.",
        add_help=False,
    )

    # --- harness ---
    sub.add_parser(
        "harness",
        help="Start a3s-code stdio harness.",
        add_help=False,
    )

    # --- watch ---
    _watch_port = os.environ.get("CS_HTTP_PORT", "8080")
    _watch_default_url = f"http://127.0.0.1:{_watch_port}"
    watch_parser = sub.add_parser(
        "watch",
        help="Watch real-time SSE events from the Supervision Gateway.",
    )
    watch_parser.add_argument(
        "--gateway-url",
        default=_watch_default_url,
        help=f"Gateway base URL (default: {_watch_default_url}).",
    )
    watch_parser.add_argument(
        "--token",
        default=os.environ.get("CS_AUTH_TOKEN"),
        help="Bearer token for Gateway authentication [CS_AUTH_TOKEN].",
    )
    watch_parser.add_argument(
        "--filter",
        default=None,
        help="Comma-separated event types to subscribe to (e.g. decision,alert).",
    )
    watch_parser.add_argument(
        "--json",
        action="store_true",
        default=False,
        help="Output raw JSON instead of formatted text.",
    )
    watch_parser.add_argument(
        "--no-color",
        action="store_true",
        default=False,
        help="Disable ANSI colour codes in output.",
    )
    watch_parser.add_argument(
        "--interactive",
        "-i",
        action="store_true",
        default=False,
        help="Prompt operator to Allow/Deny/Skip on DEFER decisions.",
    )

    return parser


def main(argv: list[str] | None = None) -> None:
    from .dotenv_loader import load_dotenv
    load_dotenv()
    parser = _build_parser()
    args, remaining = parser.parse_known_args(argv)

    if args.command is None:
        parser.print_help()
        return

    if args.command == "init":
        from .init_command import run_init

        code = run_init(
            framework=args.framework,
            target_dir=args.dir,
            force=args.force,
            auto_detect=getattr(args, "auto_detect", False),
            setup=getattr(args, "setup", False),
            dry_run=getattr(args, "dry_run", False),
        )
        sys.exit(code)

    elif args.command == "gateway":
        from ..gateway.stack import main as stack_main
        # Replace sys.argv so the delegated main() can re-parse its own flags
        sys.argv = ["clawsentry-gateway"] + remaining
        stack_main()

    elif args.command == "stack":
        from ..gateway.stack import main as stack_main
        sys.argv = ["clawsentry-stack"] + remaining
        stack_main()

    elif args.command == "harness":
        from ..adapters.a3s_gateway_harness import main as harness_main
        sys.argv = ["clawsentry-harness"] + remaining
        harness_main()

    elif args.command == "watch":
        from .watch_command import run_watch

        run_watch(
            gateway_url=args.gateway_url,
            token=args.token,
            filter_types=args.filter,
            json_mode=args.json,
            color=not args.no_color,
            interactive=args.interactive,
        )


if __name__ == "__main__":
    main()
