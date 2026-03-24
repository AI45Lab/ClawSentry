"""
Unified local stack runner for ClawSentry.

Starts:
  - Supervision Gateway (UDS + HTTP) — always
  - OpenClaw Webhook Receiver (HTTP) — only when OpenClaw is configured

The mode is auto-detected from environment variables:
  - Gateway-only: no OpenClaw env vars set (or all defaults)
  - Full stack: OPENCLAW_WEBHOOK_TOKEN or OPENCLAW_ENFORCEMENT_ENABLED set

Usage:
  cd src/clawsentry
  python -m gateway.stack
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import logging
import os
import sys
from typing import Optional

import uvicorn

from starlette.responses import Response

from fastapi import Request as _FastAPIRequest

from ..adapters.openclaw_bootstrap import (
    DEFAULT_WEBHOOK_TOKEN,
    OpenClawBootstrapConfig,
    OpenClawRuntime,
    build_openclaw_runtime,
    create_openclaw_webhook_app,
)
from .detection_config import DetectionConfig, build_detection_config_from_env
from .idempotency import periodic_cleanup
from .llm_factory import build_analyzer_from_env
from .policy_engine import L1PolicyEngine
from .server import (
    DEFAULT_HTTP_HOST,
    DEFAULT_HTTP_PORT,
    DEFAULT_TRAJECTORY_DB_PATH,
    DEFAULT_TRAJECTORY_RETENTION_SECONDS,
    DEFAULT_UDS_PATH,
    SupervisionGateway,
    create_http_app,
    start_uds_server,
)
from .session_enforcement import EnforcementAction, SessionEnforcementPolicy

logger = logging.getLogger("ahp-stack")

DEFAULT_WEBHOOK_HOST = "127.0.0.1"
DEFAULT_WEBHOOK_PORT = 8081


def _has_openclaw_config(bootstrap_cfg: OpenClawBootstrapConfig) -> bool:
    """Detect whether the user has explicitly configured OpenClaw integration.

    Returns True when either:
    - webhook_token differs from the built-in default, OR
    - enforcement_enabled is True
    """
    if bootstrap_cfg.webhook_token != DEFAULT_WEBHOOK_TOKEN:
        return True
    if bootstrap_cfg.enforcement_enabled:
        return True
    return False


def _build_parser() -> argparse.ArgumentParser:
    bootstrap_defaults = OpenClawBootstrapConfig.from_env()

    parser = argparse.ArgumentParser(
        description="Run ClawSentry local stack (Gateway + OpenClaw Webhook Receiver)."
    )
    parser.add_argument("--uds-path", default=bootstrap_defaults.gateway_uds_path)
    parser.add_argument("--gateway-host", default=os.getenv("CS_HTTP_HOST", DEFAULT_HTTP_HOST))
    parser.add_argument(
        "--gateway-port",
        type=int,
        default=int(os.getenv("CS_HTTP_PORT", str(DEFAULT_HTTP_PORT))),
    )
    parser.add_argument("--webhook-host", default=os.getenv("OPENCLAW_WEBHOOK_HOST", DEFAULT_WEBHOOK_HOST))
    parser.add_argument(
        "--webhook-port",
        type=int,
        default=int(os.getenv("OPENCLAW_WEBHOOK_PORT", str(DEFAULT_WEBHOOK_PORT))),
    )
    parser.add_argument(
        "--trajectory-db-path",
        default=os.getenv("CS_TRAJECTORY_DB_PATH", DEFAULT_TRAJECTORY_DB_PATH),
    )
    parser.add_argument(
        "--trajectory-retention-seconds",
        type=int,
        default=int(
            os.getenv(
                "AHP_TRAJECTORY_RETENTION_SECONDS",
                str(DEFAULT_TRAJECTORY_RETENTION_SECONDS),
            )
        ),
    )

    parser.add_argument(
        "--webhook-token",
        default=bootstrap_defaults.webhook_token,
    )
    parser.add_argument(
        "--webhook-secret",
        default=bootstrap_defaults.webhook_secret,
    )
    parser.add_argument(
        "--webhook-require-https",
        action="store_true",
        default=bootstrap_defaults.webhook_require_https,
        help="Require HTTPS for webhook endpoint (localhost exempt).",
    )
    parser.add_argument(
        "--webhook-max-body-bytes",
        type=int,
        default=bootstrap_defaults.webhook_max_body_bytes,
    )

    parser.add_argument(
        "--source-protocol-version",
        default=bootstrap_defaults.source_protocol_version,
    )
    parser.add_argument(
        "--git-short-sha",
        default=bootstrap_defaults.git_short_sha,
    )
    parser.add_argument(
        "--profile-version",
        type=int,
        default=bootstrap_defaults.profile_version,
    )
    parser.add_argument(
        "--gateway-transport-preference",
        default=bootstrap_defaults.gateway_transport_preference,
        choices=("uds_first", "http_first"),
        help="OpenClaw Gateway client transport order.",
    )

    return parser


def _build_openclaw_runtime(
    *,
    webhook_token: str,
    webhook_secret: Optional[str],
    webhook_require_https: bool,
    webhook_max_body_bytes: int,
    source_protocol_version: str,
    git_short_sha: str,
    profile_version: int,
    uds_path: str,
    gateway_host: str,
    gateway_port: int,
    gateway_transport_preference: str,
) -> OpenClawRuntime:
    config = OpenClawBootstrapConfig(
        webhook_token=webhook_token,
        webhook_secret=webhook_secret,
        webhook_require_https=webhook_require_https,
        webhook_max_body_bytes=webhook_max_body_bytes,
        source_protocol_version=source_protocol_version,
        git_short_sha=git_short_sha,
        profile_version=profile_version,
        gateway_http_url=f"http://{gateway_host}:{gateway_port}/ahp",
        gateway_uds_path=uds_path,
        gateway_transport_preference=gateway_transport_preference,
    )
    return build_openclaw_runtime(config)


VALID_RESOLVE_DECISIONS = {"allow-once", "deny"}


def add_resolve_endpoint(app, approval_client):
    """Register POST /ahp/resolve on an existing FastAPI app."""
    from .server import _make_auth_dependency, _read_auth_token

    verify_auth = _make_auth_dependency(_read_auth_token())

    @app.post("/ahp/resolve")
    async def resolve_endpoint(request: _FastAPIRequest):
        from fastapi.responses import JSONResponse

        auth_result = await verify_auth(request)
        if isinstance(auth_result, Response):
            return auth_result

        if approval_client is None:
            return JSONResponse(
                {"error": "resolve not available (no OpenClaw enforcement)"},
                status_code=503,
            )

        try:
            body = await request.json()
        except Exception:
            return JSONResponse({"error": "invalid JSON body"}, status_code=400)

        approval_id = body.get("approval_id")
        decision = body.get("decision")
        reason = body.get("reason", "")

        if not approval_id or not decision:
            return JSONResponse(
                {"error": "approval_id and decision are required"},
                status_code=400,
            )
        if decision not in VALID_RESOLVE_DECISIONS:
            return JSONResponse(
                {"error": f"decision must be one of {sorted(VALID_RESOLVE_DECISIONS)}"},
                status_code=400,
            )

        try:
            await approval_client.resolve(approval_id, decision, reason=reason)
        except Exception as e:
            logger.exception("resolve failed for %s", approval_id)
            return JSONResponse(
                {"error": f"resolve failed: {e}"},
                status_code=502,
            )

        return JSONResponse({"status": "ok", "approval_id": approval_id})


def validate_stack_config(
    *,
    enforcement_enabled: bool,
    operator_token: str,
    ws_url: str,
) -> None:
    """Preflight validation for stack configuration.

    Exits with helpful error messages if configuration is invalid.
    """
    errors: list[str] = []

    if enforcement_enabled:
        if not operator_token:
            errors.append(
                "OPENCLAW_OPERATOR_TOKEN is empty but OPENCLAW_ENFORCEMENT_ENABLED=true.\n"
                "  The WS connection to OpenClaw will fail without a valid token.\n"
                "  Find your token in: ~/.openclaw/openclaw.json → gateway.auth.token\n"
                "  Set it: export OPENCLAW_OPERATOR_TOKEN=<your-token>"
            )
        if not ws_url:
            errors.append(
                "OPENCLAW_WS_URL is empty but OPENCLAW_ENFORCEMENT_ENABLED=true.\n"
                "  Set it: export OPENCLAW_WS_URL=ws://127.0.0.1:18789"
            )
        elif not ws_url.startswith(("ws://", "wss://")):
            errors.append(
                f"OPENCLAW_WS_URL must start with ws:// or wss://, got: {ws_url}\n"
                "  Example: export OPENCLAW_WS_URL=ws://127.0.0.1:18789"
            )

    if errors:
        print("\n[clawsentry] Configuration errors detected:\n", file=sys.stderr)
        for i, err in enumerate(errors, 1):
            print(f"  {i}. {err}\n", file=sys.stderr)
        sys.exit(1)


async def run_stack(args: argparse.Namespace) -> None:
    # Preflight validation for enforcement-related config
    bootstrap_cfg = OpenClawBootstrapConfig.from_env()
    openclaw_mode = _has_openclaw_config(bootstrap_cfg)

    validate_stack_config(
        enforcement_enabled=bootstrap_cfg.enforcement_enabled,
        operator_token=bootstrap_cfg.openclaw_operator_token,
        ws_url=bootstrap_cfg.openclaw_ws_url,
    )

    # Build session enforcement policy from env vars
    _enf_enabled = os.getenv("AHP_SESSION_ENFORCEMENT_ENABLED", "false").lower() in ("true", "1", "yes")
    _enf_threshold = int(os.getenv("AHP_SESSION_ENFORCEMENT_THRESHOLD", "3"))
    _enf_action_raw = os.getenv("AHP_SESSION_ENFORCEMENT_ACTION", "defer").lower()
    _enf_action_map = {
        "defer": EnforcementAction.DEFER,
        "block": EnforcementAction.BLOCK,
        "l3_require": EnforcementAction.L3_REQUIRE,
    }
    _enf_action = _enf_action_map.get(_enf_action_raw, EnforcementAction.DEFER)
    _enf_cooldown = int(os.getenv("AHP_SESSION_ENFORCEMENT_COOLDOWN_SECONDS", "600"))
    session_enforcement = SessionEnforcementPolicy(
        enabled=_enf_enabled,
        threshold=_enf_threshold,
        action=_enf_action,
        cooldown_seconds=_enf_cooldown,
    )

    # Build detection config from CS_ environment variables
    detection_config = build_detection_config_from_env()

    # Build gateway first, then configure LLM analyzer with trajectory store
    gateway = SupervisionGateway(
        trajectory_db_path=args.trajectory_db_path,
        trajectory_retention_seconds=args.trajectory_retention_seconds,
        session_enforcement=session_enforcement,
        detection_config=detection_config,
    )
    analyzer = build_analyzer_from_env(
        trajectory_store=gateway.trajectory_store,
        patterns_path=detection_config.attack_patterns_path,
    )
    if analyzer is not None:
        # Replace the default rule-only engine with one backed by the LLM analyzer.
        # This creates a fresh SessionRiskTracker; safe at startup since no events
        # have been processed yet.
        gateway.policy_engine = L1PolicyEngine(analyzer=analyzer, config=detection_config)
    gateway_app = create_http_app(gateway)

    # OpenClaw runtime + webhook only when configured
    openclaw_runtime: Optional[OpenClawRuntime] = None
    if openclaw_mode:
        openclaw_runtime = _build_openclaw_runtime(
            webhook_token=args.webhook_token,
            webhook_secret=args.webhook_secret,
            webhook_require_https=args.webhook_require_https,
            webhook_max_body_bytes=args.webhook_max_body_bytes,
            source_protocol_version=args.source_protocol_version,
            git_short_sha=args.git_short_sha,
            profile_version=args.profile_version,
            uds_path=args.uds_path,
            gateway_host=args.gateway_host,
            gateway_port=args.gateway_port,
            gateway_transport_preference=args.gateway_transport_preference,
        )
        webhook_app = create_openclaw_webhook_app(openclaw_runtime)

        if args.webhook_token == DEFAULT_WEBHOOK_TOKEN:
            logger.warning(
                "Using default OPENCLAW_WEBHOOK_TOKEN=%s. Set OPENCLAW_WEBHOOK_TOKEN in production.",
                DEFAULT_WEBHOOK_TOKEN,
            )

    # Register /ahp/resolve — proxies DEFER decisions to OpenClaw WS client
    add_resolve_endpoint(
        gateway_app,
        openclaw_runtime.approval_client if openclaw_runtime else None,
    )

    uds_server = await start_uds_server(gateway, args.uds_path)
    cleanup_task = asyncio.create_task(periodic_cleanup(gateway.idempotency_cache, interval_seconds=10.0))

    gateway_server = uvicorn.Server(
        uvicorn.Config(
            gateway_app,
            host=args.gateway_host,
            port=args.gateway_port,
            log_level="info",
            access_log=False,
        )
    )

    webhook_server: Optional[uvicorn.Server] = None
    if openclaw_mode:
        webhook_server = uvicorn.Server(
            uvicorn.Config(
                webhook_app,
                host=args.webhook_host,
                port=args.webhook_port,
                log_level="info",
                access_log=False,
            )
        )

    # Start WS event listener if enforcement is enabled
    enforcement_enabled = openclaw_runtime.config.enforcement_enabled if openclaw_runtime else False
    if enforcement_enabled:
        try:
            await openclaw_runtime.approval_client.connect()
            if openclaw_runtime.approval_client.connected:
                await openclaw_runtime.approval_client.start_listening(
                    openclaw_runtime.adapter.handle_ws_approval_event,
                )
                logger.info("OpenClaw WS enforcement listener active")
            else:
                logger.warning("OpenClaw WS connection failed; enforcement disabled for this session")
        except Exception:
            logger.exception("Failed to start OpenClaw WS enforcement listener")

    if openclaw_mode:
        logger.info(
            "Full stack starting: gateway=http://%s:%s/ahp uds=%s webhook=http://%s:%s/webhook/openclaw",
            args.gateway_host,
            args.gateway_port,
            args.uds_path,
            args.webhook_host,
            args.webhook_port,
        )
    else:
        logger.info(
            "Gateway-only starting: gateway=http://%s:%s/ahp uds=%s (no OpenClaw config detected)",
            args.gateway_host,
            args.gateway_port,
            args.uds_path,
        )

    tasks: set[asyncio.Task] = set()
    gateway_task = asyncio.create_task(gateway_server.serve())
    tasks.add(gateway_task)

    webhook_task: Optional[asyncio.Task] = None
    if webhook_server is not None:
        webhook_task = asyncio.create_task(webhook_server.serve())
        tasks.add(webhook_task)

    try:
        done, _ = await asyncio.wait(
            tasks,
            return_when=asyncio.FIRST_COMPLETED,
        )
        if done:
            logger.warning("A stack server exited; shutting down.")
    finally:
        # Stop WS listener
        if enforcement_enabled and openclaw_runtime is not None:
            try:
                await openclaw_runtime.approval_client.close()
            except Exception:
                logger.exception("Error closing OpenClaw WS client")

        gateway_server.should_exit = True
        if webhook_server is not None:
            webhook_server.should_exit = True

        gather_tasks = [gateway_task]
        if webhook_task is not None:
            gather_tasks.append(webhook_task)
        await asyncio.gather(*gather_tasks, return_exceptions=True)

        cleanup_task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await cleanup_task

        uds_server.close()
        await uds_server.wait_closed()
        if os.path.exists(args.uds_path):
            os.unlink(args.uds_path)


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(name)s] %(message)s")
    from ..cli.dotenv_loader import load_dotenv
    load_dotenv()
    parser = _build_parser()
    args = parser.parse_args()
    try:
        asyncio.run(run_stack(args))
    except KeyboardInterrupt:
        logger.info("Stack stopped by user.")


if __name__ == "__main__":
    main()
