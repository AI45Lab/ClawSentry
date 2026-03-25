"""OpenClaw runtime bootstrap helpers (P1-1 unified assembly)."""

from __future__ import annotations

from dataclasses import dataclass
import os
import time
from typing import Any, Optional

from .openclaw_adapter import OpenClawAdapter, OpenClawAdapterConfig
from .openclaw_gateway_client import OpenClawGatewayClient
from .openclaw_normalizer import OpenClawNormalizer
from .openclaw_webhook_receiver import create_webhook_app
from .openclaw_ws_client import OpenClawApprovalClient, OpenClawApprovalClientConfig
from .webhook_security import WebhookSecurityConfig

DEFAULT_WEBHOOK_TOKEN = "dev-openclaw-token"
DEFAULT_WEBHOOK_MAX_BODY_BYTES = 1_048_576
DEFAULT_WEBHOOK_REQUIRE_HTTPS = False
DEFAULT_SOURCE_PROTOCOL_VERSION = "1.0"
DEFAULT_GIT_SHORT_SHA = "dev"
DEFAULT_PROFILE_VERSION = 1
DEFAULT_GATEWAY_HTTP_HOST = "127.0.0.1"
DEFAULT_GATEWAY_HTTP_PORT = 8080
DEFAULT_GATEWAY_UDS_PATH = "/tmp/clawsentry.sock"
DEFAULT_DEFAULT_DEADLINE_MS = 100
DEFAULT_MAX_RPC_RETRIES = 1
DEFAULT_RETRY_BACKOFF_MS = 50
DEFAULT_MAX_RETRY_BUDGET = 3
DEFAULT_GATEWAY_TRANSPORT_PREFERENCE = "uds_first"


def _env_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _env_int(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        return int(raw)
    except (TypeError, ValueError):
        return default


def _normalize_transport_preference(value: str) -> str:
    normalized = value.strip().lower()
    if normalized in {"uds_first", "http_first"}:
        return normalized
    return DEFAULT_GATEWAY_TRANSPORT_PREFERENCE


@dataclass(frozen=True)
class OpenClawBootstrapConfig:
    """Single-entry configuration for OpenClaw hook + webhook runtime."""

    webhook_token: str = DEFAULT_WEBHOOK_TOKEN
    webhook_token_secondary: Optional[str] = None
    webhook_secret: Optional[str] = None
    webhook_require_https: bool = DEFAULT_WEBHOOK_REQUIRE_HTTPS
    webhook_max_body_bytes: int = DEFAULT_WEBHOOK_MAX_BODY_BYTES

    source_protocol_version: str = DEFAULT_SOURCE_PROTOCOL_VERSION
    git_short_sha: str = DEFAULT_GIT_SHORT_SHA
    profile_version: int = DEFAULT_PROFILE_VERSION

    gateway_http_url: str = f"http://{DEFAULT_GATEWAY_HTTP_HOST}:{DEFAULT_GATEWAY_HTTP_PORT}/ahp"
    gateway_uds_path: str = DEFAULT_GATEWAY_UDS_PATH
    gateway_auth_token: str = ""
    gateway_transport_preference: str = DEFAULT_GATEWAY_TRANSPORT_PREFERENCE

    default_deadline_ms: int = DEFAULT_DEFAULT_DEADLINE_MS
    max_rpc_retries: int = DEFAULT_MAX_RPC_RETRIES
    retry_backoff_ms: int = DEFAULT_RETRY_BACKOFF_MS
    max_retry_budget: int = DEFAULT_MAX_RETRY_BUDGET

    enforcement_enabled: bool = False
    openclaw_ws_url: str = "ws://127.0.0.1:18789"
    openclaw_operator_token: str = ""

    @classmethod
    def from_env(cls, **overrides: Any) -> "OpenClawBootstrapConfig":
        host = os.getenv("CS_HTTP_HOST", DEFAULT_GATEWAY_HTTP_HOST)
        port = _env_int("CS_HTTP_PORT", DEFAULT_GATEWAY_HTTP_PORT)
        default_http_url = f"http://{host}:{port}/ahp"

        base = cls(
            webhook_token=os.getenv("OPENCLAW_WEBHOOK_TOKEN", DEFAULT_WEBHOOK_TOKEN),
            webhook_token_secondary=os.getenv("OPENCLAW_WEBHOOK_TOKEN_SECONDARY") or None,
            webhook_secret=os.getenv("OPENCLAW_WEBHOOK_SECRET") or None,
            webhook_require_https=_env_bool(
                "OPENCLAW_WEBHOOK_REQUIRE_HTTPS", DEFAULT_WEBHOOK_REQUIRE_HTTPS
            ),
            webhook_max_body_bytes=_env_int(
                "OPENCLAW_WEBHOOK_MAX_BODY_BYTES", DEFAULT_WEBHOOK_MAX_BODY_BYTES
            ),
            source_protocol_version=os.getenv(
                "OPENCLAW_SOURCE_PROTOCOL_VERSION", DEFAULT_SOURCE_PROTOCOL_VERSION
            ),
            git_short_sha=os.getenv("OPENCLAW_MAPPING_GIT_SHA", DEFAULT_GIT_SHORT_SHA),
            profile_version=_env_int(
                "OPENCLAW_MAPPING_PROFILE_VERSION", DEFAULT_PROFILE_VERSION
            ),
            gateway_http_url=os.getenv("AHP_HTTP_URL", default_http_url),
            gateway_uds_path=os.getenv("CS_UDS_PATH", DEFAULT_GATEWAY_UDS_PATH),
            gateway_auth_token=os.getenv("CS_AUTH_TOKEN", ""),
            gateway_transport_preference=_normalize_transport_preference(
                os.getenv(
                    "OPENCLAW_GATEWAY_TRANSPORT_PREFERENCE",
                    DEFAULT_GATEWAY_TRANSPORT_PREFERENCE,
                )
            ),
            default_deadline_ms=_env_int(
                "OPENCLAW_GATEWAY_DEFAULT_DEADLINE_MS", DEFAULT_DEFAULT_DEADLINE_MS
            ),
            max_rpc_retries=_env_int(
                "OPENCLAW_GATEWAY_MAX_RPC_RETRIES", DEFAULT_MAX_RPC_RETRIES
            ),
            retry_backoff_ms=_env_int(
                "OPENCLAW_GATEWAY_RETRY_BACKOFF_MS", DEFAULT_RETRY_BACKOFF_MS
            ),
            max_retry_budget=_env_int(
                "OPENCLAW_MAX_RETRY_BUDGET", DEFAULT_MAX_RETRY_BUDGET
            ),
            enforcement_enabled=_env_bool(
                "OPENCLAW_ENFORCEMENT_ENABLED", False
            ),
            openclaw_ws_url=os.getenv(
                "OPENCLAW_WS_URL", "ws://127.0.0.1:18789"
            ),
            openclaw_operator_token=os.getenv(
                "OPENCLAW_OPERATOR_TOKEN", ""
            ),
        )

        if not overrides:
            return base

        data = base.__dict__.copy()
        for key, value in overrides.items():
            if value is None:
                continue
            if key not in data:
                raise TypeError(f"Unknown OpenClawBootstrapConfig field: {key}")
            data[key] = value
        return cls(**data)


@dataclass
class OpenClawRuntime:
    """Built OpenClaw runtime components from one config source."""

    config: OpenClawBootstrapConfig
    adapter_config: OpenClawAdapterConfig
    webhook_security: WebhookSecurityConfig
    normalizer: OpenClawNormalizer
    gateway_client: OpenClawGatewayClient
    adapter: OpenClawAdapter
    approval_client: OpenClawApprovalClient


def build_openclaw_runtime(config: OpenClawBootstrapConfig) -> OpenClawRuntime:
    """Build adapter + webhook shared components from one config object."""
    adapter_config = OpenClawAdapterConfig(
        source_protocol_version=config.source_protocol_version,
        git_short_sha=config.git_short_sha,
        profile_version=config.profile_version,
        webhook_token=config.webhook_token,
        webhook_secret=config.webhook_secret,
        require_https=config.webhook_require_https,
        max_retry_budget=config.max_retry_budget,
        gateway_http_url=config.gateway_http_url,
        gateway_uds_path=config.gateway_uds_path,
    )

    # Parse IP whitelist from env
    ip_whitelist_raw = os.getenv("AHP_WEBHOOK_IP_WHITELIST", "").strip()
    ip_whitelist: list[str] | None = None
    if ip_whitelist_raw:
        ip_whitelist = [ip.strip() for ip in ip_whitelist_raw.split(",") if ip.strip()]

    token_ttl = int(os.getenv("AHP_WEBHOOK_TOKEN_TTL_SECONDS", "86400"))

    webhook_security = WebhookSecurityConfig(
        primary_token=config.webhook_token,
        secondary_token=config.webhook_token_secondary,
        webhook_secret=config.webhook_secret,
        require_https=config.webhook_require_https,
        max_body_bytes=config.webhook_max_body_bytes,
        ip_whitelist=ip_whitelist,
        token_ttl_seconds=token_ttl,
        token_issued_at=time.time(),
    )

    normalizer = OpenClawNormalizer(
        source_protocol_version=config.source_protocol_version,
        git_short_sha=config.git_short_sha,
        profile_version=config.profile_version,
    )

    gateway_client = OpenClawGatewayClient(
        http_url=config.gateway_http_url,
        uds_path=config.gateway_uds_path,
        default_deadline_ms=config.default_deadline_ms,
        max_rpc_retries=config.max_rpc_retries,
        retry_backoff_ms=config.retry_backoff_ms,
        auth_token=config.gateway_auth_token,
        transport_preference=config.gateway_transport_preference,
    )

    approval_client_config = OpenClawApprovalClientConfig(
        ws_url=config.openclaw_ws_url,
        operator_token=config.openclaw_operator_token,
        enabled=config.enforcement_enabled,
    )
    approval_client = OpenClawApprovalClient(approval_client_config)

    adapter = OpenClawAdapter(
        config=adapter_config,
        gateway_client=gateway_client,
        approval_client=approval_client,
    )

    return OpenClawRuntime(
        config=config,
        adapter_config=adapter_config,
        webhook_security=webhook_security,
        normalizer=normalizer,
        gateway_client=gateway_client,
        adapter=adapter,
        approval_client=approval_client,
    )


def build_openclaw_runtime_from_env(**overrides: Any) -> OpenClawRuntime:
    """Build runtime from env vars, with optional explicit overrides."""
    config = OpenClawBootstrapConfig.from_env(**overrides)
    return build_openclaw_runtime(config)


def create_openclaw_webhook_app(
    runtime: OpenClawRuntime,
    *,
    idem_max_size: int = 10_000,
    idem_ttl_seconds: int = 300,
) -> Any:
    """Create webhook app using runtime-built security/normalizer/client."""
    return create_webhook_app(
        runtime.webhook_security,
        runtime.normalizer,
        runtime.gateway_client,
        idem_max_size=idem_max_size,
        idem_ttl_seconds=idem_ttl_seconds,
    )
