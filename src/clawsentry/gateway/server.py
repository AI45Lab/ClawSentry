"""
AHP Supervision Gateway — UDS + HTTP dual-transport server.

Design basis:
  - 01-scope-and-architecture.md section 6 (Sidecar + UDS + HTTP)
  - 04-policy-decision-and-fallback.md section 8-11 (SyncDecision v1 / JSON-RPC 2.0)

Transports:
  - Primary: Unix Domain Socket at /tmp/clawsentry.sock
  - Backup: HTTP at localhost:8080
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import argparse
import logging
import os
import struct
import sys
import time
from typing import Any, Optional

from pathlib import Path
import uuid
import uvicorn
from fastapi import FastAPI, Request, Response
from fastapi.responses import StreamingResponse
from starlette.responses import FileResponse, HTMLResponse
from pydantic import ValidationError

from .alert_registry import AlertRegistry
from .anti_bypass_guard import AntiBypassGuard, AntiBypassMatch
from .event_bus import EventBus
from .idempotency import IdempotencyCache, periodic_cleanup
from .session_registry import (
    DISPLAY_SCORE_RANGE,
    DISPLAY_SCORE_SEMANTICS,
    POST_ACTION_SCORE_SEMANTICS,
    SessionRegistry,
    build_compatibility_evidence_summary,
)
from .trajectory_store import (
    TrajectoryStore,
    _parse_iso_timestamp,
    DEFAULT_TRAJECTORY_DB_PATH,
    DEFAULT_TRAJECTORY_RETENTION_SECONDS,
    HIGH_RISK_LEVELS,
    MAX_WINDOW_SECONDS,
)
from .models import (
    AdapterEffectResult,
    CanonicalDecision,
    CanonicalEvent,
    DecisionContext,
    DecisionEffects,
    DecisionSource,
    DecisionTier,
    DecisionVerdict,
    EventType,
    FailureClass,
    RiskLevel,
    RPCErrorCode,
    RPC_VERSION,
    SyncDecisionErrorResponse,
    SyncDecisionRequest,
    SyncDecisionResponse,
    SessionEffectRequest,
    SessionScopeProfile,
    adapter_effect_result_summary,
    decision_effect_summary,
    decision_effects_for_trajectory,
    utc_now_iso,
)

from .defer_manager import DeferManager
from .detection_config import (
    DetectionConfig,
    build_detection_config_from_env,
    build_detection_config_with_preset,
)
from .llm_factory import build_analyzer_from_env
from .l3_runtime import build_l3_runtime_info
from .pattern_evolution import PatternEvolutionManager
from .policy_engine import L1PolicyEngine
from .post_action_analyzer import PostActionAnalyzer
from .session_scope import evaluate_session_scope, scope_protection_statement
from .metrics import LLMBudgetTracker, MetricsCollector
from .trajectory_analyzer import TrajectoryAnalyzer
from .session_enforcement import (
    EnforcementAction,
    SessionEnforcementPolicy,
)
from .enterprise import (
    build_enterprise_event_async,
    build_enterprise_live_snapshot_cached_async,
    enterprise_mode_enabled,
    enrich_alerts_payload_async,
    enrich_health_payload_async,
    enrich_replay_payload_async,
    enrich_session_risk_payload_async,
    enrich_sessions_payload_async,
    enrich_summary_payload_async,
)

logger = logging.getLogger("clawsentry")

_DEFAULT_UI_DIR = Path(__file__).parent.parent / "ui" / "dist"
DEFAULT_L3_ADVISORY_RUNNER = "llm_provider"
PUBLIC_L3_ADVISORY_RUNNERS = {"deterministic_local", DEFAULT_L3_ADVISORY_RUNNER}


def _validate_public_l3_advisory_runner(runner: str) -> None:
    if runner not in PUBLIC_L3_ADVISORY_RUNNERS:
        raise ValueError(
            "runner must be one of: "
            f"{', '.join(sorted(PUBLIC_L3_ADVISORY_RUNNERS))}; "
            "fake_llm is reserved for internal tests"
        )

# ---------------------------------------------------------------------------
# Shared risk-level helpers
# ---------------------------------------------------------------------------

_RISK_LEVEL_RANK: dict[str, int] = {"low": 0, "medium": 1, "high": 2, "critical": 3}

def _risk_rank(risk_level: Optional[str]) -> int:
    return _RISK_LEVEL_RANK.get(str(risk_level or "low").lower(), 0)


def _risk_points(risk_level: Any) -> int:
    """Return the display/L3-explainability ordinal for a risk level."""
    return _risk_rank(str(risk_level or "low"))


def _float_or_zero(value: Any) -> float:
    try:
        return float(value or 0.0)
    except (TypeError, ValueError):
        return 0.0


def _risk_velocity_from_scores(scores: list[float]) -> str:
    """Return a compact trend label for a session risk score series."""
    if len(scores) < 2:
        return "unknown"
    delta = scores[-1] - scores[0]
    if delta > 0.25:
        return "up"
    if delta < -0.25:
        return "down"
    return "flat"


def _build_window_risk_summary(
    timeline: list[dict[str, Any]],
    *,
    window_seconds: Optional[int],
    generated_at: Optional[str] = None,
) -> dict[str, Any]:
    """Build API display metrics from a session timeline.

    This reporting helper is intentionally read-only.  It never feeds the
    policy engine, and it treats legacy ``cumulative_score`` separately from
    window-aware fields.
    """
    scores = [_float_or_zero(item.get("composite_score")) for item in timeline]
    risk_points = [_risk_points(item.get("risk_level")) for item in timeline]
    high_or_critical = sum(1 for item in timeline if _risk_rank(item.get("risk_level")) >= _risk_rank("high"))
    latest_score = scores[-1] if scores else 0.0

    if scores:
        alpha = 0.3
        ewma = scores[0]
        for score in scores[1:]:
            ewma = (alpha * score) + ((1.0 - alpha) * ewma)
    else:
        ewma = 0.0

    return {
        "window_seconds": window_seconds,
        "generated_at": generated_at or utc_now_iso(),
        "event_count": len(timeline),
        "latest_composite_score": latest_score,
        "session_risk_sum": round(sum(scores), 4),
        "session_risk_ewma": round(ewma, 4),
        "risk_points_sum": int(sum(risk_points)),
        "risk_velocity": _risk_velocity_from_scores(scores),
        "high_or_critical_count": high_or_critical,
        "score_range": list(DISPLAY_SCORE_RANGE),
        "score_semantics": dict(DISPLAY_SCORE_SEMANTICS),
        "decision_affecting": False,
    }


def _build_system_security_posture(
    summary: dict[str, Any],
    *,
    window_seconds: Optional[int],
    generated_at: str,
) -> dict[str, Any]:
    """Build a display-only 0-100 system posture from reporting summary data."""
    by_risk = summary.get("by_risk_level") if isinstance(summary.get("by_risk_level"), dict) else {}
    critical_sessions = int(by_risk.get("critical") or 0)
    high_sessions = int(by_risk.get("high") or 0)
    high_trend = summary.get("high_risk_trend") if isinstance(summary.get("high_risk_trend"), dict) else {}
    trend_windows = high_trend.get("windows") if isinstance(high_trend.get("windows"), dict) else {}
    trend_15m = trend_windows.get("15m") if isinstance(trend_windows.get("15m"), dict) else {}
    high_ratio_15m = _float_or_zero(trend_15m.get("ratio"))
    invalid_event = summary.get("invalid_event") if isinstance(summary.get("invalid_event"), dict) else {}
    invalid_rate_15m = _float_or_zero(invalid_event.get("rate_15m"))

    risk_exposure = min(
        100.0,
        (20.0 * critical_sessions)
        + (10.0 * high_sessions)
        + (25.0 * high_ratio_15m)
        + (15.0 * invalid_rate_15m),
    )
    score = max(0.0, 100.0 - risk_exposure)
    if score < 50:
        level = "critical"
    elif score < 75:
        level = "elevated"
    elif score < 90:
        level = "watch"
    else:
        level = "healthy"

    driver_candidates = [
        {
            "key": "critical_sessions",
            "label": "Critical sessions",
            "value": critical_sessions,
            "impact": 20.0 * critical_sessions,
        },
        {
            "key": "high_sessions",
            "label": "High-risk sessions",
            "value": high_sessions,
            "impact": 10.0 * high_sessions,
        },
        {
            "key": "high_risk_ratio_15m",
            "label": "15m high-risk ratio",
            "value": round(high_ratio_15m, 4),
            "impact": 25.0 * high_ratio_15m,
        },
        {
            "key": "invalid_event_rate_15m",
            "label": "15m invalid-event rate",
            "value": round(invalid_rate_15m, 4),
            "impact": 15.0 * invalid_rate_15m,
        },
    ]
    drivers = [
        {k: v for k, v in item.items() if k != "impact"}
        for item in sorted(driver_candidates, key=lambda item: item["impact"], reverse=True)
        if item["impact"] > 0
    ][:3]

    return {
        "score_0_100": round(score, 1),
        "level": level,
        "drivers": drivers,
        "window_seconds": window_seconds or 3600,
        "generated_at": generated_at,
        "decision_affecting": False,
    }


def _build_decision_path_io_pressure(io_snapshot: dict[str, Any]) -> dict[str, Any]:
    reporting = io_snapshot.get("reporting") if isinstance(io_snapshot.get("reporting"), dict) else {}
    record_path = io_snapshot.get("record_path") if isinstance(io_snapshot.get("record_path"), dict) else {}
    max_reporting_seconds = 0.0
    for item in reporting.values():
        if isinstance(item, dict):
            max_reporting_seconds = max(max_reporting_seconds, _float_or_zero(item.get("max_seconds")))
    max_record_seconds = _float_or_zero(record_path.get("max_seconds"))
    max_seconds = max(max_reporting_seconds, max_record_seconds)
    if max_seconds >= 1.0:
        level = "critical"
    elif max_seconds >= 0.25:
        level = "elevated"
    elif max_seconds >= 0.05:
        level = "watch"
    else:
        level = "healthy"
    return {
        "level": level,
        "max_seconds": round(max_seconds, 6),
        "max_reporting_seconds": round(max_reporting_seconds, 6),
        "max_record_path_seconds": round(max_record_seconds, 6),
        "decision_affecting": False,
    }


def _compact_l3_evidence_summary(l3_trace: dict[str, Any] | None) -> dict[str, Any] | None:
    """Return a compact operator-facing evidence summary from an L3 trace."""
    if not isinstance(l3_trace, dict):
        return None

    evidence_summary = l3_trace.get("evidence_summary")
    if not isinstance(evidence_summary, dict):
        return None

    summary: dict[str, Any] = {}

    retained_sources = evidence_summary.get("retained_sources")
    if isinstance(retained_sources, list):
        compact_sources = [
            str(source).strip()
            for source in retained_sources
            if str(source).strip()
        ]
        if compact_sources:
            summary["retained_sources"] = compact_sources

    tool_calls = evidence_summary.get("tool_calls")
    if isinstance(tool_calls, list):
        summary["tool_calls_count"] = len(tool_calls)
    else:
        tool_calls_count = evidence_summary.get("tool_calls_count")
        if isinstance(tool_calls_count, int):
            summary["tool_calls_count"] = tool_calls_count

    toolkit_budget_mode = str(evidence_summary.get("toolkit_budget_mode") or "").strip()
    if toolkit_budget_mode:
        summary["toolkit_budget_mode"] = toolkit_budget_mode

    toolkit_budget_cap = evidence_summary.get("toolkit_budget_cap")
    if isinstance(toolkit_budget_cap, int):
        summary["toolkit_budget_cap"] = toolkit_budget_cap

    toolkit_calls_remaining = evidence_summary.get("toolkit_calls_remaining")
    if isinstance(toolkit_calls_remaining, int):
        summary["toolkit_calls_remaining"] = toolkit_calls_remaining
    toolkit_budget_exhausted = evidence_summary.get("toolkit_budget_exhausted")
    if isinstance(toolkit_budget_exhausted, bool):
        summary["toolkit_budget_exhausted"] = toolkit_budget_exhausted
    elif isinstance(toolkit_budget_cap, int) and toolkit_budget_cap > 0 and isinstance(toolkit_calls_remaining, int):
        summary["toolkit_budget_exhausted"] = toolkit_calls_remaining <= 0

    return summary or None


def _copy_budget_event(budget_event: dict[str, Any] | None) -> dict[str, Any] | None:
    """Return a copy of a budget exhaustion event payload."""
    if not isinstance(budget_event, dict):
        return None
    copied = dict(budget_event)
    budget = copied.get("budget")
    if isinstance(budget, dict):
        copied["budget"] = dict(budget)
    return copied or None


def _copy_l3_narrative_fields(review: dict[str, Any]) -> dict[str, Any]:
    copied: dict[str, Any] = {}
    for key in ("analysis_summary", "analysis_points", "operator_next_steps"):
        if key in review:
            copied[key] = review[key]
    return copied


def _new_io_metric_bucket() -> dict[str, float | int]:
    return {
        "calls": 0,
        "total_seconds": 0.0,
        "last_seconds": 0.0,
        "max_seconds": 0.0,
    }


def _observe_io_metric(bucket: dict[str, float | int], elapsed_seconds: float) -> None:
    elapsed = max(0.0, float(elapsed_seconds))
    bucket["calls"] = int(bucket["calls"]) + 1
    bucket["total_seconds"] = float(bucket["total_seconds"]) + elapsed
    bucket["last_seconds"] = elapsed
    bucket["max_seconds"] = max(float(bucket["max_seconds"]), elapsed)


def _snapshot_io_metric(bucket: dict[str, float | int]) -> dict[str, float | int]:
    return {
        "calls": int(bucket["calls"]),
        "total_seconds": round(float(bucket["total_seconds"]), 6),
        "last_seconds": round(float(bucket["last_seconds"]), 6),
        "max_seconds": round(float(bucket["max_seconds"]), 6),
    }


def _load_default_session_scope_profile() -> SessionScopeProfile | None:
    """Load the optional default scope profile applied to incoming requests."""

    raw_path = (
        os.getenv("CS_SESSION_SCOPE_PROFILE_FILE")
        or os.getenv("CS_SESSION_SCOPE_PROFILE")
        or ""
    ).strip()
    if not raw_path:
        return None
    path = Path(raw_path).expanduser()
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        return SessionScopeProfile.model_validate(payload)
    except Exception as exc:  # noqa: BLE001 - startup-time config surface
        raise RuntimeError(
            f"Failed to load CS_SESSION_SCOPE_PROFILE_FILE={path}: {exc}"
        ) from exc


def _risk_level_from_string(risk_level: str) -> RiskLevel:
    try:
        return RiskLevel(str(risk_level or "high").lower())
    except ValueError:
        return RiskLevel.HIGH


def _enforcement_action_from_config(action: str) -> EnforcementAction:
    if action == "block":
        return EnforcementAction.BLOCK
    if action == "defer":
        return EnforcementAction.DEFER
    return EnforcementAction.DEFER


def _analyzer_supports_l3(analyzer: Any) -> bool:
    """Return True when analyzer tree includes an L3-capable analyzer."""
    if analyzer is None:
        return False
    analyzer_id = str(getattr(analyzer, "analyzer_id", "") or "")
    if analyzer_id == "agent-reviewer":
        return True
    for child in getattr(analyzer, "_analyzers", []) or []:
        if _analyzer_supports_l3(child):
            return True
    return False


def _effective_requested_tier_for_l3_config(
    requested_tier: DecisionTier,
    config: DetectionConfig,
    analyzer: Any,
) -> DecisionTier:
    if (
        requested_tier == DecisionTier.L2
        and config.l3_routing_mode == "replace_l2"
        and _analyzer_supports_l3(analyzer)
    ):
        return DecisionTier.L3
    return requested_tier

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

DEFAULT_UDS_PATH = "/tmp/clawsentry.sock"
DEFAULT_HTTP_HOST = "127.0.0.1"
DEFAULT_HTTP_PORT = 8080

JSONRPC_METHOD = "ahp/sync_decision"
JSONRPC_VERSION = "2.0"


def _extract_project_config(
    payload: Optional[dict[str, Any]],
) -> tuple[Optional[str], dict[str, Any]]:
    """Extract project preset/overrides from event payload metadata.

    Returns ``(preset_name, overrides)`` where *preset_name* is ``None``
    when no project preset is specified.
    """
    if not payload or not isinstance(payload, dict):
        return None, {}
    meta = payload.get("_clawsentry_meta")
    if not isinstance(meta, dict):
        return None, {}
    preset = meta.get("project_preset")
    overrides = meta.get("project_overrides", {})
    if not isinstance(overrides, dict):
        overrides = {}
    return preset, overrides


_ADAPTER_SOURCE_FRAMEWORK_MAP: dict[str, str] = {
    "a3s-http": "a3s-code",
    "a3s-uds": "a3s-code",
    "a3s-harness": "a3s-code",
    "a3s-adapter.v1": "a3s-code",
    "a3s-http-adapter.v1": "a3s-code",
    "codex-http": "codex",
    "codex-adapter.v1": "codex",
    "openclaw": "openclaw",
    "openclaw-adapter.v1": "openclaw",
    "claude-code": "claude-code",
    "claude-code-adapter.v1": "claude-code",
}


def _infer_source_framework(
    source_framework: str | None,
    caller_adapter: str | None,
) -> str:
    """Infer framework from caller_adapter when source framework is missing."""
    explicit = str(source_framework or "").strip()
    if explicit and explicit.lower() != "unknown":
        return explicit

    adapter = str(caller_adapter or "").strip().lower()
    inferred = _ADAPTER_SOURCE_FRAMEWORK_MAP.get(adapter, "")
    if inferred:
        return inferred

    return "unknown"


def _extract_compat_event_fields(
    event: dict[str, Any],
) -> tuple[Optional[str], Optional[dict[str, Any]]]:
    payload = event.get("payload")
    if not isinstance(payload, dict):
        return None, None

    meta = payload.get("_clawsentry_meta")
    if not isinstance(meta, dict):
        return None, None

    compat_event_type: Optional[str] = None
    ahp_compat = meta.get("ahp_compat")
    if isinstance(ahp_compat, dict):
        raw_event_type = str(ahp_compat.get("raw_event_type") or "").strip()
        canonical_event_type = str(event.get("event_type") or "").strip()
        if raw_event_type and raw_event_type != canonical_event_type:
            compat_event_type = raw_event_type

    compat_observation = meta.get("compat_observation")
    if isinstance(compat_observation, dict):
        compat_observation = dict(compat_observation)
    else:
        compat_observation = None

    return compat_event_type, compat_observation


_APPROVAL_PENDING_REASON_CODE = "approval_pending"
_APPROVAL_ALLOWED_REASON_CODE = "approval_allowed"
_APPROVAL_DENIED_REASON_CODE = "approval_denied"
_APPROVAL_TIMEOUT_REASON_CODE = "approval_timeout"
_APPROVAL_NO_ROUTE_REASON_CODE = "approval_no_route"
_APPROVAL_QUEUE_FULL_REASON_CODE = "approval_queue_full"


def _is_confirmation_fast_lane(
    event: dict[str, Any],
    compat_event_type: Optional[str],
) -> bool:
    if str(compat_event_type or "").strip().lower() == "confirmation":
        return True
    return str(event.get("event_subtype") or "").strip().lower() == "compat:confirmation"


def _resolve_confirmation_approval_id(event: dict[str, Any]) -> str:
    explicit = str(event.get("approval_id") or "").strip()
    if explicit:
        return explicit

    payload = event.get("payload")
    if isinstance(payload, dict):
        payload_explicit = str(payload.get("approval_id") or "").strip()
        if payload_explicit:
            return payload_explicit
        meta = payload.get("_clawsentry_meta")
        if isinstance(meta, dict):
            compat_meta = meta.get("ahp_compat")
            if isinstance(compat_meta, dict):
                identity = compat_meta.get("identity")
                if isinstance(identity, dict):
                    compat_explicit = str(identity.get("approval_id") or "").strip()
                    if compat_explicit:
                        return compat_explicit

    event_id = str(event.get("event_id") or "").strip()
    if event_id:
        return f"bridge-confirm-{event_id}"
    return f"bridge-confirm-{uuid.uuid4().hex[:12]}"


def _approval_pending_meta(
    *,
    approval_id: str,
    approval_kind: str,
    approval_reason: str,
    approval_timeout_s: float,
) -> dict[str, Any]:
    return {
        "approval_id": approval_id,
        "approval_kind": approval_kind,
        "approval_state": "pending",
        "approval_reason": approval_reason,
        "approval_reason_code": _APPROVAL_PENDING_REASON_CODE,
        "approval_timeout_s": approval_timeout_s,
    }


def _approval_resolution_meta(
    *,
    approval_id: str,
    approval_kind: str,
    approval_state: str,
    approval_reason: str,
    approval_reason_code: str,
    approval_timeout_s: float,
) -> dict[str, Any]:
    return {
        "approval_id": approval_id,
        "approval_kind": approval_kind,
        "approval_state": approval_state,
        "approval_reason": approval_reason,
        "approval_reason_code": approval_reason_code,
        "approval_timeout_s": approval_timeout_s,
    }


def _payload_hash(payload: Any) -> str:
    encoded = json.dumps(payload, sort_keys=True, default=str).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def _redacted_preview(value: Any, *, max_len: int = 96) -> str:
    if isinstance(value, dict):
        for key in ("command", "input", "tool_input"):
            if key in value:
                value = value[key]
                break
    text = str(value or "").replace("\n", " ").strip()
    for marker in ("token=", "password=", "secret=", "api_key="):
        lower = text.lower()
        idx = lower.find(marker)
        if idx >= 0:
            end = text.find(" ", idx)
            if end < 0:
                end = len(text)
            text = text[: idx + len(marker)] + "…" + text[end:]
    if len(text) > max_len:
        return text[: max_len - 1] + "…"
    return text


def _validate_rewrite_resolution_payload(payload: Any) -> dict[str, Any]:
    """Validate operator rewrite payloads before producing MODIFY decisions."""

    if not isinstance(payload, dict) or not payload:
        raise ValueError("rewrite resolution payload must contain command or tool_input")
    if "prompt" in payload:
        raise ValueError("prompt rewrite is out of scope for decision_effects.v1")

    command = payload.get("command")
    if command is not None:
        command_text = str(command).strip()
        if not command_text:
            raise ValueError("rewrite command must be non-empty")
        return {"command": command_text}

    tool_input = payload.get("tool_input")
    if isinstance(tool_input, dict) and tool_input:
        if "prompt" in tool_input:
            raise ValueError("prompt rewrite is out of scope for decision_effects.v1")
        validated: dict[str, Any] = {"tool_input": dict(tool_input)}
        tool_name = payload.get("tool_name") or payload.get("tool")
        if tool_name is not None:
            validated["tool_name"] = str(tool_name)
        return validated

    raise ValueError("rewrite resolution payload must contain command or tool_input")


def _rewrite_effect_for_resolution(
    *,
    approval_id: str,
    event: dict[str, Any],
    replacement_payload: dict[str, Any],
    resolver_identity: str | None,
    policy_id: str,
) -> DecisionEffects:
    original_payload = event.get("payload") if isinstance(event.get("payload"), dict) else {}
    original_command = original_payload.get("command") or original_payload.get("arguments") or original_payload
    validated_payload = _validate_rewrite_resolution_payload(replacement_payload)
    target = "command" if "command" in validated_payload else "tool_input"
    return DecisionEffects(
        effect_id=f"eff-{approval_id}-rewrite",
        action_scope="action",
        rewrite_effect={
            "requested": True,
            "target": target,
            "approval_id": approval_id,
            "original_hash": _payload_hash(original_command),
            "original_preview_redacted": _redacted_preview(original_command),
            "replacement_hash": _payload_hash(validated_payload),
            "replacement_preview_redacted": _redacted_preview(validated_payload),
            "replacement_payload": dict(validated_payload),
            "redaction_policy_version": "cs.redaction.v1",
            "rewrite_source": "operator" if resolver_identity else "system",
            "policy_id": policy_id,
            "post_rewrite_validation_id": f"validation-{approval_id}",
        },
    )

# ---------------------------------------------------------------------------
# Authentication
# ---------------------------------------------------------------------------

def _read_auth_token() -> str:
    """Read auth token from environment. Empty string means auth disabled."""
    return os.getenv("CS_AUTH_TOKEN", "")


def _make_auth_dependency(auth_token: str):
    """Create a FastAPI dependency that enforces Bearer token auth.

    When auth_token is empty, returns a no-op dependency (auth disabled).
    """
    if not auth_token:
        async def _no_auth(request: Request):  # noqa: ARG001
            pass
        return _no_auth

    async def _require_bearer(request: Request):
        # 1. Try Authorization: Bearer header first
        auth_header = request.headers.get("authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header[7:]  # len("Bearer ") == 7
            if hmac.compare_digest(token, auth_token):
                return None  # Authorized via header

        # 2. Fallback: try ?token= query param (for browser EventSource)
        query_token = request.query_params.get("token", "")
        if query_token and hmac.compare_digest(query_token, auth_token):
            return None  # Authorized via query param

        # 3. Both methods failed — reject
        return Response(
            content=json.dumps({"error": "Unauthorized"}),
            status_code=401,
            media_type="application/json",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return _require_bearer


# TrajectoryStore, SessionRegistry, EventBus, AlertRegistry are in separate modules.
# Imported above from .trajectory_store, .session_registry, .event_bus, .alert_registry

# ---------------------------------------------------------------------------
# Gateway Core
# ---------------------------------------------------------------------------

class SupervisionGateway:
    """
    Core gateway logic shared between UDS and HTTP transports.

    Handles JSON-RPC 2.0 dispatch, SyncDecision v1 processing,
    idempotency, and trajectory recording.
    """

    def __init__(
        self,
        trajectory_db_path: Optional[str] = None,
        trajectory_retention_seconds: int = DEFAULT_TRAJECTORY_RETENTION_SECONDS,
        trajectory_store: Optional[TrajectoryStore] = None,
        analyzer=None,
        session_enforcement: Optional[SessionEnforcementPolicy] = None,
        detection_config: Optional[DetectionConfig] = None,
    ) -> None:
        self._detection_config = detection_config if detection_config is not None else DetectionConfig()
        self.policy_engine = L1PolicyEngine(analyzer=analyzer, config=self._detection_config)
        self.idempotency_cache = IdempotencyCache()
        effective_db_path = trajectory_db_path
        if effective_db_path is None:
            effective_db_path = os.getenv("CS_TRAJECTORY_DB_PATH", ":memory:")
        self.trajectory_store = trajectory_store or TrajectoryStore(
            db_path=effective_db_path,
            retention_seconds=trajectory_retention_seconds,
        )
        self.session_registry = SessionRegistry()
        self.event_bus = EventBus()
        self.alert_registry = AlertRegistry()
        self.session_enforcement = session_enforcement or SessionEnforcementPolicy()
        self.anti_bypass_guard = AntiBypassGuard()
        self.default_session_scope_profile = _load_default_session_scope_profile()
        self.post_action_analyzer = PostActionAnalyzer(
            whitelist_patterns=self._detection_config.post_action_whitelist,
            tier_emergency=self._detection_config.post_action_emergency,
            tier_escalate=self._detection_config.post_action_escalate,
            tier_monitor=self._detection_config.post_action_monitor,
        )
        self.trajectory_analyzer = TrajectoryAnalyzer(
            max_events_per_session=self._detection_config.trajectory_max_events,
            max_sessions=self._detection_config.trajectory_max_sessions,
        )
        # E-9: DEFER timeout manager
        self.defer_manager = DeferManager(
            timeout_action=self._detection_config.defer_timeout_action,
            timeout_s=self._detection_config.defer_timeout_s,
            max_pending=self._detection_config.defer_max_pending,
        )
        # E-5: Self-evolving pattern repository
        self.evolution_manager = PatternEvolutionManager(
            store_path=self._detection_config.evolved_patterns_path or "",
            enabled=self._detection_config.evolving_enabled,
        )
        # P3: LLM daily budget tracker
        self.budget_tracker = LLMBudgetTracker(
            daily_budget_usd=self._detection_config.llm_daily_budget_usd,
            enabled=self._detection_config.llm_token_budget_enabled,
            limit_tokens=self._detection_config.llm_daily_token_budget,
            scope=self._detection_config.llm_token_budget_scope,
            source="config",
        )
        self._budget_exhaustion_event: dict[str, Any] | None = None
        # P3: Prometheus metrics collector
        _metrics_enabled = os.getenv("CS_METRICS_ENABLED", "true").lower() not in ("0", "false", "no")
        self.metrics = MetricsCollector(
            enabled=_metrics_enabled,
            budget_tracker=self.budget_tracker,
            budget_exhausted_callback=self._handle_budget_exhausted,
        )
        self._io_metrics = {
            "record_path": {
                "calls": 0,
                "total_seconds": 0.0,
                "last_seconds": 0.0,
                "max_seconds": 0.0,
                "trajectory_store": _new_io_metric_bucket(),
                "session_registry": _new_io_metric_bucket(),
            },
            "reporting": {
                "health": _new_io_metric_bucket(),
                "report_summary": _new_io_metric_bucket(),
                "report_sessions": _new_io_metric_bucket(),
                "report_session_risk": _new_io_metric_bucket(),
                "report_session_post_action": _new_io_metric_bucket(),
                "replay_session": _new_io_metric_bucket(),
                "replay_session_page": _new_io_metric_bucket(),
                "report_alerts": _new_io_metric_bucket(),
            },
        }
        self._start_time = time.monotonic()
        self._ready = True

    def _handle_budget_exhausted(self, event: dict[str, Any]) -> None:
        """Store and broadcast the first budget exhaustion transition for the day."""
        normalized_event = dict(event)
        budget = normalized_event.get("budget")
        if isinstance(budget, dict):
            normalized_event["budget"] = dict(budget)
        self._budget_exhaustion_event = normalized_event
        self.event_bus.broadcast(normalized_event)

    def _budget_state(self) -> dict[str, Any]:
        """Return the current budget-governance state for reporting surfaces."""
        budget = self.budget_tracker.snapshot()
        if not budget.get("exhausted", False):
            self._budget_exhaustion_event = None
        return {
            "budget": budget,
            "budget_exhaustion_event": _copy_budget_event(self._budget_exhaustion_event),
        }

    def _reporting_state(self) -> dict[str, Any]:
        """Shared reporting envelope for gateway-owned surfaces."""
        payload = self._budget_state()
        payload["llm_usage_snapshot"] = self.metrics.llm_usage_snapshot()
        return payload

    def _reporting_io_state(self) -> dict[str, Any]:
        """Shared I/O envelope; call after observing the current endpoint."""
        return {"decision_path_io": self._decision_path_io_snapshot()}

    def _observe_record_path_io(
        self,
        *,
        elapsed_seconds: float,
        trajectory_store_seconds: float,
        session_registry_seconds: float,
    ) -> None:
        record_bucket = self._io_metrics["record_path"]
        _observe_io_metric(record_bucket, elapsed_seconds)
        _observe_io_metric(record_bucket["trajectory_store"], trajectory_store_seconds)
        _observe_io_metric(record_bucket["session_registry"], session_registry_seconds)

    def _observe_reporting_io(self, report_name: str, elapsed_seconds: float) -> None:
        _observe_io_metric(self._io_metrics["reporting"][report_name], elapsed_seconds)

    def _decision_path_io_snapshot(self) -> dict[str, Any]:
        record_bucket = self._io_metrics["record_path"]
        reporting_bucket = self._io_metrics["reporting"]
        trajectory_store_io = self.trajectory_store.io_metrics_snapshot()
        session_registry_io = self.session_registry.io_metrics_snapshot()
        alert_registry_io = self.alert_registry.io_metrics_snapshot()
        return {
            "record_path": {
                **_snapshot_io_metric(record_bucket),
                "trajectory_store": _snapshot_io_metric(record_bucket["trajectory_store"]),
                "session_registry": _snapshot_io_metric(record_bucket["session_registry"]),
            },
            "reporting": {
                "health": {
                    **_snapshot_io_metric(reporting_bucket["health"]),
                    "trajectory_count": trajectory_store_io["count"],
                },
                "report_summary": {
                    **_snapshot_io_metric(reporting_bucket["report_summary"]),
                    "trajectory_store": trajectory_store_io["summary"],
                },
                "report_sessions": {
                    **_snapshot_io_metric(reporting_bucket["report_sessions"]),
                    "session_registry": session_registry_io["list_sessions"],
                },
                "report_session_risk": {
                    **_snapshot_io_metric(reporting_bucket["report_session_risk"]),
                    "session_registry": session_registry_io["get_session_risk"],
                },
                "report_session_post_action": {
                    **_snapshot_io_metric(reporting_bucket["report_session_post_action"]),
                    "session_registry": session_registry_io["get_session_risk"],
                },
                "replay_session": {
                    **_snapshot_io_metric(reporting_bucket["replay_session"]),
                    "trajectory_query": trajectory_store_io["replay_session"],
                },
                "replay_session_page": {
                    **_snapshot_io_metric(reporting_bucket["replay_session_page"]),
                    "trajectory_query": trajectory_store_io["replay_session_page"],
                },
                "report_alerts": {
                    **_snapshot_io_metric(reporting_bucket["report_alerts"]),
                    "alert_registry": alert_registry_io["list_alerts"],
                },
            },
        }

    def _record_decision_path(
        self,
        *,
        event: dict[str, Any],
        decision: dict[str, Any],
        snapshot: dict[str, Any],
        meta: dict[str, Any],
        l3_trace: dict[str, Any] | None,
    ) -> int:
        is_resolution = str(meta.get("record_type") or "") == "decision_resolution"
        total_start = time.perf_counter()
        trajectory_store_seconds = 0.0
        session_registry_seconds = 0.0
        record_id = 0
        try:
            trajectory_start = time.perf_counter()
            stored_decision = dict(decision)
            if stored_decision.get("decision_effects") is not None:
                stored_decision["decision_effects"] = decision_effects_for_trajectory(
                    stored_decision.get("decision_effects")
                )
            if is_resolution:
                record_id = self.trajectory_store.record_resolution(
                    event=event,
                    decision=stored_decision,
                    snapshot=snapshot,
                    meta=meta,
                    l3_trace=l3_trace,
                )
            else:
                record_id = self.trajectory_store.record(
                    event=event,
                    decision=stored_decision,
                    snapshot=snapshot,
                    meta=meta,
                    l3_trace=l3_trace,
                )
            trajectory_store_seconds = time.perf_counter() - trajectory_start

            session_start = time.perf_counter()
            self.session_registry.record(
                event=event,
                decision=stored_decision,
                snapshot=snapshot,
                meta=meta,
            )
            session_registry_seconds = time.perf_counter() - session_start
        finally:
            self._observe_record_path_io(
                elapsed_seconds=time.perf_counter() - total_start,
                trajectory_store_seconds=trajectory_store_seconds,
                session_registry_seconds=session_registry_seconds,
            )
        return record_id

    def record_adapter_effect_result(
        self, result: AdapterEffectResult | dict[str, Any],
    ) -> dict[str, Any]:
        """Record an adapter-observed effect outcome without mutating decisions."""

        model = result if isinstance(result, AdapterEffectResult) else AdapterEffectResult(**result)
        payload = model.model_dump(mode="json")
        write_result = self.trajectory_store.record_adapter_effect_result(payload)
        self.session_registry.record_adapter_effect_result(write_result["result"])
        summary = adapter_effect_result_summary(write_result["result"])
        self.event_bus.broadcast({
            "type": "adapter_effect_result",
            "session_id": payload.get("session_id"),
            "event_id": payload.get("event_id"),
            "effect_id": payload.get("effect_id"),
            "adapter_effect_result_summary": summary,
            "created": write_result["created"],
            "timestamp": utc_now_iso(),
        })
        return write_result

    async def handle_jsonrpc(self, raw_body: bytes) -> dict[str, Any]:
        """
        Process a JSON-RPC 2.0 request and return a JSON-RPC response dict.
        """
        try:
            body = json.loads(raw_body)
        except (json.JSONDecodeError, UnicodeDecodeError) as e:
            return self._jsonrpc_error(None, -32700, f"Parse error: {e}")

        # Validate JSON-RPC envelope
        if not isinstance(body, dict):
            return self._jsonrpc_error(None, -32600, "Invalid request: not an object")

        jsonrpc_version = body.get("jsonrpc")
        if jsonrpc_version != JSONRPC_VERSION:
            return self._jsonrpc_error(
                body.get("id"), -32600,
                f"Invalid jsonrpc version: expected '{JSONRPC_VERSION}', got '{jsonrpc_version}'",
            )

        method = body.get("method")
        rpc_id = body.get("id")
        params = body.get("params", {})

        if method != JSONRPC_METHOD:
            return self._jsonrpc_error(
                rpc_id, -32601,
                f"Method not found: '{method}'. Expected '{JSONRPC_METHOD}'",
            )

        return await self._handle_sync_decision(rpc_id, params)

    def _context_with_default_session_scope(
        self,
        context: DecisionContext | None,
    ) -> DecisionContext | None:
        """Attach the configured default scope profile when request context lacks one."""

        profile = self.default_session_scope_profile
        if profile is None:
            return context
        if context is None:
            return DecisionContext(
                session_scope_profile_id=profile.profile_id,
                session_scope_profile=profile,
            )
        if context.session_scope_profile is not None:
            return context
        updates: dict[str, Any] = {"session_scope_profile": profile}
        if not context.session_scope_profile_id:
            updates["session_scope_profile_id"] = profile.profile_id
        return context.model_copy(update=updates)

    async def _run_post_action_async(
        self,
        output_text: str,
        tool_name: str,
        event_id: str,
        session_id: str,
        source_framework: str | None,
        content_origin: str | None,
        external_multiplier: float,
        finding_action: str,
        occurred_at: str,
        file_path: str | None = None,
    ) -> None:
        """Run post-action analysis in background, broadcast finding if needed."""
        try:
            loop = asyncio.get_running_loop()
            finding = await loop.run_in_executor(
                None,
                lambda: self.post_action_analyzer.analyze(
                    tool_output=output_text,
                    tool_name=tool_name,
                    event_id=event_id,
                    file_path=file_path,
                    content_origin=content_origin,
                    external_multiplier=external_multiplier,
                ),
            )
            self.session_registry.record_post_action_score(
                session_id=session_id,
                event_id=event_id,
                occurred_at=occurred_at,
                score=finding.score,
                tier=finding.tier.value,
                patterns_matched=finding.patterns_matched,
                tool_name=tool_name,
                source_framework=source_framework,
                handling=finding_action,
            )
            if finding.tier.value != "log_only":
                handling = finding_action
                if session_id and handling in ("defer", "block"):
                    enf = self.session_enforcement.force(
                        session_id,
                        action=_enforcement_action_from_config(handling),
                        high_risk_count=1,
                    )
                    self.event_bus.broadcast({
                        "type": "session_enforcement_change",
                        "session_id": session_id,
                        "state": "enforced",
                        "action": enf.action.value,
                        "high_risk_count": enf.high_risk_count,
                        "reason": f"post-action finding {finding.tier.value}",
                        "timestamp": occurred_at,
                    })
                finding_event = {
                    "type": "post_action_finding",
                    "event_id": event_id,
                    "session_id": session_id,
                    "source_framework": source_framework,
                    "tier": finding.tier.value,
                    "patterns_matched": finding.patterns_matched,
                    "score": finding.score,
                    "handling": handling,
                    "timestamp": occurred_at,
                }
                if isinstance(finding.details, dict) and finding.details.get("sanitize_advisory"):
                    finding_event["sanitize_advisory"] = finding.details["sanitize_advisory"]
                self.event_bus.broadcast(finding_event)
        except Exception:
            logger.exception("post-action analysis failed for event %s", event_id)

    async def _handle_sync_decision(
        self, rpc_id: Any, params: dict[str, Any]
    ) -> dict[str, Any]:
        """Process a SyncDecision v1 request."""
        request_id = params.get("request_id", "")

        # ENGINE_UNAVAILABLE when gateway is not ready
        if not self._ready:
            error_resp = SyncDecisionErrorResponse(
                request_id=request_id or "unknown",
                rpc_error_code=RPCErrorCode.ENGINE_UNAVAILABLE,
                rpc_error_message="Gateway is starting up",
                retry_eligible=True,
                retry_after_ms=500,
            )
            return self._jsonrpc_error_with_data(rpc_id, -32603, error_resp)

        # Check idempotency cache
        cached = self.idempotency_cache.get(request_id)
        if cached is not None:
            return self._jsonrpc_success(rpc_id, cached)

        # Validate request
        try:
            req = SyncDecisionRequest(**params)
        except ValidationError as e:
            error_resp = SyncDecisionErrorResponse(
                request_id=request_id or "unknown",
                rpc_error_code=RPCErrorCode.INVALID_REQUEST,
                rpc_error_message=f"Request validation failed: {e.error_count()} error(s)",
                retry_eligible=False,
            )
            return self._jsonrpc_error_with_data(rpc_id, -32602, error_resp)

        # Check rpc_version
        if req.rpc_version != RPC_VERSION:
            error_resp = SyncDecisionErrorResponse(
                request_id=req.request_id,
                rpc_error_code=RPCErrorCode.VERSION_NOT_SUPPORTED,
                rpc_error_message=f"Unsupported rpc_version: '{req.rpc_version}'",
                retry_eligible=False,
            )
            return self._jsonrpc_error_with_data(rpc_id, -32602, error_resp)

        req = req.model_copy(update={
            "context": self._context_with_default_session_scope(req.context)
        })

        # Check deadline
        start = time.monotonic()
        deadline_at = start + req.deadline_ms / 1000.0

        # --- Optional event-scoped preset config from harness metadata ---
        _preset_name, _preset_overrides = _extract_project_config(
            req.event.payload
        )
        project_config: Optional[DetectionConfig] = None
        if _preset_name:
            project_config = build_detection_config_with_preset(
                _preset_name, _preset_overrides,
            )

        # --- E-8: Record tool call for D4 frequency analysis ---
        if req.event.tool_name:
            self.policy_engine.session_tracker.record_tool_call(
                str(req.event.session_id or ""), req.event.tool_name
            )

        # --- Phase 2A: compromised-session quarantine check (PRE_ACTION only) ---
        quarantine = self.session_registry.get_quarantine(str(req.event.session_id or ""))
        quarantine_applied = False
        if quarantine is not None and req.event.event_type == EventType.PRE_ACTION:
            decision = CanonicalDecision(
                decision=DecisionVerdict.BLOCK,
                reason="Session quarantined / mark-blocked; subsequent PRE_ACTION blocked",
                policy_id="session-quarantine",
                risk_level=RiskLevel.HIGH,
                decision_source=DecisionSource.SYSTEM,
                decision_effects=DecisionEffects(
                    effect_id=str(
                        quarantine.get("effect_id")
                        or f"eff-{req.event.session_id}-{req.event.event_id}-session-quarantine"
                    ),
                    action_scope="session",
                    session_effect=SessionEffectRequest(
                        requested=True,
                        mode="mark_blocked",
                        reason_code=str(quarantine.get("reason_code") or "session_quarantined"),
                        capability_required="clawsentry.session_control.mark_blocked.v1",
                        fallback_on_unsupported="mark_blocked",
                    ),
                ),
                final=True,
            )
            try:
                remaining_ms = max(0, (deadline_at - time.monotonic()) * 1000)
                _, snapshot, _ = self.policy_engine.evaluate(
                    req.event, req.context, DecisionTier.L1,
                    deadline_budget_ms=remaining_ms,
                    config=project_config,
                )
            except Exception:
                logger.exception("Policy engine error during quarantine snapshot")
                from .policy_engine import RiskSnapshot
                snapshot = RiskSnapshot()
            actual_tier = DecisionTier.L1
            quarantine_applied = True

        # --- A-7: Session enforcement check (before policy_engine) ---
        enforcement = self.session_enforcement.check(
            str(req.event.session_id or "")
        )
        enforcement_applied = False
        budget_exhausted = not self.budget_tracker.can_spend()
        effective_requested_tier = req.decision_tier
        l3_runtime_reason_override: str | None = None
        l3_runtime_reason_code_override: str | None = None
        effective_config = project_config or self._detection_config
        anti_bypass_match: AntiBypassMatch | None = None
        if quarantine_applied:
            pass
        elif (
            enforcement is not None
            and req.event.event_type == EventType.PRE_ACTION
        ):
            if enforcement.action == EnforcementAction.L3_REQUIRE:
                effective_requested_tier = DecisionTier.L3
                if budget_exhausted:
                    decision = self._make_enforcement_decision(enforcement, req.event)
                    l3_runtime_reason_override = "LLM budget exhausted; operator review required"
                    l3_runtime_reason_code_override = "budget_exhausted"
                    try:
                        remaining_ms = max(0, (deadline_at - time.monotonic()) * 1000)
                        _, snapshot, _ = self.policy_engine.evaluate(
                            req.event, req.context, DecisionTier.L1,
                            deadline_budget_ms=remaining_ms,
                            config=project_config,
                        )
                    except Exception:
                        logger.exception("Policy engine error during enforcement snapshot")
                        from .policy_engine import RiskSnapshot
                        snapshot = RiskSnapshot()
                    actual_tier = DecisionTier.L1
                    enforcement_applied = True
                else:
                    session_summary = {}
                    if req.context is not None and isinstance(req.context.session_risk_summary, dict):
                        session_summary.update(req.context.session_risk_summary)
                    session_summary.update({
                        "force_l3": True,
                        "l3_require_enforced": True,
                    })
                    effective_context = (
                        req.context.model_copy(update={"session_risk_summary": session_summary})
                        if req.context is not None
                        else DecisionContext(session_risk_summary=session_summary)
                    )
                    try:
                        remaining_ms = max(0, (deadline_at - time.monotonic()) * 1000)
                        decision, snapshot, actual_tier = self.policy_engine.evaluate(
                            req.event, effective_context, DecisionTier.L3,
                            deadline_budget_ms=remaining_ms,
                            config=project_config,
                        )
                    except Exception:
                        logger.exception("Policy engine error")
                        error_resp = SyncDecisionErrorResponse(
                            request_id=req.request_id,
                            rpc_error_code=RPCErrorCode.ENGINE_INTERNAL_ERROR,
                            rpc_error_message="Internal engine error. Check server logs for details.",
                            retry_eligible=True,
                            retry_after_ms=50,
                        )
                        return self._jsonrpc_error_with_data(rpc_id, -32603, error_resp)

                    if actual_tier != DecisionTier.L3:
                        decision = self._make_enforcement_decision(enforcement, req.event)
                        l3_runtime_reason_override = "Local L3 review did not complete; operator review required"
                        l3_runtime_reason_code_override = "local_l3_not_completed"
                        enforcement_applied = True
            else:
                decision = self._make_enforcement_decision(enforcement, req.event)
                # Still need a snapshot for recording — run L1 but override decision
                try:
                    remaining_ms = max(0, (deadline_at - time.monotonic()) * 1000)
                    _, snapshot, _ = self.policy_engine.evaluate(
                        req.event, req.context, req.decision_tier,
                        deadline_budget_ms=remaining_ms,
                        config=project_config,
                    )
                except Exception:
                    logger.exception("Policy engine error during enforcement snapshot")
                    from .policy_engine import RiskSnapshot
                    snapshot = RiskSnapshot()
                actual_tier = DecisionTier.L1
                enforcement_applied = True
        else:
            anti_bypass_match = self.anti_bypass_guard.match_pre_action(
                req.event,
                req.context,
                effective_config,
            )
            # --- P3: LLM budget check — force L1 if exhausted ---
            requested_tier = req.decision_tier
            if budget_exhausted:
                requested_tier = DecisionTier.L1
                if req.decision_tier != DecisionTier.L1:
                    l3_runtime_reason_override = "LLM budget exhausted; L3 skipped"
                    l3_runtime_reason_code_override = "budget_exhausted"
            if anti_bypass_match is not None:
                if anti_bypass_match.action == "force_l2":
                    requested_tier = DecisionTier.L2
                elif anti_bypass_match.action == "force_l3":
                    requested_tier = DecisionTier.L3 if not budget_exhausted else DecisionTier.L1
                    if budget_exhausted:
                        l3_runtime_reason_override = "LLM budget exhausted; anti-bypass L3 skipped"
                        l3_runtime_reason_code_override = "budget_exhausted"
            if not budget_exhausted:
                requested_tier = _effective_requested_tier_for_l3_config(
                    requested_tier,
                    effective_config,
                    self.policy_engine.analyzer,
                )
            effective_requested_tier = requested_tier

            if anti_bypass_match is not None and anti_bypass_match.action in ("block", "defer"):
                verdict = (
                    DecisionVerdict.BLOCK
                    if anti_bypass_match.action == "block"
                    else DecisionVerdict.DEFER
                )
                policy_id = {
                    "exact_raw_repeat": "anti-bypass-exact-repeat",
                    "normalized_destructive_repeat": "anti-bypass-normalized-repeat",
                    "cross_tool_script_similarity": "anti-bypass-cross-tool-review",
                }.get(anti_bypass_match.match_type, "anti-bypass-follow-up-guard")
                decision = CanonicalDecision(
                    decision=verdict,
                    reason=(
                        "Anti-bypass follow-up guard matched "
                        f"{anti_bypass_match.match_type} after prior "
                        f"{anti_bypass_match.prior_risk_level} "
                        f"{anti_bypass_match.prior_policy_id}"
                    ),
                    policy_id=policy_id,
                    risk_level=_risk_level_from_string(anti_bypass_match.prior_risk_level),
                    decision_source=DecisionSource.POLICY,
                    failure_class=FailureClass.NONE,
                    final=True,
                )
                try:
                    remaining_ms = max(0, (deadline_at - time.monotonic()) * 1000)
                    _, snapshot, _ = self.policy_engine.evaluate(
                        req.event, req.context, DecisionTier.L1,
                        deadline_budget_ms=remaining_ms,
                        config=project_config,
                    )
                except Exception:
                    logger.exception("Policy engine error during anti-bypass snapshot")
                    from .policy_engine import RiskSnapshot
                    snapshot = RiskSnapshot()
                actual_tier = DecisionTier.L1
            else:
                # Evaluate normally
                try:
                    remaining_ms = max(0, (deadline_at - time.monotonic()) * 1000)
                    decision, snapshot, actual_tier = self.policy_engine.evaluate(
                        req.event, req.context, requested_tier,
                        deadline_budget_ms=remaining_ms,
                        config=project_config,
                    )
                except Exception:
                    logger.exception("Policy engine error")
                    error_resp = SyncDecisionErrorResponse(
                        request_id=req.request_id,
                        rpc_error_code=RPCErrorCode.ENGINE_INTERNAL_ERROR,
                        rpc_error_message="Internal engine error. Check server logs for details.",
                        retry_eligible=True,
                        retry_after_ms=50,
                    )
                    return self._jsonrpc_error_with_data(rpc_id, -32603, error_resp)

            # Annotate decision when budget forced L1-only downgrade
            if budget_exhausted and req.decision_tier != DecisionTier.L1:
                decision = decision.model_copy(update={
                    "reason": decision.reason + " [LLM budget exhausted, L1-only]"
                })

        # --- CS-012: Record decision BEFORE deadline check ---
        # Recording must happen unconditionally so that even deadline-exceeded
        # decisions are persisted to trajectory_store and session_registry.
        event_dict = req.event.model_dump(mode="json")
        decision_dict = decision.model_dump(mode="json")
        snapshot_dict = snapshot.model_dump(mode="json")
        compat_event_type, compat_observation = _extract_compat_event_fields(event_dict)
        l3_trace = snapshot.l3_trace
        l3_available = _analyzer_supports_l3(self.policy_engine.analyzer)
        if actual_tier == DecisionTier.L3 or l3_trace is not None:
            l3_available = True
        l3_info = build_l3_runtime_info(
            requested_tier=req.decision_tier,
            effective_tier=effective_requested_tier,
            actual_tier=actual_tier,
            l3_available=l3_available,
            l3_trace=l3_trace,
            l3_reason=l3_runtime_reason_override,
            l3_reason_code=l3_runtime_reason_code_override,
        )
        meta_dict = {
            "request_id": req.request_id,
            "actual_tier": actual_tier.value,
            "deadline_ms": req.deadline_ms,
            "record_type": "decision",
            **l3_info,
            "caller_adapter": (
                req.context.caller_adapter
                if req.context and req.context.caller_adapter
                else "unknown"
            ),
        }
        if anti_bypass_match is not None:
            meta_dict["anti_bypass"] = anti_bypass_match.to_metadata()
            meta_dict["anti_bypass_memory_evictions"] = self.anti_bypass_guard.memory_evictions
        compat_evidence_summary = build_compatibility_evidence_summary(event_dict)
        if compat_evidence_summary is not None:
            # Operator-facing replay/session summaries only; not a canonical
            # decision source and intentionally compact.
            meta_dict["evidence_summary"] = compat_evidence_summary
        l3_trace_summary = _compact_l3_evidence_summary(l3_trace)
        if l3_trace_summary is not None:
            meta_dict["l3_trace_summary"] = l3_trace_summary
        # CS-024: Keep stream/session framework consistent for HTTP adapters.
        event_dict["source_framework"] = _infer_source_framework(
            event_dict.get("source_framework"),
            meta_dict.get("caller_adapter"),
        )
        approval_bridge_kind: str | None = None
        approval_bridge_id: str | None = None
        approval_bridge_timeout_s: float | None = None
        approval_bridge_enabled = False
        if _is_confirmation_fast_lane(event_dict, compat_event_type):
            approval_bridge_kind = "confirmation"
            approval_bridge_id = _resolve_confirmation_approval_id(event_dict)
            approval_bridge_timeout_s = float((project_config or self._detection_config).defer_timeout_s)
            approval_bridge_enabled = bool(
                self._detection_config.defer_bridge_enabled
                and (project_config is None or project_config.defer_bridge_enabled)
            )
            event_dict["approval_id"] = approval_bridge_id
            decision = CanonicalDecision(
                decision=DecisionVerdict.DEFER,
                reason="confirmation observed",
                policy_id="confirmation-bridge",
                risk_level=decision.risk_level,
                decision_source=DecisionSource.POLICY,
                final=False,
            )
            decision_dict = decision.model_dump(mode="json")
            meta_dict.update(
                _approval_pending_meta(
                    approval_id=approval_bridge_id,
                    approval_kind=approval_bridge_kind,
                    approval_reason=str(decision_dict.get("reason") or "confirmation observed"),
                    approval_timeout_s=approval_bridge_timeout_s,
                )
            )
        _sid = str(event_dict.get("session_id") or "")
        previous_risk_level = self.session_registry.get_current_risk(_sid)
        pending_trajectory_alerts: list[dict[str, Any]] = []

        # --- E-4 Phase 2: Trajectory analysis ---
        # Run before persistence so configured DEFER/BLOCK handling is recorded
        # with the decision returned to the caller.
        try:
            traj_event = {
                "session_id": _sid,
                "event_id": req.event.event_id,
                "tool_name": req.event.tool_name or "",
                "occurred_at_ts": _parse_iso_timestamp(
                    str(event_dict.get("occurred_at") or "")
                ),
                "payload": req.event.payload or {},
            }
            handling = (project_config or self._detection_config).trajectory_alert_action
            traj_matches = self.trajectory_analyzer.record(traj_event)
            for tm in traj_matches:
                pending_trajectory_alerts.append({
                    "type": "trajectory_alert",
                    "session_id": _sid,
                    "sequence_id": tm.sequence_id,
                    "risk_level": tm.risk_level,
                    "matched_event_ids": tm.matched_event_ids,
                    "reason": tm.reason,
                    "handling": handling,
                    "timestamp": str(event_dict.get("occurred_at") or utc_now_iso()),
                })
                if (
                    handling in ("defer", "block")
                    and req.event.event_type == EventType.PRE_ACTION
                    and not enforcement_applied
                    and _risk_rank(tm.risk_level) >= _risk_rank("high")
                ):
                    verdict = (
                        DecisionVerdict.BLOCK
                        if handling == "block"
                        else DecisionVerdict.DEFER
                    )
                    if decision.decision == DecisionVerdict.BLOCK and verdict != DecisionVerdict.BLOCK:
                        continue
                    decision = CanonicalDecision(
                        decision=verdict,
                        reason=f"Trajectory alert {tm.sequence_id}: {tm.reason}",
                        policy_id="trajectory-alert",
                        risk_level=_risk_level_from_string(tm.risk_level),
                        decision_source=DecisionSource.POLICY,
                        final=True,
                    )
                    decision_dict = decision.model_dump(mode="json")
                    snapshot_dict["risk_level"] = decision.risk_level.value
        except Exception:
            logger.exception("trajectory analysis failed for event %s", req.event.event_id)

        # --- Benchmark mode: no human DEFER waits ---
        # Apply before persistence/SSE so audit records and live events carry
        # the deterministic auto-resolution metadata promised by benchmark mode.
        effective_config = project_config or self._detection_config
        effective_mode = effective_config.mode
        if (
            effective_mode == "benchmark"
            and effective_config.benchmark_auto_resolve_defer
            and decision.decision == DecisionVerdict.DEFER
            and req.event.event_type == EventType.PRE_ACTION
        ):
            benchmark_action = effective_config.benchmark_defer_action
            resolved_verdict = DecisionVerdict.BLOCK
            if benchmark_action == "allow":
                resolved_verdict = DecisionVerdict.ALLOW
            elif benchmark_action == "allow_low_block_high":
                original_risk = getattr(decision.risk_level, "value", str(decision.risk_level))
                resolved_verdict = (
                    DecisionVerdict.ALLOW
                    if _risk_rank(original_risk) <= _risk_rank("low")
                    else DecisionVerdict.BLOCK
                )
            original_reason = decision.reason
            decision = CanonicalDecision(
                decision=resolved_verdict,
                reason=(
                    "Benchmark mode auto-resolved DEFER to "
                    f"{resolved_verdict.value}: {original_reason}"
                ),
                policy_id=decision.policy_id or "benchmark-auto-resolve",
                risk_level=decision.risk_level,
                decision_source=DecisionSource.POLICY,
                final=True,
            )
            decision_dict = decision.model_dump(mode="json")
            meta_dict.update({
                "auto_resolved": True,
                "auto_resolve_mode": "benchmark",
                "original_verdict": "defer",
                "benchmark_defer_action": benchmark_action,
            })

        record_id = self._record_decision_path(
            event=event_dict,
            decision=decision_dict,
            snapshot=snapshot_dict,
            meta=meta_dict,
            l3_trace=l3_trace,
        )
        self.anti_bypass_guard.record_final_decision(
            event=req.event,
            decision=decision,
            snapshot=snapshot,
            meta=meta_dict,
            record_id=record_id,
            config=effective_config,
        )

        current_risk_level = str(snapshot_dict.get("risk_level") or decision_dict.get("risk_level") or "low")
        occurred_at = str(event_dict.get("occurred_at") or utc_now_iso())
        self._maybe_create_l3_advisory_snapshot(
            config=project_config or self._detection_config,
            session_id=_sid,
            event_id=str(event_dict.get("event_id") or "unknown"),
            record_id=record_id,
            current_risk_level=current_risk_level,
            pending_trajectory_alerts=pending_trajectory_alerts,
            compat_event_type=compat_event_type,
        )

        for alert in pending_trajectory_alerts:
            self.event_bus.broadcast(alert)

        # --- A-7: Check if threshold is newly breached ---
        session_id = str(event_dict.get("session_id") or "")
        if session_id and self.session_enforcement.enabled:
            stats = self.session_registry.get_session_stats(session_id)
            new_enf = self.session_enforcement.evaluate_threshold(
                session_id, stats.get("high_risk_event_count", 0)
            )
            if new_enf:
                self.event_bus.broadcast(
                    {
                        "type": "session_enforcement_change",
                        "session_id": session_id,
                        "state": "enforced",
                        "action": new_enf.action.value,
                        "high_risk_count": new_enf.high_risk_count,
                        "timestamp": str(event_dict.get("occurred_at") or utc_now_iso()),
                    }
                )

        # --- CS-013/CS-016: SSE broadcasts BEFORE deadline check ---
        # Event broadcasts must happen unconditionally so that watch CLI and
        # /report/stream subscribers always receive events, even when the
        # request exceeds its deadline.
        if previous_risk_level is None and session_id:
            self.event_bus.broadcast(
                {
                    "type": "session_start",
                    "session_id": session_id,
                    "agent_id": str(event_dict.get("agent_id") or "unknown"),
                    "source_framework": str(event_dict.get("source_framework") or "unknown"),
                    "timestamp": occurred_at,
                }
            )
            self.metrics.session_started()

        # --- P3: Record metrics ---
        _latency_s = time.monotonic() - start
        _source_fw = str(event_dict.get("source_framework") or "unknown")
        _risk_score_val = float(snapshot_dict.get("composite_score") or 0.0)
        self.metrics.record_decision(
            verdict=str(decision_dict.get("decision") or "unknown"),
            risk_level=current_risk_level,
            risk_score=_risk_score_val,
            tier=actual_tier.value,
            source_framework=_source_fw,
            latency_s=_latency_s,
        )

        decision_event = {
            "type": "decision",
            "session_id": session_id,
            "event_id": str(event_dict.get("event_id") or "unknown"),
            "risk_level": current_risk_level,
            "decision": str(decision_dict.get("decision") or "unknown"),
            "tool_name": event_dict.get("tool_name"),
            "actual_tier": actual_tier.value,
            "l3_available": l3_info["l3_available"],
            "l3_requested": l3_info["l3_requested"],
            "l3_state": l3_info["l3_state"],
            "l3_reason": l3_info["l3_reason"],
            "l3_reason_code": l3_info["l3_reason_code"],
            "timestamp": occurred_at,
            "reason": str(decision_dict.get("reason") or ""),
            "command": str(
                event_dict.get("tool_name", "")
                if meta_dict.get("anti_bypass") is not None
                else (
                    event_dict.get("payload", {}).get("command", "")
                    or event_dict.get("tool_name", "")
                )
            ),
            "trigger_detail": (l3_trace or {}).get("trigger_detail"),
            "approval_id": event_dict.get("approval_id"),
            "expires_at": event_dict.get("payload", {}).get("expiresAtMs"),
        }
        if compat_event_type:
            decision_event["compat_event_type"] = compat_event_type
        if compat_observation is not None:
            decision_event["compat_observation"] = compat_observation
        if meta_dict.get("anti_bypass") is not None:
            decision_event["anti_bypass"] = meta_dict["anti_bypass"]
            decision_event["anti_bypass_memory_evictions"] = self.anti_bypass_guard.memory_evictions
        effect_summary = decision_effect_summary(decision_dict.get("decision_effects"))
        if effect_summary is not None:
            decision_event["effect_summary"] = effect_summary
            decision_event["decision_effect_summary"] = effect_summary
        if decision_dict.get("scope_evaluation") is not None:
            decision_event["scope_evaluation"] = decision_dict["scope_evaluation"]
        for key in (
            "approval_kind",
            "approval_state",
            "approval_reason",
            "approval_reason_code",
            "approval_timeout_s",
            "auto_resolved",
            "auto_resolve_mode",
            "original_verdict",
            "benchmark_defer_action",
        ):
            if meta_dict.get(key) is not None:
                decision_event[key] = meta_dict.get(key)
        decision_event.update(self._reporting_state())
        evidence_summary = _compact_l3_evidence_summary(l3_trace)
        if evidence_summary is not None:
            decision_event["evidence_summary"] = evidence_summary
        self.event_bus.broadcast(decision_event)

        if (
            previous_risk_level is not None
            and _risk_rank(current_risk_level) > _risk_rank(previous_risk_level)
        ):
            self.event_bus.broadcast(
                {
                    "type": "session_risk_change",
                    "session_id": session_id,
                    "previous_risk": previous_risk_level,
                    "current_risk": current_risk_level,
                    "trigger_event": str(event_dict.get("event_id") or "unknown"),
                    "timestamp": occurred_at,
                }
            )

        if session_id and _risk_rank(current_risk_level) >= _risk_rank("high"):
            import uuid as _uuid
            alert_id = f"alert-{_uuid.uuid4().hex[:12]}"
            triggered_at_ts = time.time()
            severity = current_risk_level  # "high" or "critical"
            session_data = self.session_registry.get_session_stats(session_id)
            high_risk_count = session_data.get("high_risk_event_count", 1)
            message = (
                f"Session risk escalated to {current_risk_level.upper()}: "
                f"{high_risk_count} high-risk event(s) detected"
            )
            alert = {
                "alert_id": alert_id,
                "severity": severity,
                "metric": "session_risk_escalation",
                "session_id": session_id,
                "message": message,
                "details": {
                    "previous_risk": previous_risk_level,
                    "current_risk": current_risk_level,
                    "high_risk_count": high_risk_count,
                    "cumulative_score": session_data.get("cumulative_score", 0),
                    "trigger_event_id": str(event_dict.get("event_id") or "unknown"),
                    "tool_name": event_dict.get("tool_name"),
                },
                "triggered_at": occurred_at,
                "triggered_at_ts": triggered_at_ts,
                "acknowledged": False,
                "acknowledged_by": None,
                "acknowledged_at": None,
            }
            self.alert_registry.add(alert)
            self.event_bus.broadcast(
                {
                    "type": "alert",
                    "alert_id": alert_id,
                    "severity": severity,
                    "metric": "session_risk_escalation",
                    "session_id": session_id,
                    "current_risk": current_risk_level,
                    "message": message,
                    "timestamp": occurred_at,
                }
            )

        # --- E-4: Post-action security analysis (fire-and-forget) ---
        if req.event.event_type == EventType.POST_ACTION:
            output_text = str(
                req.event.payload.get("output", "")
                or req.event.payload.get("result", "")
                or ""
            )
            if output_text:
                _pa_meta = (req.event.payload or {}).get("_clawsentry_meta") or {}
                _pa_origin = _pa_meta.get("content_origin") if isinstance(_pa_meta, dict) else None
                _pa_file_path = None
                if isinstance(_pa_meta, dict):
                    _pa_file_path = _pa_meta.get("file_path")
                if not _pa_file_path:
                    _pa_file_path = (
                        req.event.payload.get("file_path")
                        or req.event.payload.get("path")
                        or req.event.payload.get("target_path")
                    )
                asyncio.create_task(self._run_post_action_async(
                    output_text=output_text,
                    tool_name=req.event.tool_name or "unknown",
                    event_id=req.event.event_id,
                    session_id=session_id,
                    source_framework=str(event_dict.get("source_framework") or "unknown"),
                    content_origin=_pa_origin,
                    external_multiplier=(project_config or self._detection_config).external_content_post_action_multiplier,
                    finding_action=(project_config or self._detection_config).post_action_finding_action,
                    occurred_at=occurred_at,
                    file_path=str(_pa_file_path) if _pa_file_path else None,
                ))

        # --- E-5: Extract candidate pattern from confirmed high-risk events ---
        if (
            self.evolution_manager.enabled
            and req.event.event_type == EventType.PRE_ACTION
            and decision.risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL)
        ):
            try:
                candidate_id = self.evolution_manager.extract_candidate(
                    event_id=req.event.event_id,
                    session_id=str(req.event.session_id or ""),
                    tool_name=req.event.tool_name or "",
                    command=str(req.event.payload.get("command", "")) if req.event.payload else "",
                    risk_level=decision.risk_level,
                    source_framework=str(event_dict.get("source_framework") or "unknown"),
                    reasons=decision.reason.split("; ") if decision.reason else [],
                )
                if candidate_id:
                    self.event_bus.broadcast({
                        "type": "pattern_candidate",
                        "pattern_id": candidate_id,
                        "session_id": session_id,
                        "source_framework": str(event_dict.get("source_framework") or "unknown"),
                        "status": "candidate",
                        "timestamp": occurred_at,
                    })
            except Exception:
                logger.warning("evolved pattern extraction failed", exc_info=True)

        if approval_bridge_kind == "confirmation":
            approval_id = approval_bridge_id or _resolve_confirmation_approval_id(event_dict)
            approval_timeout_s = float(approval_bridge_timeout_s or (project_config or self._detection_config).defer_timeout_s)
            resolution_recorded_at = utc_now_iso()
            resolution_event = dict(event_dict)
            resolution_event["occurred_at"] = resolution_recorded_at
            resolution_event["approval_id"] = approval_id
            resolution_meta = {
                **meta_dict,
                "approval_id": approval_id,
            }

            if not approval_bridge_enabled:
                decision = CanonicalDecision(
                    decision=DecisionVerdict.BLOCK,
                    reason="Confirmation approval has no route; blocking",
                    policy_id="confirmation-bridge",
                    risk_level=decision.risk_level,
                    decision_source=DecisionSource.SYSTEM,
                    failure_class=FailureClass.APPROVAL_NO_ROUTE,
                    final=True,
                )
                decision_dict = decision.model_dump(mode="json")
                resolution_approval = _approval_resolution_meta(
                    approval_id=approval_id,
                    approval_kind=approval_bridge_kind,
                    approval_state="no_route",
                    approval_reason="Confirmation approval has no route; blocking",
                    approval_reason_code=_APPROVAL_NO_ROUTE_REASON_CODE,
                    approval_timeout_s=approval_timeout_s,
                )
                self._record_decision_path(
                    event=resolution_event,
                    decision=decision_dict,
                    snapshot=snapshot_dict,
                    meta={
                        **resolution_meta,
                        **resolution_approval,
                        "record_type": "decision_resolution",
                    },
                    l3_trace=l3_trace,
                )
                self.event_bus.broadcast({
                    "type": "defer_resolved",
                    "session_id": session_id,
                    **resolution_approval,
                    "resolved_decision": decision_dict["decision"],
                    "resolved_reason": decision_dict["reason"],
                    "timestamp": resolution_recorded_at,
                })
            elif not self.defer_manager.register_approval(
                approval_id,
                approval_kind=approval_bridge_kind,
                session_id=session_id,
                tool_name=req.event.tool_name or "",
                summary=str(req.event.payload.get("command", "") if req.event.payload else "") or None,
            ):
                decision = CanonicalDecision(
                    decision=DecisionVerdict.BLOCK,
                    reason=f"Confirmation approval queue full ({self.defer_manager.max_pending}), blocking",
                    policy_id="confirmation-bridge",
                    risk_level=decision.risk_level,
                    decision_source=DecisionSource.SYSTEM,
                    failure_class=FailureClass.APPROVAL_QUEUE_FULL,
                    final=True,
                )
                decision_dict = decision.model_dump(mode="json")
                resolution_approval = _approval_resolution_meta(
                    approval_id=approval_id,
                    approval_kind=approval_bridge_kind,
                    approval_state="queue_full",
                    approval_reason=f"Confirmation approval queue full ({self.defer_manager.max_pending}), blocking",
                    approval_reason_code=_APPROVAL_QUEUE_FULL_REASON_CODE,
                    approval_timeout_s=approval_timeout_s,
                )
                self._record_decision_path(
                    event=resolution_event,
                    decision=decision_dict,
                    snapshot=snapshot_dict,
                    meta={
                        **resolution_meta,
                        **resolution_approval,
                        "record_type": "decision_resolution",
                    },
                    l3_trace=l3_trace,
                )
                self.event_bus.broadcast({
                    "type": "defer_resolved",
                    "session_id": session_id,
                    **resolution_approval,
                    "resolved_decision": decision_dict["decision"],
                    "resolved_reason": decision_dict["reason"],
                    "timestamp": resolution_recorded_at,
                })
            else:
                self.metrics.defer_registered()
                pending_approval = _approval_pending_meta(
                    approval_id=approval_id,
                    approval_kind=approval_bridge_kind,
                    approval_reason=str(meta_dict.get("approval_reason") or decision_dict.get("reason") or "confirmation observed"),
                    approval_timeout_s=approval_timeout_s,
                )
                self.event_bus.broadcast({
                    "type": "defer_pending",
                    "session_id": session_id,
                    **pending_approval,
                    "tool_name": req.event.tool_name or "",
                    "command": str(
                        req.event.tool_name or ""
                        if meta_dict.get("anti_bypass") is not None
                        else (req.event.payload.get("command", "") if req.event.payload else "")
                    ),
                    "reason": str(decision_dict.get("reason") or ""),
                    "timeout_s": approval_timeout_s,
                    "timestamp": occurred_at,
                })

                _resolved_decision, _resolved_reason = await self.defer_manager.wait_for_resolution(approval_id)
                approval_record = self.defer_manager.get_approval(approval_id)
                approval_state = approval_record.approval_state or "resolved"
                approval_reason = approval_record.reason or _resolved_reason
                approval_reason_code = approval_record.reason_code or (
                    _APPROVAL_ALLOWED_REASON_CODE
                    if _resolved_decision in ("allow", "allow-once", "allow-always")
                    else _APPROVAL_DENIED_REASON_CODE
                )

                if _resolved_decision in ("allow", "allow-once", "allow-always"):
                    decision_source = (
                        DecisionSource.OPERATOR
                        if approval_state == "resolved"
                        else DecisionSource.SYSTEM
                    )
                    approval_payload = approval_record.resolution_payload
                    if isinstance(approval_payload, dict) and approval_payload:
                        try:
                            validated_payload = _validate_rewrite_resolution_payload(approval_payload)
                            rewrite_effects = _rewrite_effect_for_resolution(
                                approval_id=approval_id,
                                event=event_dict,
                                replacement_payload=validated_payload,
                                resolver_identity=approval_record.resolver_identity,
                                policy_id="confirmation-bridge",
                            )
                        except ValueError as exc:
                            decision = CanonicalDecision(
                                decision=DecisionVerdict.BLOCK,
                                reason=f"Rewrite validation failed: {exc}",
                                policy_id="confirmation-bridge",
                                risk_level=decision.risk_level,
                                decision_source=DecisionSource.SYSTEM,
                                failure_class=FailureClass.INPUT_INVALID,
                                final=True,
                            )
                        else:
                            decision = CanonicalDecision(
                                decision=DecisionVerdict.MODIFY,
                                reason=(
                                    f"Operator approved rewrite: {approval_reason}"
                                    if approval_state == "resolved" and approval_reason
                                    else "Operator approved rewrite"
                                ),
                                policy_id="confirmation-bridge",
                                risk_level=decision.risk_level,
                                decision_source=decision_source,
                                modified_payload=validated_payload,
                                decision_effects=rewrite_effects,
                                failure_class=FailureClass.NONE,
                                final=True,
                            )
                    else:
                        decision = CanonicalDecision(
                            decision=DecisionVerdict.ALLOW,
                            reason=(
                                f"Operator approved: {approval_reason}"
                                if approval_state == "resolved" and approval_reason
                                else "Operator approved"
                                if approval_state == "resolved"
                                else approval_reason or "Approval timeout auto-allow"
                            ),
                            policy_id="confirmation-bridge",
                            risk_level=decision.risk_level,
                            decision_source=decision_source,
                            failure_class=(
                                FailureClass.APPROVAL_TIMEOUT
                                if approval_state == "timeout"
                                else FailureClass.NONE
                            ),
                            final=True,
                        )
                else:
                    decision_source = (
                        DecisionSource.OPERATOR
                        if approval_state == "resolved"
                        else DecisionSource.SYSTEM
                    )
                    decision = CanonicalDecision(
                        decision=DecisionVerdict.BLOCK,
                        reason=(
                            f"Operator denied: {approval_reason}"
                            if approval_state == "resolved" and approval_reason
                            else "Operator denied"
                            if approval_state == "resolved"
                            else approval_reason or "Approval denied"
                        ),
                        policy_id="confirmation-bridge",
                        risk_level=decision.risk_level,
                        decision_source=decision_source,
                        failure_class=(
                            FailureClass.APPROVAL_TIMEOUT
                            if approval_state == "timeout"
                            else FailureClass.NONE
                        ),
                        final=True,
                    )

                decision_dict = decision.model_dump(mode="json")
                resolution_recorded_at = utc_now_iso()
                resolution_event = dict(event_dict)
                resolution_event["occurred_at"] = resolution_recorded_at
                resolution_event["approval_id"] = approval_id
                resolution_approval = _approval_resolution_meta(
                    approval_id=approval_id,
                    approval_kind=approval_bridge_kind,
                    approval_state=approval_state,
                    approval_reason=approval_reason,
                    approval_reason_code=approval_reason_code,
                    approval_timeout_s=float(approval_record.timeout_s or approval_timeout_s),
                )
                self._record_decision_path(
                    event=resolution_event,
                    decision=decision_dict,
                    snapshot=snapshot_dict,
                    meta={
                        **resolution_meta,
                        **resolution_approval,
                        "record_type": "decision_resolution",
                    },
                    l3_trace=l3_trace,
                )
                self.metrics.defer_resolved()
                self.event_bus.broadcast({
                    "type": "defer_resolved",
                    "session_id": session_id,
                    **resolution_approval,
                    "resolved_decision": decision_dict["decision"],
                    "resolved_reason": decision_dict["reason"],
                    "timestamp": resolution_recorded_at,
                })

        # --- P1: DEFER bridge — wait for operator approval ---
        if (
            self._detection_config.defer_bridge_enabled
            and (project_config is None or project_config.defer_bridge_enabled)
            and decision.decision == DecisionVerdict.DEFER
            and req.event.event_type == EventType.PRE_ACTION
            and not enforcement_applied
        ):
            defer_id = f"cs-defer-{uuid.uuid4().hex[:12]}"
            if not self.defer_manager.register_defer(defer_id):
                # Queue full — fall back to block
                decision = CanonicalDecision(
                    decision=DecisionVerdict.BLOCK,
                    reason=f"DEFER queue full ({self.defer_manager.max_pending}), blocking",
                    policy_id="defer-bridge",
                    risk_level=decision.risk_level,
                    decision_source=DecisionSource.POLICY,
                    failure_class=FailureClass.APPROVAL_QUEUE_FULL,
                    final=True,
                )
                decision_dict = decision.model_dump(mode="json")
                resolution_recorded_at = utc_now_iso()
                resolution_event = dict(event_dict)
                resolution_event["occurred_at"] = resolution_recorded_at
                resolution_event["approval_id"] = defer_id
                resolution_approval = _approval_resolution_meta(
                    approval_id=defer_id,
                    approval_kind="defer",
                    approval_state="queue_full",
                    approval_reason=f"DEFER queue full ({self.defer_manager.max_pending}), blocking",
                    approval_reason_code=_APPROVAL_QUEUE_FULL_REASON_CODE,
                    approval_timeout_s=float((project_config or self._detection_config).defer_timeout_s),
                )
                resolution_meta = {
                    **meta_dict,
                    **resolution_approval,
                }
                self._record_decision_path(
                    event=resolution_event,
                    decision=decision_dict,
                    snapshot=snapshot_dict,
                    meta={
                        **resolution_meta,
                        "record_type": "decision_resolution",
                    },
                    l3_trace=l3_trace,
                )
                self.event_bus.broadcast({
                    "type": "defer_resolved",
                    "session_id": session_id,
                    **resolution_approval,
                    "resolved_decision": decision_dict["decision"],
                    "resolved_reason": decision_dict["reason"],
                    "timestamp": resolution_recorded_at,
                })
            else:
                self.metrics.defer_registered()

                # Broadcast defer_pending event
                _defer_timeout = (project_config or self._detection_config).defer_timeout_s
                pending_approval = _approval_pending_meta(
                    approval_id=defer_id,
                    approval_kind="defer",
                    approval_reason=str(decision_dict.get("reason") or ""),
                    approval_timeout_s=float(_defer_timeout),
                )
                self.event_bus.broadcast({
                    "type": "defer_pending",
                    "session_id": session_id,
                    **pending_approval,
                    "tool_name": req.event.tool_name or "",
                    "command": str(
                        req.event.tool_name or ""
                        if meta_dict.get("anti_bypass") is not None
                        else (req.event.payload.get("command", "") if req.event.payload else "")
                    ),
                    "reason": str(decision_dict.get("reason") or ""),
                    "timeout_s": _defer_timeout,
                    "timestamp": occurred_at,
                })

                # Wait for operator resolution
                _resolved_decision, _resolved_reason = await self.defer_manager.wait_for_resolution(defer_id)
                approval_record = self.defer_manager.get_approval(defer_id)

                # Convert to final CanonicalDecision
                if _resolved_decision in ("allow", "allow-once"):
                    decision_source = (
                        DecisionSource.OPERATOR
                        if (approval_record.approval_state or "resolved") == "resolved"
                        else DecisionSource.SYSTEM
                    )
                    approval_payload = approval_record.resolution_payload
                    if isinstance(approval_payload, dict) and approval_payload:
                        try:
                            validated_payload = _validate_rewrite_resolution_payload(approval_payload)
                            rewrite_effects = _rewrite_effect_for_resolution(
                                approval_id=defer_id,
                                event=event_dict,
                                replacement_payload=validated_payload,
                                resolver_identity=approval_record.resolver_identity,
                                policy_id="defer-bridge",
                            )
                        except ValueError as exc:
                            decision = CanonicalDecision(
                                decision=DecisionVerdict.BLOCK,
                                reason=f"Rewrite validation failed: {exc}",
                                policy_id="defer-bridge",
                                risk_level=decision.risk_level,
                                decision_source=DecisionSource.SYSTEM,
                                failure_class=FailureClass.INPUT_INVALID,
                                final=True,
                            )
                        else:
                            decision = CanonicalDecision(
                                decision=DecisionVerdict.MODIFY,
                                reason=(
                                    f"Operator approved rewrite: {_resolved_reason}"
                                    if (approval_record.approval_state or "resolved") == "resolved" and _resolved_reason
                                    else "Operator approved rewrite"
                                ),
                                policy_id="defer-bridge",
                                risk_level=decision.risk_level,
                                decision_source=decision_source,
                                modified_payload=validated_payload,
                                decision_effects=rewrite_effects,
                                failure_class=FailureClass.NONE,
                                final=True,
                            )
                    else:
                        decision = CanonicalDecision(
                            decision=DecisionVerdict.ALLOW,
                            reason=(
                                f"Operator approved: {_resolved_reason}"
                                if (approval_record.approval_state or "resolved") == "resolved" and _resolved_reason
                                else "Operator approved"
                                if (approval_record.approval_state or "resolved") == "resolved"
                                else _resolved_reason or "Approval timeout auto-allow"
                            ),
                            policy_id="defer-bridge",
                            risk_level=decision.risk_level,
                            decision_source=decision_source,
                            failure_class=(
                                FailureClass.APPROVAL_TIMEOUT
                                if (approval_record.approval_state or "resolved") == "timeout"
                                else FailureClass.NONE
                            ),
                            final=True,
                        )
                else:
                    decision = CanonicalDecision(
                        decision=DecisionVerdict.BLOCK,
                        reason=(
                            f"Operator denied: {_resolved_reason}"
                            if (approval_record.approval_state or "resolved") == "resolved" and _resolved_reason
                            else "Operator denied"
                            if (approval_record.approval_state or "resolved") == "resolved"
                            else _resolved_reason or "Approval timeout auto-block"
                        ),
                        policy_id="defer-bridge",
                        risk_level=decision.risk_level,
                        decision_source=(
                            DecisionSource.OPERATOR
                            if (approval_record.approval_state or "resolved") == "resolved"
                            else DecisionSource.SYSTEM
                        ),
                        failure_class=(
                            FailureClass.APPROVAL_TIMEOUT
                            if (approval_record.approval_state or "resolved") == "timeout"
                            else FailureClass.NONE
                        ),
                        final=True,
                    )

                # Update dict for response
                decision_dict = decision.model_dump(mode="json")

                resolution_recorded_at = utc_now_iso()
                resolution_event = dict(event_dict)
                resolution_event["occurred_at"] = resolution_recorded_at
                resolution_event["approval_id"] = defer_id
                resolution_approval = _approval_resolution_meta(
                    approval_id=defer_id,
                    approval_kind="defer",
                    approval_state=approval_record.approval_state or "resolved",
                    approval_reason=approval_record.reason or _resolved_reason,
                    approval_reason_code=approval_record.reason_code or (
                        _APPROVAL_ALLOWED_REASON_CODE
                        if _resolved_decision in ("allow", "allow-once", "allow-always")
                        else _APPROVAL_DENIED_REASON_CODE
                    ),
                    approval_timeout_s=float(approval_record.timeout_s or _defer_timeout),
                )
                resolution_meta = {
                    **meta_dict,
                    **resolution_approval,
                }
                self._record_decision_path(
                    event=resolution_event,
                    decision=decision_dict,
                    snapshot=snapshot_dict,
                    meta={
                        **resolution_meta,
                        "record_type": "decision_resolution",
                    },
                    l3_trace=l3_trace,
                )

                self.metrics.defer_resolved()

                # Broadcast defer_resolved event
                self.event_bus.broadcast({
                    "type": "defer_resolved",
                    "session_id": session_id,
                    **resolution_approval,
                    "resolved_decision": decision_dict["decision"],
                    "resolved_reason": decision_dict["reason"],
                    "timestamp": resolution_recorded_at,
                })

        # Check if we exceeded deadline (after recording + broadcasts, so
        # audit trail and SSE events are intact)
        if time.monotonic() > deadline_at:
            error_resp = SyncDecisionErrorResponse(
                request_id=req.request_id,
                rpc_error_code=RPCErrorCode.DEADLINE_EXCEEDED,
                rpc_error_message=f"Decision took longer than deadline_ms={req.deadline_ms}",
                retry_eligible=True,
                retry_after_ms=50,
                fallback_decision=decision,
            )
            return self._jsonrpc_error_with_data(rpc_id, -32604, error_resp)

        # Build success response
        resp = SyncDecisionResponse(
            request_id=req.request_id,
            decision=decision,
            actual_tier=actual_tier,
            l3_available=l3_info["l3_available"],
            l3_requested=l3_info["l3_requested"],
            l3_state=l3_info["l3_state"],
            l3_reason=l3_info["l3_reason"],
            l3_reason_code=l3_info["l3_reason_code"],
            served_at=utc_now_iso(),
        )
        resp_dict = resp.model_dump(mode="json")

        # Cache response
        self.idempotency_cache.put(req.request_id, resp_dict, req.deadline_ms)

        return self._jsonrpc_success(rpc_id, resp_dict)

    def _make_enforcement_decision(
        self, enforcement, event: CanonicalEvent,
    ) -> CanonicalDecision:
        """Build a decision that overrides normal evaluation due to A-7 enforcement."""
        if enforcement.action == EnforcementAction.BLOCK:
            verdict = DecisionVerdict.BLOCK
            policy_id = "session-enforcement-A7"
            reason = (
                f"Session enforcement: BLOCK after {enforcement.high_risk_count} "
                f"high-risk events (threshold reached)"
            )
        elif enforcement.action == EnforcementAction.L3_REQUIRE:
            verdict = DecisionVerdict.DEFER
            policy_id = "session-enforcement-A7-L3"
            reason = (
                f"Session enforcement: L3 review required after "
                f"{enforcement.high_risk_count} high-risk events"
            )
        else:
            # DEFER (default)
            verdict = DecisionVerdict.DEFER
            policy_id = "session-enforcement-A7"
            reason = (
                f"Session enforcement: DEFER after {enforcement.high_risk_count} "
                f"high-risk events (threshold reached)"
            )
        decision_effects = None
        if verdict == DecisionVerdict.BLOCK:
            decision_effects = DecisionEffects(
                effect_id=f"eff-{event.session_id}-{event.event_id}-session-quarantine",
                action_scope="session",
                session_effect=SessionEffectRequest(
                    requested=True,
                    mode="mark_blocked",
                    reason_code="session_enforcement_threshold",
                    capability_required="clawsentry.session_control.mark_blocked.v1",
                    fallback_on_unsupported="mark_blocked",
                ),
            )
        return CanonicalDecision(
            decision=verdict,
            reason=reason,
            policy_id=policy_id,
            risk_level=RiskLevel.HIGH,
            decision_source=DecisionSource.POLICY,
            policy_version="A7",
            decision_effects=decision_effects,
            failure_class=FailureClass.NONE,
            final=True,
        )

    def health(self) -> dict[str, Any]:
        """Return gateway health status."""
        start = time.perf_counter()
        uptime = time.monotonic() - self._start_time
        payload = {
            "status": "healthy",
            "uptime_seconds": round(uptime, 1),
            "cache_size": self.idempotency_cache.size(),
            "trajectory_count": self.trajectory_store.count(),
            "trajectory_backend": "sqlite",
            "policy_engine": "L1+L2",
            "rpc_version": RPC_VERSION,
            "auth_enabled": bool(os.getenv("CS_AUTH_TOKEN")),
        }
        payload.update(self._reporting_state())
        self._observe_reporting_io("health", time.perf_counter() - start)
        payload.update(self._reporting_io_state())
        return payload

    def report_summary(self, window_seconds: Optional[int] = None) -> dict[str, Any]:
        """Return cross-framework summary metrics from trajectory records."""
        start = time.perf_counter()
        since_seconds = window_seconds if window_seconds and window_seconds > 0 else None
        summary = self.trajectory_store.summary(since_seconds=since_seconds)
        generated_at = utc_now_iso()
        summary["generated_at"] = generated_at
        summary["window_seconds"] = since_seconds
        summary["system_security_posture"] = _build_system_security_posture(
            summary,
            window_seconds=since_seconds,
            generated_at=generated_at,
        )
        summary.update(self._reporting_state())
        self._observe_reporting_io("report_summary", time.perf_counter() - start)
        io_state = self._reporting_io_state()
        summary.update(io_state)
        summary["decision_path_io_pressure"] = _build_decision_path_io_pressure(
            io_state["decision_path_io"]
        )
        return summary

    def replay_session(
        self,
        session_id: str,
        limit: int = 100,
        window_seconds: Optional[int] = None,
    ) -> dict[str, Any]:
        """Return timeline records for a session (most recent first by append order)."""
        start = time.perf_counter()
        since_seconds = window_seconds if window_seconds and window_seconds > 0 else None
        records = self.trajectory_store.replay_session(
            session_id=session_id,
            limit=limit,
            since_seconds=since_seconds,
        )
        payload = {
            "session_id": session_id,
            "record_count": len(records),
            "records": records,
            "generated_at": utc_now_iso(),
            "window_seconds": since_seconds,
        }
        payload["l3_advisory"] = self._l3_advisory_payload(session_id)
        payload.update(self._reporting_state())
        self._observe_reporting_io("replay_session", time.perf_counter() - start)
        payload.update(self._reporting_io_state())
        return payload

    def replay_session_page(
        self,
        session_id: str,
        *,
        limit: int = 100,
        cursor: Optional[int] = None,
        window_seconds: Optional[int] = None,
    ) -> dict[str, Any]:
        """Return a paged replay payload for a session."""
        start = time.perf_counter()
        since_seconds = window_seconds if window_seconds and window_seconds > 0 else None
        page = self.trajectory_store.replay_session_page(
            session_id=session_id,
            limit=limit,
            cursor=cursor,
            since_seconds=since_seconds,
        )
        payload = {
            "session_id": session_id,
            "record_count": len(page["records"]),
            "records": page["records"],
            "next_cursor": page["next_cursor"],
            "generated_at": utc_now_iso(),
            "window_seconds": since_seconds,
        }
        payload["l3_advisory"] = self._l3_advisory_payload(session_id)
        payload.update(self._reporting_state())
        self._observe_reporting_io("replay_session_page", time.perf_counter() - start)
        payload.update(self._reporting_io_state())
        return payload

    def report_sessions(
        self,
        *,
        status: str = "active",
        sort: str = "risk_level",
        limit: int = 50,
        min_risk: Optional[str] = None,
        window_seconds: Optional[int] = None,
        max_limit: int = 200,
    ) -> dict[str, Any]:
        start = time.perf_counter()
        since_seconds = window_seconds if window_seconds and window_seconds > 0 else None
        effective_limit = min(max(limit, 1), max(max_limit, 1))
        generated_at = utc_now_iso()
        result = self.session_registry.list_sessions(
            status=status,
            sort=sort,
            min_risk=min_risk,
            limit=effective_limit,
            max_limit=max_limit,
            since_seconds=since_seconds,
        )
        generated_at = utc_now_iso()
        for session in result.get("sessions", []):
            if not isinstance(session, dict):
                continue
            session_id = str(session.get("session_id") or "")
            if since_seconds is None:
                window_summary = {
                    "window_seconds": since_seconds,
                    "generated_at": generated_at,
                    "event_count": int(session.get("event_count") or 0),
                    "latest_composite_score": _float_or_zero(session.get("latest_composite_score")),
                    "session_risk_sum": round(_float_or_zero(session.get("session_risk_sum")), 4),
                    "session_risk_ewma": round(_float_or_zero(session.get("session_risk_ewma")), 4),
                    "risk_points_sum": int(session.get("risk_points_sum") or 0),
                    "risk_velocity": str(session.get("risk_velocity") or "unknown"),
                    "high_or_critical_count": int(session.get("high_risk_event_count") or 0),
                    "score_range": list(DISPLAY_SCORE_RANGE),
                    "score_semantics": dict(DISPLAY_SCORE_SEMANTICS),
                    "decision_affecting": False,
                }
                session["window_risk_summary"] = window_summary
            else:
                timeline = self.session_registry.get_session_risk(
                    session_id,
                    limit=1000,
                    since_seconds=since_seconds,
                ).get("risk_timeline", [])
                if not isinstance(timeline, list):
                    timeline = []
                window_summary = _build_window_risk_summary(
                    timeline,
                    window_seconds=since_seconds,
                    generated_at=generated_at,
                )
                session["latest_composite_score"] = window_summary["latest_composite_score"]
                session["session_risk_sum"] = window_summary["session_risk_sum"]
                session["session_risk_ewma"] = window_summary["session_risk_ewma"]
                session["risk_points_sum"] = window_summary["risk_points_sum"]
                session["risk_velocity"] = window_summary["risk_velocity"]
                session["window_risk_summary"] = window_summary
            session["score_range"] = list(DISPLAY_SCORE_RANGE)
            session["score_semantics"] = dict(DISPLAY_SCORE_SEMANTICS)
            latest_review = self.trajectory_store.latest_l3_advisory_review(
                session_id=session_id
            )
            if latest_review is not None:
                session["l3_advisory_latest"] = latest_review
                latest_action = self._l3_advisory_action_for_review(latest_review)
                if latest_action is not None:
                    session["l3_advisory_latest_action"] = latest_action
        result["generated_at"] = generated_at
        result["window_seconds"] = since_seconds
        result.update(self._reporting_state())
        self._observe_reporting_io("report_sessions", time.perf_counter() - start)
        result.update(self._reporting_io_state())
        return result

    def _l3_advisory_payload(self, session_id: str) -> dict[str, Any]:
        snapshots = self.trajectory_store.list_l3_evidence_snapshots(session_id=session_id)
        reviews = self.trajectory_store.list_l3_advisory_reviews(session_id=session_id)
        jobs = self.trajectory_store.list_l3_advisory_jobs(session_id=session_id)
        latest_review = reviews[-1] if reviews else None
        latest_job = jobs[-1] if jobs else None
        latest_snapshot = None
        if latest_review is not None:
            latest_snapshot = self.trajectory_store.get_l3_evidence_snapshot(
                str(latest_review.get("snapshot_id") or "")
            )
            matching_jobs = [
                job for job in jobs
                if job.get("review_id") == latest_review.get("review_id")
                or job.get("snapshot_id") == latest_review.get("snapshot_id")
            ]
            if matching_jobs:
                latest_job = matching_jobs[-1]
        latest_action = self.trajectory_store.build_l3_advisory_action_summary(
            review=latest_review,
            job=latest_job,
            snapshot=latest_snapshot,
        )
        return {
            "snapshots": snapshots,
            "reviews": reviews,
            "jobs": jobs,
            "latest_review": latest_review,
            "latest_job": latest_job,
            "latest_action": latest_action,
        }

    def _l3_advisory_action_for_review(
        self,
        review: dict[str, Any] | None,
        *,
        job: dict[str, Any] | None = None,
    ) -> dict[str, Any] | None:
        if review is None:
            return None
        snapshot = self.trajectory_store.get_l3_evidence_snapshot(
            str(review.get("snapshot_id") or "")
        )
        if job is None:
            candidates = self.trajectory_store.list_l3_advisory_jobs(
                session_id=str(review.get("session_id") or ""),
                snapshot_id=str(review.get("snapshot_id") or ""),
            )
            for candidate in reversed(candidates):
                if candidate.get("review_id") == review.get("review_id"):
                    job = candidate
                    break
            if job is None and candidates:
                job = candidates[-1]
        return self.trajectory_store.build_l3_advisory_action_summary(
            review=review,
            job=job,
            snapshot=snapshot,
        )

    def _broadcast_l3_advisory_action(
        self,
        review: dict[str, Any] | None,
        *,
        job: dict[str, Any] | None = None,
    ) -> None:
        action = self._l3_advisory_action_for_review(review, job=job)
        if action is None:
            return
        event = dict(action)
        event["timestamp"] = action.get("created_at") or utc_now_iso()
        self.event_bus.broadcast(event)

    def report_session_risk(
        self,
        session_id: str,
        *,
        limit: int = 100,
        window_seconds: Optional[int] = None,
    ) -> dict[str, Any]:
        start = time.perf_counter()
        since_seconds = window_seconds if window_seconds and window_seconds > 0 else None
        effective_limit = min(max(limit, 1), 1000)
        result = self.session_registry.get_session_risk(
            session_id,
            limit=effective_limit,
            since_seconds=since_seconds,
        )
        timeline = result.get("risk_timeline") if isinstance(result.get("risk_timeline"), list) else []
        window_summary = _build_window_risk_summary(
            timeline,
            window_seconds=since_seconds,
        )
        result["latest_composite_score"] = window_summary["latest_composite_score"]
        result["session_risk_sum"] = window_summary["session_risk_sum"]
        result["session_risk_ewma"] = window_summary["session_risk_ewma"]
        result["risk_points_sum"] = window_summary["risk_points_sum"]
        result["risk_velocity"] = window_summary["risk_velocity"]
        result["window_risk_summary"] = window_summary
        result["score_range"] = list(DISPLAY_SCORE_RANGE)
        result["score_semantics"] = dict(DISPLAY_SCORE_SEMANTICS)
        result["l3_advisory"] = self._l3_advisory_payload(session_id)
        result["generated_at"] = utc_now_iso()
        result["window_seconds"] = since_seconds
        result.update(self._reporting_state())
        self._observe_reporting_io("report_session_risk", time.perf_counter() - start)
        result.update(self._reporting_io_state())
        return result

    def report_session_post_action_scores(
        self,
        session_id: str,
        *,
        limit: int = 100,
        window_seconds: Optional[int] = None,
    ) -> dict[str, Any]:
        """Return post-action guard scores and session-level EWMA for a session."""
        start = time.perf_counter()
        since_seconds = window_seconds if window_seconds and window_seconds > 0 else None
        effective_limit = min(max(limit, 1), 1000)
        risk_payload = self.session_registry.get_session_risk(
            session_id,
            limit=effective_limit,
            since_seconds=since_seconds,
        )
        payload = {
            "session_id": session_id,
            "latest_post_action_score": risk_payload.get("latest_post_action_score", 0.0),
            "post_action_score_sum": risk_payload.get("post_action_score_sum", 0.0),
            "post_action_score_avg": risk_payload.get("post_action_score_avg", 0.0),
            "post_action_score_ewma": risk_payload.get("post_action_score_ewma", 0.0),
            "post_action_event_count": risk_payload.get("post_action_event_count", 0),
            "post_action_score_summary": risk_payload.get("post_action_score_summary", {}),
            "post_action_scores": risk_payload.get("post_action_scores", []),
            "score_range": [0.0, 3.0],
            "score_semantics": dict(POST_ACTION_SCORE_SEMANTICS),
            "generated_at": utc_now_iso(),
            "window_seconds": since_seconds,
            "decision_affecting": False,
        }
        self._observe_reporting_io("report_session_post_action", time.perf_counter() - start)
        payload.update(self._reporting_state())
        payload.update(self._reporting_io_state())
        return payload

    def create_l3_evidence_snapshot(
        self,
        *,
        session_id: str,
        trigger_event_id: str,
        trigger_reason: str,
        trigger_detail: str | None = None,
        to_record_id: int | None = None,
        from_record_id: int | None = None,
        max_records: int = 50,
        max_tool_calls: int = 4,
    ) -> dict[str, Any]:
        snapshot = self.trajectory_store.create_l3_evidence_snapshot(
            session_id=session_id,
            trigger_event_id=trigger_event_id,
            trigger_reason=trigger_reason,
            trigger_detail=trigger_detail,
            to_record_id=to_record_id,
            from_record_id=from_record_id,
            max_records=max_records,
            max_tool_calls=max_tool_calls,
        )
        self.event_bus.broadcast({
            "type": "l3_advisory_snapshot",
            "session_id": session_id,
            "snapshot_id": snapshot["snapshot_id"],
            "trigger_event_id": trigger_event_id,
            "trigger_reason": trigger_reason,
            "trigger_detail": trigger_detail,
            "event_range": snapshot["event_range"],
            "advisory_only": True,
            "canonical_decision_mutated": False,
            "timestamp": snapshot["created_at"],
        })
        return snapshot

    def record_l3_advisory_review(
        self,
        *,
        snapshot_id: str,
        risk_level: str,
        findings: list[str] | None = None,
        confidence: float | None = None,
        recommended_operator_action: str = "inspect",
        advisory_only: bool = True,
        l3_state: str = "completed",
        l3_reason_code: str | None = None,
        extra_fields: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        review = self.trajectory_store.record_l3_advisory_review(
            snapshot_id=snapshot_id,
            risk_level=risk_level,
            findings=findings,
            confidence=confidence,
            recommended_operator_action=recommended_operator_action,
            advisory_only=advisory_only,
            l3_state=l3_state,
            l3_reason_code=l3_reason_code,
            extra_fields=extra_fields,
        )
        self.event_bus.broadcast({
            "type": "l3_advisory_review",
            "session_id": review["session_id"],
            "snapshot_id": snapshot_id,
            "review_id": review["review_id"],
            "risk_level": review["risk_level"],
            "recommended_operator_action": review["recommended_operator_action"],
            "l3_state": review["l3_state"],
            "l3_reason_code": review.get("l3_reason_code"),
            "advisory_only": True,
            "canonical_decision_mutated": False,
            "timestamp": review["created_at"],
            **_copy_l3_narrative_fields(review),
        })
        self._broadcast_l3_advisory_action(review)
        return review

    def update_l3_advisory_review(
        self,
        review_id: str,
        *,
        risk_level: str | None = None,
        findings: list[str] | None = None,
        confidence: float | None = None,
        recommended_operator_action: str | None = None,
        l3_state: str | None = None,
        l3_reason_code: str | None = None,
        extra_fields: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        review = self.trajectory_store.update_l3_advisory_review(
            review_id,
            risk_level=risk_level,
            findings=findings,
            confidence=confidence,
            recommended_operator_action=recommended_operator_action,
            l3_state=l3_state,
            l3_reason_code=l3_reason_code,
            extra_fields=extra_fields,
        )
        self.event_bus.broadcast({
            "type": "l3_advisory_review",
            "session_id": review["session_id"],
            "snapshot_id": review["snapshot_id"],
            "review_id": review["review_id"],
            "risk_level": review["risk_level"],
            "recommended_operator_action": review["recommended_operator_action"],
            "l3_state": review["l3_state"],
            "l3_reason_code": review.get("l3_reason_code"),
            "advisory_only": True,
            "canonical_decision_mutated": False,
            "timestamp": review.get("completed_at") or review["created_at"],
            **_copy_l3_narrative_fields(review),
        })
        self._broadcast_l3_advisory_action(review)
        return review

    def run_local_l3_advisory_review(self, *, snapshot_id: str) -> dict[str, Any]:
        review = self.trajectory_store.run_local_l3_advisory_review(snapshot_id)
        self.event_bus.broadcast({
            "type": "l3_advisory_review",
            "session_id": review["session_id"],
            "snapshot_id": review["snapshot_id"],
            "review_id": review["review_id"],
            "risk_level": review["risk_level"],
            "recommended_operator_action": review["recommended_operator_action"],
            "l3_state": review["l3_state"],
            "l3_reason_code": review.get("l3_reason_code"),
            "advisory_only": True,
            "canonical_decision_mutated": False,
            "timestamp": review.get("completed_at") or review["created_at"],
            **_copy_l3_narrative_fields(review),
        })
        self._broadcast_l3_advisory_action(review)
        return review

    def enqueue_l3_advisory_job(
        self,
        *,
        snapshot_id: str,
        runner: str = DEFAULT_L3_ADVISORY_RUNNER,
    ) -> dict[str, Any]:
        _validate_public_l3_advisory_runner(runner)
        job = self.trajectory_store.enqueue_l3_advisory_job(
            snapshot_id,
            runner=runner,
        )
        self.event_bus.broadcast({
            "type": "l3_advisory_job",
            "session_id": job["session_id"],
            "snapshot_id": job["snapshot_id"],
            "job_id": job["job_id"],
            "job_state": job["job_state"],
            "runner": job["runner"],
            "advisory_only": True,
            "canonical_decision_mutated": False,
            "timestamp": job["updated_at"],
        })
        return job

    def run_l3_advisory_job_local(self, *, job_id: str) -> dict[str, Any]:
        result = self.trajectory_store.run_l3_advisory_job_local(job_id)
        job = result["job"]
        review = result["review"]
        self.event_bus.broadcast({
            "type": "l3_advisory_job",
            "session_id": job["session_id"],
            "snapshot_id": job["snapshot_id"],
            "job_id": job["job_id"],
            "job_state": job["job_state"],
            "runner": job["runner"],
            "review_id": job.get("review_id"),
            "advisory_only": True,
            "canonical_decision_mutated": False,
            "timestamp": job["updated_at"],
        })
        self.event_bus.broadcast({
            "type": "l3_advisory_review",
            "session_id": review["session_id"],
            "snapshot_id": review["snapshot_id"],
            "review_id": review["review_id"],
            "risk_level": review["risk_level"],
            "recommended_operator_action": review["recommended_operator_action"],
            "l3_state": review["l3_state"],
            "advisory_only": True,
            "canonical_decision_mutated": False,
            "timestamp": review.get("completed_at") or review["created_at"],
            **_copy_l3_narrative_fields(review),
        })
        action = self._l3_advisory_action_for_review(review, job=job)
        self._broadcast_l3_advisory_action(review, job=job)
        return {**result, "action": action, "advisory_only": True, "canonical_decision_mutated": False}

    def run_l3_advisory_worker(
        self,
        *,
        job_id: str,
        worker_name: str,
    ) -> dict[str, Any]:
        from .l3_advisory_worker import (
            FakeLLMAdvisoryWorker,
            LLMProviderAdvisoryWorker,
            run_l3_advisory_worker_job,
        )

        workers = {
            FakeLLMAdvisoryWorker.runner_name: FakeLLMAdvisoryWorker(),
            LLMProviderAdvisoryWorker.runner_name: LLMProviderAdvisoryWorker(),
        }
        worker = workers.get(worker_name)
        if worker is None:
            raise ValueError(f"unsupported advisory worker {worker_name!r}")
        job = self.trajectory_store.get_l3_advisory_job(job_id)
        if job is None:
            raise ValueError(f"job {job_id!r} was not found")
        if job.get("runner") != worker.runner_name:
            raise ValueError(
                f"job runner {job.get('runner')!r} does not match worker {worker.runner_name!r}"
            )

        result = run_l3_advisory_worker_job(
            store=self.trajectory_store,
            job_id=job_id,
            worker=worker,
        )
        job = result["job"]
        review = result["review"]
        self.event_bus.broadcast({
            "type": "l3_advisory_job",
            "session_id": job["session_id"],
            "snapshot_id": job["snapshot_id"],
            "job_id": job["job_id"],
            "job_state": job["job_state"],
            "runner": job["runner"],
            "review_id": job.get("review_id"),
            "advisory_only": True,
            "canonical_decision_mutated": False,
            "timestamp": job["updated_at"],
        })
        self.event_bus.broadcast({
            "type": "l3_advisory_review",
            "session_id": review["session_id"],
            "snapshot_id": review["snapshot_id"],
            "review_id": review["review_id"],
            "risk_level": review["risk_level"],
            "recommended_operator_action": review["recommended_operator_action"],
            "l3_state": review["l3_state"],
            "advisory_only": True,
            "canonical_decision_mutated": False,
            "timestamp": review.get("completed_at") or review["created_at"],
            **_copy_l3_narrative_fields(review),
        })
        action = self._l3_advisory_action_for_review(review, job=job)
        self._broadcast_l3_advisory_action(review, job=job)
        return {**result, "action": action, "advisory_only": True, "canonical_decision_mutated": False}

    def list_l3_advisory_jobs(
        self,
        *,
        session_id: str | None = None,
        state: str | None = None,
        runner: str | None = None,
    ) -> dict[str, Any]:
        jobs = self.trajectory_store.list_l3_advisory_jobs(
            session_id=session_id,
            job_state=state,
            runner=runner,
        )
        return {
            "jobs": jobs,
            "count": len(jobs),
            "advisory_only": True,
            "canonical_decision_mutated": False,
        }

    def run_next_l3_advisory_job(
        self,
        *,
        runner: str = DEFAULT_L3_ADVISORY_RUNNER,
        session_id: str | None = None,
        dry_run: bool = False,
    ) -> dict[str, Any]:
        _validate_public_l3_advisory_runner(runner)
        queued = self.trajectory_store.list_l3_advisory_jobs(
            session_id=session_id,
            job_state="queued",
            runner=runner,
        )
        selected = queued[0] if queued else None
        if dry_run:
            return {
                "selected_jobs": [selected] if selected else [],
                "result": None,
                "ran_count": 0,
                "dry_run": True,
                "advisory_only": True,
                "canonical_decision_mutated": False,
            }
        if selected is None:
            return {
                "selected_jobs": [],
                "result": None,
                "ran_count": 0,
                "dry_run": False,
                "advisory_only": True,
                "canonical_decision_mutated": False,
            }
        if runner == "deterministic_local":
            result = self.run_l3_advisory_job_local(job_id=selected["job_id"])
        else:
            result = self.run_l3_advisory_worker(
                job_id=selected["job_id"],
                worker_name=runner,
            )
        return {
            "selected_jobs": [selected],
            "result": result,
            "ran_count": 1,
            "dry_run": False,
            "advisory_only": True,
            "canonical_decision_mutated": False,
        }

    def drain_l3_advisory_jobs(
        self,
        *,
        runner: str = DEFAULT_L3_ADVISORY_RUNNER,
        session_id: str | None = None,
        max_jobs: int = 1,
        dry_run: bool = False,
    ) -> dict[str, Any]:
        _validate_public_l3_advisory_runner(runner)
        if max_jobs < 1 or max_jobs > 10:
            raise ValueError("max_jobs must be between 1 and 10")
        queued = self.trajectory_store.list_l3_advisory_jobs(
            session_id=session_id,
            job_state="queued",
            runner=runner,
        )
        selected = queued[:max_jobs]
        if dry_run:
            return {
                "selected_jobs": selected,
                "results": [],
                "ran_count": 0,
                "max_jobs": max_jobs,
                "dry_run": True,
                "advisory_only": True,
                "canonical_decision_mutated": False,
            }

        results: list[dict[str, Any]] = []
        for _ in range(max_jobs):
            next_result = self.run_next_l3_advisory_job(
                runner=runner,
                session_id=session_id,
                dry_run=False,
            )
            if next_result.get("ran_count") != 1 or next_result.get("result") is None:
                break
            results.append(next_result["result"])
        return {
            "selected_jobs": selected,
            "results": results,
            "ran_count": len(results),
            "max_jobs": max_jobs,
            "dry_run": False,
            "advisory_only": True,
            "canonical_decision_mutated": False,
        }

    def run_operator_l3_full_review(
        self,
        *,
        session_id: str,
        trigger_event_id: str,
        trigger_detail: str | None = None,
        from_record_id: int | None = None,
        to_record_id: int | None = None,
        max_records: int = 100,
        max_tool_calls: int = 0,
        runner: str = DEFAULT_L3_ADVISORY_RUNNER,
        run: bool = True,
    ) -> dict[str, Any]:
        _validate_public_l3_advisory_runner(runner)
        snapshot = self.create_l3_evidence_snapshot(
            session_id=session_id,
            trigger_event_id=trigger_event_id,
            trigger_reason="operator_full_review",
            trigger_detail=trigger_detail or "operator_requested_full_review",
            from_record_id=from_record_id,
            to_record_id=to_record_id,
            max_records=max_records,
            max_tool_calls=max_tool_calls,
        )
        job = self.enqueue_l3_advisory_job(
            snapshot_id=snapshot["snapshot_id"],
            runner=runner,
        )
        review = None
        completed_job = job
        if run:
            if runner == "deterministic_local":
                result = self.run_l3_advisory_job_local(job_id=job["job_id"])
            else:
                result = self.run_l3_advisory_worker(
                    job_id=job["job_id"],
                    worker_name=runner,
                )
            completed_job = result["job"]
            review = result["review"]
        return {
            "snapshot": snapshot,
            "job": completed_job,
            "review": review,
            "action": self._l3_advisory_action_for_review(review, job=completed_job),
            "advisory_only": True,
            "canonical_decision_mutated": False,
        }

    @staticmethod
    def _is_l3_heartbeat_compatible_event(compat_event_type: str | None) -> str | None:
        compat = str(compat_event_type or "").strip().lower()
        if compat in {"heartbeat", "idle", "success", "rate_limit"}:
            return compat
        return None

    def _heartbeat_backlog_exists(
        self,
        *,
        session_id: str,
        runner: str,
    ) -> bool:
        for job in self.trajectory_store.list_l3_advisory_jobs(
            session_id=session_id,
            runner=runner,
        ):
            if job.get("job_state") not in {"queued", "running"}:
                continue
            snapshot = self.trajectory_store.get_l3_evidence_snapshot(
                str(job.get("snapshot_id") or "")
            )
            if snapshot and snapshot.get("trigger_reason") == "heartbeat_aggregate":
                return True
        return False

    def _latest_terminal_heartbeat_review_to_record(self, *, session_id: str) -> int:
        latest_to_record = 0
        for review in self.trajectory_store.list_l3_advisory_reviews(session_id=session_id):
            if str(review.get("l3_state") or "") not in {"completed", "failed", "degraded"}:
                continue
            snapshot = self.trajectory_store.get_l3_evidence_snapshot(
                str(review.get("snapshot_id") or "")
            )
            if not snapshot or snapshot.get("trigger_reason") != "heartbeat_aggregate":
                continue
            event_range = snapshot.get("event_range") or {}
            latest_to_record = max(latest_to_record, int(event_range.get("to_record_id") or 0))
        return latest_to_record

    def _has_high_risk_evidence_delta(
        self,
        *,
        session_id: str,
        from_record_id: int,
        to_record_id: int,
    ) -> bool:
        records = self.trajectory_store._query_records_by_id_range(
            session_id=session_id,
            from_record_id=max(from_record_id, 1),
            to_record_id=to_record_id,
        )
        for record in records:
            risk_level = str(
                record.get("decision", {}).get("risk_level")
                or record.get("risk_snapshot", {}).get("risk_level")
                or "low"
            ).lower()
            if risk_level in HIGH_RISK_LEVELS:
                return True
        return False

    def maybe_create_l3_heartbeat_advisory_snapshot(
        self,
        *,
        config: DetectionConfig,
        session_id: str,
        event_id: str,
        record_id: int,
        compat_event_type: str | None,
        runner: str = "deterministic_local",
    ) -> dict[str, Any] | None:
        """Queue one heartbeat aggregate advisory job when flags and evidence allow it."""

        compat = self._is_l3_heartbeat_compatible_event(compat_event_type)
        if compat is None:
            return None
        if not config.l3_advisory_async_enabled or not config.l3_heartbeat_review_enabled:
            return None
        if not session_id or record_id <= 0:
            return None
        if self._heartbeat_backlog_exists(session_id=session_id, runner=runner):
            return None

        last_terminal_to = self._latest_terminal_heartbeat_review_to_record(session_id=session_id)
        from_record_id = last_terminal_to + 1 if last_terminal_to > 0 else 1
        if record_id < from_record_id:
            return None
        if not self._has_high_risk_evidence_delta(
            session_id=session_id,
            from_record_id=from_record_id,
            to_record_id=record_id,
        ):
            return None

        try:
            snapshot = self.create_l3_evidence_snapshot(
                session_id=session_id,
                trigger_event_id=event_id,
                trigger_reason="heartbeat_aggregate",
                trigger_detail=f"{compat}_delta",
                from_record_id=from_record_id,
                to_record_id=record_id,
            )
            self.enqueue_l3_advisory_job(
                snapshot_id=snapshot["snapshot_id"],
                runner=runner,
            )
            return snapshot
        except Exception:
            logger.exception(
                "failed to create L3 heartbeat advisory snapshot for session %s event %s",
                session_id,
                event_id,
            )
            return None

    def _maybe_create_l3_advisory_snapshot(
        self,
        *,
        config: DetectionConfig,
        session_id: str,
        event_id: str,
        record_id: int,
        current_risk_level: str,
        pending_trajectory_alerts: list[dict[str, Any]],
        compat_event_type: str | None = None,
    ) -> dict[str, Any] | None:
        if not config.l3_advisory_async_enabled:
            return None
        if not session_id or record_id <= 0:
            return None

        heartbeat_snapshot = self.maybe_create_l3_heartbeat_advisory_snapshot(
            config=config,
            session_id=session_id,
            event_id=event_id,
            record_id=record_id,
            compat_event_type=compat_event_type,
        )
        if heartbeat_snapshot is not None:
            return heartbeat_snapshot
        if config.l3_heartbeat_review_enabled and self._is_l3_heartbeat_compatible_event(compat_event_type) is None:
            # When heartbeat aggregation is explicitly enabled, non-compat
            # high-risk records become evidence deltas for the next heartbeat;
            # they do not start a hidden scheduler-like queue by themselves.
            return None

        trigger_reason: str | None = None
        trigger_detail: str | None = None
        for alert in pending_trajectory_alerts:
            if _risk_rank(str(alert.get("risk_level") or "low")) >= _risk_rank("high"):
                trigger_reason = "trajectory_alert"
                trigger_detail = str(alert.get("sequence_id") or alert.get("reason") or "").strip() or None
                break

        if trigger_reason is None and _risk_rank(current_risk_level) >= _risk_rank("high"):
            trigger_reason = "threshold"

        if trigger_reason is None:
            return None

        try:
            snapshot = self.create_l3_evidence_snapshot(
                session_id=session_id,
                trigger_event_id=event_id,
                trigger_reason=trigger_reason,
                trigger_detail=trigger_detail,
                to_record_id=record_id,
            )
            self.enqueue_l3_advisory_job(snapshot_id=snapshot["snapshot_id"])
            return snapshot
        except Exception:
            logger.exception(
                "failed to create L3 advisory evidence snapshot for session %s event %s",
                session_id,
                event_id,
            )
            return None

    def report_alerts(
        self,
        *,
        severity: Optional[str] = None,
        acknowledged: Optional[bool] = None,
        window_seconds: Optional[int] = None,
        limit: int = 100,
    ) -> dict[str, Any]:
        start = time.perf_counter()
        since_seconds = window_seconds if window_seconds and window_seconds > 0 else None
        effective_limit = min(max(limit, 1), 1000)
        result = self.alert_registry.list_alerts(
            severity=severity,
            acknowledged=acknowledged,
            since_seconds=since_seconds,
            limit=effective_limit,
        )
        result["generated_at"] = utc_now_iso()
        result["window_seconds"] = since_seconds
        result.update(self._reporting_state())
        self._observe_reporting_io("report_alerts", time.perf_counter() - start)
        result.update(self._reporting_io_state())
        return result

    def acknowledge_alert(
        self,
        alert_id: str,
        acknowledged_by: str,
    ) -> Optional[dict[str, Any]]:
        return self.alert_registry.acknowledge(alert_id, acknowledged_by)

    # --- JSON-RPC helpers ---

    @staticmethod
    def _jsonrpc_success(rpc_id: Any, result: Any) -> dict[str, Any]:
        return {"jsonrpc": JSONRPC_VERSION, "id": rpc_id, "result": result}

    @staticmethod
    def _jsonrpc_error(
        rpc_id: Any, code: int, message: str, data: Any = None,
    ) -> dict[str, Any]:
        error: dict[str, Any] = {"code": code, "message": message}
        if data is not None:
            error["data"] = data
        return {"jsonrpc": JSONRPC_VERSION, "id": rpc_id, "error": error}

    @staticmethod
    def _jsonrpc_error_with_data(
        rpc_id: Any, code: int, error_resp: SyncDecisionErrorResponse,
    ) -> dict[str, Any]:
        return SupervisionGateway._jsonrpc_error(
            rpc_id, code,
            error_resp.rpc_error_message,
            error_resp.model_dump(mode="json"),
        )


# ---------------------------------------------------------------------------
# HTTP Transport (FastAPI)
# ---------------------------------------------------------------------------

class _RateLimiter:
    """Simple sliding-window rate limiter per client identifier."""

    _MAX_CLIENTS = 10_000  # Prevent unbounded memory growth

    def __init__(self, max_requests: int, window_seconds: float):
        self._max = max_requests
        self._window = window_seconds
        self._buckets: dict[str, list[float]] = {}

    def check(self, client_id: str) -> bool:
        """Return True if allowed, False if rate limited."""
        now = time.monotonic()
        bucket = self._buckets.setdefault(client_id, [])
        bucket[:] = [t for t in bucket if now - t < self._window]
        if len(bucket) >= self._max:
            return False
        bucket.append(now)
        # Evict stale clients to prevent unbounded growth
        if len(self._buckets) > self._MAX_CLIENTS:
            oldest_key = next(iter(self._buckets))
            del self._buckets[oldest_key]
        return True


def _find_and_reload_pattern_matcher(analyzer) -> bool:
    """Traverse analyzer hierarchy to find and reload PatternMatcher.

    Works with both RuleBasedAnalyzer (direct _pattern_matcher) and
    CompositeAnalyzer (nested _analyzers list).
    """
    if hasattr(analyzer, '_pattern_matcher'):
        analyzer._pattern_matcher.reload()
        return True
    if hasattr(analyzer, '_analyzers'):
        for a in analyzer._analyzers:
            if hasattr(a, '_pattern_matcher'):
                a._pattern_matcher.reload()
                return True
    return False


def create_http_app(
    gateway: SupervisionGateway,
    *,
    ui_dir: Path | None = None,
) -> FastAPI:
    """Create FastAPI application for the HTTP transport."""
    app = FastAPI(title="AHP Supervision Gateway", version="1.0")

    auth_token = _read_auth_token()
    if not auth_token:
        logger.warning(
            "CS_AUTH_TOKEN not set — HTTP endpoints are UNAUTHENTICATED. "
            "Set CS_AUTH_TOKEN for production deployments."
        )
    elif len(auth_token) < 32:
        logger.warning(
            "CS_AUTH_TOKEN is shorter than 32 chars — "
            "consider using a stronger token for production."
        )

    verify_auth = _make_auth_dependency(auth_token)
    report_event_types = {
        "decision",
        "session_risk_change",
        "session_start",
        "alert",
        "session_enforcement_change",
        "post_action_finding",
        "trajectory_alert",
        "pattern_candidate",
        "pattern_evolved",
        "defer_pending",
        "defer_resolved",
        "budget_exhausted",
        "l3_advisory_snapshot",
        "l3_advisory_review",
        "l3_advisory_job",
        "l3_advisory_action",
        "adapter_effect_result",
    }
    enterprise_enabled = enterprise_mode_enabled()

    def _enterprise_get(path: str, **kwargs):
        def decorator(func):
            if enterprise_enabled:
                app.get(path, **kwargs)(func)
            return func

        return decorator

    # Rate limiter (0 = disabled)
    rate_limit_per_min = int(os.getenv("CS_RATE_LIMIT_PER_MINUTE", "300"))
    rate_limiter: _RateLimiter | None = None
    if rate_limit_per_min > 0:
        rate_limiter = _RateLimiter(max_requests=rate_limit_per_min, window_seconds=60.0)

    def _check_rate_limit(request: Request) -> Response | None:
        if rate_limiter is None:
            return None
        client_ip = request.client.host if request.client else "unknown"
        if not rate_limiter.check(client_ip):
            error_resp = SyncDecisionErrorResponse(
                request_id="rate-limited",
                rpc_error_code=RPCErrorCode.RATE_LIMITED,
                rpc_error_message="Rate limit exceeded",
                retry_eligible=True,
                retry_after_ms=1000,
            )
            return Response(
                content=json.dumps(error_resp.model_dump()),
                status_code=429,
                media_type="application/json",
            )
        return None

    @app.post("/ahp")
    async def ahp_endpoint(request: Request):
        auth_result = await verify_auth(request)
        if isinstance(auth_result, Response):
            return auth_result
        rl_result = _check_rate_limit(request)
        if rl_result is not None:
            return rl_result
        body = await request.body()
        if len(body) > 10 * 1024 * 1024:
            return Response(
                content=json.dumps({"error": "Payload too large"}),
                status_code=413,
                media_type="application/json",
            )
        result = await gateway.handle_jsonrpc(body)
        return Response(
            content=json.dumps(result),
            media_type="application/json",
        )

    @app.post("/ahp/adapter-effect-result")
    async def adapter_effect_result_endpoint(request: Request):
        auth_result = await verify_auth(request)
        if isinstance(auth_result, Response):
            return auth_result
        rl_result = _check_rate_limit(request)
        if rl_result is not None:
            return rl_result
        try:
            body = await request.json()
            result = gateway.record_adapter_effect_result(body)
        except ValidationError as exc:
            return Response(
                content=json.dumps({"error": f"adapter effect result validation failed: {exc.error_count()} error(s)"}),
                status_code=400,
                media_type="application/json",
            )
        except Exception as exc:  # noqa: BLE001
            logger.exception("adapter effect result writeback failed")
            return Response(
                content=json.dumps({"error": f"adapter effect result writeback failed: {exc}"}),
                status_code=500,
                media_type="application/json",
            )
        return Response(
            content=json.dumps(result),
            media_type="application/json",
        )

    @app.post("/ahp/scope/preview")
    async def scope_preview_endpoint(request: Request):
        auth_result = await verify_auth(request)
        if isinstance(auth_result, Response):
            return auth_result
        rl_result = _check_rate_limit(request)
        if rl_result is not None:
            return rl_result
        try:
            body = await request.json()
            profile = SessionScopeProfile.model_validate(body.get("profile"))
            if body.get("confirm") is True:
                profile = profile.model_copy(update={"confirmed": True, "dry_run": False})
            event = CanonicalEvent.model_validate(body.get("event"))
            evaluation = evaluate_session_scope(
                event,
                DecisionContext(session_scope_profile=profile),
            )
        except ValidationError as exc:
            return Response(
                content=json.dumps({"error": f"scope preview validation failed: {exc.error_count()} error(s)"}),
                status_code=400,
                media_type="application/json",
            )
        except Exception as exc:  # noqa: BLE001
            return Response(
                content=json.dumps({"error": f"scope preview failed: {exc}"}),
                status_code=400,
                media_type="application/json",
            )

        summary = evaluation.summary().model_dump(mode="json") if evaluation else None
        enforced = bool(summary and summary.get("enforced"))
        return {
            "valid": True,
            "mode": "enforced" if enforced else "dry_run_only",
            "profile_id": profile.profile_id,
            "scope_evaluation": summary,
            "protection_statement": scope_protection_statement(enforced=enforced),
        }

    # --- a3s-code HTTP transport (B-1) ---
    from ..adapters.a3s_adapter import InProcessA3SAdapter
    from ..adapters.a3s_gateway_harness import A3SGatewayHarness

    _a3s_adapter = InProcessA3SAdapter(gateway)
    _a3s_harness = A3SGatewayHarness(_a3s_adapter)

    @app.post("/ahp/a3s")
    async def ahp_a3s_endpoint(request: Request):
        auth_result = await verify_auth(request)
        if isinstance(auth_result, Response):
            return auth_result
        rl_result = _check_rate_limit(request)
        if rl_result is not None:
            return rl_result

        body_bytes = await request.body()
        if len(body_bytes) > 10 * 1024 * 1024:
            return Response(
                content=json.dumps({"error": "Payload too large"}),
                status_code=413,
                media_type="application/json",
            )
        try:
            body = json.loads(body_bytes.decode("utf-8"))
        except Exception:
            return Response(
                content=json.dumps({"error": "invalid JSON body"}),
                status_code=400,
                media_type="application/json",
            )
        response = await _a3s_harness.dispatch_async(body)
        if response is None:
            return Response(status_code=204)
        return response

    # --- Codex HTTP transport (E-9 Phase 2) ---
    from ..adapters.codex_adapter import CodexAdapter
    _codex_adapter = CodexAdapter()
    _codex_in_process = InProcessA3SAdapter(gateway)

    @app.post("/ahp/codex")
    async def ahp_codex_endpoint(request: Request):
        auth_result = await verify_auth(request)
        if isinstance(auth_result, Response):
            return auth_result
        rl_result = _check_rate_limit(request)
        if rl_result is not None:
            return rl_result
        try:
            body = await request.json()
        except Exception:
            return Response(
                content=json.dumps({"error": "invalid JSON body"}),
                status_code=400,
                media_type="application/json",
            )

        event = _codex_adapter.normalize_hook_event(
            hook_type=body.get("event_type", ""),
            payload=body.get("payload", {}),
            session_id=body.get("session_id"),
            agent_id=body.get("agent_id"),
        )
        if event is None:
            return {"result": {"action": "continue", "reason": "unrecognized event type"}}

        # Route through in-process Gateway evaluation
        try:
            decision = await _codex_in_process.request_decision(event)
            return {"result": {
                "action": decision.decision.value,
                "reason": decision.reason,
                "risk_level": decision.risk_level.value,
            }}
        except Exception:
            logger.exception("Codex endpoint evaluation failed")
            # Fail-closed: block on evaluation error to prevent unsafe operations
            return {"result": {"action": "block", "reason": "evaluation error (fail-closed)"}}

    @app.get("/health")
    async def health_endpoint():
        return gateway.health()

    @_enterprise_get("/enterprise/health")
    async def enterprise_health_endpoint(request: Request):
        auth_result = await verify_auth(request)
        if isinstance(auth_result, Response):
            return auth_result
        return await enrich_health_payload_async(gateway.health(), gateway)

    # --- P3: Prometheus /metrics endpoint ---
    _metrics_auth_enabled = os.getenv("CS_METRICS_AUTH", "").lower() in ("1", "true", "yes")

    @app.get("/metrics")
    async def metrics_endpoint(request: Request):
        if _metrics_auth_enabled:
            auth_result = await verify_auth(request)
            if isinstance(auth_result, Response):
                return auth_result
        data = gateway.metrics.generate_metrics_text()
        return Response(
            content=data,
            media_type="text/plain; version=0.0.4; charset=utf-8",
        )

    @app.get("/report/summary")
    async def report_summary_endpoint(request: Request, window_seconds: Optional[int] = None):
        auth_result = await verify_auth(request)
        if isinstance(auth_result, Response):
            return auth_result
        if window_seconds is not None and (window_seconds < 1 or window_seconds > MAX_WINDOW_SECONDS):
            return Response(
                content=json.dumps({"error": f"window_seconds must be between 1 and {MAX_WINDOW_SECONDS}"}),
                status_code=400,
                media_type="application/json",
            )
        return gateway.report_summary(window_seconds=window_seconds)

    @_enterprise_get("/enterprise/report/summary")
    async def enterprise_report_summary_endpoint(
        request: Request,
        window_seconds: Optional[int] = None,
    ):
        auth_result = await verify_auth(request)
        if isinstance(auth_result, Response):
            return auth_result
        if window_seconds is not None and (window_seconds < 1 or window_seconds > MAX_WINDOW_SECONDS):
            return Response(
                content=json.dumps({"error": f"window_seconds must be between 1 and {MAX_WINDOW_SECONDS}"}),
                status_code=400,
                media_type="application/json",
            )
        return await enrich_summary_payload_async(
            gateway.report_summary(window_seconds=window_seconds),
            gateway,
            window_seconds=window_seconds,
        )

    @_enterprise_get("/enterprise/report/live")
    async def enterprise_report_live_endpoint(request: Request, cached: bool = False):
        auth_result = await verify_auth(request)
        if isinstance(auth_result, Response):
            return auth_result
        if cached:
            return await build_enterprise_live_snapshot_cached_async(gateway)
        return await build_enterprise_live_snapshot_cached_async(gateway, force_refresh=True)

    @app.get("/report/stream")
    async def report_stream_endpoint(
        request: Request,
        session_id: Optional[str] = None,
        min_risk: Optional[str] = None,
        types: Optional[str] = None,
    ):
        auth_result = await verify_auth(request)
        if isinstance(auth_result, Response):
            return auth_result
        if min_risk is not None and min_risk not in {"low", "medium", "high", "critical"}:
            return Response(
                content=json.dumps({"error": "min_risk must be one of: low, medium, high, critical"}),
                status_code=400,
                media_type="application/json",
            )

        event_types = set(report_event_types)
        if types:
            requested_types = {item.strip() for item in types.split(",") if item.strip()}
            if not requested_types or not requested_types.issubset(event_types):
                return Response(
                    content=json.dumps({"error": "types must be a comma-separated subset of: decision, session_risk_change, session_start, alert, session_enforcement_change, post_action_finding, trajectory_alert, pattern_candidate, pattern_evolved, defer_pending, defer_resolved, adapter_effect_result, budget_exhausted, l3_advisory_snapshot, l3_advisory_review, l3_advisory_job, l3_advisory_action"}),
                    status_code=400,
                    media_type="application/json",
                )
            event_types = requested_types

        subscriber_id, queue = gateway.event_bus.subscribe(
            session_id=session_id,
            min_risk=min_risk,
            event_types=event_types,
        )
        if subscriber_id is None or queue is None:
            return Response(
                content=json.dumps({"error": "Too many SSE subscribers"}),
                status_code=503,
                media_type="application/json",
            )

        async def event_generator():
            yield ": connected\n\n"  # Immediately flush headers to client
            try:
                while True:
                    try:
                        event = await asyncio.wait_for(queue.get(), timeout=15.0)
                        event_type = str(event.get("type") or "message")
                        # Keep "type" in data payload so clients that only parse data: lines
                        # (e.g. urllib-based watch CLI) can still dispatch on event type.
                        payload = {**event, "type": event_type}
                        yield f"event: {event_type}\ndata: {json.dumps(payload)}\n\n"
                    except asyncio.TimeoutError:
                        yield ": keepalive\n\n"
            finally:
                gateway.event_bus.unsubscribe(subscriber_id)

        return StreamingResponse(event_generator(), media_type="text/event-stream")

    @_enterprise_get("/enterprise/report/stream")
    async def enterprise_report_stream_endpoint(
        request: Request,
        session_id: Optional[str] = None,
        min_risk: Optional[str] = None,
        types: Optional[str] = None,
    ):
        auth_result = await verify_auth(request)
        if isinstance(auth_result, Response):
            return auth_result
        if min_risk is not None and min_risk not in {"low", "medium", "high", "critical"}:
            return Response(
                content=json.dumps({"error": "min_risk must be one of: low, medium, high, critical"}),
                status_code=400,
                media_type="application/json",
            )

        event_types = set(report_event_types)
        if types:
            requested_types = {item.strip() for item in types.split(",") if item.strip()}
            if not requested_types or not requested_types.issubset(event_types):
                return Response(
                    content=json.dumps({"error": "types must be a comma-separated subset of: decision, session_risk_change, session_start, alert, session_enforcement_change, post_action_finding, trajectory_alert, pattern_candidate, pattern_evolved, defer_pending, defer_resolved, adapter_effect_result, budget_exhausted, l3_advisory_snapshot, l3_advisory_review, l3_advisory_job, l3_advisory_action"}),
                    status_code=400,
                    media_type="application/json",
                )
            event_types = requested_types

        subscriber_id, queue = gateway.event_bus.subscribe(
            session_id=session_id,
            min_risk=min_risk,
            event_types=event_types,
        )
        if subscriber_id is None or queue is None:
            return Response(
                content=json.dumps({"error": "Too many SSE subscribers"}),
                status_code=503,
                media_type="application/json",
            )

        async def event_generator():
            yield ": connected\n\n"
            try:
                while True:
                    try:
                        event = await asyncio.wait_for(queue.get(), timeout=15.0)
                        event_type = str(event.get("type") or "message")
                        payload = await build_enterprise_event_async({**event, "type": event_type}, gateway)
                        yield f"event: {event_type}\ndata: {json.dumps(payload)}\n\n"
                    except asyncio.TimeoutError:
                        yield ": keepalive\n\n"
            finally:
                gateway.event_bus.unsubscribe(subscriber_id)

        return StreamingResponse(event_generator(), media_type="text/event-stream")

    @app.get("/report/sessions")
    async def report_sessions_endpoint(
        request: Request,
        status: str = "active",
        sort: str = "risk_level",
        limit: int = 50,
        min_risk: Optional[str] = None,
        window_seconds: Optional[int] = None,
    ):
        auth_result = await verify_auth(request)
        if isinstance(auth_result, Response):
            return auth_result
        if window_seconds is not None and (window_seconds < 1 or window_seconds > MAX_WINDOW_SECONDS):
            return Response(
                content=json.dumps({"error": f"window_seconds must be between 1 and {MAX_WINDOW_SECONDS}"}),
                status_code=400,
                media_type="application/json",
            )
        if status not in {"active", "all"}:
            return Response(
                content=json.dumps({"error": "status must be one of: active, all"}),
                status_code=400,
                media_type="application/json",
            )
        if sort not in {"risk_level", "last_event"}:
            return Response(
                content=json.dumps({"error": "sort must be one of: risk_level, last_event"}),
                status_code=400,
                media_type="application/json",
            )
        if min_risk is not None and min_risk not in {"low", "medium", "high", "critical"}:
            return Response(
                content=json.dumps({"error": "min_risk must be one of: low, medium, high, critical"}),
                status_code=400,
                media_type="application/json",
            )
        effective_limit = min(max(limit, 1), 200)
        return gateway.report_sessions(
            status=status,
            sort=sort,
            limit=effective_limit,
            min_risk=min_risk,
            window_seconds=window_seconds,
        )

    @_enterprise_get("/enterprise/report/sessions")
    async def enterprise_report_sessions_endpoint(
        request: Request,
        status: str = "active",
        sort: str = "risk_level",
        limit: int = 50,
        min_risk: Optional[str] = None,
        window_seconds: Optional[int] = None,
    ):
        auth_result = await verify_auth(request)
        if isinstance(auth_result, Response):
            return auth_result
        if window_seconds is not None and (window_seconds < 1 or window_seconds > MAX_WINDOW_SECONDS):
            return Response(
                content=json.dumps({"error": f"window_seconds must be between 1 and {MAX_WINDOW_SECONDS}"}),
                status_code=400,
                media_type="application/json",
            )
        if status not in {"active", "all"}:
            return Response(
                content=json.dumps({"error": "status must be one of: active, all"}),
                status_code=400,
                media_type="application/json",
            )
        if sort not in {"risk_level", "last_event"}:
            return Response(
                content=json.dumps({"error": "sort must be one of: risk_level, last_event"}),
                status_code=400,
                media_type="application/json",
            )
        if min_risk is not None and min_risk not in {"low", "medium", "high", "critical"}:
            return Response(
                content=json.dumps({"error": "min_risk must be one of: low, medium, high, critical"}),
                status_code=400,
                media_type="application/json",
            )
        effective_limit = min(max(limit, 1), 5000)
        return await enrich_sessions_payload_async(
            gateway.report_sessions(
                status=status,
                sort=sort,
                limit=effective_limit,
                min_risk=min_risk,
                window_seconds=window_seconds,
                max_limit=5000,
            ),
            gateway,
        )

    @app.get("/report/session/{session_id}/risk")
    async def report_session_risk_endpoint(
        request: Request,
        session_id: str,
        limit: int = 100,
        window_seconds: Optional[int] = None,
    ):
        auth_result = await verify_auth(request)
        if isinstance(auth_result, Response):
            return auth_result
        if window_seconds is not None and (window_seconds < 1 or window_seconds > MAX_WINDOW_SECONDS):
            return Response(
                content=json.dumps({"error": f"window_seconds must be between 1 and {MAX_WINDOW_SECONDS}"}),
                status_code=400,
                media_type="application/json",
            )
        effective_limit = min(max(limit, 1), 1000)
        return gateway.report_session_risk(
            session_id=session_id,
            limit=effective_limit,
            window_seconds=window_seconds,
        )

    @app.get("/report/session/{session_id}/post-action")
    async def report_session_post_action_scores_endpoint(
        request: Request,
        session_id: str,
        limit: int = 100,
        window_seconds: Optional[int] = None,
    ):
        auth_result = await verify_auth(request)
        if isinstance(auth_result, Response):
            return auth_result
        if window_seconds is not None and (window_seconds < 1 or window_seconds > MAX_WINDOW_SECONDS):
            return Response(
                content=json.dumps({"error": f"window_seconds must be between 1 and {MAX_WINDOW_SECONDS}"}),
                status_code=400,
                media_type="application/json",
            )
        effective_limit = min(max(limit, 1), 1000)
        return gateway.report_session_post_action_scores(
            session_id=session_id,
            limit=effective_limit,
            window_seconds=window_seconds,
        )

    @app.post("/report/session/{session_id}/l3-advisory/snapshots")
    async def create_l3_advisory_snapshot_endpoint(
        request: Request,
        session_id: str,
        body: dict[str, Any],
    ):
        auth_result = await verify_auth(request)
        if isinstance(auth_result, Response):
            return auth_result
        try:
            snapshot = gateway.create_l3_evidence_snapshot(
                session_id=session_id,
                trigger_event_id=str(body.get("trigger_event_id") or ""),
                trigger_reason=str(body.get("trigger_reason") or "operator"),
                trigger_detail=(
                    str(body.get("trigger_detail"))
                    if body.get("trigger_detail") is not None
                    else None
                ),
                to_record_id=(
                    int(body["to_record_id"])
                    if body.get("to_record_id") is not None
                    else None
                ),
                from_record_id=(
                    int(body["from_record_id"])
                    if body.get("from_record_id") is not None
                    else None
                ),
                max_records=int(body.get("max_records") or 50),
                max_tool_calls=int(body.get("max_tool_calls") or 4),
            )
        except (TypeError, ValueError) as exc:
            return Response(
                content=json.dumps({"error": str(exc)}),
                status_code=400,
                media_type="application/json",
            )
        return {"snapshot": snapshot}

    @app.get("/report/session/{session_id}/l3-advisory/snapshots")
    async def list_l3_advisory_snapshots_endpoint(
        request: Request,
        session_id: str,
    ):
        auth_result = await verify_auth(request)
        if isinstance(auth_result, Response):
            return auth_result
        return {
            "session_id": session_id,
            "snapshots": gateway.trajectory_store.list_l3_evidence_snapshots(session_id=session_id),
        }

    @app.get("/report/l3-advisory/snapshot/{snapshot_id}")
    async def get_l3_advisory_snapshot_endpoint(
        request: Request,
        snapshot_id: str,
    ):
        auth_result = await verify_auth(request)
        if isinstance(auth_result, Response):
            return auth_result
        snapshot = gateway.trajectory_store.get_l3_evidence_snapshot(snapshot_id)
        if snapshot is None:
            return Response(
                content=json.dumps({"error": "snapshot not found"}),
                status_code=404,
                media_type="application/json",
            )
        return {
            "snapshot": snapshot,
            "records": gateway.trajectory_store.replay_l3_evidence_snapshot(snapshot_id),
        }

    @app.get("/report/l3-advisory/jobs")
    async def list_l3_advisory_jobs_endpoint(
        request: Request,
        session_id: Optional[str] = None,
        state: Optional[str] = None,
        runner: Optional[str] = None,
    ):
        auth_result = await verify_auth(request)
        if isinstance(auth_result, Response):
            return auth_result
        try:
            return gateway.list_l3_advisory_jobs(
                session_id=session_id,
                state=state,
                runner=runner,
            )
        except ValueError as exc:
            return Response(
                content=json.dumps({"error": str(exc)}),
                status_code=400,
                media_type="application/json",
            )

    @app.post("/report/l3-advisory/jobs/run-next")
    async def run_next_l3_advisory_job_endpoint(
        request: Request,
        body: dict[str, Any] | None = None,
    ):
        auth_result = await verify_auth(request)
        if isinstance(auth_result, Response):
            return auth_result
        body = body or {}
        try:
            return gateway.run_next_l3_advisory_job(
                runner=str(body.get("runner") or DEFAULT_L3_ADVISORY_RUNNER),
                session_id=(
                    str(body.get("session_id"))
                    if body.get("session_id") is not None
                    else None
                ),
                dry_run=bool(body.get("dry_run", False)),
            )
        except ValueError as exc:
            status_code = 404 if "was not found" in str(exc) else 400
            return Response(
                content=json.dumps({"error": str(exc)}),
                status_code=status_code,
                media_type="application/json",
            )

    @app.post("/report/l3-advisory/jobs/drain")
    async def drain_l3_advisory_jobs_endpoint(
        request: Request,
        body: dict[str, Any] | None = None,
    ):
        auth_result = await verify_auth(request)
        if isinstance(auth_result, Response):
            return auth_result
        body = body or {}
        try:
            return gateway.drain_l3_advisory_jobs(
                runner=str(body.get("runner") or DEFAULT_L3_ADVISORY_RUNNER),
                session_id=(
                    str(body.get("session_id"))
                    if body.get("session_id") is not None
                    else None
                ),
                max_jobs=int(body.get("max_jobs") or 1),
                dry_run=bool(body.get("dry_run", False)),
            )
        except (TypeError, ValueError) as exc:
            status_code = 404 if "was not found" in str(exc) else 400
            return Response(
                content=json.dumps({"error": str(exc)}),
                status_code=status_code,
                media_type="application/json",
            )

    @app.post("/report/l3-advisory/snapshot/{snapshot_id}/jobs")
    async def enqueue_l3_advisory_job_endpoint(
        request: Request,
        snapshot_id: str,
        body: dict[str, Any] | None = None,
    ):
        auth_result = await verify_auth(request)
        if isinstance(auth_result, Response):
            return auth_result
        try:
            job = gateway.enqueue_l3_advisory_job(
                snapshot_id=snapshot_id,
                runner=str((body or {}).get("runner") or DEFAULT_L3_ADVISORY_RUNNER),
            )
        except ValueError as exc:
            status_code = 404 if "was not found" in str(exc) else 400
            return Response(
                content=json.dumps({"error": str(exc)}),
                status_code=status_code,
                media_type="application/json",
            )
        return {"job": job}

    @app.post("/report/l3-advisory/reviews")
    async def create_l3_advisory_review_endpoint(
        request: Request,
        body: dict[str, Any],
    ):
        auth_result = await verify_auth(request)
        if isinstance(auth_result, Response):
            return auth_result
        try:
            review = gateway.record_l3_advisory_review(
                snapshot_id=str(body.get("snapshot_id") or ""),
                risk_level=str(body.get("risk_level") or "medium"),
                findings=[
                    str(item)
                    for item in (
                        body.get("findings")
                        if isinstance(body.get("findings"), list)
                        else []
                    )
                ],
                confidence=(
                    float(body["confidence"])
                    if body.get("confidence") is not None
                    else None
                ),
                recommended_operator_action=str(
                    body.get("recommended_operator_action") or "inspect"
                ),
                advisory_only=bool(body.get("advisory_only", True)),
                l3_state=str(body.get("l3_state") or "completed"),
                l3_reason_code=(
                    str(body.get("l3_reason_code"))
                    if body.get("l3_reason_code") is not None
                    else None
                ),
                extra_fields={
                    key: body[key]
                    for key in ("analysis_summary", "analysis_points", "operator_next_steps")
                    if key in body
                },
            )
        except (TypeError, ValueError) as exc:
            return Response(
                content=json.dumps({"error": str(exc)}),
                status_code=400,
                media_type="application/json",
            )
        return {"review": review}

    @app.patch("/report/l3-advisory/review/{review_id}")
    async def update_l3_advisory_review_endpoint(
        request: Request,
        review_id: str,
        body: dict[str, Any],
    ):
        auth_result = await verify_auth(request)
        if isinstance(auth_result, Response):
            return auth_result
        try:
            review = gateway.update_l3_advisory_review(
                review_id,
                risk_level=(
                    str(body.get("risk_level"))
                    if body.get("risk_level") is not None
                    else None
                ),
                findings=(
                    [str(item) for item in body.get("findings")]
                    if isinstance(body.get("findings"), list)
                    else None
                ),
                confidence=(
                    float(body["confidence"])
                    if body.get("confidence") is not None
                    else None
                ),
                recommended_operator_action=(
                    str(body.get("recommended_operator_action"))
                    if body.get("recommended_operator_action") is not None
                    else None
                ),
                l3_state=(
                    str(body.get("l3_state"))
                    if body.get("l3_state") is not None
                    else None
                ),
                l3_reason_code=(
                    str(body.get("l3_reason_code"))
                    if body.get("l3_reason_code") is not None
                    else None
                ),
                extra_fields={
                    key: body[key]
                    for key in ("analysis_summary", "analysis_points", "operator_next_steps")
                    if key in body
                },
            )
        except (TypeError, ValueError) as exc:
            status_code = 404 if "was not found" in str(exc) else 400
            return Response(
                content=json.dumps({"error": str(exc)}),
                status_code=status_code,
                media_type="application/json",
            )
        return {"review": review}

    @app.post("/report/l3-advisory/snapshot/{snapshot_id}/run-local-review")
    async def run_l3_advisory_local_review_endpoint(
        request: Request,
        snapshot_id: str,
    ):
        auth_result = await verify_auth(request)
        if isinstance(auth_result, Response):
            return auth_result
        try:
            review = gateway.run_local_l3_advisory_review(snapshot_id=snapshot_id)
        except ValueError as exc:
            status_code = 404 if "was not found" in str(exc) else 400
            return Response(
                content=json.dumps({"error": str(exc)}),
                status_code=status_code,
                media_type="application/json",
            )
        return {"review": review}

    @app.post("/report/l3-advisory/job/{job_id}/run-local")
    async def run_l3_advisory_job_local_endpoint(
        request: Request,
        job_id: str,
    ):
        auth_result = await verify_auth(request)
        if isinstance(auth_result, Response):
            return auth_result
        try:
            result = gateway.run_l3_advisory_job_local(job_id=job_id)
        except ValueError as exc:
            status_code = 404 if "was not found" in str(exc) else 400
            return Response(
                content=json.dumps({"error": str(exc)}),
                status_code=status_code,
                media_type="application/json",
            )
        return result

    @app.post("/report/l3-advisory/job/{job_id}/run-worker")
    async def run_l3_advisory_worker_endpoint(
        request: Request,
        job_id: str,
        body: dict[str, Any] | None = None,
    ):
        auth_result = await verify_auth(request)
        if isinstance(auth_result, Response):
            return auth_result
        try:
            worker_name = str((body or {}).get("worker") or DEFAULT_L3_ADVISORY_RUNNER)
            _validate_public_l3_advisory_runner(worker_name)
            result = gateway.run_l3_advisory_worker(
                job_id=job_id,
                worker_name=worker_name,
            )
        except ValueError as exc:
            status_code = 404 if "was not found" in str(exc) else 400
            return Response(
                content=json.dumps({"error": str(exc)}),
                status_code=status_code,
                media_type="application/json",
            )
        return result

    @app.post("/report/session/{session_id}/l3-advisory/full-review")
    async def run_l3_advisory_operator_full_review_endpoint(
        request: Request,
        session_id: str,
        body: dict[str, Any] | None = None,
    ):
        auth_result = await verify_auth(request)
        if isinstance(auth_result, Response):
            return auth_result
        body = body or {}
        try:
            result = gateway.run_operator_l3_full_review(
                session_id=session_id,
                trigger_event_id=str(body.get("trigger_event_id") or "operator_full_review"),
                trigger_detail=(
                    str(body.get("trigger_detail"))
                    if body.get("trigger_detail") is not None
                    else None
                ),
                from_record_id=(
                    int(body["from_record_id"])
                    if body.get("from_record_id") is not None
                    else None
                ),
                to_record_id=(
                    int(body["to_record_id"])
                    if body.get("to_record_id") is not None
                    else None
                ),
                max_records=int(body.get("max_records") or 100),
                max_tool_calls=int(body.get("max_tool_calls") or 0),
                runner=str(body.get("runner") or DEFAULT_L3_ADVISORY_RUNNER),
                run=bool(body.get("run", True)),
            )
        except (TypeError, ValueError) as exc:
            status_code = 404 if "was not found" in str(exc) else 400
            return Response(
                content=json.dumps({"error": str(exc)}),
                status_code=status_code,
                media_type="application/json",
            )
        return result

    @_enterprise_get("/enterprise/report/session/{session_id}/risk")
    async def enterprise_report_session_risk_endpoint(
        request: Request,
        session_id: str,
        limit: int = 100,
        window_seconds: Optional[int] = None,
    ):
        auth_result = await verify_auth(request)
        if isinstance(auth_result, Response):
            return auth_result
        if window_seconds is not None and (window_seconds < 1 or window_seconds > MAX_WINDOW_SECONDS):
            return Response(
                content=json.dumps({"error": f"window_seconds must be between 1 and {MAX_WINDOW_SECONDS}"}),
                status_code=400,
                media_type="application/json",
            )
        effective_limit = min(max(limit, 1), 1000)
        return await enrich_session_risk_payload_async(
            gateway.report_session_risk(
                session_id=session_id,
                limit=effective_limit,
                window_seconds=window_seconds,
            ),
            gateway,
        )

    @app.get("/report/session/{session_id}")
    async def report_session_endpoint(
        request: Request,
        session_id: str,
        limit: int = 100,
        window_seconds: Optional[int] = None,
    ):
        auth_result = await verify_auth(request)
        if isinstance(auth_result, Response):
            return auth_result
        if window_seconds is not None and (window_seconds < 1 or window_seconds > MAX_WINDOW_SECONDS):
            return Response(
                content=json.dumps({"error": f"window_seconds must be between 1 and {MAX_WINDOW_SECONDS}"}),
                status_code=400,
                media_type="application/json",
            )
        effective_limit = min(max(limit, 1), 1000)
        return gateway.replay_session(
            session_id=session_id,
            limit=effective_limit,
            window_seconds=window_seconds,
        )

    @_enterprise_get("/enterprise/report/session/{session_id}")
    async def enterprise_report_session_endpoint(
        request: Request,
        session_id: str,
        limit: int = 100,
        window_seconds: Optional[int] = None,
    ):
        auth_result = await verify_auth(request)
        if isinstance(auth_result, Response):
            return auth_result
        if window_seconds is not None and (window_seconds < 1 or window_seconds > MAX_WINDOW_SECONDS):
            return Response(
                content=json.dumps({"error": f"window_seconds must be between 1 and {MAX_WINDOW_SECONDS}"}),
                status_code=400,
                media_type="application/json",
            )
        effective_limit = min(max(limit, 1), 1000)
        return await enrich_replay_payload_async(
            gateway.replay_session(
                session_id=session_id,
                limit=effective_limit,
                window_seconds=window_seconds,
            )
        )

    @app.get("/report/session/{session_id}/page")
    async def report_session_page_endpoint(
        request: Request,
        session_id: str,
        limit: int = 100,
        cursor: Optional[int] = None,
        window_seconds: Optional[int] = None,
    ):
        auth_result = await verify_auth(request)
        if isinstance(auth_result, Response):
            return auth_result
        if window_seconds is not None and (window_seconds < 1 or window_seconds > MAX_WINDOW_SECONDS):
            return Response(
                content=json.dumps({"error": f"window_seconds must be between 1 and {MAX_WINDOW_SECONDS}"}),
                status_code=400,
                media_type="application/json",
            )
        if cursor is not None and cursor < 1:
            return Response(
                content=json.dumps({"error": "cursor must be >= 1"}),
                status_code=400,
                media_type="application/json",
            )
        effective_limit = min(max(limit, 1), 500)
        return gateway.replay_session_page(
            session_id=session_id,
            limit=effective_limit,
            cursor=cursor,
            window_seconds=window_seconds,
        )

    @_enterprise_get("/enterprise/report/session/{session_id}/page")
    async def enterprise_report_session_page_endpoint(
        request: Request,
        session_id: str,
        limit: int = 100,
        cursor: Optional[int] = None,
        window_seconds: Optional[int] = None,
    ):
        auth_result = await verify_auth(request)
        if isinstance(auth_result, Response):
            return auth_result
        if window_seconds is not None and (window_seconds < 1 or window_seconds > MAX_WINDOW_SECONDS):
            return Response(
                content=json.dumps({"error": f"window_seconds must be between 1 and {MAX_WINDOW_SECONDS}"}),
                status_code=400,
                media_type="application/json",
            )
        if cursor is not None and cursor < 1:
            return Response(
                content=json.dumps({"error": "cursor must be >= 1"}),
                status_code=400,
                media_type="application/json",
            )
        effective_limit = min(max(limit, 1), 500)
        return await enrich_replay_payload_async(
            gateway.replay_session_page(
                session_id=session_id,
                limit=effective_limit,
                cursor=cursor,
                window_seconds=window_seconds,
            )
        )

    @app.get("/report/alerts")
    async def report_alerts_endpoint(
        request: Request,
        severity: Optional[str] = None,
        acknowledged: Optional[str] = None,
        window_seconds: Optional[int] = None,
        limit: int = 100,
    ):
        auth_result = await verify_auth(request)
        if isinstance(auth_result, Response):
            return auth_result
        if severity is not None and severity not in {"low", "medium", "high", "critical"}:
            return Response(
                content=json.dumps({"error": "severity must be one of: low, medium, high, critical"}),
                status_code=400,
                media_type="application/json",
            )
        if acknowledged is not None and acknowledged not in {"true", "false"}:
            return Response(
                content=json.dumps({"error": "acknowledged must be 'true' or 'false'"}),
                status_code=400,
                media_type="application/json",
            )
        if window_seconds is not None and (window_seconds < 1 or window_seconds > MAX_WINDOW_SECONDS):
            return Response(
                content=json.dumps({"error": f"window_seconds must be between 1 and {MAX_WINDOW_SECONDS}"}),
                status_code=400,
                media_type="application/json",
            )
        ack_filter: Optional[bool] = None
        if acknowledged is not None:
            ack_filter = acknowledged == "true"
        effective_limit = min(max(limit, 1), 1000)
        return gateway.report_alerts(
            severity=severity,
            acknowledged=ack_filter,
            window_seconds=window_seconds,
            limit=effective_limit,
        )

    @_enterprise_get("/enterprise/report/alerts")
    async def enterprise_report_alerts_endpoint(
        request: Request,
        severity: Optional[str] = None,
        acknowledged: Optional[str] = None,
        window_seconds: Optional[int] = None,
        limit: int = 100,
    ):
        auth_result = await verify_auth(request)
        if isinstance(auth_result, Response):
            return auth_result
        if severity is not None and severity not in {"low", "medium", "high", "critical"}:
            return Response(
                content=json.dumps({"error": "severity must be one of: low, medium, high, critical"}),
                status_code=400,
                media_type="application/json",
            )
        if acknowledged is not None and acknowledged not in {"true", "false"}:
            return Response(
                content=json.dumps({"error": "acknowledged must be 'true' or 'false'"}),
                status_code=400,
                media_type="application/json",
            )
        if window_seconds is not None and (window_seconds < 1 or window_seconds > MAX_WINDOW_SECONDS):
            return Response(
                content=json.dumps({"error": f"window_seconds must be between 1 and {MAX_WINDOW_SECONDS}"}),
                status_code=400,
                media_type="application/json",
            )
        ack_filter: Optional[bool] = None
        if acknowledged is not None:
            ack_filter = acknowledged == "true"
        effective_limit = min(max(limit, 1), 1000)
        return await enrich_alerts_payload_async(
            gateway.report_alerts(
                severity=severity,
                acknowledged=ack_filter,
                window_seconds=window_seconds,
                limit=effective_limit,
            ),
            gateway,
        )

    @app.post("/report/alerts/{alert_id}/acknowledge")
    async def acknowledge_alert_endpoint(
        request: Request,
        alert_id: str,
    ):
        auth_result = await verify_auth(request)
        if isinstance(auth_result, Response):
            return auth_result
        try:
            body = await request.json()
        except Exception:
            body = {}
        acknowledged_by = str(body.get("acknowledged_by") or "unknown")
        result = gateway.acknowledge_alert(alert_id, acknowledged_by)
        if result is None:
            return Response(
                content=json.dumps({"error": f"Alert '{alert_id}' not found"}),
                status_code=404,
                media_type="application/json",
            )
        return result

    # --- Session enforcement management (A-7) ---

    @app.get("/report/session/{session_id}/enforcement")
    async def get_enforcement_endpoint(request: Request, session_id: str):
        auth_result = await verify_auth(request)
        if isinstance(auth_result, Response):
            return auth_result
        return gateway.session_enforcement.get_status(session_id)

    @app.post("/report/session/{session_id}/enforcement")
    async def post_enforcement_endpoint(request: Request, session_id: str):
        auth_result = await verify_auth(request)
        if isinstance(auth_result, Response):
            return auth_result
        try:
            body = await request.json()
        except Exception:
            return Response(
                content=json.dumps({"error": "invalid JSON body"}),
                status_code=400,
                media_type="application/json",
            )
        action = str(body.get("action", "")).lower()
        if action != "release":
            return Response(
                content=json.dumps({"error": "action must be 'release'"}),
                status_code=400,
                media_type="application/json",
            )
        released = gateway.session_enforcement.release(session_id)
        if released:
            gateway.event_bus.broadcast(
                {
                    "type": "session_enforcement_change",
                    "session_id": session_id,
                    "state": "released",
                    "action": None,
                    "high_risk_count": None,
                    "timestamp": utc_now_iso(),
                }
            )
        return {
            "session_id": session_id,
            "released": released,
        }

    @app.get("/report/session/{session_id}/quarantine")
    async def get_quarantine_endpoint(request: Request, session_id: str):
        auth_result = await verify_auth(request)
        if isinstance(auth_result, Response):
            return auth_result
        return {
            "session_id": session_id,
            "quarantine": gateway.session_registry.get_quarantine(session_id),
        }

    @app.post("/report/session/{session_id}/quarantine")
    async def post_quarantine_endpoint(request: Request, session_id: str):
        auth_result = await verify_auth(request)
        if isinstance(auth_result, Response):
            return auth_result
        try:
            body = await request.json()
        except Exception:
            return Response(
                content=json.dumps({"error": "invalid JSON body"}),
                status_code=400,
                media_type="application/json",
            )
        action = str(body.get("action", "")).lower()
        if action != "release":
            return Response(
                content=json.dumps({"error": "action must be 'release'"}),
                status_code=400,
                media_type="application/json",
            )
        released = gateway.session_registry.release_quarantine(
            session_id,
            released_by=str(body.get("released_by") or "operator"),
            reason=(
                str(body.get("reason"))
                if body.get("reason") is not None
                else None
            ),
        )
        gateway.event_bus.broadcast({
            "type": "session_enforcement_change",
            "session_id": session_id,
            "state": "quarantine_released" if released else "quarantine_not_found",
            "action": None,
            "high_risk_count": None,
            "timestamp": utc_now_iso(),
        })
        return {
            "session_id": session_id,
            "released": released,
            "quarantine": gateway.session_registry.get_quarantine(session_id),
        }

    # --- E-5: Self-evolving pattern endpoints ---

    @app.get("/ahp/patterns")
    async def list_patterns_endpoint(request: Request):
        auth_result = await verify_auth(request)
        if isinstance(auth_result, Response):
            return auth_result
        status = gateway.evolution_manager.status()
        return Response(
            content=json.dumps({
                **status,
                "patterns": gateway.evolution_manager.list_patterns(),
            }),
            media_type="application/json",
        )

    @app.post("/ahp/patterns/confirm")
    async def confirm_pattern_endpoint(request: Request):
        auth_result = await verify_auth(request)
        if isinstance(auth_result, Response):
            return auth_result
        if not gateway.evolution_manager._enabled:
            return Response(
                content=json.dumps({"error": "pattern evolution is disabled (CS_EVOLVING_ENABLED=0)"}),
                status_code=403,
                media_type="application/json",
            )
        try:
            body = await request.json()
        except Exception:
            return Response(
                content=json.dumps({"error": "invalid JSON"}),
                status_code=400,
                media_type="application/json",
            )
        pattern_id = body.get("pattern_id")
        confirmed = body.get("confirmed")
        if not pattern_id or not isinstance(confirmed, bool):
            return Response(
                content=json.dumps({"error": "pattern_id and confirmed (bool) are required"}),
                status_code=400,
                media_type="application/json",
            )
        result = gateway.evolution_manager.confirm(pattern_id, confirmed=confirmed)
        if result == "not_found":
            return Response(
                content=json.dumps({"error": "pattern not found"}),
                status_code=404,
                media_type="application/json",
            )
        # Broadcast SSE event
        gateway.event_bus.broadcast({
            "type": "pattern_evolved",
            "pattern_id": pattern_id,
            "action": result,
            "result": result,
            "timestamp": utc_now_iso(),
        })
        # Trigger hot-reload so new experimental/stable patterns take effect
        if result in ("promoted_to_experimental", "promoted_to_stable"):
            if not _find_and_reload_pattern_matcher(gateway.policy_engine._analyzer):
                logger.warning("could not hot-reload PatternMatcher: no RuleBasedAnalyzer found")
        return Response(
            content=json.dumps({"result": result, "pattern_id": pattern_id}),
            media_type="application/json",
        )

    # --- Web Dashboard UI (static SPA) ---
    _ui_dir = ui_dir if ui_dir is not None else _DEFAULT_UI_DIR
    if _ui_dir.exists() and (_ui_dir / "index.html").exists():
        _index_html = (_ui_dir / "index.html").read_text()

        @app.get("/ui/{path:path}")
        async def ui_spa_fallback(path: str):
            """SPA fallback: serve index.html for unmatched /ui/* paths."""
            # Check if requested path is a real file
            file_path = _ui_dir / path
            if file_path.is_file() and file_path.resolve().is_relative_to(
                _ui_dir.resolve()
            ):
                return FileResponse(str(file_path))
            return HTMLResponse(_index_html)

        @app.get("/ui")
        async def ui_root():
            return HTMLResponse(_index_html)

    return app


# ---------------------------------------------------------------------------
# UDS Transport (asyncio)
# ---------------------------------------------------------------------------

async def _uds_client_handler(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    gateway: SupervisionGateway,
) -> None:
    """Handle a single UDS client connection using length-prefixed framing."""
    try:
        while True:
            # Read 4-byte length prefix (big-endian uint32)
            length_bytes = await reader.readexactly(4)
            msg_length = struct.unpack("!I", length_bytes)[0]

            if msg_length == 0 or msg_length > 10 * 1024 * 1024:  # 10MB limit
                logger.warning("UDS: rejected frame with length %d", msg_length)
                break

            data = await reader.readexactly(msg_length)
            result = await gateway.handle_jsonrpc(data)
            response_bytes = json.dumps(result).encode("utf-8")

            # Write length-prefixed response
            writer.write(struct.pack("!I", len(response_bytes)))
            writer.write(response_bytes)
            await writer.drain()

    except (asyncio.IncompleteReadError, ConnectionResetError):
        pass
    except Exception:
        logger.exception("UDS client handler error")
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass


async def start_uds_server(
    gateway: SupervisionGateway,
    path: str = DEFAULT_UDS_PATH,
) -> Optional[asyncio.AbstractServer]:
    """Start the Unix Domain Socket server (Unix/Linux/macOS only)."""
    if sys.platform == "win32":
        logger.warning("UDS not supported on Windows, using HTTP transport only")
        return None

    # Remove stale socket file
    if os.path.exists(path):
        os.unlink(path)

    async def handler(reader, writer):
        await _uds_client_handler(reader, writer, gateway)

    server = await asyncio.start_unix_server(handler, path=path)
    os.chmod(path, 0o600)  # Only owner can access
    logger.info(f"UDS server listening on {path} (mode=0600)")
    return server


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

async def run_gateway(
    uds_path: str = DEFAULT_UDS_PATH,
    http_host: str = DEFAULT_HTTP_HOST,
    http_port: int = DEFAULT_HTTP_PORT,
    trajectory_db_path: str = DEFAULT_TRAJECTORY_DB_PATH,
    trajectory_retention_seconds: int = DEFAULT_TRAJECTORY_RETENTION_SECONDS,
    ssl_certfile: str | None = None,
    ssl_keyfile: str | None = None,
) -> None:
    """Run the Supervision Gateway with both UDS and HTTP transports."""
    # Build detection config from canonical CS_ environment variables.
    detection_config = build_detection_config_from_env()
    logger.info("DetectionConfig: %s", detection_config)

    gateway = SupervisionGateway(
        trajectory_db_path=trajectory_db_path,
        trajectory_retention_seconds=trajectory_retention_seconds,
        detection_config=detection_config,
    )

    # Wire LLM analyzer (same pattern as stack.py)
    analyzer = build_analyzer_from_env(
        trajectory_store=gateway.trajectory_store,
        session_registry=gateway.session_registry,
        patterns_path=detection_config.attack_patterns_path,
        evolved_patterns_path=detection_config.evolved_patterns_path if detection_config.evolving_enabled else None,
        l3_budget_ms=detection_config.l3_budget_ms,
        metrics=gateway.metrics,
    )
    if analyzer is not None:
        gateway.policy_engine = L1PolicyEngine(analyzer=analyzer, config=detection_config)

    app = create_http_app(gateway)

    # Start UDS server
    uds_server = await start_uds_server(gateway, uds_path)

    # Start periodic cleanup
    cleanup_task = asyncio.create_task(
        periodic_cleanup(gateway.idempotency_cache, interval_seconds=10.0)
    )

    # Start HTTP server
    uvicorn_kwargs: dict[str, Any] = {
        "app": app,
        "host": http_host,
        "port": http_port,
        "log_level": "info",
        "access_log": False,
    }
    if ssl_certfile and ssl_keyfile:
        uvicorn_kwargs["ssl_certfile"] = ssl_certfile
        uvicorn_kwargs["ssl_keyfile"] = ssl_keyfile
        logger.info("HTTPS enabled (cert=%s, key=%s)", ssl_certfile, ssl_keyfile)
    config = uvicorn.Config(**uvicorn_kwargs)
    server = uvicorn.Server(config)

    logger.info(
        "Gateway starting: UDS=%s, HTTP=%s:%s, TrajectoryDB=%s",
        uds_path,
        http_host,
        http_port,
        trajectory_db_path,
    )

    try:
        await server.serve()
    finally:
        cleanup_task.cancel()
        uds_server.close()
        await uds_server.wait_closed()
        if os.path.exists(uds_path):
            os.unlink(uds_path)


def _gateway_args_from_env() -> dict:
    """Read gateway configuration from environment variables."""
    args: dict[str, Any] = {
        "uds_path": os.environ.get("CS_UDS_PATH", DEFAULT_UDS_PATH),
        "http_host": os.environ.get("CS_HTTP_HOST", DEFAULT_HTTP_HOST),
        "http_port": int(os.environ.get("CS_HTTP_PORT", str(DEFAULT_HTTP_PORT))),
        "trajectory_db_path": os.environ.get(
            "CS_TRAJECTORY_DB_PATH", DEFAULT_TRAJECTORY_DB_PATH
        ),
        "trajectory_retention_seconds": int(os.environ.get(
            "AHP_TRAJECTORY_RETENTION_SECONDS",
            str(DEFAULT_TRAJECTORY_RETENTION_SECONDS),
        )),
    }
    ssl_cert = os.environ.get("AHP_SSL_CERTFILE", "").strip() or None
    ssl_key = os.environ.get("AHP_SSL_KEYFILE", "").strip() or None
    if ssl_cert and ssl_key:
        args["ssl_certfile"] = ssl_cert
        args["ssl_keyfile"] = ssl_key
    return args


def _build_gateway_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="clawsentry-gateway",
        description=(
            "Run the ClawSentry Supervision Gateway.\n\n"
            "All options can also be set via environment variables (shown in brackets).\n"
            "CLI flags take precedence over environment variables."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--uds-path",
        default=None,
        metavar="PATH",
        help=f"Unix domain socket path [CS_UDS_PATH] (default: {DEFAULT_UDS_PATH})",
    )
    parser.add_argument(
        "--host",
        default=None,
        metavar="HOST",
        help=f"HTTP bind host [CS_HTTP_HOST] (default: {DEFAULT_HTTP_HOST})",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=None,
        metavar="PORT",
        help=f"HTTP bind port [CS_HTTP_PORT] (default: {DEFAULT_HTTP_PORT})",
    )
    parser.add_argument(
        "--trajectory-db-path",
        default=None,
        metavar="PATH",
        help=f"SQLite trajectory DB path [CS_TRAJECTORY_DB_PATH] (default: {DEFAULT_TRAJECTORY_DB_PATH})",
    )
    parser.add_argument(
        "--trajectory-retention-seconds",
        type=int,
        default=None,
        metavar="SECONDS",
        help=f"Trajectory retention window [AHP_TRAJECTORY_RETENTION_SECONDS] (default: {DEFAULT_TRAJECTORY_RETENTION_SECONDS})",
    )
    parser.add_argument("--env-file", default=None, help="Explicit local env file for secrets/runtime values.")
    parser.add_argument(
        "--ssl-certfile",
        default=None,
        metavar="PATH",
        help="TLS certificate file [AHP_SSL_CERTFILE] (enables HTTPS when combined with --ssl-keyfile)",
    )
    parser.add_argument(
        "--ssl-keyfile",
        default=None,
        metavar="PATH",
        help="TLS private key file [AHP_SSL_KEYFILE]",
    )
    return parser


def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(name)s] %(message)s")
    from ..cli.dotenv_loader import (
        EnvFileError,
        apply_env_file_to_legacy_environ,
        resolve_explicit_env_file,
    )
    pre = argparse.ArgumentParser(add_help=False)
    pre.add_argument("--env-file", default=None)
    pre_args, _ = pre.parse_known_args()
    try:
        parsed_env = resolve_explicit_env_file(
            cli_env_file=Path(pre_args.env_file) if pre_args.env_file else None,
            environ=os.environ,
        )
    except EnvFileError as exc:
        raise SystemExit(str(exc)) from exc
    apply_env_file_to_legacy_environ(parsed_env, environ=os.environ)

    parser = _build_gateway_parser()
    args = parser.parse_args()

    # Build kwargs: env-derived defaults, then override with explicit CLI flags
    kwargs = _gateway_args_from_env()
    if args.uds_path is not None:
        kwargs["uds_path"] = args.uds_path
    if args.host is not None:
        kwargs["http_host"] = args.host
    if args.port is not None:
        kwargs["http_port"] = args.port
    if args.trajectory_db_path is not None:
        kwargs["trajectory_db_path"] = args.trajectory_db_path
    if args.trajectory_retention_seconds is not None:
        kwargs["trajectory_retention_seconds"] = args.trajectory_retention_seconds
    if args.ssl_certfile is not None:
        kwargs["ssl_certfile"] = args.ssl_certfile
    if args.ssl_keyfile is not None:
        kwargs["ssl_keyfile"] = args.ssl_keyfile

    try:
        asyncio.run(run_gateway(**kwargs))
    except KeyboardInterrupt:
        logger.info("Gateway stopped by user.")


if __name__ == "__main__":
    main()
