"""Helpers for deriving explicit per-decision L3 runtime status."""

from __future__ import annotations

import enum
from typing import Any

from .models import DecisionTier


class L3RunState(str, enum.Enum):
    ENABLED = "enabled"
    NOT_TRIGGERED = "not_triggered"
    SKIPPED = "skipped"
    RUNNING = "running"
    COMPLETED = "completed"
    DEGRADED = "degraded"


class L3ReasonCode(str, enum.Enum):
    TRIGGER_NOT_MATCHED = "trigger_not_matched"
    HARD_CAP_EXCEEDED = "hard_cap_exceeded"
    LLM_CALL_FAILED = "llm_call_failed"
    MAX_TURNS_EXCEEDED = "max_turns_exceeded"
    LLM_RESPONSE_PARSE_FAILED = "llm_response_parse_failed"
    LLM_RESPONSE_UNRESOLVABLE_RISK_LEVEL = "llm_response_unresolvable_risk_level"
    FORMAT_RETRY_FAILED = "format_retry_failed"
    ANALYSIS_EXCEPTION = "analysis_exception"
    REQUESTED_NON_WHITELISTED_TOOL = "requested_non_whitelisted_tool"
    TOOL_CALL_BUDGET_EXHAUSTED = "tool_call_budget_exhausted"
    BUDGET_EXHAUSTED = "budget_exhausted"
    ANALYSIS_BUDGET_EXCEEDED = "analysis_budget_exceeded"
    LOCAL_L3_UNAVAILABLE = "local_l3_unavailable"
    LOCAL_L3_NOT_COMPLETED = "local_l3_not_completed"
    REQUESTED_BUT_NOT_RUN = "requested_but_not_run"
    UNKNOWN_DEGRADED = "unknown_degraded"


def infer_l3_reason_code(
    *,
    state: str | None,
    reason: str | None,
    trigger_reason: str,
    degraded: bool,
) -> str | None:
    normalized = str(reason or "").strip().lower()

    if trigger_reason == "trigger_not_matched" or state == L3RunState.NOT_TRIGGERED.value:
        return L3ReasonCode.TRIGGER_NOT_MATCHED.value
    if "hard cap exceeded" in normalized:
        return L3ReasonCode.HARD_CAP_EXCEEDED.value
    if "llm call failed" in normalized:
        return L3ReasonCode.LLM_CALL_FAILED.value
    if "max reasoning turns exceeded" in normalized:
        return L3ReasonCode.MAX_TURNS_EXCEEDED.value
    if "format retry failed" in normalized:
        return L3ReasonCode.FORMAT_RETRY_FAILED.value
    if "response parse failed" in normalized:
        return L3ReasonCode.LLM_RESPONSE_PARSE_FAILED.value
    if "unresolvable risk level" in normalized:
        return L3ReasonCode.LLM_RESPONSE_UNRESOLVABLE_RISK_LEVEL.value
    if "requested non-whitelisted tool" in normalized:
        return L3ReasonCode.REQUESTED_NON_WHITELISTED_TOOL.value
    if "tool call budget exhausted" in normalized:
        return L3ReasonCode.TOOL_CALL_BUDGET_EXHAUSTED.value
    if "analysis_budget_exceeded" in normalized or "analysis budget exceeded" in normalized:
        return L3ReasonCode.ANALYSIS_BUDGET_EXCEEDED.value
    if "budget exhausted" in normalized:
        return L3ReasonCode.BUDGET_EXHAUSTED.value
    if "local l3 unavailable" in normalized:
        return L3ReasonCode.LOCAL_L3_UNAVAILABLE.value
    if "local l3 review did not complete" in normalized:
        return L3ReasonCode.LOCAL_L3_NOT_COMPLETED.value
    if "analysis degraded" in normalized:
        return L3ReasonCode.ANALYSIS_EXCEPTION.value
    if state == L3RunState.SKIPPED.value:
        return L3ReasonCode.REQUESTED_BUT_NOT_RUN.value
    if degraded or state == L3RunState.DEGRADED.value:
        return L3ReasonCode.UNKNOWN_DEGRADED.value
    return None


def build_l3_runtime_info(
    *,
    requested_tier: DecisionTier,
    effective_tier: DecisionTier,
    actual_tier: DecisionTier,
    l3_available: bool,
    l3_trace: dict[str, Any] | None,
    l3_reason: str | None = None,
    l3_reason_code: str | None = None,
) -> dict[str, Any]:
    """Build compact L3 runtime metadata for responses, replay, and SSE."""

    requested = requested_tier == DecisionTier.L3 or effective_tier == DecisionTier.L3
    state: str | None = None
    reason = l3_reason

    trace_reason = ""
    trace_reason_code: str | None = None
    trigger_reason = ""
    degraded = False
    if isinstance(l3_trace, dict):
        trace_reason = str(l3_trace.get("degradation_reason") or "").strip()
        trace_reason_code = str(l3_trace.get("l3_reason_code") or "").strip() or None
        trigger_reason = str(l3_trace.get("trigger_reason") or "").strip()
        degraded = bool(l3_trace.get("degraded"))

    if actual_tier == DecisionTier.L3:
        state = L3RunState.COMPLETED.value
    elif requested:
        if actual_tier == DecisionTier.L1 and trigger_reason == "trigger_not_matched":
            state = L3RunState.NOT_TRIGGERED.value
            reason = reason or trace_reason or "L3 trigger not matched"
        elif degraded:
            state = L3RunState.DEGRADED.value
            reason = reason or trace_reason
        else:
            state = L3RunState.SKIPPED.value
    elif l3_available:
        state = L3RunState.ENABLED.value

    reason_code = l3_reason_code or trace_reason_code or infer_l3_reason_code(
        state=state,
        reason=reason,
        trigger_reason=trigger_reason,
        degraded=degraded,
    )

    return {
        "l3_available": l3_available,
        "l3_requested": requested,
        "l3_state": state,
        "l3_reason": reason,
        "l3_reason_code": reason_code,
    }
