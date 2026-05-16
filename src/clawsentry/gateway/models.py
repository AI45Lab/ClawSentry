"""
Canonical data models for the AHP Supervision Gateway.

Design basis:
  - 02-unified-ahp-contract.md section 2-3 (Canonical Event / Decision)
  - 04-policy-decision-and-fallback.md section 8-13 (SyncDecision v1 / RiskSnapshot)
"""

from __future__ import annotations

import enum
import re
import time as _time
from dataclasses import dataclass as _dataclass
from datetime import datetime, timezone
from typing import Any, Literal, Optional
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SCHEMA_VERSION_PATTERN = re.compile(r"^ahp\.\d+\.\d+$")
OPENCLAW_MAPPING_PROFILE_PATTERN = re.compile(
    r"^openclaw@[A-Za-z0-9._-]+/protocol\.v\d+(?:\.\d+)*/profile\.v[1-9]\d*$"
)
CURRENT_SCHEMA_VERSION = "ahp.1.0"
RPC_VERSION = "sync_decision.1.0"

SENTINEL_SESSION_TEMPLATE = "unknown_session:{framework}"
SENTINEL_AGENT_TEMPLATE = "unknown_agent:{framework}"


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class EventType(str, enum.Enum):
    PRE_ACTION = "pre_action"
    POST_ACTION = "post_action"
    PRE_PROMPT = "pre_prompt"
    POST_RESPONSE = "post_response"
    ERROR = "error"
    SESSION = "session"


class DecisionVerdict(str, enum.Enum):
    ALLOW = "allow"
    BLOCK = "block"
    MODIFY = "modify"
    DEFER = "defer"


class ActionScope(str, enum.Enum):
    ACTION = "action"
    SESSION = "session"


class SessionEffectMode(str, enum.Enum):
    MARK_BLOCKED = "mark_blocked"
    GRACEFUL_STOP = "graceful_stop"


class RewriteTarget(str, enum.Enum):
    COMMAND = "command"
    TOOL_INPUT = "tool_input"


class SanitizeTarget(str, enum.Enum):
    COMMAND = "command"
    TOOL_INPUT = "tool_input"
    TOOL_OUTPUT = "tool_output"


class RewriteSource(str, enum.Enum):
    POLICY = "policy"
    OPERATOR = "operator"
    SYSTEM = "system"


class SessionScopeSource(str, enum.Enum):
    OPERATOR = "operator"
    PROJECT_TEMPLATE = "project_template"
    LLM_INDUCED = "llm_induced"


class SessionScopeVerdict(str, enum.Enum):
    ALLOW = "allow"
    DEFER = "defer"
    DENY = "deny"
    NEUTRAL = "neutral"


class EffectOutcome(str, enum.Enum):
    SESSION_QUARANTINE = "session_quarantine"
    SESSION_GRACEFUL_STOP = "session_graceful_stop"
    COMMAND_REWRITE = "command_rewrite"
    TOOL_INPUT_REWRITE = "tool_input_rewrite"
    COMMAND_SANITIZE = "command_sanitize"
    TOOL_INPUT_SANITIZE = "tool_input_sanitize"
    TOOL_OUTPUT_SANITIZE = "tool_output_sanitize"
    TOOL_OUTPUT_WOULD_SANITIZE = "tool_output_would_sanitize"


class DecisionSource(str, enum.Enum):
    POLICY = "policy"
    MANUAL = "manual"
    SYSTEM = "system"
    OPERATOR = "operator"


class RiskLevel(str, enum.Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


RISK_LEVEL_ORDER: dict[RiskLevel, int] = {
    RiskLevel.LOW: 0,
    RiskLevel.MEDIUM: 1,
    RiskLevel.HIGH: 2,
    RiskLevel.CRITICAL: 3,
}


class FailureClass(str, enum.Enum):
    NONE = "none"
    INPUT_INVALID = "input_invalid"
    APPROVAL_TIMEOUT = "approval_timeout"
    APPROVAL_NO_ROUTE = "approval_no_route"
    APPROVAL_QUEUE_FULL = "approval_queue_full"
    AUTH_INVALID_TOKEN = "auth_invalid_token"
    AUTH_RATE_LIMITED = "auth_rate_limited"
    AUTH_INVALID_SIGNATURE = "auth_invalid_signature"
    AUTH_TIMESTAMP_EXPIRED = "auth_timestamp_expired"
    UPSTREAM_UNAVAILABLE = "upstream_unavailable"
    INTERNAL_ERROR = "internal_error"


class DecisionTier(str, enum.Enum):
    L1 = "L1"
    L2 = "L2"
    L3 = "L3"


class AgentTrustLevel(str, enum.Enum):
    UNTRUSTED = "untrusted"
    STANDARD = "standard"
    ELEVATED = "elevated"
    PRIVILEGED = "privileged"


class RPCErrorCode(str, enum.Enum):
    INVALID_REQUEST = "INVALID_REQUEST"
    EVENT_SCHEMA_MISMATCH = "EVENT_SCHEMA_MISMATCH"
    DEADLINE_EXCEEDED = "DEADLINE_EXCEEDED"
    ENGINE_UNAVAILABLE = "ENGINE_UNAVAILABLE"
    ENGINE_INTERNAL_ERROR = "ENGINE_INTERNAL_ERROR"
    RATE_LIMITED = "RATE_LIMITED"
    VERSION_NOT_SUPPORTED = "VERSION_NOT_SUPPORTED"


class ClassifiedBy(str, enum.Enum):
    L1 = "L1"
    L2 = "L2"
    L3 = "L3"
    MANUAL = "manual"


DECISION_EFFECTS_VERSION = "cs.decision_effects.v1"
ADAPTER_EFFECT_RESULT_VERSION = "cs.adapter_effect_result.v1"
SESSION_SCOPE_VERSION = "cs.session_scope.v1"
ACTION_EFFECT_VERSION = "cs.action_effect.v1"
DENIED_EFFECT_VERSION = "cs.denied_effect.v1"


# ---------------------------------------------------------------------------
# Canonical Event (02 section 2)
# ---------------------------------------------------------------------------

class NormalizationMeta(BaseModel):
    """Minimum normalization metadata for framework_meta.normalization."""
    rule_id: str
    inferred: bool
    confidence: str
    raw_event_type: str
    raw_event_source: str
    missing_fields: list[str] = Field(default_factory=list)
    fallback_rule: Optional[str] = None


class FrameworkMeta(BaseModel):
    """Framework-specific metadata preserved from the source event."""
    normalization: Optional[NormalizationMeta] = None
    deployment_env: Optional[str] = None

    model_config = {"extra": "allow"}


class SessionScopeBaseRules(BaseModel):
    """Non-overridable base restrictions for a session scope profile."""

    model_config = ConfigDict(extra="forbid")

    denied_tools: list[str] = Field(default_factory=list)
    denied_paths: list[str] = Field(default_factory=list)
    denied_domains: list[str] = Field(default_factory=list)
    denied_command_prefixes: list[str] = Field(default_factory=list)
    denied_skill_ids: list[str] = Field(default_factory=list)
    denied_mcp_servers: list[str] = Field(default_factory=list)
    denied_mcp_tools: list[str] = Field(default_factory=list)
    denied_mcp_statuses: list[str] = Field(default_factory=list)
    denied_mcp_trust_levels: list[str] = Field(default_factory=list)
    denied_skill_trust_states: list[str] = Field(default_factory=list)
    denied_capabilities: list[str] = Field(default_factory=list)


class SessionScopeTaskRules(BaseModel):
    """Task-specific allow/defer rules layered under base restrictions."""

    model_config = ConfigDict(extra="forbid")

    allowed_tools: list[str] = Field(default_factory=list)
    allowed_path_prefixes: list[str] = Field(default_factory=list)
    allowed_domains: list[str] = Field(default_factory=list)
    allowed_command_prefixes: list[str] = Field(default_factory=list)
    allowed_skill_ids: list[str] = Field(default_factory=list)
    allowed_mcp_servers: list[str] = Field(default_factory=list)
    allowed_mcp_tools: list[str] = Field(default_factory=list)
    allowed_mcp_statuses: list[str] = Field(default_factory=list)
    allowed_mcp_trust_levels: list[str] = Field(default_factory=list)
    allowed_skill_trust_states: list[str] = Field(default_factory=list)
    queued_categories: list[str] = Field(default_factory=list)
    allowed_capabilities: list[str] = Field(default_factory=list)
    queued_capabilities: list[str] = Field(default_factory=list)


class ActionEffectTarget(BaseModel):
    """Redacted target evidence for a normalized action effect."""

    model_config = ConfigDict(extra="forbid")

    kind: str = "path"
    path_hash: Optional[str] = None
    path_role: Optional[str] = None
    workspace_relation: Optional[str] = None


class ActionEffectEnvelope(BaseModel):
    """Deterministic, redacted effect profile for a pre-action event."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    schema_: str = Field(default=ACTION_EFFECT_VERSION, alias="schema")
    effects: list[str] = Field(default_factory=list)
    tool_name: Optional[str] = None
    canonical_argv_hash: Optional[str] = None
    raw_payload_hash: Optional[str] = None
    targets: list[ActionEffectTarget] = Field(default_factory=list)
    interpreters: list[str] = Field(default_factory=list)
    wrapper_chain: list[str] = Field(default_factory=list)
    confidence: Literal["low", "medium", "high"] = "low"
    evidence_rules: list[str] = Field(default_factory=list)
    analysis_state: Literal["complete", "incomplete", "unsupported", "failed"] = "complete"
    disabled_capabilities: list[str] = Field(default_factory=list)

    @field_validator("schema_")
    @classmethod
    def validate_schema(cls, v: str) -> str:
        if v != ACTION_EFFECT_VERSION:
            raise ValueError(f"schema must be '{ACTION_EFFECT_VERSION}', got '{v}'")
        return v

    def to_summary(self) -> dict[str, Any]:
        return {
            "schema": self.schema_,
            "effects": list(self.effects),
            "tool_name": self.tool_name,
            "canonical_argv_hash": self.canonical_argv_hash,
            "raw_payload_hash": self.raw_payload_hash,
            "targets": [target.model_dump(mode="json", exclude_none=True) for target in self.targets],
            "interpreters": list(self.interpreters),
            "wrapper_chain": list(self.wrapper_chain),
            "confidence": self.confidence,
            "evidence_rules": list(self.evidence_rules),
            "analysis_state": self.analysis_state,
            "disabled_capabilities": list(self.disabled_capabilities),
        }


class DeniedEffectRecord(BaseModel):
    """Compact terminal-denial memory for capability-equivalent repeats."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    schema_: str = Field(default=DENIED_EFFECT_VERSION, alias="schema")
    session_id_hash: str
    prior_event_id: str
    prior_decision: str
    capability: str
    effect_hash: str
    target_hashes: list[str] = Field(default_factory=list)
    artifact_family: Optional[str] = None
    policy_id: str
    policy_version: str
    expires_at: str

    @field_validator("schema_")
    @classmethod
    def validate_schema(cls, v: str) -> str:
        if v != DENIED_EFFECT_VERSION:
            raise ValueError(f"schema must be '{DENIED_EFFECT_VERSION}', got '{v}'")
        return v


class SessionScopeProvenance(BaseModel):
    """Audit provenance for an explicit or generated session scope."""

    model_config = ConfigDict(extra="forbid")

    user_objective_hash: Optional[str] = None
    generated_by: Optional[str] = None
    confirmed_by: Optional[str] = None


class SessionScopeProfile(BaseModel):
    """AHP-native representation of Rbase ∪ Rtask session scope."""

    model_config = ConfigDict(extra="forbid")

    scope_version: str = SESSION_SCOPE_VERSION
    profile_id: str = Field(..., min_length=1)
    source: SessionScopeSource = SessionScopeSource.OPERATOR
    confirmed: bool = False
    dry_run: bool = True
    base_rules: SessionScopeBaseRules = Field(default_factory=SessionScopeBaseRules)
    task_rules: SessionScopeTaskRules = Field(default_factory=SessionScopeTaskRules)
    provenance: SessionScopeProvenance = Field(default_factory=SessionScopeProvenance)

    @field_validator("scope_version")
    @classmethod
    def validate_scope_version(cls, v: str) -> str:
        if v != SESSION_SCOPE_VERSION:
            raise ValueError(
                f"scope_version must be '{SESSION_SCOPE_VERSION}', got '{v}'"
            )
        return v


class SessionScopeEvaluationSummary(BaseModel):
    """Decision/report-safe summary of scope evaluation."""

    model_config = ConfigDict(extra="forbid")

    profile_id: str
    source: SessionScopeSource
    confirmed: bool
    dry_run: bool
    enforced: bool
    verdict: SessionScopeVerdict
    reason_codes: list[str] = Field(default_factory=list)


class CanonicalEvent(BaseModel):
    """
    Unified event model per 02-unified-ahp-contract.md section 2.

    Required fields: schema_version, event_id, trace_id, event_type,
    session_id, agent_id, source_framework, occurred_at, payload.
    """
    # --- Required fields ---
    schema_version: str = Field(default=CURRENT_SCHEMA_VERSION)
    event_id: str = Field(..., min_length=1)
    trace_id: str = Field(..., min_length=1)
    event_type: EventType
    session_id: str = Field(..., min_length=1)
    agent_id: str = Field(..., min_length=1)
    source_framework: str = Field(..., min_length=1)
    occurred_at: str  # UTC ISO8601
    payload: dict[str, Any] = Field(default_factory=dict)

    # --- Suggested fields ---
    parent_event_id: Optional[str] = None
    depth: Optional[int] = Field(default=None, ge=0)
    tool_name: Optional[str] = None
    risk_hints: list[str] = Field(default_factory=list)
    framework_meta: Optional[FrameworkMeta] = None
    event_subtype: Optional[str] = None
    run_id: Optional[str] = None
    approval_id: Optional[str] = None
    source_seq: Optional[int] = Field(default=None, ge=0)
    source_protocol_version: Optional[str] = None
    mapping_profile: Optional[str] = None

    @field_validator("schema_version")
    @classmethod
    def validate_schema_version(cls, v: str) -> str:
        if not SCHEMA_VERSION_PATTERN.match(v):
            raise ValueError(
                f"schema_version must match 'ahp.<major>.<minor>', got '{v}'"
            )
        return v

    @field_validator("occurred_at")
    @classmethod
    def validate_occurred_at(cls, v: str) -> str:
        try:
            datetime.fromisoformat(v.replace("Z", "+00:00"))
        except (ValueError, TypeError):
            raise ValueError(f"occurred_at must be valid UTC ISO8601, got '{v}'")
        return v

    @model_validator(mode="after")
    def validate_conditional_fields(self) -> "CanonicalEvent":
        # event_subtype required for a3s-code / openclaw
        if self.source_framework in ("a3s-code", "openclaw"):
            if not self.event_subtype:
                raise ValueError(
                    f"event_subtype is required when source_framework='{self.source_framework}'"
                )
        # openclaw requires source_protocol_version and mapping_profile
        if self.source_framework == "openclaw":
            if not self.source_protocol_version:
                raise ValueError(
                    "source_protocol_version is required when source_framework='openclaw'"
                )
            if not self.mapping_profile:
                raise ValueError(
                    "mapping_profile is required when source_framework='openclaw'"
                )
            if not OPENCLAW_MAPPING_PROFILE_PATTERN.match(self.mapping_profile):
                raise ValueError(
                    "mapping_profile must match "
                    "'openclaw@<git_short_sha>/protocol.v<source_protocol_version>/profile.v<n>'"
                )
        return self

    @staticmethod
    def sentinel_session_id(framework: str) -> str:
        return SENTINEL_SESSION_TEMPLATE.format(framework=framework)

    @staticmethod
    def sentinel_agent_id(framework: str) -> str:
        return SENTINEL_AGENT_TEMPLATE.format(framework=framework)


# ---------------------------------------------------------------------------
# Canonical Decision (02 section 3)
# ---------------------------------------------------------------------------

class SessionEffectRequest(BaseModel):
    """Requested session-scope effect; never claims adapter enforcement."""

    model_config = ConfigDict(extra="forbid")

    requested: bool = True
    mode: SessionEffectMode = SessionEffectMode.MARK_BLOCKED
    reason_code: Optional[str] = None
    capability_required: Optional[str] = None
    fallback_on_unsupported: Optional[str] = None


class RewriteEffectRequest(BaseModel):
    """Requested command/tool-input rewrite effect and audit envelope."""

    model_config = ConfigDict(extra="forbid")

    requested: bool = True
    target: RewriteTarget
    approval_id: Optional[str] = None
    original_hash: str
    original_preview_redacted: str
    replacement_hash: str
    replacement_preview_redacted: str
    replacement_payload: Optional[dict[str, Any]] = None
    redaction_policy_version: str = "cs.redaction.v1"
    rewrite_source: RewriteSource
    policy_id: Optional[str] = None
    post_rewrite_validation_id: Optional[str] = None


class SanitizeEffectRequest(BaseModel):
    """Requested sanitizer effect; enforcement is recorded by adapters only."""

    model_config = ConfigDict(extra="forbid")

    requested: bool = True
    target: SanitizeTarget
    original_hash: str
    original_preview_redacted: str
    sanitized_hash: Optional[str] = None
    sanitized_preview_redacted: Optional[str] = None
    replacement_payload: Optional[dict[str, Any]] = None
    redaction_policy_version: str = "cs.redaction.v1"
    sanitizer_source: RewriteSource = RewriteSource.POLICY
    redaction_counts: dict[str, int] = Field(default_factory=dict)
    redaction_types: list[str] = Field(default_factory=list)
    advisory_only: bool = False
    outcome: Optional[EffectOutcome] = None

    @model_validator(mode="after")
    def validate_sanitizer_contract(self) -> "SanitizeEffectRequest":
        if self.target == SanitizeTarget.TOOL_OUTPUT:
            if self.replacement_payload is not None:
                raise ValueError("tool_output sanitizer cannot carry replacement_payload")
            if self.outcome is None:
                self.outcome = EffectOutcome.TOOL_OUTPUT_WOULD_SANITIZE
            self.advisory_only = True
        elif self.outcome is None:
            self.outcome = (
                EffectOutcome.COMMAND_SANITIZE
                if self.target == SanitizeTarget.COMMAND
                else EffectOutcome.TOOL_INPUT_SANITIZE
            )
        return self


class DecisionEffects(BaseModel):
    """Request-only effect envelope attached to a canonical decision."""

    model_config = ConfigDict(extra="forbid")

    effect_version: str = DECISION_EFFECTS_VERSION
    effect_id: str = Field(..., min_length=1)
    action_scope: ActionScope = ActionScope.ACTION
    session_effect: Optional[SessionEffectRequest] = None
    rewrite_effect: Optional[RewriteEffectRequest] = None
    sanitize_effect: Optional[SanitizeEffectRequest] = None

    @field_validator("effect_version")
    @classmethod
    def validate_effect_version(cls, v: str) -> str:
        if v != DECISION_EFFECTS_VERSION:
            raise ValueError(
                f"effect_version must be '{DECISION_EFFECTS_VERSION}', got '{v}'"
            )
        return v


class AdapterEffectResult(BaseModel):
    """Observed adapter effect outcome recorded after host translation."""

    model_config = ConfigDict(extra="forbid")

    effect_version: str = ADAPTER_EFFECT_RESULT_VERSION
    effect_id: str = Field(..., min_length=1)
    framework: str = Field(..., min_length=1)
    adapter: str = Field(..., min_length=1)
    requested: list[EffectOutcome] = Field(default_factory=list)
    enforced: list[EffectOutcome] = Field(default_factory=list)
    degraded: list[EffectOutcome] = Field(default_factory=list)
    unsupported: list[EffectOutcome] = Field(default_factory=list)
    degrade_reason: Optional[str] = None
    host_ack: Optional[dict[str, Any]] = None
    smoke_evidence: Optional[dict[str, Any]] = None
    event_id: Optional[str] = None
    tool_use_id: Optional[str] = None
    session_id: Optional[str] = None
    result_kind: Optional[str] = None
    idempotency_key: Optional[str] = None

    @field_validator("effect_version")
    @classmethod
    def validate_effect_version(cls, v: str) -> str:
        if v != ADAPTER_EFFECT_RESULT_VERSION:
            raise ValueError(
                f"effect_version must be '{ADAPTER_EFFECT_RESULT_VERSION}', got '{v}'"
            )
        return v

    @model_validator(mode="after")
    def validate_outcome_consistency(self) -> "AdapterEffectResult":
        enforced = set(self.enforced)
        degraded = set(self.degraded)
        unsupported = set(self.unsupported)
        overlap = enforced & (degraded | unsupported)
        if overlap:
            names = ", ".join(sorted(item.value for item in overlap))
            raise ValueError(
                f"effect outcome cannot be both enforced and degraded/unsupported: {names}"
            )
        if (degraded or unsupported) and not self.degrade_reason:
            raise ValueError(
                "degrade_reason is required for degraded or unsupported adapter effect results"
            )
        if not self.result_kind:
            if self.enforced:
                self.result_kind = "enforced"
            elif self.degraded:
                self.result_kind = "degraded"
            elif self.unsupported:
                self.result_kind = "unsupported"
            else:
                self.result_kind = "observed"
        if not self.idempotency_key:
            target_id = self.tool_use_id or self.event_id or self.session_id or "unknown"
            self.idempotency_key = (
                f"{self.effect_id}:{self.adapter}:{target_id}:{self.result_kind}"
            )
        return self


def decision_effects_for_trajectory(
    effects: DecisionEffects | dict[str, Any] | None,
) -> Optional[dict[str, Any]]:
    """Return trajectory-safe effects with response-only payloads stripped."""

    if effects is None:
        return None
    model = effects if isinstance(effects, DecisionEffects) else DecisionEffects(**effects)
    payload = model.model_dump(mode="json")
    rewrite_effect = payload.get("rewrite_effect")
    if isinstance(rewrite_effect, dict) and "replacement_payload" in rewrite_effect:
        rewrite_effect["replacement_payload"] = None
    sanitize_effect = payload.get("sanitize_effect")
    if isinstance(sanitize_effect, dict) and "replacement_payload" in sanitize_effect:
        sanitize_effect["replacement_payload"] = None
    return payload


def decision_effect_summary(
    effects: DecisionEffects | dict[str, Any] | None,
) -> Optional[dict[str, Any]]:
    """Compact live-stream/session summary for requested decision effects."""

    safe = decision_effects_for_trajectory(effects)
    if safe is None:
        return None
    session_effect = safe.get("session_effect") or {}
    rewrite_effect = safe.get("rewrite_effect") or {}
    sanitize_effect = safe.get("sanitize_effect") or {}
    summary: dict[str, Any] = {
        "effect_id": safe.get("effect_id"),
        "effect_version": safe.get("effect_version"),
        "action_scope": safe.get("action_scope"),
    }
    if session_effect:
        summary["session_effect"] = {
            key: session_effect.get(key)
            for key in (
                "requested",
                "mode",
                "reason_code",
                "capability_required",
                "fallback_on_unsupported",
            )
            if session_effect.get(key) is not None
        }
    if rewrite_effect:
        summary["rewrite_effect"] = {
            key: rewrite_effect.get(key)
            for key in (
                "requested",
                "target",
                "approval_id",
                "original_hash",
                "original_preview_redacted",
                "replacement_hash",
                "replacement_preview_redacted",
                "redaction_policy_version",
                "rewrite_source",
                "policy_id",
                "post_rewrite_validation_id",
            )
            if rewrite_effect.get(key) is not None
        }
    if sanitize_effect:
        summary["sanitize_effect"] = {
            key: sanitize_effect.get(key)
            for key in (
                "requested",
                "target",
                "original_hash",
                "original_preview_redacted",
                "sanitized_hash",
                "sanitized_preview_redacted",
                "redaction_policy_version",
                "sanitizer_source",
                "redaction_counts",
                "redaction_types",
                "advisory_only",
                "outcome",
            )
            if sanitize_effect.get(key) is not None
        }
    return summary


def adapter_effect_result_summary(
    result: AdapterEffectResult | dict[str, Any] | None,
) -> Optional[dict[str, Any]]:
    """Compact live-stream/session summary for observed adapter outcomes."""

    if result is None:
        return None
    model = result if isinstance(result, AdapterEffectResult) else AdapterEffectResult(**result)
    return {
        "effect_id": model.effect_id,
        "effect_version": model.effect_version,
        "framework": model.framework,
        "adapter": model.adapter,
        "requested": [item.value for item in model.requested],
        "enforced": [item.value for item in model.enforced],
        "degraded": [item.value for item in model.degraded],
        "unsupported": [item.value for item in model.unsupported],
        "degrade_reason": model.degrade_reason,
        "event_id": model.event_id,
        "tool_use_id": model.tool_use_id,
        "session_id": model.session_id,
        "result_kind": model.result_kind,
    }

class CanonicalDecision(BaseModel):
    """
    Unified decision model per 02-unified-ahp-contract.md section 3.

    Only produced by policy / manual / system — never by Adapters.
    """
    decision: DecisionVerdict
    reason: str
    policy_id: str
    risk_level: RiskLevel
    decision_source: DecisionSource
    policy_version: str = "1.0"
    decision_latency_ms: Optional[float] = None
    modified_payload: Optional[dict[str, Any]] = None
    decision_effects: Optional[DecisionEffects] = None
    scope_evaluation: Optional[SessionScopeEvaluationSummary] = None
    retry_after_ms: Optional[int] = None
    failure_class: FailureClass = FailureClass.NONE
    final: Optional[bool] = None

    @model_validator(mode="after")
    def validate_decision_constraints(self) -> "CanonicalDecision":
        # allow/block must be final=true
        if self.decision in (DecisionVerdict.ALLOW, DecisionVerdict.BLOCK):
            if self.final is None:
                self.final = True
            elif not self.final:
                raise ValueError(
                    f"decision='{self.decision.value}' must have final=true"
                )
        # modify requires modified_payload
        if self.decision == DecisionVerdict.MODIFY and self.modified_payload is None:
            raise ValueError(
                "modified_payload is required when decision='modify'"
            )
        if self.decision_effects is not None:
            if (
                self.decision_effects.rewrite_effect is not None
                and self.decision != DecisionVerdict.MODIFY
            ):
                raise ValueError("rewrite_effect requires decision='modify'")
            sanitize_effect = self.decision_effects.sanitize_effect
            if sanitize_effect is not None:
                if (
                    sanitize_effect.target == SanitizeTarget.TOOL_OUTPUT
                    and self.decision == DecisionVerdict.MODIFY
                ):
                    raise ValueError("tool_output sanitize_effect cannot produce decision='modify'")
                if (
                    sanitize_effect.target in (SanitizeTarget.COMMAND, SanitizeTarget.TOOL_INPUT)
                    and sanitize_effect.replacement_payload is not None
                    and self.decision != DecisionVerdict.MODIFY
                ):
                    raise ValueError(
                        "input sanitize_effect with replacement_payload requires decision='modify'"
                    )
            if (
                self.decision_effects.action_scope == ActionScope.SESSION
                and self.decision not in (DecisionVerdict.BLOCK, DecisionVerdict.DEFER)
            ):
                raise ValueError(
                    "session action_scope requires decision='block' or decision='defer'"
                )
        return self


# ---------------------------------------------------------------------------
# Canary Token (injection leak detection)
# ---------------------------------------------------------------------------

@_dataclass
class CanaryToken:
    """Single canary token injected into DecisionContext for leak detection."""
    token: str
    injected_at: float

    @classmethod
    def generate(cls) -> "CanaryToken":
        return cls(
            token=f"<!-- ahp-ref:{uuid4().hex[:16]} -->",
            injected_at=_time.time(),
        )

    def check_leak(self, text: str) -> float:
        """Return injection score: 1.5 for full match, 1.0 for core match, 0.0 otherwise."""
        if self.token in text:
            return 1.5
        core = self.token.replace("<!-- ", "").replace(" -->", "")
        if core in text:
            return 1.0
        return 0.0


# ---------------------------------------------------------------------------
# Skill Trust Control Plane Models
# ---------------------------------------------------------------------------

class SkillRegistryRecord(BaseModel):
    """Canonical registry record for a skill identity."""

    model_config = ConfigDict(extra="forbid")

    canonical_skill_id: str = Field(..., min_length=1)
    canonical_name: str = Field(..., min_length=1)
    aliases: list[str] = Field(default_factory=list)
    content_hashes: dict[str, str] = Field(default_factory=dict)
    sbom: Optional[dict[str, Any]] = None
    checksum_evidence: dict[str, str] = Field(default_factory=dict)
    signature_evidence: Optional[dict[str, Any]] = None
    advisory_evidence: list[dict[str, Any]] = Field(default_factory=list)
    source: dict[str, Any] = Field(default_factory=dict)
    trust_level: Literal["trusted", "local_unreviewed", "unknown", "untrusted"] = "unknown"
    admission_scan_id: Optional[str] = None
    policy_fingerprint: Optional[str] = None
    list_state: Literal[
        "allowlist",
        "greylist",
        "blacklist",
        "unlisted",
        "revoked",
        "disabled",
    ] = "unlisted"
    status: Literal[
        "trusted",
        "ambiguous_alias",
        "hash_changed",
        "quarantined",
        "revoked",
        "local_unreviewed",
        "unknown",
    ] = "unknown"


class SkillTrustListEntry(BaseModel):
    """Trust-list state for a canonical skill identity and scope."""

    model_config = ConfigDict(extra="forbid")

    canonical_skill_id: str = Field(..., min_length=1)
    list_state: Literal[
        "allowlist",
        "greylist",
        "blacklist",
        "unlisted",
        "revoked",
        "disabled",
    ] = "unlisted"
    scope: Literal["workspace", "user_home", "project", "global"] = "workspace"
    reason_code: str = Field(..., min_length=1)
    evidence_hashes: list[str] = Field(default_factory=list)
    policy_fingerprint: str = Field(..., min_length=1)
    expires_at: Optional[str] = None
    disabled_until: Optional[str] = None
    review_required: bool = True


class SkillTrustTransitionEvent(BaseModel):
    """Auditable trust-list transition event."""

    model_config = ConfigDict(extra="forbid")

    transition_id: str = Field(..., min_length=1)
    registry_snapshot_id: str = Field(..., min_length=1)
    canonical_skill_id: str = Field(..., min_length=1)
    from_state: Literal["unlisted", "allowlist", "greylist", "blacklist", "revoked", "disabled"]
    to_state: Literal["allowlist", "greylist", "blacklist", "revoked", "disabled"]
    reason_code: str = Field(..., min_length=1)
    evidence_hashes: list[str] = Field(default_factory=list)
    scope: Literal["workspace", "user_home", "project", "global"] = "workspace"
    actor_type: Literal["policy", "operator", "manual_migration", "system"] = "policy"
    operator_id_hash: Optional[str] = None
    override_id: Optional[str] = None
    policy_fingerprint: str = Field(..., min_length=1)
    previous_policy_fingerprint: Optional[str] = None
    expires_at: Optional[str] = None
    disabled_until: Optional[str] = None
    review_required: bool = True


class AdmissionFinding(BaseModel):
    """Deterministic admission scanner finding; evidence until policy consumes it."""

    model_config = ConfigDict(extra="forbid")

    finding_id: str = Field(..., min_length=1)
    finding_family: Literal[
        "alias",
        "provenance",
        "hash",
        "control_language",
        "description_consistency",
        "cross_skill_overlap",
    ]
    severity: RiskLevel = RiskLevel.LOW
    confidence: Literal["low", "medium", "high"] = "low"
    decision_affecting: bool = False
    evidence_hashes: list[str] = Field(default_factory=list)
    evidence_summary: str = ""
    policy_fingerprint: Optional[str] = None


class AdmissionReport(BaseModel):
    """Scanner report for a skill root."""

    model_config = ConfigDict(extra="forbid")

    scan_id: str = "scan-local"
    skill_root_hash: str
    content_hashes: dict[str, str] = Field(default_factory=dict)
    sbom: Optional[dict[str, Any]] = None
    checksum_evidence: dict[str, str] = Field(default_factory=dict)
    signature_evidence: Optional[dict[str, Any]] = None
    advisory_evidence: list[dict[str, Any]] = Field(default_factory=list)
    findings: list[AdmissionFinding] = Field(default_factory=list)
    admission_risk: RiskLevel = RiskLevel.LOW
    policy_fingerprint: Optional[str] = None


class FirstUseScanState(BaseModel):
    """Explicit first-use scan lifecycle state for audit/replay."""

    model_config = ConfigDict(extra="forbid")

    state: Literal[
        "scan_not_started",
        "scan_running_sync",
        "scan_completed",
        "scan_pending_budget_exhausted",
        "scan_failed",
    ] = "scan_not_started"
    admission_scan_id: Optional[str] = None
    failure_class: Optional[str] = None
    admission_risk: Literal["low", "medium", "high", "critical", "unknown"] = "unknown"
    policy_fingerprint: Optional[str] = None


class SkillTrustContext(BaseModel):
    """Runtime skill identity and trust evidence resolved before policy evaluation."""

    model_config = ConfigDict(extra="forbid")

    registry_status: Literal["matched", "unknown", "ambiguous", "hash_mismatch", "unbound"] = "unbound"
    canonical_skill_id: Optional[str] = None
    presented_name: Optional[str] = None
    alias_match_type: Literal[
        "exact",
        "singular_plural",
        "hyphen_underscore",
        "near_name",
        "none",
    ] = "none"
    provenance_claim: Optional[str] = None
    admission_scan_id: Optional[str] = None
    admission_risk: Literal["low", "medium", "high", "critical", "unknown"] = "unknown"
    trust_list_state: Optional[Literal[
        "allowlist",
        "greylist",
        "blacklist",
        "unlisted",
        "revoked",
        "disabled",
    ]] = None
    first_use_scan: Optional[FirstUseScanState] = None
    invariant_violations: list[str] = Field(default_factory=list)
    policy_fingerprint: Optional[str] = None


class LineageEvent(BaseModel):
    """Redactable skill-to-tool-to-output lineage event."""

    model_config = ConfigDict(extra="forbid")

    event_id: str = Field(..., min_length=1)
    session_id: str = Field(..., min_length=1)
    canonical_skill_id: Optional[str] = None
    tool_name: str = Field(..., min_length=1)
    output_provenance_label: Optional[str] = None
    parent_event_id: Optional[str] = None
    content_hash: Optional[str] = None
    policy_version: str = Field(..., min_length=1)


class McpContext(BaseModel):
    """Runtime MCP server/tool trust evidence for capability narrowing."""

    model_config = ConfigDict(extra="forbid")

    server_name: Optional[str] = None
    tool_name: Optional[str] = None
    resource_kind: Optional[str] = None
    resource_uri_hash: Optional[str] = None
    trust_level: Literal["trusted", "local_unreviewed", "unknown", "untrusted"] = "unknown"
    status: Literal["allowlist", "greylist", "blacklist", "unlisted", "revoked", "disabled"] = "unlisted"


# ---------------------------------------------------------------------------
# RiskSnapshot (04 section 13)
# ---------------------------------------------------------------------------

class RiskDimensions(BaseModel):
    """D1-D6 dimension values."""
    d1: int = Field(..., ge=0, le=3)  # Tool type danger
    d2: int = Field(..., ge=0, le=3)  # Target path sensitivity
    d3: int = Field(..., ge=0, le=3)  # Command pattern danger
    d4: int = Field(..., ge=0, le=2)  # Context risk accumulation
    d5: int = Field(..., ge=0, le=2)  # Agent trust level
    d6: float = Field(default=0.0, ge=0.0, le=3.0)  # Injection detection


class RiskOverride(BaseModel):
    """L2/manual override information."""
    original_level: RiskLevel
    reason: str
    approved_by: Optional[str] = None


class RiskSnapshot(BaseModel):
    """
    Immutable risk snapshot per 04-policy-decision-and-fallback.md section 13.

    Once produced, must not change during the decision/retry lifecycle.
    """
    model_config = ConfigDict(frozen=True)

    risk_level: RiskLevel
    composite_score: float = Field(..., ge=0)  # v2: base*injection_multiplier (D6)
    dimensions: RiskDimensions
    short_circuit_rule: Optional[str] = None  # SC-1..SC-8 or null
    missing_dimensions: list[str] = Field(default_factory=list)
    classified_by: ClassifiedBy
    classified_at: str  # UTC ISO8601
    override: Optional[RiskOverride] = None
    l1_snapshot: Optional["RiskSnapshot"] = None
    l3_trace: Optional[dict] = Field(default=None, exclude=True)
    l2_l3_summary: Optional[dict[str, Any]] = None
    rule_hits: list[str] = Field(default_factory=list)
    skill_trust_findings: list[dict[str, Any]] = Field(default_factory=list)
    taint_flow_summary: Optional[dict[str, Any]] = None
    effect_summary: Optional[dict[str, Any]] = None

    @field_validator("short_circuit_rule")
    @classmethod
    def validate_short_circuit(cls, v: Optional[str]) -> Optional[str]:
        if v is not None and v not in (
            "SC-1",
            "SC-2",
            "SC-3",
            "SC-4",
            "SC-5",
            "SC-6",
            "SC-7",
            "SC-8",
        ):
            raise ValueError(f"short_circuit_rule must be SC-1..SC-8, got '{v}'")
        return v

    @field_validator("classified_at")
    @classmethod
    def validate_classified_at(cls, v: str) -> str:
        try:
            datetime.fromisoformat(v.replace("Z", "+00:00"))
        except (ValueError, TypeError):
            raise ValueError(f"classified_at must be valid UTC ISO8601, got '{v}'")
        return v


# ---------------------------------------------------------------------------
# Post-Action Security Types
# ---------------------------------------------------------------------------

class PostActionResponseTier(str, enum.Enum):
    """Graduated response tiers for post-action security findings."""
    LOG_ONLY = "log_only"
    MONITOR = "monitor"
    ESCALATE = "escalate"
    EMERGENCY = "emergency"


@_dataclass
class PostActionFinding:
    """Result from post-action security analysis."""
    tier: PostActionResponseTier
    patterns_matched: list[str]
    score: float
    details: dict[str, Any] | None = None

    def __post_init__(self) -> None:
        self.patterns_matched = list(self.patterns_matched)  # defensive copy
        self.details = dict(self.details) if self.details else {}  # defensive copy
        if not (0.0 <= self.score <= 3.0):
            raise ValueError(
                f"PostActionFinding.score must be in [0.0, 3.0], got {self.score}"
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "tier": self.tier.value,
            "patterns_matched": self.patterns_matched,
            "score": self.score,
            "details": self.details,
        }


# ---------------------------------------------------------------------------
# SyncDecision v1 RPC (04 section 8-9)
# ---------------------------------------------------------------------------

class DecisionContext(BaseModel):
    """Optional decision context per 04 section 8.2."""
    session_risk_summary: Optional[dict[str, Any]] = None
    agent_trust_level: Optional[AgentTrustLevel] = None
    workspace_id: Optional[str] = None
    caller_adapter: Optional[str] = None
    recent_facts: Optional[list[str]] = None
    memory_summary: Optional[str] = None
    current_task: Optional[str] = None
    context_hints: Optional[list[str]] = None
    intent_summary: Optional[str] = None
    planning_summary: Optional[str] = None
    reasoning_summary: Optional[str] = None
    cognition_hints: Optional[list[str]] = None
    session_scope_profile_id: Optional[str] = None
    session_scope_profile: Optional[SessionScopeProfile] = None
    skill_trust: Optional[SkillTrustContext] = None
    mcp_context: Optional[McpContext] = None


class SyncDecisionRequest(BaseModel):
    """
    SyncDecision v1 request envelope per 04 section 8.1.

    Mapped to JSON-RPC 2.0 as:
      method: "ahp/sync_decision"
      params: SyncDecisionRequest
    """
    rpc_version: str = Field(default=RPC_VERSION)
    request_id: str = Field(..., min_length=1)
    deadline_ms: int = Field(..., gt=0, le=120000)  # Hard upper limit 120s (L3 needs LLM round-trips on slow providers)
    decision_tier: DecisionTier
    event: CanonicalEvent
    context: Optional[DecisionContext] = None

    # Note: rpc_version validation is handled at gateway level (server.py)
    # to return the specific VERSION_NOT_SUPPORTED error code.


class SyncDecisionResponse(BaseModel):
    """
    SyncDecision v1 success response per 04 section 9.1.

    rpc_status is always "ok".
    """
    rpc_version: str = Field(default=RPC_VERSION)
    request_id: str = Field(..., min_length=1)
    rpc_status: str = Field(default="ok")
    decision: CanonicalDecision
    actual_tier: DecisionTier
    l3_available: Optional[bool] = None
    l3_requested: Optional[bool] = None
    l3_state: Optional[str] = None
    l3_reason: Optional[str] = None
    l3_reason_code: Optional[str] = None
    agent_safety_feedback: Optional[dict[str, Any]] = None
    served_at: str  # UTC ISO8601

    @field_validator("served_at")
    @classmethod
    def validate_served_at(cls, v: str) -> str:
        try:
            datetime.fromisoformat(v.replace("Z", "+00:00"))
        except (ValueError, TypeError):
            raise ValueError(f"served_at must be valid UTC ISO8601, got '{v}'")
        return v

    @field_validator("rpc_status")
    @classmethod
    def validate_rpc_status(cls, v: str) -> str:
        if v != "ok":
            raise ValueError(f"rpc_status must be 'ok' for success response, got '{v}'")
        return v


class SyncDecisionErrorResponse(BaseModel):
    """
    SyncDecision v1 error response per 04 section 9.2.

    rpc_status is always "error".
    """
    rpc_version: str = Field(default=RPC_VERSION)
    request_id: str = Field(..., min_length=1)
    rpc_status: str = Field(default="error")
    rpc_error_code: RPCErrorCode
    rpc_error_message: str
    retry_eligible: bool
    retry_after_ms: Optional[int] = Field(default=None, gt=0)
    fallback_decision: Optional[CanonicalDecision] = None

    @model_validator(mode="after")
    def validate_retry_fields(self) -> "SyncDecisionErrorResponse":
        if self.retry_eligible and self.retry_after_ms is None:
            raise ValueError(
                "retry_after_ms is required when retry_eligible=true"
            )
        return self


# ---------------------------------------------------------------------------
# Utility: current UTC ISO8601
# ---------------------------------------------------------------------------

def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def extract_risk_hints(tool_name: Optional[str], command: str) -> list[str]:
    """Extract risk hints from tool_name and command string.

    Shared across A3S and OpenClaw adapters.
    """
    hints: list[str] = []
    if tool_name and tool_name.lower() in ("bash", "shell", "exec", "sudo"):
        hints.append("shell_execution")
    cmd_lower = command.lower()
    if "rm " in cmd_lower or "sudo" in cmd_lower:
        hints.append("destructive_pattern")
    return hints
