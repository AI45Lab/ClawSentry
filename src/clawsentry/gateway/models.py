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
from typing import Any, Optional
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


class DecisionSource(str, enum.Enum):
    POLICY = "policy"
    MANUAL = "manual"
    SYSTEM = "system"


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
    AUTH_INVALID_TOKEN = "auth_invalid_token"
    AUTH_RATE_LIMITED = "auth_rate_limited"
    AUTH_INVALID_SIGNATURE = "auth_invalid_signature"
    AUTH_TIMESTAMP_EXPIRED = "auth_timestamp_expired"
    UPSTREAM_UNAVAILABLE = "upstream_unavailable"
    INTERNAL_ERROR = "internal_error"


class DecisionTier(str, enum.Enum):
    L1 = "L1"
    L2 = "L2"


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
    MANUAL = "manual"


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
    short_circuit_rule: Optional[str] = None  # SC-1/SC-2/SC-3 or null
    missing_dimensions: list[str] = Field(default_factory=list)
    classified_by: ClassifiedBy
    classified_at: str  # UTC ISO8601
    override: Optional[RiskOverride] = None
    l1_snapshot: Optional["RiskSnapshot"] = None
    l3_trace: Optional[dict] = Field(default=None, exclude=True)

    @field_validator("short_circuit_rule")
    @classmethod
    def validate_short_circuit(cls, v: Optional[str]) -> Optional[str]:
        if v is not None and v not in ("SC-1", "SC-2", "SC-3"):
            raise ValueError(f"short_circuit_rule must be SC-1/SC-2/SC-3, got '{v}'")
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


class SyncDecisionRequest(BaseModel):
    """
    SyncDecision v1 request envelope per 04 section 8.1.

    Mapped to JSON-RPC 2.0 as:
      method: "ahp/sync_decision"
      params: SyncDecisionRequest
    """
    rpc_version: str = Field(default=RPC_VERSION)
    request_id: str = Field(..., min_length=1)
    deadline_ms: int = Field(..., gt=0, le=5000)  # Hard upper limit 5000ms
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
