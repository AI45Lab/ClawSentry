"""
a3s-code Adapter — Hook event to Canonical Event normalization.

Design basis:
  - 02-unified-ahp-contract.md section 4.1 (a3s-code -> Canonical mapping)
  - 02-unified-ahp-contract.md section 4.1.2 (PostResponse re-mapping rule)
  - 04-policy-decision-and-fallback.md section 11.2-11.3 (retry / fallback)
"""

from __future__ import annotations

import asyncio
import json
import logging
import struct
import sys
import time
import uuid
from typing import Any, Optional

from .event_id import generate_event_id as _generate_event_id
from ..gateway.models import (
    CanonicalDecision,
    CanonicalEvent,
    DecisionContext,
    DecisionTier,
    DecisionVerdict,
    EventType,
    FrameworkMeta,
    NormalizationMeta,
    RPC_VERSION,
    SyncDecisionRequest,
    extract_risk_hints,
    utc_now_iso,
)
from ..gateway.policy_engine import make_fallback_decision

logger = logging.getLogger("a3s-adapter")

# ---------------------------------------------------------------------------
# E-8: Content origin inference
# ---------------------------------------------------------------------------

_EXTERNAL_TOOLS = frozenset({
    "http_request", "web_fetch", "fetch", "web_search",
    "mcp__fetch__fetch",
})
_USER_TOOLS = frozenset({
    "read_file", "write_file", "edit_file", "grep", "glob",
    "read", "write", "edit",
})
import re as _re
_BASH_EXTERNAL_PATTERN = _re.compile(
    r"(?:\bcurl\b|\bwget\b|https?://)", _re.IGNORECASE
)


def infer_content_origin(tool_name: str | None, payload: dict[str, Any]) -> str:
    """Infer whether event content originates from external or user sources.

    Returns ``"external"``, ``"user"``, or ``"unknown"``.
    """
    tool = (tool_name or "").lower()
    if tool in _EXTERNAL_TOOLS:
        return "external"
    if tool in _USER_TOOLS:
        # Files in /tmp/ or similar may be external-originated
        path = str(payload.get("file_path", "") or payload.get("path", "") or "")
        if path.startswith("/tmp/") or path.startswith("/var/tmp/"):
            return "external"
        return "user"
    if tool in ("bash", "shell", "terminal", "command", "exec"):
        cmd = str(payload.get("command", ""))
        if _BASH_EXTERNAL_PATTERN.search(cmd):
            return "external"
        return "user"
    return "unknown"

# ---------------------------------------------------------------------------
# Hook -> Canonical Event Type Mapping (02 section 4.1.1)
# ---------------------------------------------------------------------------

# a3s-code HookEventType -> (Canonical event_type, blocking)
_HOOK_MAPPING: dict[str, tuple[EventType, bool]] = {
    "PreToolUse":    (EventType.PRE_ACTION, True),
    "PostToolUse":   (EventType.POST_ACTION, False),
    "PrePrompt":     (EventType.PRE_PROMPT, True),
    "GenerateStart": (EventType.PRE_PROMPT, True),
    "PostResponse":  (EventType.POST_RESPONSE, False),  # After payload reclassify
    "Idle":          (EventType.SESSION, False),
    "Heartbeat":     (EventType.SESSION, False),
    "Success":       (EventType.SESSION, False),
    "RateLimit":     (EventType.SESSION, False),
    "Confirmation":  (EventType.SESSION, False),
    "ContextPerception": (EventType.SESSION, False),
    "MemoryRecall":      (EventType.SESSION, False),
    "Planning":      (EventType.SESSION, False),
    "Reasoning":     (EventType.SESSION, False),
    "IntentDetection": (EventType.SESSION, False),
    "SessionStart":  (EventType.SESSION, False),
    "SessionEnd":    (EventType.SESSION, False),
    "OnError":       (EventType.ERROR, False),
}

# Not mapped (per 02 section 4.1.1)
_UNMAPPED_HOOKS = frozenset({"GenerateEnd", "SkillLoad", "SkillUnload"})

# Session event subtypes
_SESSION_SUBTYPES = {
    "SessionStart": "session:start",
    "SessionEnd": "session:end",
    "Idle": "compat:idle",
    "Heartbeat": "compat:heartbeat",
    "Success": "compat:success",
    "RateLimit": "compat:rate_limit",
    "Confirmation": "compat:confirmation",
    "ContextPerception": "compat:context_perception",
    "MemoryRecall": "compat:memory_recall",
    "Planning": "compat:planning",
    "Reasoning": "compat:reasoning",
    "IntentDetection": "compat:intent_detection",
}


# ---------------------------------------------------------------------------
# PostResponse re-mapping (02 section 4.1.2)
# ---------------------------------------------------------------------------

def _reclassify_post_action(
    ahp_event_type: str, payload: dict[str, Any],
    source_framework: str = "a3s-code",
) -> tuple[EventType, Optional[NormalizationMeta]]:
    """
    Apply PostResponse re-mapping rule per 02 section 4.1.2.

    AHP protocol maps PostResponse -> PostAction. We reclassify based on
    payload field signature:
    - payload contains 'response_text' -> post_response
    - payload contains 'tool' + 'result' -> post_action
    """
    if ahp_event_type != "PostAction":
        return _HOOK_MAPPING.get(ahp_event_type, (EventType.PRE_ACTION, True))[0], None

    # Check payload signature for PostResponse
    if "response_text" in payload:
        norm = NormalizationMeta(
            rule_id="a3s-post-response-reclassify",
            inferred=True,
            confidence="high",
            raw_event_type="PostAction",
            raw_event_source=source_framework,
        )
        return EventType.POST_RESPONSE, norm

    # Default: keep as post_action
    return EventType.POST_ACTION, None


# ---------------------------------------------------------------------------
# Core Adapter
# ---------------------------------------------------------------------------

class A3SCodeAdapter:
    """
    Adapter for normalizing a3s-code Hook events into Canonical Events.

    Responsibilities:
    - Map HookEventType to Canonical EventType.
    - Apply PostResponse re-mapping rule.
    - Generate stable event_id.
    - Populate framework_meta.normalization.
    - Send SyncDecision requests to Gateway (UDS client).
    - Apply local fallback when Gateway unreachable.
    """

    _DEFAULT_SOURCE_FRAMEWORK = "a3s-code"
    CALLER_ADAPTER_ID = "a3s-adapter.v1"

    def __init__(
        self,
        uds_path: str = "/tmp/clawsentry.sock",
        default_deadline_ms: int = 4500,
        max_rpc_retries: int = 1,
        retry_backoff_ms: int = 50,
        source_framework: str | None = None,
    ) -> None:
        self.uds_path = uds_path
        self.default_deadline_ms = default_deadline_ms
        self.max_rpc_retries = max_rpc_retries
        self.retry_backoff_ms = retry_backoff_ms
        self.source_framework = source_framework or self._DEFAULT_SOURCE_FRAMEWORK
        self.last_decision_response_metadata: dict[str, Any] = {}

    def normalize_hook_event(
        self,
        hook_type: str,
        payload: dict[str, Any],
        session_id: Optional[str] = None,
        agent_id: Optional[str] = None,
        trace_id: Optional[str] = None,
    ) -> Optional[CanonicalEvent]:
        """
        Normalize a raw a3s-code Hook event into a CanonicalEvent.

        Returns None for unmapped hook types.
        """
        if hook_type in _UNMAPPED_HOOKS:
            return None

        # Determine event_type and normalization metadata
        norm_meta: Optional[NormalizationMeta] = None

        if hook_type in _HOOK_MAPPING:
            event_type = _HOOK_MAPPING[hook_type][0]

            # PostResponse re-mapping: check AHP-level PostAction
            if hook_type == "PostToolUse":
                # Check if this is actually a PostResponse reclassified at AHP level
                event_type, norm_meta = _reclassify_post_action("PostAction", payload, self.source_framework)
                if norm_meta is None:
                    # Standard PostToolUse normalization
                    norm_meta = NormalizationMeta(
                        rule_id="a3s-hook-direct-map",
                        inferred=False,
                        confidence="high",
                        raw_event_type=hook_type,
                        raw_event_source=self.source_framework,
                    )
            else:
                norm_meta = NormalizationMeta(
                    rule_id="a3s-hook-direct-map",
                    inferred=False,
                    confidence="high",
                    raw_event_type=hook_type,
                    raw_event_source=self.source_framework,
                )
        else:
            logger.warning(f"Unknown hook type: {hook_type}")
            return None

        # Determine event_subtype
        event_subtype = _SESSION_SUBTYPES.get(hook_type, hook_type)

        # Handle sentinel values
        effective_session_id = session_id or CanonicalEvent.sentinel_session_id(self.source_framework)
        effective_agent_id = agent_id or CanonicalEvent.sentinel_agent_id(self.source_framework)
        effective_trace_id = trace_id or str(uuid.uuid4())

        # Track missing fields in normalization
        missing_fields = []
        if not session_id:
            missing_fields.append("session_id")
        if not agent_id:
            missing_fields.append("agent_id")
        if missing_fields:
            norm_meta.missing_fields = missing_fields
            norm_meta.fallback_rule = "sentinel_value"

        occurred_at = utc_now_iso()

        # Extract tool_name from payload
        tool_name = payload.get("tool") or payload.get("tool_name")
        payload_meta = payload.get("_clawsentry_meta")
        approval_id = payload.get("approval_id")
        if approval_id is None and isinstance(payload_meta, dict):
            compat_meta = payload_meta.get("ahp_compat")
            if isinstance(compat_meta, dict):
                identity = compat_meta.get("identity")
                if isinstance(identity, dict):
                    approval_id = identity.get("approval_id")

        # Generate stable event_id
        event_id = _generate_event_id(
            self.source_framework,
            effective_session_id,
            event_subtype,
            occurred_at,
            payload,
        )

        framework_meta = FrameworkMeta(normalization=norm_meta)

        # Extract risk_hints (shared utility in models.py)
        risk_hints = extract_risk_hints(tool_name, str(payload.get("command", "")))

        # E-8: Inject content origin metadata
        origin = infer_content_origin(tool_name, payload)
        enriched_payload = dict(payload)
        existing_meta = enriched_payload.get("_clawsentry_meta")
        merged_meta = dict(existing_meta) if isinstance(existing_meta, dict) else {}
        merged_meta["content_origin"] = origin
        enriched_payload["_clawsentry_meta"] = merged_meta

        return CanonicalEvent(
            event_id=event_id,
            trace_id=effective_trace_id,
            event_type=event_type,
            session_id=effective_session_id,
            agent_id=effective_agent_id,
            source_framework=self.source_framework,
            occurred_at=occurred_at,
            payload=enriched_payload,
            event_subtype=event_subtype,
            tool_name=tool_name,
            risk_hints=risk_hints,
            framework_meta=framework_meta,
            approval_id=str(approval_id) if approval_id not in (None, "") else None,
        )

    def is_blocking(self, hook_type: str) -> bool:
        """Check if a hook type requires synchronous decision (blocking)."""
        if hook_type in _HOOK_MAPPING:
            return _HOOK_MAPPING[hook_type][1]
        return False

    # -------------------------------------------------------------------
    # Gateway Communication (UDS client)
    # -------------------------------------------------------------------

    async def request_decision(
        self,
        event: CanonicalEvent,
        context: Optional[DecisionContext] = None,
        deadline_ms: Optional[int] = None,
        decision_tier: DecisionTier = DecisionTier.L1,
    ) -> CanonicalDecision:
        """
        Send a SyncDecision request to the Gateway.

        Implements retry logic per 04 section 11.2 and local fallback per 11.3.
        """
        self.last_decision_response_metadata = {}
        effective_deadline = deadline_ms or self.default_deadline_ms
        request_id = f"a3s-{event.event_id}-{int(time.monotonic() * 1000)}"
        deadline_start = time.monotonic()
        effective_context = context
        if effective_context is None:
            effective_context = DecisionContext(
                caller_adapter=self.CALLER_ADAPTER_ID
            )
        elif not effective_context.caller_adapter:
            effective_context = effective_context.model_copy(
                update={"caller_adapter": self.CALLER_ADAPTER_ID}
            )

        req = SyncDecisionRequest(
            request_id=request_id,
            deadline_ms=effective_deadline,
            decision_tier=decision_tier,
            event=event,
            context=effective_context,
        )

        # Retry loop per 04 section 11.2
        last_error: Optional[Exception] = None
        for attempt in range(1 + self.max_rpc_retries):
            elapsed_ms = (time.monotonic() - deadline_start) * 1000
            remaining_ms = effective_deadline - elapsed_ms

            # Check if enough budget for retry
            if attempt > 0:
                min_required = self.retry_backoff_ms + 20
                if remaining_ms < min_required:
                    break
                await asyncio.sleep(self.retry_backoff_ms / 1000.0)

            try:
                response = await self._send_uds_request(req)
                if "result" in response:
                    result = response["result"]
                    if result.get("rpc_status") == "ok":
                        self.last_decision_response_metadata = {
                            key: result[key]
                            for key in (
                                "agent_safety_feedback",
                                "agent_advisory_feedback",
                            )
                            if result.get(key) is not None
                        }
                        return CanonicalDecision(**result["decision"])
                    # RPC returned error
                    error_data = result
                elif "error" in response:
                    error_data = response["error"].get("data", {})
                    if error_data.get("retry_eligible") and attempt < self.max_rpc_retries:
                        continue
                    if "fallback_decision" in error_data and error_data["fallback_decision"]:
                        return CanonicalDecision(**error_data["fallback_decision"])
                break
            except Exception as e:
                last_error = e
                logger.warning(f"Gateway request failed (attempt {attempt + 1}): {e}")
                continue

        # All retries exhausted or gateway unreachable: local fallback
        logger.warning(f"Falling back to local decision for event {event.event_id}")
        has_high_danger = bool(
            set(event.risk_hints) & {"destructive_pattern", "shell_execution"}
        )
        return make_fallback_decision(event, risk_hints_contain_high_danger=has_high_danger)

    async def _send_uds_request(self, req: SyncDecisionRequest) -> dict[str, Any]:
        """Send a JSON-RPC 2.0 request over UDS with length-prefixed framing."""
        if sys.platform == "win32":
            raise OSError("UDS not supported on Windows")

        jsonrpc_body = json.dumps({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "ahp/sync_decision",
            "params": req.model_dump(mode="json"),
        }).encode("utf-8")

        reader, writer = await asyncio.open_unix_connection(self.uds_path)
        try:
            # Send length-prefixed message
            writer.write(struct.pack("!I", len(jsonrpc_body)))
            writer.write(jsonrpc_body)
            await writer.drain()

            # Read length-prefixed response (+0.5s buffer so Gateway can send DEADLINE_EXCEEDED)
            length_bytes = await asyncio.wait_for(
                reader.readexactly(4),
                timeout=req.deadline_ms / 1000.0 + 0.5,
            )
            resp_length = struct.unpack("!I", length_bytes)[0]
            if resp_length > 10 * 1024 * 1024:  # 10MB limit
                raise ValueError(f"Response too large: {resp_length} bytes")
            resp_data = await asyncio.wait_for(
                reader.readexactly(resp_length),
                timeout=req.deadline_ms / 1000.0 + 0.5,
            )
            return json.loads(resp_data)
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass


# ---------------------------------------------------------------------------
# In-process Adapter (for HTTP endpoint)
# ---------------------------------------------------------------------------

class InProcessA3SAdapter(A3SCodeAdapter):
    """A3S adapter that routes decisions through Gateway in-process (no UDS/HTTP)."""

    CALLER_ADAPTER_ID = "a3s-http-adapter.v1"

    def __init__(self, gateway) -> None:
        super().__init__()
        self._gateway = gateway

    async def request_decision(
        self,
        event: CanonicalEvent,
        context: Optional[DecisionContext] = None,
        deadline_ms: Optional[int] = None,
        decision_tier: DecisionTier = DecisionTier.L1,
    ) -> CanonicalDecision:
        effective_deadline = deadline_ms or self.default_deadline_ms
        self.last_decision_response_metadata = {}
        request_id = f"a3s-http-{event.event_id}-{int(time.monotonic() * 1000)}"
        effective_context = context
        if effective_context is None:
            effective_context = DecisionContext(
                caller_adapter=self.CALLER_ADAPTER_ID
            )
        elif not effective_context.caller_adapter:
            effective_context = effective_context.model_copy(
                update={"caller_adapter": self.CALLER_ADAPTER_ID}
            )

        req = SyncDecisionRequest(
            request_id=request_id,
            deadline_ms=effective_deadline,
            decision_tier=decision_tier,
            event=event,
            context=effective_context,
        )
        jsonrpc_body = json.dumps({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "ahp/sync_decision",
            "params": req.model_dump(mode="json"),
        }).encode("utf-8")

        try:
            response = await self._gateway.handle_jsonrpc(jsonrpc_body)
            if "result" in response:
                result = response["result"]
                if result.get("rpc_status") == "ok":
                    self.last_decision_response_metadata = {
                        key: result[key]
                        for key in (
                            "agent_safety_feedback",
                            "agent_advisory_feedback",
                        )
                        if result.get(key) is not None
                    }
                    return CanonicalDecision(**result["decision"])
            elif "error" in response:
                error_data = response["error"].get("data", {})
                if "fallback_decision" in error_data and error_data["fallback_decision"]:
                    return CanonicalDecision(**error_data["fallback_decision"])
        except Exception as e:
            logger.warning("InProcessA3SAdapter gateway call failed: %s", e)

        # Fallback
        has_high_danger = bool(
            set(event.risk_hints) & {"destructive_pattern", "shell_execution"}
        )
        return make_fallback_decision(event, risk_hints_contain_high_danger=has_high_danger)
