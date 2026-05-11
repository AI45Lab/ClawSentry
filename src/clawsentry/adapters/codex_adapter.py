"""Codex event normalization adapter.

Normalizes Codex events (function_call, function_call_output,
agent_message, session_meta, session_end) into CanonicalEvent.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from ..gateway.models import (
    CanonicalEvent,
    EventType,
    FrameworkMeta,
    NormalizationMeta,
    extract_risk_hints,
)
from .a3s_adapter import infer_content_origin
from .event_id import generate_event_id

logger = logging.getLogger(__name__)

# Codex hook_type → EventType mapping
_HOOK_TYPE_MAP: dict[str, EventType] = {
    "function_call": EventType.PRE_ACTION,
    "function_call_output": EventType.POST_ACTION,
    "agent_message": EventType.POST_RESPONSE,
    "session_meta": EventType.SESSION,
    "session_end": EventType.SESSION,
}

_NATIVE_HOOK_TYPE_MAP: dict[str, EventType] = {
    "PreToolUse": EventType.PRE_ACTION,
    "PermissionRequest": EventType.PRE_ACTION,
    "PostToolUse": EventType.POST_ACTION,
    "UserPromptSubmit": EventType.PRE_PROMPT,
    "SessionStart": EventType.SESSION,
    "Stop": EventType.SESSION,
    "PreCompact": EventType.SESSION,
    "PostCompact": EventType.SESSION,
}

_NATIVE_SESSION_SUBTYPES: dict[str, str] = {
    "SessionStart": "session:start",
    "Stop": "session:stop",
    "PreCompact": "session:pre_compact",
    "PostCompact": "session:post_compact",
}


class CodexAdapter:
    """Normalize Codex events → CanonicalEvent."""

    _DEFAULT_SOURCE_FRAMEWORK = "codex"

    def __init__(
        self,
        source_framework: str | None = None,
    ) -> None:
        self.source_framework = source_framework or self._DEFAULT_SOURCE_FRAMEWORK

    def normalize_hook_event(
        self,
        hook_type: str,
        payload: dict[str, Any],
        session_id: str | None = None,
        agent_id: str | None = None,
    ) -> CanonicalEvent | None:
        """Normalize a Codex event to CanonicalEvent."""
        event_type = _HOOK_TYPE_MAP.get(hook_type)
        if event_type is None:
            logger.debug("Unknown Codex hook_type: %s", hook_type)
            return None

        # Extract tool name and arguments
        tool_name = payload.get("name") or payload.get("tool_name")
        arguments = payload.get("arguments", {})

        # Build unified payload
        unified_payload: dict[str, Any] = {**payload}
        if arguments and isinstance(arguments, dict):
            unified_payload.update(arguments)

        # Risk hints (reuse shared utility)
        command_str = str(arguments.get("command", "")) if isinstance(arguments, dict) else ""
        risk_hints = extract_risk_hints(tool_name, command_str)

        # Content origin
        origin = infer_content_origin(tool_name, unified_payload)
        unified_payload["_clawsentry_meta"] = {"content_origin": origin}

        # Event subtype
        if event_type == EventType.SESSION:
            subtype = "session:start" if hook_type == "session_meta" else "session:end"
        elif event_type == EventType.PRE_ACTION:
            subtype = "pre_action"
        elif hook_type == "agent_message":
            subtype = "agent_message"
        else:
            subtype = "post_action"

        # Generate event ID
        now = datetime.now(timezone.utc)
        event_id = generate_event_id(
            self.source_framework, session_id or "unknown",
            subtype, now.isoformat(), unified_payload,
        )

        # Session/agent fallbacks
        effective_session = session_id or f"unknown_session:{self.source_framework}"
        effective_agent = agent_id or f"unknown_agent:{self.source_framework}"
        missing: list[str] = []
        if session_id is None:
            missing.append("session_id")
        if agent_id is None:
            missing.append("agent_id")

        norm_meta = NormalizationMeta(
            rule_id="codex-hook-direct-map",
            inferred=False,
            confidence="high",
            raw_event_type=hook_type,
            raw_event_source=self.source_framework,
            missing_fields=missing,
            fallback_rule="sentinel_value" if missing else None,
        )

        return CanonicalEvent(
            schema_version="ahp.1.0",
            event_id=event_id,
            trace_id=payload.get("call_id", event_id),
            event_type=event_type,
            session_id=effective_session,
            agent_id=effective_agent,
            source_framework=self.source_framework,
            occurred_at=now.isoformat(),
            payload=unified_payload,
            tool_name=tool_name,
            risk_hints=risk_hints,
            event_subtype=subtype,
            framework_meta=FrameworkMeta(normalization=norm_meta),
        )

    def normalize_native_hook_event(
        self,
        message: dict[str, Any],
        *,
        agent_id: str | None = None,
    ) -> CanonicalEvent | None:
        """Normalize Codex CLI native hook stdin into a CanonicalEvent.

        This path is intentionally separate from session JSONL normalization:
        native hooks use Claude-style top-level fields such as
        ``hook_event_name``, ``tool_name`` and ``tool_input``, while session
        logs use ``function_call`` / ``function_call_output`` records.
        """
        hook_event_name = message.get("hook_event_name")
        if not isinstance(hook_event_name, str):
            logger.debug("Codex native hook missing hook_event_name")
            return None

        event_type = _NATIVE_HOOK_TYPE_MAP.get(hook_event_name)
        if event_type is None:
            logger.debug("Unknown Codex native hook event: %s", hook_event_name)
            return None

        raw_tool_name = message.get("tool_name")
        tool_name = raw_tool_name.lower() if isinstance(raw_tool_name, str) else None
        tool_input = message.get("tool_input")
        arguments = dict(tool_input) if isinstance(tool_input, dict) else {}

        unified_payload: dict[str, Any] = {
            key: value
            for key, value in message.items()
            if key not in {"hook_event_name", "tool_name", "tool_input"}
        }
        if tool_name:
            unified_payload["tool"] = tool_name
            unified_payload["tool_name"] = tool_name
            unified_payload["raw_tool_name"] = raw_tool_name
        if arguments:
            unified_payload["arguments"] = arguments
            for key in ("command", "file_path", "path", "target", "target_path"):
                if key in arguments and key not in unified_payload:
                    unified_payload[key] = arguments[key]

        command_str = str(arguments.get("command", "")) if arguments else ""
        risk_hints = extract_risk_hints(tool_name, command_str)

        origin = infer_content_origin(tool_name, unified_payload)
        existing_meta = unified_payload.get("_clawsentry_meta")
        meta = dict(existing_meta) if isinstance(existing_meta, dict) else {}
        meta["content_origin"] = origin
        unified_payload["_clawsentry_meta"] = meta

        if event_type == EventType.SESSION:
            subtype = _NATIVE_SESSION_SUBTYPES.get(hook_event_name, hook_event_name)
        else:
            subtype = hook_event_name

        now = datetime.now(timezone.utc)
        session_id = message.get("session_id")
        effective_session = (
            session_id
            if isinstance(session_id, str) and session_id.strip()
            else f"unknown_session:{self.source_framework}"
        )
        effective_agent = agent_id or f"unknown_agent:{self.source_framework}"
        missing: list[str] = []
        if not isinstance(session_id, str) or not session_id.strip():
            missing.append("session_id")
        if agent_id is None:
            missing.append("agent_id")

        trace_id = (
            message.get("tool_use_id")
            or message.get("turn_id")
            or message.get("session_id")
        )
        if not isinstance(trace_id, str) or not trace_id.strip():
            trace_id = None

        event_id = generate_event_id(
            self.source_framework,
            effective_session,
            subtype,
            now.isoformat(),
            unified_payload,
        )

        norm_meta = NormalizationMeta(
            rule_id="codex-native-hook-direct-map",
            inferred=False,
            confidence="high",
            raw_event_type=hook_event_name,
            raw_event_source=self.source_framework,
            missing_fields=missing,
            fallback_rule="sentinel_value" if missing else None,
        )

        return CanonicalEvent(
            schema_version="ahp.1.0",
            event_id=event_id,
            trace_id=trace_id or event_id,
            event_type=event_type,
            session_id=effective_session,
            agent_id=effective_agent,
            source_framework=self.source_framework,
            occurred_at=now.isoformat(),
            payload=unified_payload,
            tool_name=tool_name,
            risk_hints=risk_hints,
            event_subtype=subtype,
            framework_meta=FrameworkMeta(normalization=norm_meta),
        )
