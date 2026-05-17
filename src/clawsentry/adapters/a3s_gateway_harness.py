"""Standard a3s-code AHP stdio harness bridged to ClawSentry Gateway."""

from __future__ import annotations

import argparse
import asyncio
import copy
import json
import logging
import os
import re as _re
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Optional

try:
    from .a3s_adapter import A3SCodeAdapter
    from .codex_adapter import CodexAdapter
    from .gemini_adapter import GeminiAdapter, decision_to_gemini_hook_output
    from .kimi_adapter import KimiAdapter, decision_to_kimi_hook_output
    from ..gateway.models import (
        AdapterEffectResult,
        AgentTrustLevel,
        CanonicalDecision,
        DecisionContext,
        DecisionVerdict,
    )
except ImportError:
    # Support direct script execution:
    # python src/clawsentry/adapters/a3s_gateway_harness.py
    from pathlib import Path

    _SRC_ROOT = str(Path(__file__).resolve().parent.parent.parent)
    if _SRC_ROOT not in sys.path:
        sys.path.insert(0, _SRC_ROOT)
    from clawsentry.adapters.a3s_adapter import A3SCodeAdapter  # type: ignore[no-redef]
    from clawsentry.adapters.codex_adapter import CodexAdapter  # type: ignore[no-redef]
    from clawsentry.adapters.gemini_adapter import GeminiAdapter, decision_to_gemini_hook_output  # type: ignore[no-redef]
    from clawsentry.adapters.kimi_adapter import KimiAdapter, decision_to_kimi_hook_output  # type: ignore[no-redef]
    from clawsentry.gateway.models import (  # type: ignore[no-redef]
        AdapterEffectResult,
        AgentTrustLevel,
        CanonicalDecision,
        DecisionContext,
        DecisionVerdict,
    )

import time as _time

logger = logging.getLogger("a3s-gateway-harness")


def _monitoring_disabled_by_env() -> bool:
    raw = os.environ.get("CS_PROJECT_ENABLED", os.environ.get("CS_ENABLED", "true"))
    return str(raw).strip().lower() in {"0", "false", "no", "off"}

_EVENT_TO_HOOK: dict[str, str] = {
    "pre_action": "PreToolUse",
    "pre_tool_use": "PreToolUse",
    "post_action": "PostToolUse",
    "post_tool_use": "PostToolUse",
    "pre_prompt": "PrePrompt",
    "user_prompt_submit": "PrePrompt",
    "post_response": "PostResponse",
    "idle": "Idle",
    "heartbeat": "Heartbeat",
    "success": "Success",
    "rate_limit": "RateLimit",
    "confirmation": "Confirmation",
    "context_perception": "ContextPerception",
    "memory_recall": "MemoryRecall",
    "planning": "Planning",
    "reasoning": "Reasoning",
    "intent_detection": "IntentDetection",
    "generate_start": "GenerateStart",
    "session_start": "SessionStart",
    "session_end": "SessionEnd",
    "error": "OnError",
}

_OBSERVABILITY_COMPAT_EVENT_TYPES = frozenset({
    "idle",
    "heartbeat",
    "success",
    "rate_limit",
    "confirmation",
    "context_perception",
    "memory_recall",
    "planning",
    "reasoning",
    "intent_detection",
})
_COMPAT_INTERVAL_LIMITED_EVENT_TYPES = frozenset({"idle", "heartbeat"})


_CAMEL_RE1 = _re.compile(r"(?<=[a-z0-9])([A-Z])")
_CAMEL_RE2 = _re.compile(r"(?<=[A-Z])([A-Z][a-z])")


def _camel_to_snake(name: str) -> str:
    """Convert CamelCase to snake_case: PreToolUse -> pre_tool_use."""
    s = _CAMEL_RE1.sub(r"_\1", name)
    s = _CAMEL_RE2.sub(r"_\1", s)
    return s.lower()


def _normalize_event_type(value: Any) -> str:
    """Normalize A3S/Hook event names across CamelCase and snake_case forms."""
    if not isinstance(value, str):
        return ""
    event_type = value.strip()
    if not event_type:
        return ""
    if event_type.islower():
        return event_type
    return _camel_to_snake(event_type)


def _extract_tool_input_content(tool_input: dict[str, Any]) -> str | None:
    """Extract host-native write/edit body text for policy analysis."""
    parts: list[str] = []
    for key in ("content", "new_string", "old_string", "text", "body", "input", "code"):
        value = tool_input.get(key)
        if isinstance(value, str) and value:
            parts.append(value)

    edits = tool_input.get("edits")
    if isinstance(edits, list):
        for edit in edits:
            if not isinstance(edit, dict):
                continue
            for key in ("new_string", "old_string", "content"):
                value = edit.get(key)
                if isinstance(value, str) and value:
                    parts.append(value)

    if not parts:
        return None
    return "\n".join(dict.fromkeys(parts))


def _log_stderr(msg: str) -> None:
    ts = datetime.now().strftime("%H:%M:%S")
    print(f"[{ts}] [a3s-gateway-harness] {msg}", file=sys.stderr, flush=True)


_DIAG_LOG = os.environ.get("CS_HARNESS_DIAG_LOG", "")


def _diag(msg: str) -> None:
    """Write diagnostic message to file if CS_HARNESS_DIAG_LOG is set."""
    if not _DIAG_LOG:
        return
    try:
        ts = datetime.now().strftime("%H:%M:%S.%f")
        with open(_DIAG_LOG, "a") as f:
            f.write(f"[{ts}] {msg}\n")
    except OSError:
        pass


def _resolve_payload(raw: Any) -> dict[str, Any]:
    if isinstance(raw, dict):
        payload = dict(raw)
    else:
        payload = {}

    if "arguments" not in payload and isinstance(payload.get("args"), dict):
        payload["arguments"] = payload["args"]

    if "tool" not in payload and isinstance(payload.get("tool_name"), str):
        payload["tool"] = payload["tool_name"]

    args = payload.get("arguments")
    if isinstance(args, dict):
        for key in ("command", "path", "target", "file_path"):
            if key in args and key not in payload:
                payload[key] = args[key]

    return payload


def _resolve_string(*values: Any) -> Optional[str]:
    for v in values:
        if isinstance(v, str) and v.strip():
            return v
    return None


_AHP_COMPAT_IDENTITY_FIELDS = (
    "event_id",
    "trace_id",
    "parent_event_id",
    "depth",
    "run_id",
    "approval_id",
    "source_seq",
    "source_protocol_version",
    "mapping_profile",
    "occurred_at",
)

_AHP_COMPAT_CARRIED_FIELDS = (
    "context",
    "metadata",
    "query",
    "target",
    "summary",
    "task",
    "strategy",
    "constraints",
    "reasoning_type",
    "problem_statement",
    "hints",
    "prompt",
    "language_hint",
    "detected_intent",
    "target_hints",
)


def _merge_clawsentry_meta(payload: dict[str, Any], extra: dict[str, Any]) -> None:
    meta = payload.get("_clawsentry_meta")
    if not isinstance(meta, dict):
        meta = {}
        payload["_clawsentry_meta"] = meta
    meta.update(extra)


def _codex_skill_name_from_payload(payload: dict[str, Any]) -> str | None:
    return _codex_skill_name_from_payload_texts(payload, known_skill_names=None)


def _codex_payload_texts(payload: dict[str, Any]) -> list[str]:
    texts: list[str] = []
    for key in ("command", "path", "file_path"):
        value = payload.get(key)
        if isinstance(value, str):
            texts.append(_codex_skill_attribution_text(value) if key == "command" else value)
    arguments = payload.get("arguments")
    if isinstance(arguments, dict):
        for key in ("command", "path", "file_path"):
            value = arguments.get(key)
            if isinstance(value, str):
                texts.append(_codex_skill_attribution_text(value) if key == "command" else value)
    return texts


def _strip_shell_comment(line: str) -> str:
    quote: str | None = None
    escaped = False
    for index, char in enumerate(line):
        if escaped:
            escaped = False
            continue
        if char == "\\":
            escaped = True
            continue
        if char in {"'", '"'}:
            quote = None if quote == char else char if quote is None else quote
            continue
        if quote is None and char == "#":
            return line[:index]
    return line


def _codex_skill_attribution_text(command: str) -> str:
    """Return command text relevant for skill path attribution.

    Skill names inside shell comments or heredoc bodies are often validation text
    or output content, not executed skill paths. Keep direct shell command lines
    and strip those incidental regions before runtime metadata attribution.
    """

    lines: list[str] = []
    heredoc_end: str | None = None
    heredoc_pattern = _re.compile(r"<<-?\s*['\"]?([A-Za-z_][A-Za-z0-9_]*)['\"]?")
    for raw_line in command.splitlines():
        if heredoc_end is not None:
            if raw_line.strip() == heredoc_end:
                heredoc_end = None
            continue
        line = _strip_shell_comment(raw_line)
        match = heredoc_pattern.search(line)
        if match:
            before_heredoc = line[:match.start()]
            if before_heredoc.strip():
                lines.append(before_heredoc)
            heredoc_end = match.group(1)
            continue
        lines.append(line)
    return "\n".join(lines)


def _codex_skill_name_from_payload_texts(
    payload: dict[str, Any],
    *,
    known_skill_names: set[str] | None,
) -> str | None:
    names = _codex_skill_names_from_payload_texts(
        payload,
        known_skill_names=known_skill_names,
    )
    return names[0] if names else None


def _codex_skill_names_from_payload_texts(
    payload: dict[str, Any],
    *,
    known_skill_names: set[str] | None,
) -> list[str]:
    texts = _codex_payload_texts(payload)
    names: list[str] = []
    for text in texts:
        for match in _re.finditer(r"(?:^|/)(?:\.agents/)?skills/([^/\s'\";|&]+)(?:/|$)", text):
            names.append(match.group(1))
    if not known_skill_names:
        return list(dict.fromkeys(names))
    path_contexts = ("/scripts", "/SKILL.md", "/README.md", "/references", "/data")
    split_path_matches: list[tuple[int, int, str]] = []
    for text_index, text in enumerate(texts):
        for skill_name in known_skill_names:
            path_pattern = (
                r"(?<![A-Za-z0-9_.-])"
                + _re.escape(skill_name)
                + r"(?=(?:"
                + "|".join(_re.escape(item) for item in path_contexts)
                + r")(?:/|['\"\s),]|$))"
            )
            match = _re.search(path_pattern, text)
            if match:
                split_path_matches.append((text_index, match.start(), skill_name))
    names.extend(skill_name for _text_index, _offset, skill_name in sorted(split_path_matches))
    return list(dict.fromkeys(names))


def _load_codex_skill_runtime_metadata(skill_name: str) -> dict[str, Any] | None:
    raw_by_skill, _metadata_source = _load_codex_skill_runtime_metadata_bundle()
    raw = raw_by_skill.get(skill_name)
    if not isinstance(raw, dict):
        return None
    return copy.deepcopy(raw)


def _runtime_metadata_paths_from_context(
    payload: dict[str, Any] | None = None,
    *,
    framework: str = "codex",
) -> list[tuple[Path, str]]:
    paths: list[tuple[Path, str]] = []
    metadata_path = os.environ.get("CS_SKILL_TRUST_METADATA_PATH")
    if metadata_path:
        paths.append((Path(metadata_path).expanduser(), "env_runtime_metadata"))

    payload = payload or {}
    cwd = payload.get("cwd")
    if isinstance(cwd, str) and cwd.strip():
        start = Path(cwd).expanduser()
        for root in (start, *start.parents):
            paths.append((root / ".clawsentry" / "skill-trust-runtime.json", "cwd_runtime_metadata"))

    if framework == "codex":
        codex_home = os.environ.get("CODEX_HOME")
        if codex_home:
            paths.append((
                Path(codex_home).expanduser() / "clawsentry" / "skill-trust-raw.json",
                "codex_home_runtime_metadata",
            ))
    return paths


def _load_skill_runtime_metadata_bundle(
    payload: dict[str, Any] | None = None,
    *,
    framework: str = "codex",
) -> tuple[dict[str, Any], str | None]:
    for metadata_path, metadata_source in _runtime_metadata_paths_from_context(
        payload,
        framework=framework,
    ):
        if not metadata_path.is_file():
            continue
        try:
            bundle = json.loads(metadata_path.read_text(encoding="utf-8"))
        except Exception:
            continue
        raw_by_skill = bundle.get("raw_metadata_by_skill") if isinstance(bundle, dict) else None
        if isinstance(raw_by_skill, dict):
            return raw_by_skill, metadata_source
    return {}, None


def _load_codex_skill_runtime_metadata_bundle() -> tuple[dict[str, Any], str | None]:
    return _load_skill_runtime_metadata_bundle(framework="codex")


def _enrich_skill_trust_from_runtime_bundle(
    payload: dict[str, Any],
    *,
    framework: str,
) -> None:
    raw_by_skill, metadata_source = _load_skill_runtime_metadata_bundle(
        payload,
        framework=framework,
    )
    if not raw_by_skill:
        return
    skill_names = _codex_skill_names_from_payload_texts(
        payload,
        known_skill_names={str(name) for name in raw_by_skill},
    )
    if not skill_names:
        return
    candidates: list[tuple[int, str, dict[str, Any]]] = []
    for index, skill_name in enumerate(skill_names):
        raw_candidate = raw_by_skill.get(skill_name)
        if isinstance(raw_candidate, dict):
            candidates.append((index, skill_name, raw_candidate))
    if not candidates:
        return
    _index, skill_name, raw = min(candidates, key=lambda item: item[0])
    raw = copy.deepcopy(raw)
    lineage_raw = {
        "presented_name": raw.get("presented_name") or skill_name,
        "provenance_claim": raw.get("provenance_claim"),
        "admission_scan_id": raw.get("admission_scan_id"),
        "policy_fingerprint": raw.get("policy_fingerprint"),
        "metadata_source": metadata_source or "runtime_metadata",
    }
    if raw.get("skill_root_path"):
        lineage_raw["skill_root_path"] = raw.get("skill_root_path")
    _merge_clawsentry_meta(
        payload,
        {
            "skill_trust_raw": raw,
            "skill_lineage_raw": lineage_raw,
        },
    )


def _enrich_codex_skill_trust_from_runtime_bundle(payload: dict[str, Any]) -> None:
    _enrich_skill_trust_from_runtime_bundle(payload, framework="codex")


def _enrich_host_skill_trust_from_runtime_bundle(
    payload: dict[str, Any],
    *,
    framework: str,
) -> None:
    _enrich_skill_trust_from_runtime_bundle(payload, framework=framework)


def _build_ahp_compat_meta(
    params: dict[str, Any],
    *,
    raw_event_type: str,
    normalized_event_type: str,
    session_id: Optional[str],
    agent_id: Optional[str],
) -> Optional[dict[str, Any]]:
    preserved_fields = {
        key: copy.deepcopy(params[key])
        for key in _AHP_COMPAT_CARRIED_FIELDS
        if key in params
    }
    context_present = "context" in preserved_fields
    metadata_present = "metadata" in preserved_fields

    identity: dict[str, Any] = {}
    if raw_event_type:
        identity["event_type"] = raw_event_type
    if normalized_event_type and normalized_event_type != raw_event_type:
        identity["normalized_event_type"] = normalized_event_type
    if session_id:
        identity["session_id"] = session_id
    if agent_id:
        identity["agent_id"] = agent_id

    for key in _AHP_COMPAT_IDENTITY_FIELDS:
        value = params.get(key)
        if value is not None:
            identity[key] = copy.deepcopy(value)

    compat_event_type = _normalize_event_type(raw_event_type) or _normalize_event_type(normalized_event_type)
    if (
        compat_event_type not in _OBSERVABILITY_COMPAT_EVENT_TYPES
        and not context_present
        and not metadata_present
        and len(identity) <= 4
    ):
        return None

    compat: dict[str, Any] = {
        "preservation_mode": "compatibility-carrying",
        "source": "a3s-ingress",
        "raw_event_type": raw_event_type or normalized_event_type,
        "context_present": context_present,
        "metadata_present": metadata_present,
        "identity": identity,
    }
    compat.update(preserved_fields)
    return compat


def _decision_to_ahp_result(decision: CanonicalDecision) -> dict[str, Any]:
    action = "continue"
    if decision.decision == DecisionVerdict.BLOCK:
        action = "block"
    elif decision.decision == DecisionVerdict.MODIFY:
        action = "modify"
    elif decision.decision == DecisionVerdict.DEFER:
        action = "defer"

    result: dict[str, Any] = {
        "action": action,
        "decision": decision.decision.value,
        "reason": decision.reason,
        "metadata": {
            "source": "clawsentry-gateway-harness",
            "policy_id": decision.policy_id,
            "risk_level": decision.risk_level.value,
            "decision_source": decision.decision_source.value,
            "final": decision.final,
        },
    }
    if decision.modified_payload is not None:
        result["modified_payload"] = decision.modified_payload
    if getattr(decision, "decision_effects", None) is not None:
        result["decision_effects"] = decision.decision_effects.model_dump(mode="json")
    if decision.retry_after_ms is not None:
        result["retry_after_ms"] = decision.retry_after_ms

    return result


def _requested_effect_outcomes(decision_effects: dict[str, Any] | None) -> list[str]:
    if not isinstance(decision_effects, dict):
        return []
    outcomes: list[str] = []
    session_effect = decision_effects.get("session_effect")
    if isinstance(session_effect, dict) and session_effect.get("requested"):
        mode = str(session_effect.get("mode") or "mark_blocked")
        outcomes.append(
            "session_graceful_stop"
            if mode == "graceful_stop"
            else "session_quarantine"
        )
    rewrite_effect = decision_effects.get("rewrite_effect")
    if isinstance(rewrite_effect, dict) and rewrite_effect.get("requested"):
        target = str(rewrite_effect.get("target") or "command")
        outcomes.append(
            "tool_input_rewrite" if target == "tool_input" else "command_rewrite"
        )
    sanitize_effect = decision_effects.get("sanitize_effect")
    if isinstance(sanitize_effect, dict) and sanitize_effect.get("requested"):
        target = str(sanitize_effect.get("target") or "tool_output")
        if target == "tool_output":
            return outcomes
        outcome = sanitize_effect.get("outcome")
        if outcome:
            outcomes.append(str(outcome))
        else:
            outcomes.append(
                {
                    "command": "command_sanitize",
                    "tool_input": "tool_input_sanitize",
                }.get(target, "tool_input_sanitize")
            )
    return outcomes


def _record_inprocess_adapter_effect_result(
    adapter: A3SCodeAdapter,
    event: Any,
    result: dict[str, Any],
    *,
    enforced: bool,
    degraded_reason: str | None = None,
) -> None:
    gateway = getattr(adapter, "_gateway", None)
    if gateway is None:
        return
    decision_effects = result.get("decision_effects")
    outcomes = _requested_effect_outcomes(
        decision_effects if isinstance(decision_effects, dict) else None
    )
    if not outcomes:
        return
    try:
        effect_id = str(decision_effects.get("effect_id") or "unknown")
        payload = AdapterEffectResult(
            effect_id=effect_id,
            framework=str(getattr(adapter, "source_framework", "a3s-code") or "a3s-code"),
            adapter=str(getattr(adapter, "CALLER_ADAPTER_ID", "a3s-gateway-harness")),
            requested=outcomes,
            enforced=outcomes if enforced else [],
            degraded=[] if enforced else outcomes,
            degrade_reason=degraded_reason,
            event_id=str(getattr(event, "event_id", "") or ""),
            session_id=str(getattr(event, "session_id", "") or ""),
        )
        gateway.record_adapter_effect_result(payload)
    except Exception:  # noqa: BLE001
        logger.debug("adapter effect result writeback failed", exc_info=True)


class A3SGatewayHarness:
    """Bridge AHP stdio requests to ClawSentry Gateway decisions."""

    def __init__(
        self,
        adapter: A3SCodeAdapter,
        *,
        protocol_version: str = "2.0",
        harness_name: str = "a3s-gateway-harness",
        harness_version: str = "1.0.0",
        default_session_id: str = "ahp-session",
        default_agent_id: str = "ahp-agent",
        async_mode: bool = False,
        async_shutdown_grace_seconds: float = 0.1,
        compat_observation_window_seconds: float = 2.0,
        clock: Callable[[], float] | None = None,
    ) -> None:
        self.adapter = adapter
        self.protocol_version = protocol_version
        self.harness_name = harness_name
        self.harness_version = harness_version
        self.default_session_id = default_session_id
        self.default_agent_id = default_agent_id
        self.async_mode = async_mode
        self.async_shutdown_grace_seconds = max(0.0, float(async_shutdown_grace_seconds))
        self.compat_observation_window_seconds = max(
            0.0,
            float(compat_observation_window_seconds),
        )
        self._clock = clock or _time.monotonic
        self._compat_observation_state: dict[tuple[str, str, str], dict[str, Any]] = {}

    def _clear_compat_observation_state(
        self,
        *,
        session_id: str,
        agent_id: Optional[str] = None,
    ) -> None:
        if not self._compat_observation_state:
            return

        stale_keys = [
            key
            for key in self._compat_observation_state
            if key[1] == session_id and (agent_id is None or key[2] == agent_id)
        ]
        for key in stale_keys:
            self._compat_observation_state.pop(key, None)

    def _prune_compat_observation_state(
        self,
        *,
        now: float,
        exclude_key: tuple[str, str, str] | None = None,
    ) -> None:
        if (
            self.compat_observation_window_seconds <= 0
            or not self._compat_observation_state
        ):
            return

        stale_keys = [
            key
            for key, state in self._compat_observation_state.items()
            if key != exclude_key
            and (now - float(state.get("last_emit_at") or 0.0))
            >= self.compat_observation_window_seconds
        ]
        for key in stale_keys:
            self._compat_observation_state.pop(key, None)

    def _handshake_result(self) -> dict[str, Any]:
        return {
            "protocol_version": self.protocol_version,
            "harness_info": {
                "name": self.harness_name,
                "version": self.harness_version,
                "capabilities": [
                    "pre_action",
                    "post_action",
                    "pre_prompt",
                    "post_response",
                    "idle",
                    "heartbeat",
                    "success",
                    "rate_limit",
                    "confirmation",
                    "context_perception",
                    "memory_recall",
                    "planning",
                    "reasoning",
                    "intent_detection",
                    "session",
                    "error",
                ],
                "enforcement_capabilities": [
                    "clawsentry.decision_effects.v1",
                    "clawsentry.session_control.mark_blocked.v1",
                    "clawsentry.command_rewrite.v1",
                    "a3s.command_rewrite.modified_payload.v1",
                ],
            },
        }

    def _sample_compat_event(
        self,
        *,
        event_type: str,
        session_id: str,
        agent_id: str,
    ) -> tuple[bool, Optional[dict[str, Any]]]:
        now = self._clock()
        key = (event_type, session_id, agent_id)
        self._prune_compat_observation_state(now=now, exclude_key=key)

        if (
            event_type not in _COMPAT_INTERVAL_LIMITED_EVENT_TYPES
            or self.compat_observation_window_seconds <= 0
        ):
            return True, None

        state = self._compat_observation_state.get(key)

        if state is not None:
            elapsed = now - float(state.get("last_emit_at") or 0.0)
            if elapsed < self.compat_observation_window_seconds:
                state["suppressed_count"] = int(state.get("suppressed_count") or 0) + 1
                self._compat_observation_state[key] = state
                return False, {
                    "strategy": "interval_limit",
                    "window_seconds": self.compat_observation_window_seconds,
                    "sampled_out": True,
                }

        suppressed_since_last_emit = 0
        if state is not None:
            suppressed_since_last_emit = int(state.get("suppressed_count") or 0)

        self._compat_observation_state[key] = {
            "last_emit_at": now,
            "suppressed_count": 0,
        }

        compat_observation: dict[str, Any] = {
            "strategy": "interval_limit",
            "window_seconds": self.compat_observation_window_seconds,
        }
        if suppressed_since_last_emit > 0:
            compat_observation["suppressed_since_last_emit"] = suppressed_since_last_emit
        return True, compat_observation

    async def _handle_event(self, params: dict[str, Any]) -> dict[str, Any]:
        raw_event_type = str(params.get("event_type") or "")
        event_type_raw = _normalize_event_type(raw_event_type)
        payload = _resolve_payload(params.get("payload"))
        session_id = _resolve_string(
            params.get("session_id"),
            params.get("sessionKey"),
            payload.get("session_id"),
            payload.get("sessionKey"),
            self.default_session_id,
        )
        agent_id = _resolve_string(
            params.get("agent_id"),
            params.get("agentId"),
            payload.get("agent_id"),
            payload.get("agentId"),
            self.default_agent_id,
        )
        compat_cleanup_agent_id = _resolve_string(
            params.get("agent_id"),
            params.get("agentId"),
            payload.get("agent_id"),
            payload.get("agentId"),
        )

        try:
            if _monitoring_disabled_by_env():
                return {
                    "action": "continue",
                    "decision": "allow",
                    "reason": "monitoring disabled by env",
                    "metadata": {"source": "clawsentry-gateway-harness"},
                }

            hook_type = _EVENT_TO_HOOK.get(event_type_raw)
            if hook_type is None:
                return {
                    "action": "continue",
                    "decision": "allow",
                    "reason": f"Unmapped event_type: {event_type_raw or 'unknown'}",
                    "metadata": {"source": "clawsentry-gateway-harness"},
                }

            trace_id = _resolve_string(
                params.get("trace_id"),
                payload.get("trace_id"),
            )

            should_emit_event, compat_observation = self._sample_compat_event(
                event_type=event_type_raw,
                session_id=session_id or self.default_session_id,
                agent_id=agent_id or self.default_agent_id,
            )
            if compat_observation is not None:
                _merge_clawsentry_meta(payload, {"compat_observation": compat_observation})
            if not should_emit_event:
                return {
                    "action": "continue",
                    "decision": "allow",
                    "reason": (
                        f"Compatibility observation event '{event_type_raw}' sampled out "
                        f"within {self.compat_observation_window_seconds:.1f}s window"
                    ),
                    "metadata": {
                        "source": "clawsentry-gateway-harness",
                        "compat_event_type": event_type_raw,
                        "compat_observation": compat_observation,
                    },
                }

            ahp_compat = _build_ahp_compat_meta(
                params,
                raw_event_type=raw_event_type,
                normalized_event_type=event_type_raw,
                session_id=session_id,
                agent_id=agent_id,
            )
            if ahp_compat is not None:
                _merge_clawsentry_meta(payload, {"ahp_compat": ahp_compat})

            # Inject project preset info into payload before normalization
            project_preset = params.get("_project_preset")
            project_overrides = params.get("_project_overrides")
            if project_preset or project_overrides:
                project_meta: dict[str, Any] = {}
                if project_preset:
                    project_meta["project_preset"] = project_preset
                if project_overrides:
                    project_meta["project_overrides"] = project_overrides
                _merge_clawsentry_meta(payload, project_meta)

            evt = self.adapter.normalize_hook_event(
                hook_type,
                payload,
                session_id=session_id,
                agent_id=agent_id,
                trace_id=trace_id,
            )
            if evt is None:
                return {
                    "action": "continue",
                    "decision": "allow",
                    "reason": f"Event filtered: hook_type={hook_type}",
                    "metadata": {"source": "clawsentry-gateway-harness"},
                }

            # Ensure project preset info survives normalization (adapter may
            # rebuild _clawsentry_meta, so merge it into the event payload).
            if evt.payload is not None:
                preserved_meta: dict[str, Any] = {}
                if ahp_compat is not None:
                    preserved_meta["ahp_compat"] = ahp_compat
                if project_preset:
                    preserved_meta["project_preset"] = project_preset
                if project_overrides:
                    preserved_meta["project_overrides"] = project_overrides
                if preserved_meta:
                    _merge_clawsentry_meta(evt.payload, preserved_meta)
                _enrich_host_skill_trust_from_runtime_bundle(
                    evt.payload,
                    framework=self.adapter.source_framework,
                )

            decision = await self.adapter.request_decision(evt)
            result = _decision_to_ahp_result(decision)
            _record_inprocess_adapter_effect_result(
                self.adapter,
                evt,
                result,
                enforced=True,
            )
            return result
        finally:
            if event_type_raw == "session_end" and session_id is not None:
                self._clear_compat_observation_state(
                    session_id=session_id,
                    agent_id=compat_cleanup_agent_id,
                )

    def _convert_native_hook(self, msg: dict[str, Any]) -> dict[str, Any]:
        """Convert native Claude Code hook JSON to harness event params.

        Claude Code sends hooks with this stdin format::

            {
                "hook_event_name": "PreToolUse",
                "tool_name": "Bash",
                "tool_input": {"command": "ls -la"},
                "session_id": "...",
                "cwd": "/workspace",
                ...
            }

        We need to map this to our internal params format::

            {
                "event_type": "pre_tool_use",
                "session_id": "...",
                "payload": {"tool": "Bash", "arguments": {"command": "ls -la"}, ...}
            }
        """
        params: dict[str, Any] = {}

        # event_type: Claude Code uses "hook_event_name", others use "event_type"/"hook_type"
        event_type = (
            msg.get("event_type")
            or msg.get("hook_event_name")
            or msg.get("hook_type", "")
        )
        params["event_type"] = _normalize_event_type(event_type)

        # payload: Claude Code sends tool_name/tool_input at top level, not nested
        payload = msg.get("payload")
        if payload is None:
            # Build payload from Claude Code's flat structure
            payload: dict[str, Any] = {}
            tool_name = msg.get("tool_name")
            if tool_name:
                payload["tool"] = tool_name
            tool_input = msg.get("tool_input")
            if isinstance(tool_input, dict):
                payload["arguments"] = tool_input
                # Lift common fields for risk assessment
                for key in ("command", "file_path", "path"):
                    if key in tool_input and key not in payload:
                        payload[key] = tool_input[key]
                if "content" not in payload:
                    content = _extract_tool_input_content(tool_input)
                    if content:
                        payload["content"] = content
            if isinstance(msg.get("prompt"), str):
                payload["prompt"] = msg["prompt"]
            # Carry over other context fields
            for key in ("cwd", "working_directory", "permission_mode", "transcript_path"):
                if key in msg:
                    payload[key] = msg[key]
        params["payload"] = payload

        # Lift session_id / agent_id to params level for _handle_event
        for key in ("session_id", "agent_id"):
            if key in msg:
                params[key] = msg[key]
            elif isinstance(payload, dict) and key in payload:
                params[key] = payload[key]

        return params

    async def _handle_codex_native_hook(
        self,
        msg: dict[str, Any],
        *,
        project_meta: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Normalize a Codex native hook then use the existing Gateway transport."""
        evt = CodexAdapter(
            source_framework=self.adapter.source_framework
        ).normalize_native_hook_event(
            msg,
            agent_id=_resolve_string(
                msg.get("agent_id"),
                msg.get("agentId"),
                self.default_agent_id,
            ),
        )
        if evt is None:
            return {
                "action": "continue",
                "decision": "allow",
                "reason": "Event filtered: codex native hook",
                "metadata": {"source": "clawsentry-gateway-harness"},
            }

        if project_meta and evt.payload is not None:
            _merge_clawsentry_meta(evt.payload, project_meta)
        if evt.payload is not None:
            _enrich_codex_skill_trust_from_runtime_bundle(evt.payload)

        decision = await self.adapter.request_decision(
            evt,
            DecisionContext(agent_trust_level=AgentTrustLevel.STANDARD),
        )
        result = _decision_to_ahp_result(decision)
        _record_inprocess_adapter_effect_result(
            self.adapter,
            evt,
            result,
            enforced=False,
            degraded_reason="codex_pretool_effects_unsupported",
        )
        return result

    async def _handle_kimi_native_hook(
        self,
        msg: dict[str, Any],
        *,
        project_meta: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Normalize a Kimi CLI native hook then use the Gateway transport."""
        evt = KimiAdapter(
            source_framework=self.adapter.source_framework
        ).normalize_native_hook_event(
            msg,
            agent_id=_resolve_string(
                msg.get("agent_id"),
                msg.get("agentId"),
                self.default_agent_id,
            ),
        )
        if evt is None:
            return {
                "action": "continue",
                "decision": "allow",
                "reason": "Event filtered: kimi native hook",
                "metadata": {"source": "clawsentry-gateway-harness"},
            }

        if project_meta and evt.payload is not None:
            _merge_clawsentry_meta(evt.payload, project_meta)
        if evt.payload is not None:
            _enrich_host_skill_trust_from_runtime_bundle(evt.payload, framework="kimi-cli")

        decision = await self.adapter.request_decision(evt)
        result = _decision_to_ahp_result(decision)
        event_name = str(msg.get("hook_event_name", ""))
        action = str(result.get("action", "continue"))
        enforced = action in {"continue", "allow", "block"} and event_name in {
            "PreToolUse",
            "UserPromptSubmit",
            "Stop",
        }
        degraded_reason = None if enforced else "kimi_native_hooks_do_not_support_modify_or_defer_effects"
        _record_inprocess_adapter_effect_result(
            self.adapter,
            evt,
            result,
            enforced=enforced,
            degraded_reason=degraded_reason,
        )
        return result

    async def _handle_gemini_native_hook(
        self,
        msg: dict[str, Any],
        *,
        project_meta: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Normalize a Gemini CLI native hook then use the Gateway transport."""
        evt = GeminiAdapter(
            source_framework=self.adapter.source_framework
        ).normalize_native_hook_event(
            msg,
            agent_id=_resolve_string(
                msg.get("agent_id"),
                msg.get("agentId"),
                self.default_agent_id,
            ),
        )
        if evt is None:
            return {
                "action": "continue",
                "decision": "allow",
                "reason": "Event filtered: gemini native hook",
                "metadata": {"source": "clawsentry-gateway-harness"},
            }

        if project_meta and evt.payload is not None:
            _merge_clawsentry_meta(evt.payload, project_meta)
        if evt.payload is not None:
            _enrich_host_skill_trust_from_runtime_bundle(evt.payload, framework="gemini-cli")

        decision = await self.adapter.request_decision(evt)
        result = _decision_to_ahp_result(decision)
        event_name = str(msg.get("hook_event_name", ""))
        can_enforce = event_name in {
            "BeforeAgent",
            "AfterAgent",
            "BeforeModel",
            "AfterModel",
            "BeforeTool",
            "AfterTool",
        }
        _record_inprocess_adapter_effect_result(
            self.adapter,
            evt,
            result,
            enforced=can_enforce,
            degraded_reason=None if can_enforce else "gemini_hook_effect_is_advisory_or_partial",
        )
        return result

    async def dispatch_async(self, msg: dict[str, Any]) -> Optional[dict[str, Any]]:
        req_id = msg.get("id")
        method = msg.get("method")

        # --- JSON-RPC 2.0 path (a3s-code AHP protocol) ---
        if method is not None:
            params_raw = msg.get("params")
            params = params_raw if isinstance(params_raw, dict) else {}

            if method == "ahp/handshake":
                if req_id is None:
                    return None
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": self._handshake_result(),
                }

            try:
                result = await self._handle_event(params)
            except Exception:  # noqa: BLE001
                logger.exception("Failed handling AHP event")
                if req_id is None:
                    return None
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {
                        "code": -32000,
                        "message": "AHP harness internal error",
                        "data": {"detail": "Internal harness error. Check server logs for details."},
                    },
                }

            if req_id is None:
                return None

            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": result,
            }

        # --- Native hook path (host CLI / direct hook command) ---
        params = self._convert_native_hook(msg)
        native_framework = str(getattr(self.adapter, "source_framework", "") or "").lower()
        is_codex_native_hook = native_framework == "codex" and "hook_event_name" in msg
        is_gemini_native_hook = (
            native_framework == "gemini-cli" and "hook_event_name" in msg
        )
        is_kimi_native_hook = (
            native_framework == "kimi-cli" and "hook_event_name" in msg
        )
        is_claude_code_hook = (
            native_framework == "claude-code" and "hook_event_name" in msg
        )

        project_meta: dict[str, Any] = {}
        if _monitoring_disabled_by_env():
            _diag("monitoring disabled by CS_PROJECT_ENABLED/CS_ENABLED")
            if is_claude_code_hook or is_codex_native_hook or is_gemini_native_hook or is_kimi_native_hook:
                return None  # exit 0 = allow
            return {"result": {"action": "continue", "reason": "monitoring disabled by env"}}

        if self.async_mode:
            # Dispatch in background — don't block the hook
            if is_codex_native_hook:
                asyncio.ensure_future(
                    self._async_dispatch_codex_native(msg, project_meta=project_meta)
                )
            elif is_gemini_native_hook:
                asyncio.ensure_future(
                    self._async_dispatch_gemini_native(msg, project_meta=project_meta)
                )
            elif is_kimi_native_hook:
                asyncio.ensure_future(
                    self._async_dispatch_kimi_native(msg, project_meta=project_meta)
                )
            else:
                asyncio.ensure_future(self._async_dispatch(params))
            if is_claude_code_hook or is_codex_native_hook or is_gemini_native_hook or is_kimi_native_hook:
                return None  # host native hook: empty stdout + exit 0 = allow
            return {"result": {"action": "continue", "reason": "async: event dispatched"}}
        try:
            if is_codex_native_hook:
                result = await self._handle_codex_native_hook(
                    msg,
                    project_meta=project_meta,
                )
            elif is_gemini_native_hook:
                result = await self._handle_gemini_native_hook(
                    msg,
                    project_meta=project_meta,
                )
            elif is_kimi_native_hook:
                result = await self._handle_kimi_native_hook(
                    msg,
                    project_meta=project_meta,
                )
            else:
                result = await self._handle_event(params)
        except Exception:  # noqa: BLE001
            logger.exception("Failed handling native hook event")
            if is_claude_code_hook or is_codex_native_hook or is_gemini_native_hook or is_kimi_native_hook:
                return None  # allow on error (fail-open for hooks)
            return {"result": {"action": "continue", "reason": "harness internal error"}}

        if is_codex_native_hook:
            return self._to_codex_hook_response(
                result,
                msg.get("hook_event_name", ""),
                msg,
            )
        if is_gemini_native_hook:
            return decision_to_gemini_hook_output(
                result,
                str(msg.get("hook_event_name", "")),
                msg,
            )
        if is_kimi_native_hook:
            return decision_to_kimi_hook_output(
                result,
                str(msg.get("hook_event_name", "")),
                msg,
            )
        if is_claude_code_hook:
            return self._to_claude_code_response(result, msg.get("hook_event_name", ""))
        return {"result": result}

    def _to_codex_hook_response(
        self,
        result: dict[str, Any],
        hook_event_name: str,
        raw_msg: dict[str, Any] | None = None,
    ) -> dict[str, Any] | None:
        """Convert internal decision to Codex native hook response format.

        Codex native hooks have event-specific response contracts:
        PreToolUse uses ``permissionDecision=deny``; PermissionRequest uses
        ``decision.behavior``; PostToolUse can replace/contain a completed
        tool result with ``continue: false``; UserPromptSubmit and Stop accept
        the legacy ``decision: block`` shape.  Stop is guarded against an
        already-active continuation to avoid infinite continuation loops.
        """
        action = result.get("action", "continue")
        metadata = result.get("metadata", {})
        policy_id = metadata.get("policy_id", "")
        risk_level = metadata.get("risk_level", "unknown")
        reason = result.get("reason", "Blocked by ClawSentry security policy")
        message = f"[ClawSentry] {reason} (risk: {risk_level})"

        if hook_event_name == "PermissionRequest" and action in ("continue", "allow"):
            if policy_id.startswith("fallback-"):
                _log_stderr(
                    "Gateway unreachable — fail-open for Codex PermissionRequest "
                    f"(would have been: {action})"
                )
                return None
            if risk_level != "low":
                return None
            return {
                "hookSpecificOutput": {
                    "hookEventName": hook_event_name,
                    "decision": {"behavior": "allow"},
                },
            }

        if action in ("continue", "allow"):
            return None

        if policy_id.startswith("fallback-"):
            _log_stderr(
                f"Gateway unreachable — fail-open for Codex {hook_event_name} "
                f"(would have been: {action})"
            )
            return None

        if hook_event_name == "PermissionRequest" and action in ("block", "defer"):
            return {
                "hookSpecificOutput": {
                    "hookEventName": hook_event_name,
                    "decision": {
                        "behavior": "deny",
                        "message": message,
                    },
                },
            }

        if action in ("block", "defer"):
            if hook_event_name == "PreToolUse":
                return {
                    "hookSpecificOutput": {
                        "hookEventName": hook_event_name,
                        "permissionDecision": "deny",
                        "permissionDecisionReason": message,
                    },
                }
            if hook_event_name == "PostToolUse":
                return {
                    "continue": False,
                    "stopReason": message,
                    "hookSpecificOutput": {
                        "hookEventName": hook_event_name,
                        "additionalContext": message,
                    },
                }
            if hook_event_name == "UserPromptSubmit":
                return {
                    "decision": "block",
                    "reason": message,
                }
            if hook_event_name == "Stop":
                if raw_msg and raw_msg.get("stop_hook_active") is True:
                    _log_stderr(
                        "Codex Stop hook already active — fail-open to avoid continuation loop"
                    )
                    return None
                return {
                    "decision": "block",
                    "reason": message,
                }

        return None

    def _to_claude_code_response(
        self, result: dict[str, Any], hook_event_name: str,
    ) -> dict[str, Any] | None:
        """Convert internal decision to Claude Code hook response format.

        Claude Code PreToolUse hooks control execution via:
        - Return None → exit 0 → allow
        - Return hookSpecificOutput with permissionDecision: "deny" → block
        - Exit code 2 → block (handled by run_stdio)

        We use the hookSpecificOutput approach for richer feedback.

        **Fail-open on gateway unreachable**: When the Gateway is down,
        fallback decisions (DEFER/BLOCK) would break the developer workflow
        by blocking ALL tool calls.  We fail-open and log a warning instead.
        """
        action = result.get("action", "continue")
        if action in ("continue", "allow"):
            return None  # exit 0 = allow

        metadata = result.get("metadata", {})
        policy_id = metadata.get("policy_id", "")

        # Fail-open when Gateway is unreachable — don't break developer workflow.
        # Fallback decisions have policy_id "fallback-fail-closed" or "fallback-defer".
        if policy_id.startswith("fallback-"):
            _log_stderr(
                f"Gateway unreachable — fail-open for {hook_event_name} "
                f"(would have been: {action})"
            )
            return None  # allow: monitoring is down, don't block tools

        if action in ("block", "defer"):
            reason = result.get("reason", "Blocked by ClawSentry security policy")
            risk_level = metadata.get("risk_level", "unknown")
            message = f"[ClawSentry] {reason} (risk: {risk_level})"
            if hook_event_name == "UserPromptSubmit":
                return {
                    "decision": "block",
                    "reason": message,
                }
            return {
                "hookSpecificOutput": {
                    "hookEventName": hook_event_name,
                    "permissionDecision": "deny",
                    "permissionDecisionReason": message,
                },
            }

        return None  # unknown action = allow

    async def _async_dispatch(self, params: dict[str, Any]) -> None:
        """Background dispatch to gateway. Errors are logged, not raised."""
        try:
            await self._handle_event(params)
        except Exception:  # noqa: BLE001
            logger.debug("Async dispatch failed (non-blocking)", exc_info=True)

    async def _async_dispatch_codex_native(
        self,
        msg: dict[str, Any],
        *,
        project_meta: dict[str, Any] | None = None,
    ) -> None:
        """Background dispatch for Codex native hooks. Errors are non-blocking."""
        try:
            await self._handle_codex_native_hook(msg, project_meta=project_meta)
        except Exception:  # noqa: BLE001
            logger.debug("Codex async dispatch failed (non-blocking)", exc_info=True)

    async def _async_dispatch_kimi_native(
        self,
        msg: dict[str, Any],
        *,
        project_meta: dict[str, Any] | None = None,
    ) -> None:
        """Background dispatch for Kimi native hooks. Errors are non-blocking."""
        try:
            await self._handle_kimi_native_hook(msg, project_meta=project_meta)
        except Exception:  # noqa: BLE001
            logger.debug("Kimi async dispatch failed (non-blocking)", exc_info=True)

    async def _async_dispatch_gemini_native(
        self,
        msg: dict[str, Any],
        *,
        project_meta: dict[str, Any] | None = None,
    ) -> None:
        """Background dispatch for Gemini native hooks. Errors are non-blocking."""
        try:
            await self._handle_gemini_native_hook(msg, project_meta=project_meta)
        except Exception:  # noqa: BLE001
            logger.debug("Gemini async dispatch failed (non-blocking)", exc_info=True)

    def _suppress_native_stderr(self) -> bool:
        """Return whether hook stderr must stay empty for the host protocol."""
        return (
            str(getattr(self.adapter, "source_framework", "") or "").lower()
            in {"gemini-cli", "kimi-cli"}
        )

    def _log_hook_stderr(self, msg: str) -> None:
        """Emit stderr diagnostics unless the host treats stderr as hook output."""
        if self._suppress_native_stderr():
            _diag(f"stderr-suppressed: {msg}")
            return
        _log_stderr(msg)

    def run_stdio(self) -> None:
        self._log_hook_stderr("harness started")
        _diag(f"harness started (async={self.async_mode}, uds={self.adapter.uds_path})")
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            for raw_line in sys.stdin:
                line = raw_line.strip()
                if not line:
                    continue
                try:
                    msg = json.loads(line)
                except json.JSONDecodeError as exc:
                    self._log_hook_stderr(f"invalid json: {exc}")
                    _diag(f"invalid json: {exc}")
                    continue

                _diag(f"recv: hook_event={msg.get('hook_event_name', msg.get('method', '?'))} tool={msg.get('tool_name', '?')}")
                try:
                    response = loop.run_until_complete(self.dispatch_async(msg))
                except Exception as exc:
                    _diag(f"dispatch error: {exc}")
                    self._log_hook_stderr(f"dispatch error: {exc}")
                    continue
                _diag(f"response: {json.dumps(response, ensure_ascii=False) if response else 'None (allow)'}")
                if response is not None:
                    print(json.dumps(response, ensure_ascii=False), flush=True)
        except Exception as exc:
            _diag(f"run_stdio fatal: {exc}")
            raise
        finally:
            # Wait for any --async background tasks to complete
            pending = asyncio.all_tasks(loop)
            if pending:
                if self.async_mode:
                    _diag(
                        f"best-effort wait for {len(pending)} async tasks "
                        f"({self.async_shutdown_grace_seconds:.3f}s)"
                    )
                    _done, still_pending = loop.run_until_complete(
                        asyncio.wait(
                            pending,
                            timeout=self.async_shutdown_grace_seconds,
                        )
                    )
                    for task in still_pending:
                        task.cancel()
                    if still_pending:
                        loop.run_until_complete(
                            asyncio.gather(*still_pending, return_exceptions=True)
                        )
                else:
                    _diag(f"waiting for {len(pending)} async tasks")
                    loop.run_until_complete(asyncio.wait(pending, timeout=5.0))
            loop.close()
            _diag("harness exited")


def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run a3s-code AHP stdio harness bridged to ClawSentry Gateway."
    )
    parser.add_argument(
        "--uds-path",
        default=os.getenv("CS_UDS_PATH", "/tmp/clawsentry.sock"),
    )
    parser.add_argument(
        "--default-deadline-ms",
        type=int,
        default=int(os.getenv("A3S_GATEWAY_DEFAULT_DEADLINE_MS", "4500")),
    )
    parser.add_argument(
        "--max-rpc-retries",
        type=int,
        default=int(os.getenv("A3S_GATEWAY_MAX_RPC_RETRIES", "1")),
    )
    parser.add_argument(
        "--retry-backoff-ms",
        type=int,
        default=int(os.getenv("A3S_GATEWAY_RETRY_BACKOFF_MS", "50")),
    )
    parser.add_argument(
        "--framework",
        default=os.getenv("CS_FRAMEWORK", "a3s-code"),
        help="Source framework identifier (default: a3s-code).",
    )
    parser.add_argument(
        "--default-session-id",
        default=os.getenv("A3S_GATEWAY_DEFAULT_SESSION_ID", "ahp-session"),
    )
    parser.add_argument(
        "--default-agent-id",
        default=os.getenv("A3S_GATEWAY_DEFAULT_AGENT_ID", "ahp-agent"),
    )
    parser.add_argument(
        "--async",
        dest="async_mode",
        action="store_true",
        default=False,
        help="Return immediately for native hook events (fire-and-forget).",
    )
    return parser


def main() -> None:
    parser = _build_arg_parser()
    args = parser.parse_args()

    adapter = A3SCodeAdapter(
        uds_path=args.uds_path,
        default_deadline_ms=args.default_deadline_ms,
        max_rpc_retries=args.max_rpc_retries,
        retry_backoff_ms=args.retry_backoff_ms,
        source_framework=args.framework,
    )
    harness = A3SGatewayHarness(
        adapter,
        default_session_id=args.default_session_id,
        default_agent_id=args.default_agent_id,
        async_mode=args.async_mode,
    )
    harness.run_stdio()


if __name__ == "__main__":
    main()
