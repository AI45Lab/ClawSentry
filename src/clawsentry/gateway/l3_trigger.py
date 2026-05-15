"""Deterministic L3 trigger policy for Phase 5.2."""

from __future__ import annotations

import json
import re
from typing import Any

from .command_normalization import matches_shell_command_token
from .models import CanonicalEvent, DecisionContext, RiskLevel, RiskSnapshot
from .risk_signals import (
    build_archive_command_signals,
    build_base_event_signals,
    has_network_indicator,
    has_recon_indicator,
    has_staging_indicator,
)


_RISK_LEVEL_SCORE = {
    RiskLevel.LOW: 0,
    RiskLevel.MEDIUM: 1,
    RiskLevel.HIGH: 2,
    RiskLevel.CRITICAL: 3,
    "low": 0,
    "medium": 1,
    "high": 2,
    "critical": 3,
}

_HIGH_RISK_TOOLS = frozenset({
    "bash", "shell", "exec", "sudo", "chmod", "chown", "write", "edit",
    "write_file", "edit_file", "create_file",
})

_MANUAL_FLAGS = ("l3_escalate", "force_l3", "manual_l3_escalation")
_CUMULATIVE_THRESHOLD = 5
_COMPLEX_PAYLOAD_LENGTH = 512
_COMPLEX_PAYLOAD_DEPTH = 3
_COMPLEX_PAYLOAD_KEYS = 6


class L3TriggerPolicy:
    """Decide when to escalate from L2 to L3 deep review."""

    def trigger_metadata(
        self,
        event: CanonicalEvent,
        context: DecisionContext | None,
        l1_snapshot: RiskSnapshot,
        session_risk_history: list[Any],
    ) -> dict[str, str] | None:
        if self._has_manual_flag(context):
            return {"trigger_reason": "manual_l3_escalate"}
        if self._has_eager_profile(context):
            return {"trigger_reason": "eager"}
        pattern_detail = self._suspicious_pattern_detail(event, session_risk_history)
        if pattern_detail is not None:
            return {
                "trigger_reason": "suspicious_pattern",
                "trigger_detail": pattern_detail,
            }
        if self._cumulative_risk_score(session_risk_history, l1_snapshot) >= _CUMULATIVE_THRESHOLD:
            return {"trigger_reason": "cumulative_risk"}
        if self._is_high_risk_tool(event) and self._payload_complexity(event.payload or {}):
            return {"trigger_reason": "high_risk_complex_payload"}
        return None

    def trigger_reason(
        self,
        event: CanonicalEvent,
        context: DecisionContext | None,
        l1_snapshot: RiskSnapshot,
        session_risk_history: list[Any],
    ) -> str | None:
        metadata = self.trigger_metadata(event, context, l1_snapshot, session_risk_history)
        return None if metadata is None else metadata["trigger_reason"]

    def should_trigger(
        self,
        event: CanonicalEvent,
        context: DecisionContext | None,
        l1_snapshot: RiskSnapshot,
        session_risk_history: list[Any],
    ) -> bool:
        return self.trigger_metadata(event, context, l1_snapshot, session_risk_history) is not None

    def _has_manual_flag(self, context: DecisionContext | None) -> bool:
        if context is None or not isinstance(context.session_risk_summary, dict):
            return False
        return any(bool(context.session_risk_summary.get(flag)) for flag in _MANUAL_FLAGS)

    def _has_eager_profile(self, context: DecisionContext | None) -> bool:
        if context is None or not isinstance(context.session_risk_summary, dict):
            return False
        return str(context.session_risk_summary.get("l3_trigger_profile") or "").lower() == "eager"

    def _cumulative_risk_score(self, history: list[Any], current: RiskSnapshot) -> int:
        total = 0
        for item in history:
            level = self._extract_risk_level(item)
            total += _RISK_LEVEL_SCORE.get(level, 0)
        total += _RISK_LEVEL_SCORE.get(current.risk_level, 0)
        return total

    def _extract_risk_level(self, item: Any) -> Any:
        if isinstance(item, RiskSnapshot):
            return item.risk_level
        if isinstance(item, dict):
            if "risk_level" in item:
                return str(item.get("risk_level") or "").lower()
            decision = item.get("decision", {})
            if isinstance(decision, dict):
                return str(decision.get("risk_level") or "").lower()
        return None

    def _is_high_risk_tool(self, event: CanonicalEvent) -> bool:
        return str(event.tool_name or "").lower() in _HIGH_RISK_TOOLS

    def _detect_suspicious_pattern(
        self,
        event: CanonicalEvent,
        history: list[Any],
    ) -> bool:
        return self._suspicious_pattern_detail(event, history) is not None

    def _suspicious_pattern_detail(
        self,
        event: CanonicalEvent,
        history: list[Any],
    ) -> str | None:
        signals = [self._history_event_signal(item) for item in history]
        signals.append(self._event_signal(event))

        if len(signals) < 2:
            return None

        if self._has_secret_plus_network_pattern(signals):
            return "secret_plus_network"
        if self._has_privilege_escalation_chain(signals):
            return "privilege_escalation_chain"
        if self._has_tmp_staging_exfil_pattern(signals):
            return "tmp_staging_exfil"
        if self._has_recon_then_sudo_pattern(signals):
            return "recon_then_sudo"
        if self._has_secret_harvest_archive_pattern(signals):
            return "secret_harvest_archive"
        return None

    def _history_event_signal(self, item: Any) -> dict[str, bool]:
        if isinstance(item, dict):
            event = item.get("event", {})
            if isinstance(event, dict):
                return self._event_signal(
                    CanonicalEvent(
                        event_id=str(event.get("event_id") or "history"),
                        trace_id=str(event.get("trace_id") or "history"),
                        event_type=event.get("event_type") or "pre_action",
                        session_id=str(event.get("session_id") or "history"),
                        agent_id=str(event.get("agent_id") or "history"),
                        source_framework=str(event.get("source_framework") or "history"),
                        occurred_at=str(event.get("occurred_at") or "2026-01-01T00:00:00+00:00"),
                        payload=event.get("payload") if isinstance(event.get("payload"), dict) else {},
                        tool_name=event.get("tool_name"),
                        risk_hints=event.get("risk_hints") if isinstance(event.get("risk_hints"), list) else [],
                    )
                )
        return {
            "credential_access": False,
            "network_activity": False,
            "read_action": False,
            "write_action": False,
            "exec_action": False,
            "sudo_action": False,
            "tmp_staging": False,
            "tmp_exfil": False,
            "recon_action": False,
            "archive_action": False,
            "archive_sensitive_material": False,
        }

    def _event_signal(self, event: CanonicalEvent) -> dict[str, bool]:
        tool_name = str(event.tool_name or "").lower()
        payload_text = self._payload_text(event.payload or {})
        command_text = self._command_text(event.payload or {}, payload_text)
        path_text = ""
        if isinstance(event.payload, dict):
            path_text = str(
                event.payload.get("path")
                or event.payload.get("file_path")
                or ""
            )
        base = build_base_event_signals(
            tool_name=tool_name,
            path_text=path_text,
            payload_text=payload_text,
            command_text=command_text,
            risk_hints=event.risk_hints or [],
        )
        credential_access = base["credential_access"]
        network_activity = base["network_activity"] or has_network_indicator(payload_text)
        tmp_path_touched = base["tmp_path_touched"]
        staging_activity = base["write_action"] or has_staging_indicator(payload_text)
        recon_action = base["recon_action"] or has_recon_indicator(payload_text)
        archive = build_archive_command_signals(
            tool_name=tool_name,
            payload_text=payload_text,
            command_text=command_text,
            token_matcher=self._matches_shell_command_token,
        )

        return {
            "credential_access": credential_access,
            "network_activity": network_activity,
            "read_action": base["read_action"],
            "write_action": base["write_action"],
            "exec_action": base["exec_action"],
            "sudo_action": base["sudo_action"],
            "tmp_staging": tmp_path_touched and staging_activity,
            "tmp_exfil": tmp_path_touched and network_activity,
            "recon_action": recon_action,
            "archive_action": archive["archive_action"],
            "archive_sensitive_material": archive["archive_sensitive_material"],
        }

    def _is_archive_restore_action(self, command_text: str) -> bool:
        archive = build_archive_command_signals(
            tool_name="bash",
            command_text=command_text,
            token_matcher=self._matches_shell_command_token,
        )
        return archive["archive_restore_action"]

    def _is_archive_inspection_action(self, command_text: str) -> bool:
        archive = build_archive_command_signals(
            tool_name="bash",
            command_text=command_text,
            token_matcher=self._matches_shell_command_token,
        )
        return archive["archive_inspection_action"]

    def _command_text(self, payload: dict[str, Any], payload_text: str) -> str:
        command = payload.get("command") if isinstance(payload, dict) else None
        if isinstance(command, str):
            return command.lower()
        return payload_text

    def _matches_command_token(self, payload_text: str, token: str) -> bool:
        pattern = re.compile(rf"(?<![a-z0-9_-]){re.escape(token)}")
        return pattern.search(payload_text) is not None

    def _matches_shell_command_token(self, command_text: str, token: str) -> bool:
        return matches_shell_command_token(command_text, token)

    def _has_secret_plus_network_pattern(self, signals: list[dict[str, bool]]) -> bool:
        saw_credential = False
        saw_network = False
        for signal in signals:
            saw_credential = saw_credential or signal["credential_access"]
            saw_network = saw_network or signal["network_activity"]
            if saw_credential and saw_network:
                return True
        return False

    def _has_privilege_escalation_chain(self, signals: list[dict[str, bool]]) -> bool:
        saw_read = False
        saw_write = False
        saw_exec = False
        for signal in signals:
            if signal["read_action"]:
                saw_read = True
            if signal["write_action"] and saw_read:
                saw_write = True
            if signal["exec_action"] and saw_write:
                saw_exec = True
            if signal["sudo_action"] and (saw_write or saw_exec):
                return True
        return False

    def _has_tmp_staging_exfil_pattern(self, signals: list[dict[str, bool]]) -> bool:
        saw_tmp_staging = False
        for signal in signals:
            if signal["tmp_staging"]:
                saw_tmp_staging = True
            if signal["tmp_exfil"] and saw_tmp_staging:
                return True
        return False

    def _has_recon_then_sudo_pattern(self, signals: list[dict[str, bool]]) -> bool:
        saw_recon = False
        for signal in signals:
            if signal["recon_action"]:
                saw_recon = True
            if signal["sudo_action"] and saw_recon:
                return True
        return False

    def _has_secret_harvest_archive_pattern(self, signals: list[dict[str, bool]]) -> bool:
        credential_reads = 0
        for signal in signals:
            if signal["credential_access"]:
                credential_reads += 1
            if signal["archive_sensitive_material"] and credential_reads >= 2:
                return True
        return False

    def _payload_text(self, payload: dict[str, Any]) -> str:
        return json.dumps(payload, ensure_ascii=False, sort_keys=True).lower()

    def _payload_complexity(self, payload: Any) -> bool:
        serialized = json.dumps(payload, ensure_ascii=False, sort_keys=True)
        if len(serialized) >= _COMPLEX_PAYLOAD_LENGTH:
            return True
        if self._max_depth(payload) >= _COMPLEX_PAYLOAD_DEPTH:
            return True
        if isinstance(payload, dict) and len(payload) >= _COMPLEX_PAYLOAD_KEYS:
            return True
        return False

    def _max_depth(self, value: Any, depth: int = 1) -> int:
        if isinstance(value, dict) and value:
            return max(self._max_depth(v, depth + 1) for v in value.values())
        if isinstance(value, list) and value:
            return max(self._max_depth(v, depth + 1) for v in value)
        return depth
