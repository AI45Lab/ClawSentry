from __future__ import annotations

import json
import os
from unittest.mock import patch

import pytest

from clawsentry.gateway.anti_bypass_guard import AntiBypassGuard
from clawsentry.gateway.detection_config import DetectionConfig, build_detection_config_from_env
from clawsentry.gateway.models import (
    CanonicalDecision,
    CanonicalEvent,
    ClassifiedBy,
    DecisionSource,
    DecisionVerdict,
    EventType,
    RiskDimensions,
    RiskLevel,
    RiskSnapshot,
)
from clawsentry.gateway.server import SupervisionGateway


def _event(
    *,
    event_id: str,
    event_type: EventType = EventType.PRE_ACTION,
    session_id: str = "sess-anti-bypass",
    tool_name: str = "bash",
    payload: dict | None = None,
) -> CanonicalEvent:
    return CanonicalEvent(
        event_id=event_id,
        trace_id=f"trace-{event_id}",
        event_type=event_type,
        session_id=session_id,
        agent_id="agent-anti-bypass",
        source_framework="test",
        occurred_at="2026-04-28T00:00:00+00:00",
        payload=payload or {"command": "rm -rf /tmp/target"},
        tool_name=tool_name,
    )


def _decision(
    *,
    verdict: str = "block",
    risk_level: RiskLevel = RiskLevel.HIGH,
    policy_id: str = "test-policy",
) -> CanonicalDecision:
    return CanonicalDecision(
        decision=verdict,
        reason="test",
        policy_id=policy_id,
        risk_level=risk_level,
        decision_source=DecisionSource.POLICY,
        final=True,
    )


def _jsonrpc_request(params: dict, rpc_id: int = 1) -> bytes:
    return json.dumps({
        "jsonrpc": "2.0",
        "id": rpc_id,
        "method": "ahp/sync_decision",
        "params": params,
    }).encode()


def _sync_params(*, request_id: str, event_id: str, session_id: str = "sess-gw", tool_name: str = "bash", event_type: str = "pre_action", payload: dict | None = None) -> dict:
    return {
        "rpc_version": "sync_decision.1.0",
        "request_id": request_id,
        "deadline_ms": 1000,
        "decision_tier": "L1",
        "event": {
            "event_id": event_id,
            "trace_id": f"trace-{event_id}",
            "event_type": event_type,
            "session_id": session_id,
            "agent_id": "agent-gw",
            "source_framework": "test",
            "occurred_at": "2026-04-28T00:00:00+00:00",
            "payload": payload or {"command": "rm -rf /tmp/target"},
            "tool_name": tool_name,
        },
    }


class _FakeAntiBypassLLMProvider:
    provider_id = "fake-anti-bypass"

    def __init__(self, response: str) -> None:
        self.response = response
        self.calls: list[dict[str, object]] = []

    async def complete(
        self,
        system_prompt: str,
        user_message: str,
        timeout_ms: float,
        max_tokens: int = 256,
    ) -> str:
        self.calls.append({
            "system_prompt": system_prompt,
            "user_message": user_message,
            "timeout_ms": timeout_ms,
            "max_tokens": max_tokens,
        })
        return self.response


class _TimeoutAntiBypassLLMProvider(_FakeAntiBypassLLMProvider):
    async def complete(
        self,
        system_prompt: str,
        user_message: str,
        timeout_ms: float,
        max_tokens: int = 256,
    ) -> str:
        self.calls.append({
            "system_prompt": system_prompt,
            "user_message": user_message,
            "timeout_ms": timeout_ms,
            "max_tokens": max_tokens,
        })
        raise TimeoutError("provider timed out")


class TestAntiBypassConfig:
    def test_defaults_are_behavior_preserving(self):
        cfg = DetectionConfig()
        assert cfg.anti_bypass_guard_enabled is False
        assert cfg.anti_bypass_memory_ttl_s == 86_400.0
        assert cfg.anti_bypass_memory_max_records_per_session == 256
        assert cfg.anti_bypass_min_prior_risk == "high"
        assert cfg.anti_bypass_prior_verdicts == ("block", "defer")
        assert cfg.anti_bypass_exact_repeat_action == "block"
        assert cfg.anti_bypass_normalized_destructive_repeat_action == "defer"
        assert cfg.anti_bypass_cross_tool_similarity_action == "force_l3"
        assert cfg.anti_bypass_record_allow_decisions is False
        assert cfg.anti_bypass_same_tool_similarity_threshold == 0.88
        assert cfg.anti_bypass_llm_recognition_enabled is False
        assert cfg.anti_bypass_llm_candidate_threshold == 0.55
        assert cfg.anti_bypass_llm_confidence_threshold == 0.75
        assert cfg.anti_bypass_llm_timeout_ms == 800
        assert cfg.anti_bypass_llm_max_priors == 3
        assert cfg.anti_bypass_llm_action == "force_l3"

    def test_env_mapping_and_list_parsing(self):
        env = {
            "CS_ANTI_BYPASS_GUARD_ENABLED": "true",
            "CS_ANTI_BYPASS_MEMORY_TTL_S": "42",
            "CS_ANTI_BYPASS_MEMORY_MAX_RECORDS_PER_SESSION": "3",
            "CS_ANTI_BYPASS_MIN_PRIOR_RISK": "medium",
            "CS_ANTI_BYPASS_PRIOR_VERDICTS": "block, defer",
            "CS_ANTI_BYPASS_EXACT_REPEAT_ACTION": "defer",
            "CS_ANTI_BYPASS_NORMALIZED_DESTRUCTIVE_REPEAT_ACTION": "force_l2",
            "CS_ANTI_BYPASS_CROSS_TOOL_SIMILARITY_ACTION": "observe",
            "CS_ANTI_BYPASS_SIMILARITY_THRESHOLD": "0.5",
            "CS_ANTI_BYPASS_SAME_TOOL_SIMILARITY_THRESHOLD": "0.7",
            "CS_ANTI_BYPASS_LLM_CANDIDATE_THRESHOLD": "0.4",
            "CS_ANTI_BYPASS_LLM_CONFIDENCE_THRESHOLD": "0.8",
            "CS_ANTI_BYPASS_LLM_TIMEOUT_MS": "250",
            "CS_ANTI_BYPASS_LLM_MAX_PRIORS": "2",
            "CS_ANTI_BYPASS_LLM_ACTION": "force_l2",
            "CS_ANTI_BYPASS_RECORD_ALLOW_DECISIONS": "yes",
            "CS_ANTI_BYPASS_LLM_RECOGNITION_ENABLED": "yes",
        }
        with patch.dict(os.environ, env, clear=True):
            cfg = build_detection_config_from_env()
        assert cfg.anti_bypass_guard_enabled is True
        assert cfg.anti_bypass_memory_ttl_s == 42
        assert cfg.anti_bypass_memory_max_records_per_session == 3
        assert cfg.anti_bypass_min_prior_risk == "medium"
        assert cfg.anti_bypass_prior_verdicts == ("block", "defer")
        assert cfg.anti_bypass_exact_repeat_action == "defer"
        assert cfg.anti_bypass_normalized_destructive_repeat_action == "force_l2"
        assert cfg.anti_bypass_cross_tool_similarity_action == "observe"
        assert cfg.anti_bypass_similarity_threshold == 0.5
        assert cfg.anti_bypass_record_allow_decisions is True
        assert cfg.anti_bypass_same_tool_similarity_threshold == 0.7
        assert cfg.anti_bypass_llm_candidate_threshold == 0.4
        assert cfg.anti_bypass_llm_confidence_threshold == 0.8
        assert cfg.anti_bypass_llm_timeout_ms == 250
        assert cfg.anti_bypass_llm_max_priors == 2
        assert cfg.anti_bypass_llm_action == "force_l2"
        assert cfg.anti_bypass_llm_recognition_enabled is True

    def test_shared_llm_config_auto_enables_recognition_when_guard_enabled(self):
        env = {
            "CS_ANTI_BYPASS_GUARD_ENABLED": "true",
            "CS_LLM_PROVIDER": "openai",
            "CS_LLM_API_KEY": "sk-shared-test-key",
        }

        with patch.dict(os.environ, env, clear=True):
            cfg = build_detection_config_from_env()

        assert cfg.anti_bypass_guard_enabled is True
        assert cfg.anti_bypass_llm_recognition_enabled is True

    def test_explicit_llm_recognition_false_overrides_shared_llm_config(self):
        env = {
            "CS_ANTI_BYPASS_GUARD_ENABLED": "true",
            "CS_ANTI_BYPASS_LLM_RECOGNITION_ENABLED": "false",
            "CS_LLM_PROVIDER": "openai",
            "CS_LLM_API_KEY": "sk-shared-test-key",
        }

        with patch.dict(os.environ, env, clear=True):
            cfg = build_detection_config_from_env()

        assert cfg.anti_bypass_llm_recognition_enabled is False

    def test_custom_llm_api_key_env_participates_in_auto_enable(self):
        env = {
            "CS_ANTI_BYPASS_GUARD_ENABLED": "true",
            "CS_LLM_PROVIDER": "openai",
            "CS_LLM_API_KEY_ENV": "CUSTOM_LLM_KEY",
            "CUSTOM_LLM_KEY": "sk-custom-test-key",
        }

        with patch.dict(os.environ, env, clear=True):
            cfg = build_detection_config_from_env()

        assert cfg.anti_bypass_llm_recognition_enabled is True

    def test_shared_llm_config_without_guard_does_not_auto_enable_recognition(self):
        env = {
            "CS_LLM_PROVIDER": "openai",
            "CS_LLM_API_KEY": "sk-shared-test-key",
        }

        with patch.dict(os.environ, env, clear=True):
            cfg = build_detection_config_from_env()

        assert cfg.anti_bypass_guard_enabled is False
        assert cfg.anti_bypass_llm_recognition_enabled is False

    def test_benchmark_mode_does_not_auto_enable_external_llm_unless_explicit(self):
        env = {
            "CS_MODE": "benchmark",
            "CS_ANTI_BYPASS_GUARD_ENABLED": "true",
            "CS_LLM_PROVIDER": "openai",
            "CS_LLM_API_KEY": "sk-shared-test-key",
        }

        with patch.dict(os.environ, env, clear=True):
            cfg = build_detection_config_from_env()

        assert cfg.mode == "benchmark"
        assert cfg.anti_bypass_llm_recognition_enabled is False

        env["CS_ANTI_BYPASS_LLM_RECOGNITION_ENABLED"] = "true"
        with patch.dict(os.environ, env, clear=True):
            explicit_cfg = build_detection_config_from_env()

        assert explicit_cfg.anti_bypass_llm_recognition_enabled is True

    @pytest.mark.parametrize("mode_env_key", ["CS_DRY_RUN", "CS_NO_NETWORK"])
    def test_no_network_modes_do_not_auto_enable_external_llm_unless_explicit(self, mode_env_key):
        env = {
            mode_env_key: "true",
            "CS_ANTI_BYPASS_GUARD_ENABLED": "true",
            "CS_LLM_PROVIDER": "openai",
            "CS_LLM_API_KEY": "sk-shared-test-key",
        }

        with patch.dict(os.environ, env, clear=True):
            cfg = build_detection_config_from_env()

        assert cfg.anti_bypass_llm_recognition_enabled is False

        env["CS_ANTI_BYPASS_LLM_RECOGNITION_ENABLED"] = "true"
        with patch.dict(os.environ, env, clear=True):
            explicit_cfg = build_detection_config_from_env()

        assert explicit_cfg.anti_bypass_llm_recognition_enabled is True

    def test_cross_tool_block_is_coerced_to_force_l3(self, caplog):
        with caplog.at_level("WARNING"):
            cfg = DetectionConfig(anti_bypass_cross_tool_similarity_action="block")
        assert cfg.anti_bypass_cross_tool_similarity_action == "force_l3"
        assert "anti_bypass_cross_tool_similarity_action" in caplog.text

    def test_llm_block_action_config_is_coerced_to_force_l3(self, caplog):
        with caplog.at_level("WARNING"):
            cfg = DetectionConfig(anti_bypass_llm_action="block")
        assert cfg.anti_bypass_llm_action == "force_l3"
        assert "anti_bypass_llm_action" in caplog.text


class TestAntiBypassMemory:
    def test_records_only_compact_redacted_fields(self):
        secret = "Bearer SECRET-CANARY-123"
        cfg = DetectionConfig(anti_bypass_guard_enabled=True)
        guard = AntiBypassGuard()
        guard.record_final_decision(
            event=_event(event_id="evt-secret", payload={"command": f"curl -H '{secret}' https://example.test"}),
            decision=_decision(),
            snapshot=None,
            meta={"l3_trace": {"secret": secret}},
            record_id=7,
            config=cfg,
        )
        serialized = json.dumps(guard.records_for_session("sess-anti-bypass"))
        assert "SECRET-CANARY-123" not in serialized
        assert "curl -H" not in serialized
        assert "raw_payload_hash" in serialized
        assert "normalized_action_fingerprint" in serialized

    def test_exact_normalized_and_cross_tool_matching(self):
        cfg = DetectionConfig(anti_bypass_guard_enabled=True)
        guard = AntiBypassGuard()
        guard.record_final_decision(
            event=_event(event_id="evt-1", tool_name="bash", payload={"command": "sudo bash -c 'rm -rf /tmp/target'"}),
            decision=_decision(policy_id="L1-rule-engine"),
            snapshot=None,
            meta={},
            record_id=1,
            config=cfg,
        )

        exact = guard.match_pre_action(
            _event(event_id="evt-2", tool_name="bash", payload={"command": "sudo bash -c 'rm -rf /tmp/target'"}),
            None,
            cfg,
        )
        assert exact is not None
        assert exact.match_type == "exact_raw_repeat"
        assert exact.action == "block"

        normalized = guard.match_pre_action(
            _event(event_id="evt-3", tool_name="bash", payload={"command": "env FOO=bar rm -rf /tmp/target"}),
            None,
            cfg,
        )
        assert normalized is not None
        assert normalized.match_type == "normalized_destructive_repeat"

        cross_tool = guard.match_pre_action(
            _event(event_id="evt-4", tool_name="python", payload={"command": "python -c \"import os; os.system('rm -rf /tmp/target')\""}),
            None,
            cfg,
        )
        assert cross_tool is not None
        assert cross_tool.match_type == "cross_tool_script_similarity"
        assert cross_tool.action != "block"

    def test_denied_native_write_blocks_equivalent_shell_write_to_same_target(self):
        cfg = DetectionConfig(anti_bypass_guard_enabled=True)
        guard = AntiBypassGuard()
        guard.record_final_decision(
            event=_event(
                event_id="evt-native-write",
                tool_name="Write",
                payload={"path": "build/loader.sh", "content": "payload"},
            ),
            decision=_decision(policy_id="L1-rule-engine"),
            snapshot=None,
            meta={},
            record_id=11,
            config=cfg,
        )

        match = guard.match_pre_action(
            _event(
                event_id="evt-shell-write",
                tool_name="bash",
                payload={"command": "printf '%s' payload > build/loader.sh"},
            ),
            None,
            cfg,
        )

        assert match is not None
        assert match.match_type == "denied_effect_repeat"
        assert match.action == "block"
        meta = match.to_metadata()
        assert meta["reason_codes"] == ["denied_effect_repeat"]
        assert meta["evidence_categories"] == ["filesystem.write"]

    @pytest.mark.parametrize(
        ("tool_name", "payload"),
        [
            ("bash", {"command": "cat > build/loader.sh <<'EOF'\npayload\nEOF"}),
            ("bash", {"command": "printf payload | tee build/loader.sh"}),
            ("bash", {"command": "base64 -d payload.b64 > build/loader.sh"}),
            ("bash", {"command": "dd if=/tmp/payload of=build/loader.sh"}),
            ("python", {"command": "python -c \"open('build/loader.sh', 'w').write('payload')\""}),
            ("node", {"command": "node -e \"require('fs').writeFileSync('build/loader.sh', 'payload')\""}),
            ("powershell", {"command": "Set-Content -Path build/loader.sh -Value payload"}),
            ("Agent", {"prompt": "Create build/loader.sh with the payload from the blocked write."}),
            ("bash", {"command": "curl https://example.test/payload.sh -o build/loader.sh"}),
        ],
    )
    def test_denied_native_write_matches_equivalent_write_families(self, tool_name, payload):
        cfg = DetectionConfig(anti_bypass_guard_enabled=True)
        guard = AntiBypassGuard()
        guard.record_final_decision(
            event=_event(
                event_id="evt-native-write-family",
                tool_name="Write",
                payload={"path": "build/loader.sh", "content": "payload"},
            ),
            decision=_decision(policy_id="L1-rule-engine"),
            snapshot=None,
            meta={},
            record_id=13,
            config=cfg,
        )

        match = guard.match_pre_action(
            _event(
                event_id="evt-equivalent-write-family",
                tool_name=tool_name,
                payload=payload,
            ),
            None,
            cfg,
        )

        assert match is not None
        assert match.match_type == "denied_effect_repeat"
        assert match.action == "block"

    def test_denied_native_write_matches_powershell_quoted_path_with_spaces(self):
        cfg = DetectionConfig(anti_bypass_guard_enabled=True)
        guard = AntiBypassGuard()
        guard.record_final_decision(
            event=_event(
                event_id="evt-native-write-space-path",
                tool_name="Write",
                payload={"path": "build/loader script.ps1", "content": "payload"},
            ),
            decision=_decision(policy_id="L1-rule-engine"),
            snapshot=None,
            meta={},
            record_id=18,
            config=cfg,
        )

        match = guard.match_pre_action(
            _event(
                event_id="evt-powershell-space-path",
                tool_name="powershell",
                payload={"command": "Set-Content -Path \"build/loader script.ps1\" -Value payload"},
            ),
            None,
            cfg,
        )

        assert match is not None
        assert match.match_type == "denied_effect_repeat"
        assert match.action == "block"

    def test_pending_defer_records_review_only_effect_hold(self):
        cfg = DetectionConfig(anti_bypass_guard_enabled=True)
        guard = AntiBypassGuard()
        guard.record_final_decision(
            event=_event(
                event_id="evt-pending-write",
                tool_name="Write",
                payload={"path": "build/loader.sh", "content": "payload"},
            ),
            decision=CanonicalDecision(
                decision=DecisionVerdict.DEFER,
                reason="pending operator review",
                policy_id="L1-rule-engine",
                risk_level=RiskLevel.HIGH,
                decision_source=DecisionSource.POLICY,
                final=False,
            ),
            snapshot=None,
            meta={},
            record_id=12,
            config=cfg,
        )

        assert guard.denied_effect_records_for_session("sess-anti-bypass") == []
        pending = guard.pending_effect_holds_for_session("sess-anti-bypass")
        assert len(pending) == 1
        assert pending[0]["capability"] == "filesystem.write"

        match = guard.match_pre_action(
            _event(
                event_id="evt-shell-write",
                tool_name="bash",
                payload={"command": "printf '%s' payload > build/loader.sh"},
            ),
            None,
            cfg,
        )

        assert match is not None
        assert match.match_type == "pending_effect_equivalent"
        assert match.action == "defer"
        assert "pending_effect_equivalent" in match.reason_codes
        assert "denied_effect_repeat" not in match.reason_codes

    def test_contextual_fail_closed_block_does_not_record_denied_effect(self):
        guard = AntiBypassGuard()
        cfg = DetectionConfig(anti_bypass_guard_enabled=True)
        snapshot = RiskSnapshot(
            risk_level=RiskLevel.HIGH,
            composite_score=8.0,
            dimensions=RiskDimensions(d1=2, d2=1, d3=0, d4=2, d5=1, d6=0.0),
            classified_by=ClassifiedBy.L1,
            classified_at="2026-05-21T00:00:00+00:00",
            l2_l3_summary={"status": "contextual_review_failed_closed"},
        )

        guard.record_final_decision(
            _event(event_id="evt-contextual", payload={"command": "python3 verify.py > out.json"}),
            _decision(verdict="block"),
            snapshot,
            {},
            1,
            cfg,
        )

        assert guard.denied_effect_records_for_session("sess-anti-bypass") == []

    def test_contextual_pending_hold_does_not_match_revised_safe_script_hash(self):
        guard = AntiBypassGuard()
        cfg = DetectionConfig(anti_bypass_guard_enabled=True)
        pending_snapshot = RiskSnapshot(
            risk_level=RiskLevel.HIGH,
            composite_score=8.0,
            dimensions=RiskDimensions(d1=2, d2=1, d3=0, d4=2, d5=1, d6=0.0),
            classified_by=ClassifiedBy.L1,
            classified_at="2026-05-21T00:00:00+00:00",
            l2_l3_summary={"status": "contextual_review_deferred"},
        )

        guard.record_final_decision(
            _event(event_id="evt-contextual-pending", payload={"command": "python3 verify.py > out.json"}),
            CanonicalDecision(
                decision=DecisionVerdict.DEFER,
                reason="contextual pending",
                policy_id="L1-rule-engine",
                risk_level=RiskLevel.HIGH,
                decision_source=DecisionSource.POLICY,
                final=False,
            ),
            pending_snapshot,
            {},
            1,
            cfg,
        )

        match = guard.match_pre_action(
            _event(event_id="evt-contextual-revised", payload={"command": "python3 verify_v2.py > out.json"}),
            None,
            cfg,
        )

        assert match is None

    def test_contextual_pending_hold_matches_exact_repeat_as_contextual_repeat_only(self):
        guard = AntiBypassGuard()
        cfg = DetectionConfig(anti_bypass_guard_enabled=True)
        pending_snapshot = RiskSnapshot(
            risk_level=RiskLevel.HIGH,
            composite_score=8.0,
            dimensions=RiskDimensions(d1=2, d2=1, d3=0, d4=2, d5=1, d6=0.0),
            classified_by=ClassifiedBy.L1,
            classified_at="2026-05-21T00:00:00+00:00",
            l2_l3_summary={"status": "contextual_review_deferred"},
        )
        event = _event(event_id="evt-contextual-pending", payload={"command": "python3 verify.py > out.json"})

        guard.record_final_decision(
            event,
            CanonicalDecision(
                decision=DecisionVerdict.DEFER,
                reason="contextual pending",
                policy_id="L1-rule-engine",
                risk_level=RiskLevel.HIGH,
                decision_source=DecisionSource.POLICY,
                final=False,
            ),
            pending_snapshot,
            {},
            1,
            cfg,
        )
        match = guard.match_pre_action(event, None, cfg)

        assert match.match_type == "contextual_pending_effect_repeat"
        assert match.reason_codes == ("contextual_pending_effect_repeat",)
        assert "denied_effect_repeat" not in match.reason_codes

    def test_contextual_reviewer_block_records_denied_effect_repeat(self):
        guard = AntiBypassGuard()
        cfg = DetectionConfig(anti_bypass_guard_enabled=True)
        snapshot = RiskSnapshot(
            risk_level=RiskLevel.HIGH,
            composite_score=8.0,
            dimensions=RiskDimensions(d1=2, d2=1, d3=0, d4=2, d5=1, d6=0.0),
            classified_by=ClassifiedBy.L1,
            classified_at="2026-05-21T00:00:00+00:00",
            l2_l3_summary={"status": "contextual_review_blocked"},
        )
        event = _event(event_id="evt-contextual-terminal-block", payload={"command": "python3 verify.py > out.json"})

        guard.record_final_decision(event, _decision(verdict="block"), snapshot, {}, 1, cfg)
        match = guard.match_pre_action(event, None, cfg)

        assert match.match_type == "denied_effect_repeat"

    def test_resolved_pending_effect_allow_clears_review_hold(self):
        cfg = DetectionConfig(anti_bypass_guard_enabled=True)
        guard = AntiBypassGuard()
        event = _event(
            event_id="evt-pending-allow",
            tool_name="Write",
            payload={"path": "build/loader.sh", "content": "payload"},
        )
        guard.record_final_decision(
            event=event,
            decision=CanonicalDecision(
                decision=DecisionVerdict.DEFER,
                reason="pending operator review",
                policy_id="L1-rule-engine",
                risk_level=RiskLevel.HIGH,
                decision_source=DecisionSource.POLICY,
                final=False,
            ),
            snapshot=None,
            meta={},
            record_id=14,
            config=cfg,
        )

        guard.resolve_pending_effect_hold(
            event=event,
            decision=CanonicalDecision(
                decision=DecisionVerdict.ALLOW,
                reason="operator approved",
                policy_id="defer-bridge",
                risk_level=RiskLevel.HIGH,
                decision_source=DecisionSource.OPERATOR,
                final=True,
            ),
            record_id=15,
            config=cfg,
        )

        assert guard.pending_effect_holds_for_session("sess-anti-bypass") == []
        assert guard.denied_effect_records_for_session("sess-anti-bypass") == []
        match = guard.match_pre_action(
            _event(
                event_id="evt-shell-after-allow",
                tool_name="bash",
                payload={"command": "printf '%s' payload > build/loader.sh"},
            ),
            None,
            cfg,
        )
        assert match is None

    def test_resolved_pending_effect_block_promotes_denied_effect(self):
        cfg = DetectionConfig(anti_bypass_guard_enabled=True)
        guard = AntiBypassGuard()
        event = _event(
            event_id="evt-pending-block",
            tool_name="Write",
            payload={"path": "build/loader.sh", "content": "payload"},
        )
        guard.record_final_decision(
            event=event,
            decision=CanonicalDecision(
                decision=DecisionVerdict.DEFER,
                reason="pending operator review",
                policy_id="L1-rule-engine",
                risk_level=RiskLevel.HIGH,
                decision_source=DecisionSource.POLICY,
                final=False,
            ),
            snapshot=None,
            meta={},
            record_id=16,
            config=cfg,
        )

        guard.resolve_pending_effect_hold(
            event=event,
            decision=_decision(policy_id="defer-bridge"),
            record_id=17,
            config=cfg,
        )

        assert guard.pending_effect_holds_for_session("sess-anti-bypass") == []
        assert guard.denied_effect_records_for_session("sess-anti-bypass")
        match = guard.match_pre_action(
            _event(
                event_id="evt-shell-after-block",
                tool_name="bash",
                payload={"command": "printf '%s' payload > build/loader.sh"},
            ),
            None,
            cfg,
        )
        assert match is not None
        assert match.match_type == "denied_effect_repeat"

    def test_normal_profile_artifact_family_match_routes_review_not_block(self):
        cfg = DetectionConfig(anti_bypass_guard_enabled=True, mode="normal")
        guard = AntiBypassGuard()
        guard.record_final_decision(
            event=_event(
                event_id="evt-native-write-family-prior",
                tool_name="Write",
                payload={"path": "build/loader.sh", "content": "payload"},
            ),
            decision=_decision(policy_id="L1-rule-engine"),
            snapshot=None,
            meta={},
            record_id=14,
            config=cfg,
        )

        match = guard.match_pre_action(
            _event(
                event_id="evt-native-write-family-current",
                tool_name="bash",
                payload={"command": "printf '%s' payload > build/bootstrap.sh"},
            ),
            None,
            cfg,
        )

        assert match is not None
        assert match.match_type == "denied_effect_repeat"
        assert match.action == "defer"
        assert "artifact_family_match" in match.reason_codes

    def test_priority_ranking_prefers_older_exact_raw_over_newer_cross_tool_match(self):
        cfg = DetectionConfig(anti_bypass_guard_enabled=True)
        guard = AntiBypassGuard()
        guard.record_final_decision(
            event=_event(
                event_id="evt-older-exact",
                tool_name="bash",
                payload={"command": "rm -rf /tmp/target"},
            ),
            decision=_decision(policy_id="older-exact-policy"),
            snapshot=None,
            meta={},
            record_id=1,
            config=cfg,
        )
        guard.record_final_decision(
            event=_event(
                event_id="evt-newer-weak",
                tool_name="python",
                payload={"command": "python -c \"import shutil; shutil.rmtree('/tmp/target')\""},
            ),
            decision=_decision(policy_id="newer-cross-tool-policy"),
            snapshot=None,
            meta={},
            record_id=2,
            config=cfg,
        )

        match = guard.match_pre_action(
            _event(
                event_id="evt-current",
                tool_name="bash",
                payload={"command": "rm -rf /tmp/target"},
            ),
            None,
            cfg,
        )

        assert match is not None
        assert match.match_type == "exact_raw_repeat"
        assert match.prior_record_id == 1
        assert match.prior_policy_id == "older-exact-policy"

    def test_normalized_destructive_repeat_metadata_identifies_exact_fingerprint(self):
        cfg = DetectionConfig(anti_bypass_guard_enabled=True)
        guard = AntiBypassGuard()
        guard.record_final_decision(
            event=_event(event_id="evt-1", payload={"command": "sudo bash -c 'rm -rf /tmp/target'"}),
            decision=_decision(),
            snapshot=None,
            meta={},
            record_id=1,
            config=cfg,
        )

        match = guard.match_pre_action(
            _event(event_id="evt-2", payload={"command": "env FOO=bar rm -rf /tmp/target"}),
            None,
            cfg,
        )

        assert match is not None
        assert match.to_metadata()["recognition_source"] == "deterministic"
        assert match.to_metadata()["similarity_mode"] == "normalized_hash"
        assert match.to_metadata()["match_reason"] == "exact_normalized_fingerprint"

    def test_normalized_repeat_ignores_benign_read_like_prior(self):
        cfg = DetectionConfig(anti_bypass_guard_enabled=True)
        guard = AntiBypassGuard()
        guard.record_final_decision(
            event=_event(event_id="evt-benign-1", payload={"command": "sudo bash -c 'ls /tmp/target'"}),
            decision=_decision(risk_level=RiskLevel.HIGH),
            snapshot=None,
            meta={},
            record_id=1,
            config=cfg,
        )

        match = guard.match_pre_action(
            _event(event_id="evt-benign-2", payload={"command": "env FOO=bar ls /tmp/target"}),
            None,
            cfg,
        )

        assert match is None

    def test_same_tool_soft_similarity_matches_destructive_variants(self):
        cfg = DetectionConfig(
            anti_bypass_guard_enabled=True,
            anti_bypass_same_tool_similarity_threshold=0.88,
        )
        guard = AntiBypassGuard()
        guard.record_final_decision(
            event=_event(event_id="evt-soft-1", payload={"command": "rm -rf /tmp/target/cache"}),
            decision=_decision(),
            snapshot=None,
            meta={},
            record_id=1,
            config=cfg,
        )

        match = guard.match_pre_action(
            _event(event_id="evt-soft-2", payload={"command": "rm -rf /tmp/target/cache/"}),
            None,
            cfg,
        )

        assert match is not None
        assert match.match_type == "normalized_destructive_repeat"
        assert match.to_metadata()["similarity_mode"] == "same_tool_jaccard"
        assert match.to_metadata()["match_reason"] == "same_tool_feature_similarity"

    def test_same_tool_soft_similarity_ignores_non_destructive_overlap(self):
        cfg = DetectionConfig(
            anti_bypass_guard_enabled=True,
            anti_bypass_same_tool_similarity_threshold=0.88,
        )
        guard = AntiBypassGuard()
        guard.record_final_decision(
            event=_event(event_id="evt-read-1", payload={"command": "cat /tmp/target/cache"}),
            decision=_decision(risk_level=RiskLevel.HIGH),
            snapshot=None,
            meta={},
            record_id=1,
            config=cfg,
        )

        match = guard.match_pre_action(
            _event(event_id="evt-read-2", payload={"command": "cat /tmp/target/cache/"}),
            None,
            cfg,
        )

        assert match is None

    def test_cross_tool_python_deletion_api_matches_prior_rm_scope(self):
        cfg = DetectionConfig(anti_bypass_guard_enabled=True)
        guard = AntiBypassGuard()
        guard.record_final_decision(
            event=_event(
                event_id="evt-python-api-1",
                tool_name="bash",
                payload={"command": "rm -rf /tmp/target"},
            ),
            decision=_decision(),
            snapshot=None,
            meta={},
            record_id=1,
            config=cfg,
        )

        match = guard.match_pre_action(
            _event(
                event_id="evt-python-api-2",
                tool_name="python",
                payload={"command": "python -c \"import shutil; shutil.rmtree('/tmp/target')\""},
            ),
            None,
            cfg,
        )

        assert match is not None
        assert match.match_type == "cross_tool_script_similarity"
        assert match.action == "force_l3"
        meta = match.to_metadata()
        assert meta["similarity_mode"] == "operation_scope"
        assert "similarity" not in meta

    def test_unrelated_cross_tool_curl_labels_do_not_match_without_shared_scope(self):
        cfg = DetectionConfig(anti_bypass_guard_enabled=True)
        guard = AntiBypassGuard()
        guard.record_final_decision(
            event=_event(
                event_id="evt-curl-1",
                tool_name="bash",
                payload={"command": "curl https://updates.example/releases/app.tar.gz"},
            ),
            decision=_decision(),
            snapshot=None,
            meta={},
            record_id=1,
            config=cfg,
        )

        match = guard.match_pre_action(
            _event(
                event_id="evt-curl-2",
                tool_name="python",
                payload={"command": "curl https://metrics.example/ping/health"},
            ),
            None,
            cfg,
        )

        assert match is None

    def test_cross_tool_intent_label_metadata_does_not_report_fake_jaccard(self):
        cfg = DetectionConfig(anti_bypass_guard_enabled=True)
        guard = AntiBypassGuard()
        guard.record_final_decision(
            event=_event(
                event_id="evt-intent-1",
                tool_name="bash",
                payload={"command": "delete /tmp/target"},
            ),
            decision=_decision(),
            snapshot=None,
            meta={},
            record_id=1,
            config=cfg,
        )

        match = guard.match_pre_action(
            _event(
                event_id="evt-intent-2",
                tool_name="python",
                payload={"command": "python -c \"open('/tmp/target', 'w').truncate(0)\""},
            ),
            None,
            cfg,
        )

        assert match is not None
        meta = match.to_metadata()
        assert meta["similarity_mode"] == "intent_label"
        assert meta["match_reason"] == "destructive_intent_label"
        assert "similarity" not in meta

    def test_llm_candidates_reject_scope_only_overlap(self):
        cfg = DetectionConfig(
            anti_bypass_guard_enabled=True,
            anti_bypass_llm_recognition_enabled=True,
            anti_bypass_llm_candidate_threshold=0.99,
        )
        guard = AntiBypassGuard()
        guard.record_final_decision(
            event=_event(
                event_id="evt-scope-1",
                tool_name="bash",
                payload={"command": "curl https://updates.example/project"},
            ),
            decision=_decision(),
            snapshot=None,
            meta={},
            record_id=1,
            config=cfg,
        )

        candidates = guard.llm_candidates(
            _event(
                event_id="evt-scope-2",
                tool_name="python",
                payload={"command": "python -c \"print('/tmp/project')\""},
            ),
            None,
            cfg,
        )

        assert candidates == []

    def test_llm_candidates_reject_current_non_destructive_action(self):
        cfg = DetectionConfig(
            anti_bypass_guard_enabled=True,
            anti_bypass_llm_recognition_enabled=True,
            anti_bypass_llm_candidate_threshold=0.1,
        )
        guard = AntiBypassGuard()
        guard.record_final_decision(
            event=_event(
                event_id="evt-nondestructive-1",
                tool_name="bash",
                payload={"command": "rm -rf /tmp/project/cache"},
            ),
            decision=_decision(),
            snapshot=None,
            meta={},
            record_id=1,
            config=cfg,
        )

        candidates = guard.llm_candidates(
            _event(
                event_id="evt-nondestructive-2",
                tool_name="python",
                payload={"command": "python -c \"print('/tmp/project/cache')\""},
            ),
            None,
            cfg,
        )

        assert candidates == []

    def test_ttl_and_cap_eviction(self):
        cfg = DetectionConfig(
            anti_bypass_guard_enabled=True,
            anti_bypass_memory_max_records_per_session=1,
        )
        guard = AntiBypassGuard()
        guard.record_final_decision(_event(event_id="evt-1"), _decision(), None, {}, 1, cfg)
        guard.record_final_decision(_event(event_id="evt-2"), _decision(), None, {}, 2, cfg)
        records = guard.records_for_session("sess-anti-bypass")
        assert len(records) == 1
        assert records[0]["event_id"] == "evt-2"
        assert guard.memory_evictions == 1

    def test_non_pre_action_is_ignored(self):
        cfg = DetectionConfig(anti_bypass_guard_enabled=True)
        guard = AntiBypassGuard()
        guard.record_final_decision(
            _event(event_id="evt-post", event_type=EventType.POST_ACTION),
            _decision(),
            None,
            {},
            1,
            cfg,
        )
        assert guard.records_for_session("sess-anti-bypass") == []

    def test_non_final_decisions_are_not_recorded(self):
        cfg = DetectionConfig(anti_bypass_guard_enabled=True)
        guard = AntiBypassGuard()
        non_final_defer = CanonicalDecision(
            decision=DecisionVerdict.DEFER,
            reason="approval pending",
            policy_id="pending-review",
            risk_level=RiskLevel.HIGH,
            decision_source=DecisionSource.POLICY,
            final=False,
        )
        guard.record_final_decision(
            _event(event_id="evt-non-final"),
            non_final_defer,
            None,
            {},
            1,
            cfg,
        )
        assert guard.records_for_session("sess-anti-bypass") == []


class TestAntiBypassGatewayIntegration:
    @pytest.mark.asyncio
    async def test_default_disabled_repeated_decisions_do_not_attach_guard_metadata(self):
        gw = SupervisionGateway(detection_config=DetectionConfig())
        await gw.handle_jsonrpc(_jsonrpc_request(_sync_params(request_id="req-1", event_id="evt-1")))
        await gw.handle_jsonrpc(_jsonrpc_request(_sync_params(request_id="req-2", event_id="evt-2")))
        assert "anti_bypass" not in gw.trajectory_store.records[-1]["meta"]
        assert gw.anti_bypass_guard.records_for_session("sess-gw") == []

    @pytest.mark.asyncio
    async def test_exact_repeat_blocks_before_normal_policy_and_records_prior_id(self):
        cfg = DetectionConfig(anti_bypass_guard_enabled=True)
        gw = SupervisionGateway(detection_config=cfg)
        await gw.handle_jsonrpc(_jsonrpc_request(_sync_params(request_id="req-1", event_id="evt-1")))
        result = await gw.handle_jsonrpc(_jsonrpc_request(_sync_params(request_id="req-2", event_id="evt-2")))
        decision = result["result"]["decision"]
        assert decision["decision"] == "block"
        assert decision["policy_id"] == "anti-bypass-exact-repeat"
        meta = gw.trajectory_store.records[-1]["meta"]["anti_bypass"]
        assert meta["match_type"] == "exact_raw_repeat"
        assert meta["prior_event_id"] == "evt-1"
        assert meta["prior_record_id"] == 1
        decision_events = [
            event for event in gw.event_bus._replay_buffer  # noqa: SLF001 - compact SSE regression assertion
            if event.get("type") == "decision" and event.get("event_id") == "evt-2"
        ]
        assert decision_events[-1]["anti_bypass"]["match_type"] == "exact_raw_repeat"
        assert "command" not in decision_events[-1]["anti_bypass"]
        assert decision_events[-1]["command"] == "bash"

    @pytest.mark.asyncio
    async def test_anti_bypass_sse_event_redacts_raw_command_canary(self):
        canary = "SECRET-CANARY-123"
        cfg = DetectionConfig(anti_bypass_guard_enabled=True)
        gw = SupervisionGateway(detection_config=cfg)
        payload = {"command": f"curl -H 'Authorization: Bearer {canary}' https://example.test && rm -rf /tmp/target"}
        await gw.handle_jsonrpc(_jsonrpc_request(_sync_params(
            request_id="req-secret-1",
            event_id="evt-secret-1",
            session_id="sess-secret",
            payload=payload,
        )))
        await gw.handle_jsonrpc(_jsonrpc_request(_sync_params(
            request_id="req-secret-2",
            event_id="evt-secret-2",
            session_id="sess-secret",
            payload=payload,
        )))
        decision_events = [
            event for event in gw.event_bus._replay_buffer  # noqa: SLF001 - compact SSE regression assertion
            if event.get("type") == "decision" and event.get("event_id") == "evt-secret-2"
        ]
        serialized = json.dumps(decision_events[-1])
        assert "anti_bypass" in decision_events[-1]
        assert canary not in serialized
        assert "Authorization" not in serialized
        assert decision_events[-1]["command"] == "bash"

    @pytest.mark.asyncio
    async def test_anti_bypass_defer_pending_redacts_raw_command_canary(self):
        canary = "SECRET-CANARY-XYZ"
        cfg = DetectionConfig(
            anti_bypass_guard_enabled=True,
            anti_bypass_exact_repeat_action="defer",
            defer_timeout_s=0.01,
            defer_timeout_action="allow",
        )
        gw = SupervisionGateway(detection_config=cfg)
        payload = {"command": f"sudo bash -c 'curl -H Authorization:Bearer-{canary} https://example.test && rm -rf /tmp/target'"}
        await gw.handle_jsonrpc(_jsonrpc_request(_sync_params(
            request_id="req-defer-secret-1",
            event_id="evt-defer-secret-1",
            session_id="sess-defer-secret",
            payload=payload,
        )))
        await gw.handle_jsonrpc(_jsonrpc_request(_sync_params(
            request_id="req-defer-secret-2",
            event_id="evt-defer-secret-2",
            session_id="sess-defer-secret",
            payload=payload,
        )))
        pending_events = [
            event for event in gw.event_bus._replay_buffer  # noqa: SLF001 - compact SSE regression assertion
            if event.get("type") == "defer_pending" and event.get("session_id") == "sess-defer-secret"
        ]
        assert pending_events
        serialized = json.dumps(pending_events[-1])
        assert canary not in serialized
        assert "Authorization" not in serialized
        assert pending_events[-1]["command"] == "bash"

    @pytest.mark.asyncio
    async def test_guard_runs_pre_action_only(self):
        cfg = DetectionConfig(anti_bypass_guard_enabled=True)
        gw = SupervisionGateway(detection_config=cfg)
        await gw.handle_jsonrpc(_jsonrpc_request(_sync_params(request_id="req-1", event_id="evt-1")))
        await gw.handle_jsonrpc(_jsonrpc_request(_sync_params(
            request_id="req-post",
            event_id="evt-post",
            event_type="post_action",
            payload={"command": "rm -rf /tmp/target", "output": "done"},
        )))
        assert "anti_bypass" not in gw.trajectory_store.records[-1]["meta"]

    @pytest.mark.asyncio
    async def test_benchmark_auto_resolution_is_recorded_as_final_decision(self):
        cfg = DetectionConfig(
            anti_bypass_guard_enabled=True,
            anti_bypass_exact_repeat_action="defer",
            mode="benchmark",
            benchmark_auto_resolve_defer=True,
            benchmark_defer_action="allow",
        )
        gw = SupervisionGateway(detection_config=cfg)
        await gw.handle_jsonrpc(_jsonrpc_request(_sync_params(request_id="req-1", event_id="evt-1")))
        result = await gw.handle_jsonrpc(_jsonrpc_request(_sync_params(request_id="req-2", event_id="evt-2")))
        assert result["result"]["decision"]["decision"] == "allow"
        record = gw.trajectory_store.records[-1]
        assert record["meta"]["anti_bypass"]["action"] == "defer"
        assert record["meta"]["auto_resolved"] is True
        assert len(gw.anti_bypass_guard.records_for_session("sess-gw")) == 1

    @pytest.mark.asyncio
    async def test_llm_assisted_cross_tool_candidate_forces_l3_with_redacted_prompt(self):
        provider = _FakeAntiBypassLLMProvider(json.dumps({
            "schema": "cs.anti_bypass.recognition.v1",
            "matched": True,
            "confidence": 0.91,
            "action": "force_l3",
            "prior_record_id": 1,
            "reason_codes": ["same_destructive_followup"],
            "evidence_categories": ["operation_overlap", "scope_overlap"],
        }))
        cfg = DetectionConfig(
            anti_bypass_guard_enabled=True,
            anti_bypass_llm_recognition_enabled=True,
            anti_bypass_llm_candidate_threshold=0.1,
        )
        gw = SupervisionGateway(
            detection_config=cfg,
            anti_bypass_llm_provider=provider,
        )
        await gw.handle_jsonrpc(_jsonrpc_request(_sync_params(
            request_id="req-llm-1",
            event_id="evt-llm-1",
            session_id="sess-llm",
            tool_name="bash",
            payload={"command": "rm -rf /tmp/project/cache"},
        )))
        canary = "SECRET-CANARY-LLM"
        result = await gw.handle_jsonrpc(_jsonrpc_request(_sync_params(
            request_id="req-llm-2",
            event_id="evt-llm-2",
            session_id="sess-llm",
            tool_name="python",
            payload={
                "command": (
                    "python -c \""
                    "print('remove /tmp/project/cache'); "
                    f"print('Authorization: Bearer {canary}')\""
                )
            },
        )))

        meta = gw.trajectory_store.records[-1]["meta"]["anti_bypass"]
        assert meta["recognition_source"] == "llm_assisted"
        assert meta["similarity_mode"] == "llm_capsule"
        assert meta["llm_state"] == "matched"
        assert meta["llm_confidence"] == 0.91
        assert meta["action"] == "force_l3"
        assert result["result"]["l3_requested"] is True
        assert len(provider.calls) == 1
        prompt = json.dumps(provider.calls[0])
        assert canary not in prompt
        assert "Authorization" not in prompt
        assert "remove /tmp/project/cache" not in prompt
        assert "rm -rf /tmp/project/cache" not in prompt
        assert "sha256:" not in prompt
        assert "same_destructive_followup" not in meta["reason_codes"]

    @pytest.mark.asyncio
    async def test_llm_recognizer_is_not_called_when_deterministic_match_exists(self):
        provider = _FakeAntiBypassLLMProvider(json.dumps({
            "schema": "cs.anti_bypass.recognition.v1",
            "matched": True,
            "confidence": 0.99,
            "action": "force_l3",
            "prior_record_id": 1,
            "reason_codes": ["should_not_run"],
            "evidence_categories": ["exact_match"],
        }))
        cfg = DetectionConfig(
            anti_bypass_guard_enabled=True,
            anti_bypass_llm_recognition_enabled=True,
        )
        gw = SupervisionGateway(
            detection_config=cfg,
            anti_bypass_llm_provider=provider,
        )

        await gw.handle_jsonrpc(_jsonrpc_request(_sync_params(
            request_id="req-exact-llm-1",
            event_id="evt-exact-llm-1",
            session_id="sess-exact-llm",
            payload={"command": "rm -rf /tmp/target"},
        )))
        await gw.handle_jsonrpc(_jsonrpc_request(_sync_params(
            request_id="req-exact-llm-2",
            event_id="evt-exact-llm-2",
            session_id="sess-exact-llm",
            payload={"command": "rm -rf /tmp/target"},
        )))

        assert provider.calls == []
        meta = gw.trajectory_store.records[-1]["meta"]["anti_bypass"]
        assert meta["recognition_source"] == "deterministic"
        assert meta["similarity_mode"] == "raw_hash"

    @pytest.mark.asyncio
    async def test_llm_block_response_cannot_create_local_block(self):
        provider = _FakeAntiBypassLLMProvider(json.dumps({
            "schema": "cs.anti_bypass.recognition.v1",
            "matched": True,
            "confidence": 0.96,
            "action": "block",
            "prior_record_id": 1,
            "reason_codes": ["model_attempted_block"],
            "evidence_categories": ["operation_overlap"],
        }))
        cfg = DetectionConfig(
            anti_bypass_guard_enabled=True,
            anti_bypass_llm_recognition_enabled=True,
            anti_bypass_llm_candidate_threshold=0.1,
            anti_bypass_llm_action="force_l2",
        )
        gw = SupervisionGateway(
            detection_config=cfg,
            anti_bypass_llm_provider=provider,
        )
        await gw.handle_jsonrpc(_jsonrpc_request(_sync_params(
            request_id="req-block-llm-1",
            event_id="evt-block-llm-1",
            session_id="sess-block-llm",
            tool_name="bash",
            payload={"command": "rm -rf /tmp/project/cache"},
        )))
        await gw.handle_jsonrpc(_jsonrpc_request(_sync_params(
            request_id="req-block-llm-2",
            event_id="evt-block-llm-2",
            session_id="sess-block-llm",
            tool_name="python",
            payload={"command": "python -c \"print('remove /tmp/project/cache')\""},
        )))

        meta = gw.trajectory_store.records[-1]["meta"]["anti_bypass"]
        assert meta["recognition_source"] == "llm_assisted"
        assert meta["action"] == "force_l2"
        assert gw.trajectory_store.records[-1]["decision"]["policy_id"] != "anti-bypass-cross-tool-review"

    @pytest.mark.asyncio
    async def test_auto_enabled_llm_recognizer_runs_with_injected_provider(self):
        provider = _FakeAntiBypassLLMProvider(json.dumps({
            "schema": "cs.anti_bypass.recognition.v1",
            "matched": True,
            "confidence": 0.96,
            "action": "force_l3",
            "prior_record_id": 1,
            "reason_codes": ["destructive_label_overlap"],
            "evidence_categories": ["operation_overlap"],
        }))
        env = {
            "CS_ANTI_BYPASS_GUARD_ENABLED": "true",
            "CS_ANTI_BYPASS_LLM_CANDIDATE_THRESHOLD": "0.1",
            "CS_LLM_PROVIDER": "openai",
            "CS_LLM_API_KEY": "sk-shared-test-key",
        }
        with patch.dict(os.environ, env, clear=True):
            cfg = build_detection_config_from_env()
        gw = SupervisionGateway(detection_config=cfg, anti_bypass_llm_provider=provider)

        await gw.handle_jsonrpc(_jsonrpc_request(_sync_params(
            request_id="req-auto-llm-1",
            event_id="evt-auto-llm-1",
            session_id="sess-auto-llm",
            tool_name="bash",
            payload={"command": "rm -rf /tmp/project/cache"},
        )))
        await gw.handle_jsonrpc(_jsonrpc_request(_sync_params(
            request_id="req-auto-llm-2",
            event_id="evt-auto-llm-2",
            session_id="sess-auto-llm",
            tool_name="python",
            payload={"command": "python -c \"print('remove /tmp/project/cache')\""},
        )))

        assert cfg.anti_bypass_llm_recognition_enabled is True
        assert len(provider.calls) == 1
        assert gw.trajectory_store.records[-1]["meta"]["anti_bypass"]["recognition_source"] == "llm_assisted"

    @pytest.mark.asyncio
    async def test_llm_observe_response_cannot_weaken_configured_force_l3(self):
        provider = _FakeAntiBypassLLMProvider(json.dumps({
            "schema": "cs.anti_bypass.recognition.v1",
            "matched": True,
            "confidence": 0.96,
            "action": "observe",
            "prior_record_id": 1,
            "reason_codes": ["destructive_label_overlap"],
            "evidence_categories": ["operation_overlap"],
        }))
        cfg = DetectionConfig(
            anti_bypass_guard_enabled=True,
            anti_bypass_llm_recognition_enabled=True,
            anti_bypass_llm_candidate_threshold=0.1,
            anti_bypass_llm_action="force_l3",
        )
        gw = SupervisionGateway(detection_config=cfg, anti_bypass_llm_provider=provider)

        await gw.handle_jsonrpc(_jsonrpc_request(_sync_params(
            request_id="req-observe-llm-1",
            event_id="evt-observe-llm-1",
            session_id="sess-observe-llm",
            tool_name="bash",
            payload={"command": "rm -rf /tmp/project/cache"},
        )))
        result = await gw.handle_jsonrpc(_jsonrpc_request(_sync_params(
            request_id="req-observe-llm-2",
            event_id="evt-observe-llm-2",
            session_id="sess-observe-llm",
            tool_name="python",
            payload={"command": "python -c \"print('remove /tmp/project/cache')\""},
        )))

        meta = gw.trajectory_store.records[-1]["meta"]["anti_bypass"]
        assert meta["action"] == "force_l3"
        assert result["result"]["l3_requested"] is True

    @pytest.mark.asyncio
    async def test_llm_defer_response_cannot_create_local_defer_when_config_forces_l3(self):
        provider = _FakeAntiBypassLLMProvider(json.dumps({
            "schema": "cs.anti_bypass.recognition.v1",
            "matched": True,
            "confidence": 0.96,
            "action": "defer",
            "prior_record_id": 1,
            "reason_codes": ["destructive_label_overlap"],
            "evidence_categories": ["operation_overlap"],
        }))
        cfg = DetectionConfig(
            anti_bypass_guard_enabled=True,
            anti_bypass_llm_recognition_enabled=True,
            anti_bypass_llm_candidate_threshold=0.1,
            anti_bypass_llm_action="force_l3",
        )
        gw = SupervisionGateway(detection_config=cfg, anti_bypass_llm_provider=provider)

        await gw.handle_jsonrpc(_jsonrpc_request(_sync_params(
            request_id="req-defer-llm-1",
            event_id="evt-defer-llm-1",
            session_id="sess-defer-llm",
            tool_name="bash",
            payload={"command": "rm -rf /tmp/project/cache"},
        )))
        result = await gw.handle_jsonrpc(_jsonrpc_request(_sync_params(
            request_id="req-defer-llm-2",
            event_id="evt-defer-llm-2",
            session_id="sess-defer-llm",
            tool_name="python",
            payload={"command": "python -c \"print('remove /tmp/project/cache')\""},
        )))

        meta = gw.trajectory_store.records[-1]["meta"]["anti_bypass"]
        assert meta["action"] == "force_l3"
        assert result["result"]["decision"]["decision"] != "defer"
        assert result["result"]["l3_requested"] is True

    @pytest.mark.asyncio
    async def test_llm_scope_only_candidate_is_skipped_with_safe_probe_metadata(self):
        provider = _FakeAntiBypassLLMProvider(json.dumps({
            "schema": "cs.anti_bypass.recognition.v1",
            "matched": True,
            "confidence": 0.99,
            "action": "force_l3",
            "prior_record_id": 1,
            "reason_codes": ["target_scope_overlap"],
            "evidence_categories": ["scope_overlap"],
        }))
        cfg = DetectionConfig(
            anti_bypass_guard_enabled=True,
            anti_bypass_llm_recognition_enabled=True,
            anti_bypass_llm_candidate_threshold=0.99,
        )
        gw = SupervisionGateway(detection_config=cfg, anti_bypass_llm_provider=provider)

        await gw.handle_jsonrpc(_jsonrpc_request(_sync_params(
            request_id="req-scope-only-1",
            event_id="evt-scope-only-1",
            session_id="sess-scope-only",
            tool_name="bash",
            payload={"command": "curl https://updates.example/project"},
        )))
        await gw.handle_jsonrpc(_jsonrpc_request(_sync_params(
            request_id="req-scope-only-2",
            event_id="evt-scope-only-2",
            session_id="sess-scope-only",
            tool_name="python",
            payload={"command": "python -c \"print('/tmp/project')\""},
        )))

        meta = gw.trajectory_store.records[-1]["meta"]
        assert provider.calls == []
        assert "anti_bypass" not in meta
        assert meta["anti_bypass_probe"] == {
            "candidate_count": 0,
            "llm_state": "not_matched",
            "reason": "no_candidate",
            "budget_skipped": False,
        }

    @pytest.mark.asyncio
    async def test_llm_current_non_destructive_action_does_not_force_review(self):
        provider = _FakeAntiBypassLLMProvider(json.dumps({
            "schema": "cs.anti_bypass.recognition.v1",
            "matched": True,
            "confidence": 0.99,
            "action": "force_l3",
            "prior_record_id": 1,
            "reason_codes": ["destructive_label_overlap"],
            "evidence_categories": ["operation_overlap"],
        }))
        cfg = DetectionConfig(
            anti_bypass_guard_enabled=True,
            anti_bypass_llm_recognition_enabled=True,
            anti_bypass_llm_candidate_threshold=0.1,
        )
        gw = SupervisionGateway(detection_config=cfg, anti_bypass_llm_provider=provider)

        await gw.handle_jsonrpc(_jsonrpc_request(_sync_params(
            request_id="req-nondestructive-llm-1",
            event_id="evt-nondestructive-llm-1",
            session_id="sess-nondestructive-llm",
            tool_name="bash",
            payload={"command": "rm -rf /tmp/project/cache"},
        )))
        await gw.handle_jsonrpc(_jsonrpc_request(_sync_params(
            request_id="req-nondestructive-llm-2",
            event_id="evt-nondestructive-llm-2",
            session_id="sess-nondestructive-llm",
            tool_name="python",
            payload={"command": "python -c \"print('/tmp/project/cache')\""},
        )))

        meta = gw.trajectory_store.records[-1]["meta"]
        assert provider.calls == []
        assert "anti_bypass" not in meta
        assert meta["anti_bypass_probe"]["reason"] == "no_candidate"

    @pytest.mark.asyncio
    async def test_llm_timeout_records_safe_probe_metadata(self):
        provider = _TimeoutAntiBypassLLMProvider("")
        cfg = DetectionConfig(
            anti_bypass_guard_enabled=True,
            anti_bypass_llm_recognition_enabled=True,
            anti_bypass_llm_candidate_threshold=0.1,
            anti_bypass_llm_timeout_ms=10,
        )
        gw = SupervisionGateway(detection_config=cfg, anti_bypass_llm_provider=provider)

        await gw.handle_jsonrpc(_jsonrpc_request(_sync_params(
            request_id="req-timeout-llm-1",
            event_id="evt-timeout-llm-1",
            session_id="sess-timeout-llm",
            tool_name="bash",
            payload={"command": "rm -rf /tmp/project/cache"},
        )))
        await gw.handle_jsonrpc(_jsonrpc_request(_sync_params(
            request_id="req-timeout-llm-2",
            event_id="evt-timeout-llm-2",
            session_id="sess-timeout-llm",
            tool_name="python",
            payload={"command": "python -c \"print('remove /tmp/project/cache')\""},
        )))

        meta = gw.trajectory_store.records[-1]["meta"]
        assert len(provider.calls) == 1
        assert "anti_bypass" not in meta
        assert meta["anti_bypass_probe"] == {
            "candidate_count": 1,
            "llm_state": "degraded",
            "reason": "timeout",
            "budget_skipped": False,
        }

    @pytest.mark.asyncio
    async def test_llm_provider_unavailable_records_safe_probe_metadata(self):
        cfg = DetectionConfig(
            anti_bypass_guard_enabled=True,
            anti_bypass_llm_recognition_enabled=True,
            anti_bypass_llm_candidate_threshold=0.1,
        )
        gw = SupervisionGateway(detection_config=cfg, anti_bypass_llm_provider=None)

        await gw.handle_jsonrpc(_jsonrpc_request(_sync_params(
            request_id="req-provider-missing-1",
            event_id="evt-provider-missing-1",
            session_id="sess-provider-missing",
            tool_name="bash",
            payload={"command": "rm -rf /tmp/project/cache"},
        )))
        await gw.handle_jsonrpc(_jsonrpc_request(_sync_params(
            request_id="req-provider-missing-2",
            event_id="evt-provider-missing-2",
            session_id="sess-provider-missing",
            tool_name="python",
            payload={"command": "python -c \"print('remove /tmp/project/cache')\""},
        )))

        assert gw.trajectory_store.records[-1]["meta"]["anti_bypass_probe"] == {
            "candidate_count": 1,
            "llm_state": "disabled",
            "reason": "provider_unavailable",
            "budget_skipped": False,
        }
