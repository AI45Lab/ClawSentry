"""Tests for SessionEnforcementPolicy (A-7)."""

from __future__ import annotations

import asyncio
import json
import time
from typing import Any
from unittest.mock import patch

import pytest

from clawsentry.gateway.session_enforcement import (
    EnforcementAction,
    EnforcementState,
    SessionEnforcement,
    SessionEnforcementPolicy,
)
from clawsentry.gateway.models import DecisionTier, RiskLevel, SkillRegistryRecord
from clawsentry.gateway.detection_config import DetectionConfig
from clawsentry.gateway.semantic_analyzer import L2Result
from clawsentry.gateway.server import SupervisionGateway


# ---------------------------------------------------------------------------
# Unit tests
# ---------------------------------------------------------------------------

class TestSessionEnforcementUnit:
    """Unit tests for SessionEnforcementPolicy core logic."""

    def test_disabled_by_default(self):
        policy = SessionEnforcementPolicy()
        assert policy.enabled is False
        assert policy.check("s1") is None
        assert policy.evaluate_threshold("s1", 10) is None

    def test_below_threshold_no_enforcement(self):
        policy = SessionEnforcementPolicy(enabled=True, threshold=3)
        assert policy.evaluate_threshold("s1", 0) is None
        assert policy.evaluate_threshold("s1", 1) is None
        assert policy.evaluate_threshold("s1", 2) is None
        assert policy.check("s1") is None

    def test_breach_threshold_triggers_enforcement(self):
        policy = SessionEnforcementPolicy(enabled=True, threshold=3)
        enf = policy.evaluate_threshold("s1", 3)
        assert enf is not None
        assert enf.session_id == "s1"
        assert enf.action == EnforcementAction.DEFER
        assert enf.high_risk_count == 3

    def test_enforcement_persists_after_trigger(self):
        policy = SessionEnforcementPolicy(enabled=True, threshold=2, cooldown_seconds=600)
        policy.evaluate_threshold("s1", 2)
        enf = policy.check("s1")
        assert enf is not None
        assert enf.session_id == "s1"

    def test_cooldown_auto_release(self):
        policy = SessionEnforcementPolicy(enabled=True, threshold=2, cooldown_seconds=10)
        policy.evaluate_threshold("s1", 2)
        assert policy.check("s1") is not None

        # Fast-forward past cooldown
        enf = policy._enforced["s1"]
        enf.last_high_risk_at = time.monotonic() - 11
        assert policy.check("s1") is None

    def test_cooldown_reset_on_new_high_risk(self):
        policy = SessionEnforcementPolicy(enabled=True, threshold=2, cooldown_seconds=10)
        policy.evaluate_threshold("s1", 2)
        old_ts = policy._enforced["s1"].last_high_risk_at

        # New high risk event should NOT create a new trigger but update timestamp
        result = policy.evaluate_threshold("s1", 3)
        assert result is None  # Not a *new* trigger
        assert policy._enforced["s1"].last_high_risk_at >= old_ts
        assert policy._enforced["s1"].high_risk_count == 3

    def test_manual_release(self):
        policy = SessionEnforcementPolicy(enabled=True, threshold=2)
        policy.evaluate_threshold("s1", 2)
        assert policy.check("s1") is not None
        assert policy.release("s1") is True
        assert policy.check("s1") is None
        # Double release returns False
        assert policy.release("s1") is False

    def test_action_defer(self):
        policy = SessionEnforcementPolicy(
            enabled=True, threshold=1, action=EnforcementAction.DEFER
        )
        enf = policy.evaluate_threshold("s1", 1)
        assert enf.action == EnforcementAction.DEFER

    def test_action_block(self):
        policy = SessionEnforcementPolicy(
            enabled=True, threshold=1, action=EnforcementAction.BLOCK
        )
        enf = policy.evaluate_threshold("s1", 1)
        assert enf.action == EnforcementAction.BLOCK

    def test_action_l3_require(self):
        policy = SessionEnforcementPolicy(
            enabled=True, threshold=1, action=EnforcementAction.L3_REQUIRE
        )
        enf = policy.evaluate_threshold("s1", 1)
        assert enf.action == EnforcementAction.L3_REQUIRE

    def test_eviction(self):
        policy = SessionEnforcementPolicy(enabled=True, threshold=1)
        # Reduce max for test
        import clawsentry.gateway.session_enforcement as mod
        original = mod._MAX_TRACKED_SESSIONS
        mod._MAX_TRACKED_SESSIONS = 3
        try:
            policy.evaluate_threshold("s1", 1)
            policy.evaluate_threshold("s2", 1)
            policy.evaluate_threshold("s3", 1)
            policy.evaluate_threshold("s4", 1)
            assert len(policy._enforced) == 3
            assert "s1" not in policy._enforced
        finally:
            mod._MAX_TRACKED_SESSIONS = original

    def test_get_status_normal(self):
        policy = SessionEnforcementPolicy(enabled=True, threshold=5)
        status = policy.get_status("s1")
        assert status["state"] == "normal"
        assert status["session_id"] == "s1"
        assert status["action"] is None

    def test_get_status_enforced(self):
        policy = SessionEnforcementPolicy(enabled=True, threshold=1)
        policy.evaluate_threshold("s1", 1)
        status = policy.get_status("s1")
        assert status["state"] == "enforced"
        assert status["action"] == "defer"
        assert status["high_risk_count"] == 1

    def test_threshold_edge_exact(self):
        """Threshold=3: count=2 should not trigger, count=3 should."""
        policy = SessionEnforcementPolicy(enabled=True, threshold=3)
        assert policy.evaluate_threshold("s1", 2) is None
        enf = policy.evaluate_threshold("s1", 3)
        assert enf is not None
        assert enf.high_risk_count == 3


# ---------------------------------------------------------------------------
# Integration tests — through SupervisionGateway.handle_jsonrpc
# ---------------------------------------------------------------------------

def _build_jsonrpc(session_id: str, tool_name: str, command: str, req_id: int = 1) -> bytes:
    """Build a JSON-RPC 2.0 sync_decision request for a pre_action event."""
    return json.dumps({
        "jsonrpc": "2.0",
        "id": req_id,
        "method": "ahp/sync_decision",
        "params": {
            "request_id": f"test-{session_id}-{req_id}",
            "rpc_version": "sync_decision.1.0",
            "deadline_ms": 5000,
            "decision_tier": "L1",
            "event": {
                "schema_version": "ahp.1.0",
                "event_id": f"evt-{session_id}-{req_id}",
                "trace_id": f"trace-{session_id}",
                "event_type": "pre_action",
                "session_id": session_id,
                "agent_id": "test-agent",
                "source_framework": "test",
                "occurred_at": "2026-03-22T00:00:00Z",
                "payload": {"command": command},
                "tool_name": tool_name,
                "risk_hints": ["destructive_pattern", "shell_execution"] if "rm" in command or "chmod" in command else [],
            },
            "context": {
                "caller_adapter": "test-integration",
            },
        },
    }).encode("utf-8")


def _build_jsonrpc_with_payload(
    session_id: str,
    tool_name: str,
    payload: dict[str, Any],
    req_id: int = 1,
    context: dict[str, Any] | None = None,
    deadline_ms: int = 5000,
) -> bytes:
    """Build a JSON-RPC pre_action request with an explicit payload."""
    event_payload = dict(payload)
    risk_hints = (
        ["destructive_pattern", "shell_execution"]
        if "rm" in str(event_payload.get("command", ""))
        or "chmod" in str(event_payload.get("command", ""))
        else []
    )
    return json.dumps({
        "jsonrpc": "2.0",
        "id": req_id,
        "method": "ahp/sync_decision",
        "params": {
            "request_id": f"test-{session_id}-{req_id}",
            "rpc_version": "sync_decision.1.0",
            "deadline_ms": deadline_ms,
            "decision_tier": "L1",
            "event": {
                "schema_version": "ahp.1.0",
                "event_id": f"evt-{session_id}-{req_id}",
                "trace_id": f"trace-{session_id}",
                "event_type": "pre_action",
                "session_id": session_id,
                "agent_id": "test-agent",
                "source_framework": "test",
                "occurred_at": "2026-03-22T00:00:00Z",
                "payload": event_payload,
                "tool_name": tool_name,
                "risk_hints": risk_hints,
            },
            "context": {
                "caller_adapter": "test-integration",
                **(context or {}),
            },
        },
    }).encode("utf-8")


def _skill_registry_record(
    canonical_skill_id: str,
    canonical_name: str,
    *,
    trust_level: str,
    status: str,
    list_state: str,
) -> SkillRegistryRecord:
    return SkillRegistryRecord(
        canonical_skill_id=canonical_skill_id,
        canonical_name=canonical_name,
        aliases=[],
        content_hashes={},
        source={"framework": "test"},
        trust_level=trust_level,  # type: ignore[arg-type]
        status=status,  # type: ignore[arg-type]
        list_state=list_state,  # type: ignore[arg-type]
        policy_fingerprint="sha256:test-registry",
    )


def _build_post_action_jsonrpc(session_id: str, req_id: int = 100) -> bytes:
    """Build a JSON-RPC for a post_action event."""
    return json.dumps({
        "jsonrpc": "2.0",
        "id": req_id,
        "method": "ahp/sync_decision",
        "params": {
            "request_id": f"test-post-{session_id}-{req_id}",
            "rpc_version": "sync_decision.1.0",
            "deadline_ms": 5000,
            "decision_tier": "L1",
            "event": {
                "schema_version": "ahp.1.0",
                "event_id": f"evt-post-{session_id}-{req_id}",
                "trace_id": f"trace-{session_id}",
                "event_type": "post_action",
                "session_id": session_id,
                "agent_id": "test-agent",
                "source_framework": "test",
                "occurred_at": "2026-03-22T00:00:00Z",
                "payload": {"result": "ok"},
                "tool_name": "Bash",
            },
            "context": {
                "caller_adapter": "test-integration",
            },
        },
    }).encode("utf-8")


class TestSessionEnforcementIntegration:
    """Integration tests using SupervisionGateway.handle_jsonrpc end-to-end."""

    @pytest.fixture
    def gateway_enforced(self):
        """Gateway with enforcement enabled, threshold=3, action=defer."""
        policy = SessionEnforcementPolicy(
            enabled=True, threshold=3, action=EnforcementAction.DEFER, cooldown_seconds=600
        )
        return SupervisionGateway(
            trajectory_db_path=":memory:",
            session_enforcement=policy,
        )

    async def test_enforcement_override_after_threshold(self, gateway_enforced):
        """Send 3 high-risk pre_action → 4th is overridden to defer."""
        gw = gateway_enforced
        # Send 3 dangerous commands (these are processed normally by L1)
        for i in range(1, 4):
            resp = await gw.handle_jsonrpc(
                _build_jsonrpc("s1", "Bash", f"rm -rf /data{i}", req_id=i)
            )
            result = resp["result"]
            decision = result["decision"]
            # L1 should block these normally
            assert decision["decision"] in ("block", "defer"), f"Event {i}: {decision}"

        # 4th event should be enforcement-overridden
        resp4 = await gw.handle_jsonrpc(
            _build_jsonrpc("s1", "Bash", "rm -rf /data4", req_id=4)
        )
        result4 = resp4["result"]
        decision4 = result4["decision"]
        assert decision4["decision"] == "defer"
        assert "session-enforcement-A7" in decision4["policy_id"]

    async def test_post_action_not_affected_by_enforcement(self, gateway_enforced):
        """Post-action events should still be ALLOW even when session is enforced."""
        gw = gateway_enforced
        # Trigger enforcement
        for i in range(1, 4):
            await gw.handle_jsonrpc(
                _build_jsonrpc("s1", "Bash", f"rm -rf /x{i}", req_id=i)
            )

        # Post-action should still be allowed
        resp = await gw.handle_jsonrpc(_build_post_action_jsonrpc("s1"))
        decision = resp["result"]["decision"]
        assert decision["decision"] == "allow"

    async def test_event_bus_enforcement_change(self, gateway_enforced):
        """EventBus should receive session_enforcement_change on trigger."""
        gw = gateway_enforced
        sub_id, queue = gw.event_bus.subscribe(
            event_types={"session_enforcement_change"}
        )
        assert sub_id is not None

        # Trigger enforcement with 3 high-risk events
        for i in range(1, 4):
            await gw.handle_jsonrpc(
                _build_jsonrpc("s1", "Bash", f"rm -rf /e{i}", req_id=i)
            )

        # Check that we got the enforcement change event
        events = []
        while not queue.empty():
            events.append(queue.get_nowait())
        enforcement_events = [e for e in events if e.get("type") == "session_enforcement_change"]
        assert len(enforcement_events) >= 1
        enf_evt = enforcement_events[0]
        assert enf_evt["session_id"] == "s1"
        assert enf_evt["state"] == "enforced"
        assert enf_evt["action"] == "defer"

        gw.event_bus.unsubscribe(sub_id)

    async def test_release_restores_normal(self, gateway_enforced):
        """After manual release, decisions should go back to normal L1."""
        gw = gateway_enforced
        # Trigger enforcement
        for i in range(1, 4):
            await gw.handle_jsonrpc(
                _build_jsonrpc("s1", "Bash", f"rm -rf /r{i}", req_id=i)
            )

        # Verify enforced
        status = gw.session_enforcement.get_status("s1")
        assert status["state"] == "enforced"

        # Release
        assert gw.session_enforcement.release("s1") is True
        status = gw.session_enforcement.get_status("s1")
        assert status["state"] == "normal"

        # Next event should be processed normally by L1 (not enforcement)
        resp = await gw.handle_jsonrpc(
            _build_jsonrpc("s1", "Read", "cat /etc/hosts", req_id=10)
        )
        decision = resp["result"]["decision"]
        # Should NOT have session-enforcement policy_id
        assert "session-enforcement" not in decision.get("policy_id", "")

    async def test_disabled_enforcement_no_change(self):
        """When enforcement is disabled, behavior is identical to baseline."""
        gw = SupervisionGateway(
            trajectory_db_path=":memory:",
            session_enforcement=SessionEnforcementPolicy(enabled=False),
        )
        # Send many dangerous events
        for i in range(1, 6):
            resp = await gw.handle_jsonrpc(
                _build_jsonrpc("s1", "Bash", f"rm -rf /d{i}", req_id=i)
            )
            result = resp["result"]
            decision = result["decision"]
            # L1 blocks these, but no enforcement override
            assert "session-enforcement" not in decision.get("policy_id", "")

    async def test_l3_require_forces_local_l3_when_available(self):
        class ForcedL3Analyzer:
            analyzer_id = "test-forced-l3"

            async def analyze(self, event, context, l1_snapshot, budget_ms):
                assert context is not None
                assert context.session_risk_summary["force_l3"] is True
                return L2Result(
                    target_level=RiskLevel.HIGH,
                    reasons=["forced local L3 review"],
                    confidence=0.93,
                    analyzer_id=self.analyzer_id,
                    latency_ms=25.0,
                    trace={
                        "trigger_reason": "manual_l3_escalate",
                        "mode": "single_turn",
                        "turns": [],
                    },
                    decision_tier=DecisionTier.L3,
                )

        gw = SupervisionGateway(
            trajectory_db_path=":memory:",
            session_enforcement=SessionEnforcementPolicy(enabled=True, threshold=1, action=EnforcementAction.L3_REQUIRE),
            analyzer=ForcedL3Analyzer(),
        )
        gw.session_enforcement.force("s1", action=EnforcementAction.L3_REQUIRE)

        resp = await gw.handle_jsonrpc(_build_jsonrpc("s1", "Bash", "cat prod-token.txt", req_id=1))
        result = resp["result"]

        assert result["actual_tier"] == "L3"
        assert result["decision"]["decision"] == "block"
        assert result["l3_state"] == "completed"

    async def test_l3_require_without_local_l3_returns_defer_with_skipped_state(self):
        gw = SupervisionGateway(
            trajectory_db_path=":memory:",
            session_enforcement=SessionEnforcementPolicy(enabled=True, threshold=1, action=EnforcementAction.L3_REQUIRE),
        )
        gw.session_enforcement.force("s1", action=EnforcementAction.L3_REQUIRE)

        resp = await gw.handle_jsonrpc(_build_jsonrpc("s1", "Read", "cat /tmp/readme.txt", req_id=1))
        result = resp["result"]

        assert result["actual_tier"] in ("L1", "L2")
        assert result["decision"]["decision"] == "defer"
        assert result["l3_state"] == "skipped"
        assert result["l3_reason_code"] == "local_l3_not_completed"

    async def test_l3_require_budget_exhausted_keeps_reporting_consistent_budget_state(self):
        gw = SupervisionGateway(
            trajectory_db_path=":memory:",
            detection_config=DetectionConfig(llm_daily_budget_usd=1.0),
            session_enforcement=SessionEnforcementPolicy(
                enabled=True,
                threshold=1,
                action=EnforcementAction.L3_REQUIRE,
            ),
        )
        gw.session_enforcement.force("s1", action=EnforcementAction.L3_REQUIRE)
        sub_id, queue = gw.event_bus.subscribe(event_types={"decision"})
        try:
            gw.metrics.record_llm_call(
                provider="openai",
                tier="L2",
                status="ok",
                input_tokens=400_000,
                output_tokens=0,
            )

            resp = await gw.handle_jsonrpc(_build_jsonrpc("s1", "Read", "cat /tmp/readme.txt", req_id=2))
            result = resp["result"]

            assert result["actual_tier"] == "L1"
            assert result["decision"]["decision"] == "defer"
            assert result["l3_state"] == "skipped"
            assert result["l3_reason_code"] == "budget_exhausted"

            decision_events = []
            while not queue.empty():
                decision_events.append(queue.get_nowait())
            assert len(decision_events) == 1
            event = decision_events[0]
            assert event["budget"]["exhausted"] is True
            assert event["budget"]["daily_spend_usd"] == pytest.approx(1.0)
            assert event["budget"]["remaining_usd"] == pytest.approx(0.0)
            assert event["l3_reason_code"] == "budget_exhausted"

            for payload in (
                gw.health(),
                gw.report_summary(),
                gw.report_sessions(),
                gw.report_session_risk("s1"),
                gw.replay_session("s1"),
            ):
                assert payload["budget"]["exhausted"] is True
                assert payload["budget_exhaustion_event"]["budget"]["exhausted"] is True
                assert payload["budget_exhaustion_event"]["budget"]["daily_spend_usd"] == pytest.approx(1.0)
        finally:
            gw.event_bus.unsubscribe(sub_id)

    async def test_capability_narrowing_keeps_read_only_available_after_critical_session_risk(self):
        gw = SupervisionGateway(
            trajectory_db_path=":memory:",
            detection_config=DetectionConfig(
                capability_narrowing_enabled=True,
                defer_bridge_enabled=False,
            ),
            skill_registry_records=[
                _skill_registry_record(
                    "skill:blocked-skill",
                    "blocked-skill",
                    trust_level="untrusted",
                    status="quarantined",
                    list_state="blacklist",
                )
            ],
        )

        await gw.handle_jsonrpc(
            _build_jsonrpc_with_payload(
                "s1",
                "bash",
                {"command": "rm -rf /tmp/clawsentry-narrowing-seed"},
                req_id=1,
            )
        )

        read_resp = await gw.handle_jsonrpc(
            _build_jsonrpc_with_payload(
                "s1",
                "read_file",
                {"path": "/workspace/project/README.md"},
                req_id=2,
            )
        )
        read_decision = read_resp["result"]["decision"]
        assert read_decision["decision"] == "allow"
        assert read_decision["policy_id"] != "session-enforcement-A7"
        assert read_decision["scope_evaluation"]["enforced"] is True

        write_resp = await gw.handle_jsonrpc(
            _build_jsonrpc_with_payload(
                "s1",
                "write_file",
                {"path": "/workspace/project/README.md", "content": "changed"},
                req_id=3,
            )
        )
        write_decision = write_resp["result"]["decision"]
        assert write_decision["decision"] == "block"
        assert write_decision["policy_id"] == "session-scope"
        assert "capability-narrowing" in write_decision["scope_evaluation"]["profile_id"]

    async def test_capability_narrowing_blocks_blacklisted_skill_use(self, tmp_path, monkeypatch):
        metadata = tmp_path / "skill-trust-raw.json"
        metadata.write_text(
            json.dumps({"raw_metadata_by_skill": {"blocked-skill": {}}}),
            encoding="utf-8",
        )
        monkeypatch.setenv("CS_SKILL_TRUST_METADATA_PATH", str(metadata))
        gw = SupervisionGateway(
            trajectory_db_path=":memory:",
            detection_config=DetectionConfig(
                capability_narrowing_enabled=True,
                defer_bridge_enabled=False,
            ),
            skill_registry_records=[
                _skill_registry_record(
                    "skill:blocked-skill",
                    "blocked-skill",
                    trust_level="untrusted",
                    status="quarantined",
                    list_state="blacklist",
                )
            ],
        )

        await gw.handle_jsonrpc(
            _build_jsonrpc_with_payload(
                "s-skill-narrow",
                "bash",
                {"command": "rm -rf /tmp/clawsentry-narrowing-seed"},
                req_id=1,
            )
        )

        resp = await gw.handle_jsonrpc(
            _build_jsonrpc_with_payload(
                "s-skill-narrow",
                "read_file",
                {
                    "path": "/workspace/project/README.md",
                    "_clawsentry_meta": {
                        "skill_trust_raw": {
                            "presented_name": "blocked-skill",
                            "provenance_claim": "blocked-skill",
                        }
                    },
                },
                req_id=2,
            )
        )

        decision = resp["result"]["decision"]
        assert decision["decision"] == "block"
        assert decision["policy_id"] == "session-scope"
        assert "scope_deny:skill_trust_state blacklist" in decision["scope_evaluation"]["reason_codes"]

    async def test_capability_narrowing_defers_greylisted_skill_use(self, tmp_path, monkeypatch):
        metadata = tmp_path / "skill-trust-raw.json"
        metadata.write_text(
            json.dumps({"raw_metadata_by_skill": {"grey-skill": {}}}),
            encoding="utf-8",
        )
        monkeypatch.setenv("CS_SKILL_TRUST_METADATA_PATH", str(metadata))
        gw = SupervisionGateway(
            trajectory_db_path=":memory:",
            detection_config=DetectionConfig(
                capability_narrowing_enabled=True,
                defer_bridge_enabled=False,
            ),
            skill_registry_records=[
                _skill_registry_record(
                    "skill:grey-skill",
                    "grey-skill",
                    trust_level="local_unreviewed",
                    status="local_unreviewed",
                    list_state="greylist",
                )
            ],
        )

        await gw.handle_jsonrpc(
            _build_jsonrpc_with_payload(
                "s-grey-skill-narrow",
                "bash",
                {"command": "rm -rf /tmp/clawsentry-narrowing-seed"},
                req_id=1,
            )
        )

        resp = await gw.handle_jsonrpc(
            _build_jsonrpc_with_payload(
                "s-grey-skill-narrow",
                "read_file",
                {
                    "path": "/workspace/project/README.md",
                    "_clawsentry_meta": {
                        "skill_trust_raw": {
                            "presented_name": "grey-skill",
                            "provenance_claim": "grey-skill",
                        }
                    },
                },
                req_id=2,
            )
        )

        decision = resp["result"]["decision"]
        assert decision["decision"] == "defer"
        assert decision["policy_id"] == "session-scope"
        assert "scope_defer:skill_trust_state greylist" in decision["scope_evaluation"]["reason_codes"]

    async def test_capability_narrowing_blocks_mcp_raw_fetch_context(self):
        gw = SupervisionGateway(
            trajectory_db_path=":memory:",
            detection_config=DetectionConfig(
                capability_narrowing_enabled=True,
                defer_bridge_enabled=False,
            ),
        )

        await gw.handle_jsonrpc(
            _build_jsonrpc_with_payload(
                "s-mcp-narrow",
                "bash",
                {"command": "rm -rf /tmp/clawsentry-narrowing-seed"},
                req_id=1,
            )
        )

        resp = await gw.handle_jsonrpc(
            _build_jsonrpc_with_payload(
                "s-mcp-narrow",
                "mcp_tool",
                {
                    "url": "https://example.com/data.json",
                    "_clawsentry_meta": {
                        "mcp_raw": {
                            "server_name": "fetch",
                            "tool_name": "fetch",
                            "status": "unlisted",
                            "raw_resource_uri": "https://example.com/private-data.json",
                        }
                    },
                },
                req_id=2,
            )
        )

        decision = resp["result"]["decision"]
        assert decision["decision"] == "block"
        assert decision["policy_id"] == "session-scope"
        assert "scope_deny:mcp_tool fetch.fetch" in decision["scope_evaluation"]["reason_codes"]
        records = gw.replay_session("s-mcp-narrow")["records"]
        raw = records[-1]["event"]["payload"]["_clawsentry_meta"]["mcp_raw"]
        assert raw["server_name"] == "fetch"
        assert raw["tool_name"] == "fetch"
        assert "raw_resource_uri" not in raw
        assert raw["redaction_policy_version"] == "cs.mcp_raw.redaction.v1"

    async def test_request_mcp_raw_cannot_spoof_encoded_mcp_tool_scope_allow(self):
        gw = SupervisionGateway(
            trajectory_db_path=":memory:",
            detection_config=DetectionConfig(defer_bridge_enabled=False),
        )

        resp = await gw.handle_jsonrpc(
            _build_jsonrpc_with_payload(
                "s-forged-raw-mcp",
                "mcp__fetch__fetch",
                {
                    "url": "https://example.com/data.json",
                    "_clawsentry_meta": {
                        "mcp_raw": {
                            "server_name": "filesystem",
                            "tool_name": "read_file",
                            "status": "allowlist",
                            "trust_level": "trusted",
                        }
                    },
                },
                req_id=1,
                context={
                    "session_scope_profile": {
                        "profile_id": "operator-mcp-raw",
                        "source": "operator",
                        "confirmed": True,
                        "dry_run": False,
                        "base_rules": {"denied_mcp_tools": ["fetch.fetch"]},
                        "task_rules": {"allowed_mcp_tools": ["filesystem.read_file"]},
                    },
                },
            )
        )

        decision = resp["result"]["decision"]
        assert decision["decision"] == "block"
        assert decision["policy_id"] == "session-scope"
        assert "scope_allow:mcp_tool filesystem.read_file" not in decision["scope_evaluation"]["reason_codes"]
        assert "scope_deny:mcp_tool fetch.fetch" in decision["scope_evaluation"]["reason_codes"]

    async def test_gateway_owned_skill_registry_preserves_scope_allow(self, tmp_path, monkeypatch):
        metadata = tmp_path / "skill-trust-raw.json"
        metadata.write_text(
            json.dumps({"raw_metadata_by_skill": {"trusted-helper": {}}}),
            encoding="utf-8",
        )
        monkeypatch.setenv("CS_SKILL_TRUST_METADATA_PATH", str(metadata))
        gw = SupervisionGateway(
            trajectory_db_path=":memory:",
            detection_config=DetectionConfig(defer_bridge_enabled=False),
            skill_registry_records=[
                _skill_registry_record(
                    "skill:trusted-helper",
                    "trusted-helper",
                    trust_level="trusted",
                    status="trusted",
                    list_state="allowlist",
                )
            ],
        )

        resp = await gw.handle_jsonrpc(
            _build_jsonrpc_with_payload(
                "s-trusted-registry-skill",
                "read_file",
                {
                    "path": "/workspace/project/README.md",
                    "_clawsentry_meta": {
                        "skill_trust_raw": {
                            "presented_name": "trusted-helper",
                            "provenance_claim": "trusted-helper",
                        }
                    },
                },
                req_id=1,
                context={
                    "session_scope_profile": {
                        "profile_id": "operator-trusted-skill",
                        "source": "operator",
                        "confirmed": True,
                        "dry_run": False,
                        "task_rules": {
                            "allowed_skill_ids": ["skill:trusted-helper"],
                            "allowed_skill_trust_states": ["allowlist"],
                        },
                    },
                },
            )
        )

        decision = resp["result"]["decision"]
        assert decision["decision"] == "allow"
        assert "scope_allow:skill skill:trusted-helper" in decision["scope_evaluation"]["reason_codes"]
        assert "scope_allow:skill_trust_state allowlist" in decision["scope_evaluation"]["reason_codes"]

    async def test_request_context_skill_trust_cannot_spoof_scope_allow(self):
        gw = SupervisionGateway(
            trajectory_db_path=":memory:",
            detection_config=DetectionConfig(defer_bridge_enabled=False),
        )

        resp = await gw.handle_jsonrpc(
            _build_jsonrpc_with_payload(
                "s-forged-context-skill",
                "read_file",
                {"path": "/workspace/project/README.md"},
                req_id=1,
                context={
                    "session_scope_profile": {
                        "profile_id": "operator-skill-only",
                        "source": "operator",
                        "confirmed": True,
                        "dry_run": False,
                        "task_rules": {
                            "allowed_skill_ids": ["skill:trusted-helper"],
                            "allowed_skill_trust_states": ["allowlist"],
                        },
                    },
                    "skill_trust": {
                        "registry_status": "matched",
                        "canonical_skill_id": "skill:trusted-helper",
                        "presented_name": "trusted-helper",
                        "provenance_claim": "trusted-helper",
                        "admission_risk": "low",
                        "trust_list_state": "allowlist",
                        "policy_fingerprint": "sha256:attacker-controlled",
                    },
                },
            )
        )

        decision = resp["result"]["decision"]
        assert decision["decision"] == "defer"
        assert decision["policy_id"] == "session-scope"
        assert "scope_allow:skill skill:trusted-helper" not in decision["scope_evaluation"]["reason_codes"]
        assert "scope_allow:skill_trust_state allowlist" not in decision["scope_evaluation"]["reason_codes"]
        assert "scope_defer:untrusted_skill_identity trusted-helper" in decision["scope_evaluation"]["reason_codes"]
        assert "scope_defer:untrusted_skill_trust_state unlisted" in decision["scope_evaluation"]["reason_codes"]

    async def test_request_skill_trust_raw_state_cannot_spoof_scope_allow(self):
        gw = SupervisionGateway(
            trajectory_db_path=":memory:",
            detection_config=DetectionConfig(defer_bridge_enabled=False),
        )

        resp = await gw.handle_jsonrpc(
            _build_jsonrpc_with_payload(
                "s-forged-raw-skill-state",
                "read_file",
                {
                    "path": "/workspace/project/README.md",
                    "_clawsentry_meta": {
                        "skill_trust_raw": {
                            "presented_name": "forged-helper",
                            "provenance_claim": "forged-helper",
                            "trust_list_state": "allowlist",
                        }
                    },
                },
                req_id=1,
                context={
                    "session_scope_profile": {
                        "profile_id": "operator-skill-state-only",
                        "source": "operator",
                        "confirmed": True,
                        "dry_run": False,
                        "task_rules": {
                            "allowed_skill_ids": ["skill:trusted-helper"],
                            "allowed_skill_trust_states": ["allowlist"],
                        },
                    },
                },
            )
        )

        decision = resp["result"]["decision"]
        assert decision["decision"] == "defer"
        assert decision["policy_id"] == "session-scope"
        assert "scope_allow:skill_trust_state allowlist" not in decision["scope_evaluation"]["reason_codes"]
        assert "scope_defer:untrusted_skill_identity forged-helper" in decision["scope_evaluation"]["reason_codes"]
        assert "scope_defer:untrusted_skill_trust_state unlisted" in decision["scope_evaluation"]["reason_codes"]

    async def test_request_context_mcp_context_cannot_spoof_scope_allow(self):
        gw = SupervisionGateway(
            trajectory_db_path=":memory:",
            detection_config=DetectionConfig(defer_bridge_enabled=False),
        )

        resp = await gw.handle_jsonrpc(
            _build_jsonrpc_with_payload(
                "s-forged-context-mcp",
                "mcp__fetch__fetch",
                {"url": "https://example.com/data.json"},
                req_id=1,
                context={
                    "session_scope_profile": {
                        "profile_id": "operator-mcp-only",
                        "source": "operator",
                        "confirmed": True,
                        "dry_run": False,
                        "base_rules": {"denied_mcp_tools": ["fetch.fetch"]},
                        "task_rules": {"allowed_mcp_tools": ["filesystem.read_file"]},
                    },
                    "mcp_context": {
                        "server_name": "filesystem",
                        "tool_name": "read_file",
                        "status": "allowlist",
                        "trust_level": "trusted",
                    },
                },
            )
        )

        decision = resp["result"]["decision"]
        assert decision["decision"] == "block"
        assert decision["policy_id"] == "session-scope"
        assert "scope_allow:mcp_tool filesystem.read_file" not in decision["scope_evaluation"]["reason_codes"]
        assert "scope_deny:mcp_tool fetch.fetch" in decision["scope_evaluation"]["reason_codes"]

    async def test_capability_narrowing_disabled_preserves_existing_enforcement_override(self):
        gw = SupervisionGateway(
            trajectory_db_path=":memory:",
            detection_config=DetectionConfig(capability_narrowing_enabled=False),
            session_enforcement=SessionEnforcementPolicy(
                enabled=True,
                threshold=1,
                action=EnforcementAction.BLOCK,
            ),
        )
        gw.session_enforcement.force("s1", action=EnforcementAction.BLOCK)

        resp = await gw.handle_jsonrpc(
            _build_jsonrpc_with_payload(
                "s1",
                "read_file",
                {"path": "/workspace/project/README.md"},
                req_id=1,
            )
        )
        decision = resp["result"]["decision"]
        assert decision["decision"] == "block"
        assert decision["policy_id"] == "session-enforcement-A7"

        meta = gw.replay_session("s1")["records"][-1]["meta"]
        assert meta["capability_narrowing"] == {
            "enabled": False,
            "applied": False,
            "reason": "disabled",
        }

    async def test_capability_narrowing_audit_meta_and_sse_report_not_applied_reason(self):
        gw = SupervisionGateway(
            trajectory_db_path=":memory:",
            detection_config=DetectionConfig(capability_narrowing_enabled=True),
        )
        sub_id, queue = gw.event_bus.subscribe(event_types={"decision"})
        try:
            resp = await gw.handle_jsonrpc(
                _build_jsonrpc_with_payload(
                    "s-narrow-audit",
                    "read_file",
                    {"path": "/workspace/project/README.md"},
                    req_id=1,
                )
            )
            assert resp["result"]["decision"]["decision"] == "allow"

            records = gw.replay_session("s-narrow-audit")["records"]
            assert records[-1]["meta"]["capability_narrowing"] == {
                "enabled": True,
                "applied": False,
                "reason": "session_risk_below_threshold",
            }

            decision_events = []
            while not queue.empty():
                decision_events.append(queue.get_nowait())
            assert decision_events[-1]["capability_narrowing"] == {
                "enabled": True,
                "applied": False,
                "reason": "session_risk_below_threshold",
            }
        finally:
            gw.event_bus.unsubscribe(sub_id)

    async def test_capability_narrowing_does_not_bypass_explicit_enforcement(self):
        gw = SupervisionGateway(
            trajectory_db_path=":memory:",
            detection_config=DetectionConfig(capability_narrowing_enabled=True),
            session_enforcement=SessionEnforcementPolicy(
                enabled=True,
                threshold=1,
                action=EnforcementAction.BLOCK,
            ),
        )
        gw.session_enforcement.force("s1", action=EnforcementAction.BLOCK)

        resp = await gw.handle_jsonrpc(
            _build_jsonrpc_with_payload(
                "s1",
                "read_file",
                {"path": "/workspace/project/README.md"},
                req_id=1,
            )
        )

        decision = resp["result"]["decision"]
        assert decision["decision"] == "block"
        assert decision["policy_id"] == "session-enforcement-A7"

    async def test_capability_narrowing_does_not_downgrade_l3_require_enforcement(self):
        gw = SupervisionGateway(
            trajectory_db_path=":memory:",
            detection_config=DetectionConfig(capability_narrowing_enabled=True),
            session_enforcement=SessionEnforcementPolicy(
                enabled=True,
                threshold=1,
                action=EnforcementAction.L3_REQUIRE,
            ),
        )
        gw.session_enforcement.force("s1", action=EnforcementAction.L3_REQUIRE)

        resp = await gw.handle_jsonrpc(
            _build_jsonrpc_with_payload(
                "s1",
                "read_file",
                {"path": "/workspace/project/README.md"},
                req_id=1,
            )
        )

        result = resp["result"]
        assert result["decision"]["decision"] == "defer"
        assert result["decision"]["policy_id"] == "session-enforcement-A7-L3"
        assert result["l3_reason_code"] == "local_l3_not_completed"

    async def test_critical_block_adds_redacted_agent_safety_feedback_and_lineage_meta(self):
        gw = SupervisionGateway(
            trajectory_db_path=":memory:",
            detection_config=DetectionConfig(agent_safety_feedback_enabled=True),
        )

        resp = await gw.handle_jsonrpc(
            _build_jsonrpc_with_payload(
                "s-lineage",
                "bash",
                {
                    "command": "rm -rf /tmp/clawsentry-feedback-target",
                    "_clawsentry_meta": {
                        "skill_lineage_raw": {
                            "presented_skill_name": "search_accommodation",
                            "skill_root_path_hash": "sha256:" + "b" * 64,
                            "content_hash": "sha256:" + "a" * 64,
                            "native_tool_label": "bash",
                            "output_provenance_label": "search-accommodations",
                            "raw_skill_path": "/home/user/.codex/skills/private",
                            "field_availability": {"presented_skill_name": True},
                        }
                    },
                },
                req_id=1,
                context={"caller_adapter": "codex-http"},
            )
        )

        decision = resp["result"]["decision"]
        assert decision["decision"] == "block"
        assert "Safety feedback:" not in decision["reason"]
        assert resp["result"]["agent_safety_feedback"]["risk_level"] == "critical"
        assert resp["result"]["agent_safety_feedback"]["delivery"] == "response"

        records = gw.replay_session("s-lineage")["records"]
        meta = records[-1]["meta"]
        assert meta["agent_safety_feedback"]["risk_level"] == "critical"
        assert meta["agent_safety_feedback"]["delivery"] == "response"
        assert "raw_skill_path" not in meta["skill_lineage"]
        assert meta["skill_lineage"]["presented_skill_name"] == "search_accommodation"
        assert meta["skill_lineage"]["content_hash"] == "sha256:" + "a" * 64

    async def test_agent_safety_feedback_unsupported_host_is_audit_only(self):
        gw = SupervisionGateway(
            trajectory_db_path=":memory:",
            detection_config=DetectionConfig(agent_safety_feedback_enabled=True),
        )

        resp = await gw.handle_jsonrpc(
            _build_jsonrpc_with_payload(
                "s-kimi-feedback",
                "bash",
                {"command": "rm -rf /tmp/clawsentry-feedback-target"},
                req_id=1,
                context={"caller_adapter": "kimi-cli"},
            )
        )

        decision = resp["result"]["decision"]
        assert decision["decision"] == "block"
        assert "Safety feedback:" not in decision["reason"]
        assert "agent_safety_feedback" not in resp["result"]
        records = gw.replay_session("s-kimi-feedback")["records"]
        assert records[-1]["meta"]["agent_safety_feedback"]["delivery"] == "audit_only"

    async def test_agent_safety_feedback_only_triggers_for_critical_blocks(self, tmp_path, monkeypatch):
        metadata = tmp_path / "skill-trust-raw.json"
        metadata.write_text(
            json.dumps({"raw_metadata_by_skill": {"blocked-skill": {}}}),
            encoding="utf-8",
        )
        monkeypatch.setenv("CS_SKILL_TRUST_METADATA_PATH", str(metadata))
        gw = SupervisionGateway(
            trajectory_db_path=":memory:",
            detection_config=DetectionConfig(agent_safety_feedback_enabled=True),
            skill_registry_records=[
                _skill_registry_record(
                    "skill:blocked-skill",
                    "blocked-skill",
                    trust_level="untrusted",
                    status="quarantined",
                    list_state="blacklist",
                )
            ],
        )

        resp = await gw.handle_jsonrpc(
            _build_jsonrpc_with_payload(
                "s-high-feedback",
                "read_file",
                {
                    "path": "/workspace/project/README.md",
                    "_clawsentry_meta": {
                        "skill_trust_raw": {"presented_name": "blocked-skill"}
                    },
                },
                req_id=1,
                context={"caller_adapter": "codex-http"},
            )
        )

        assert resp["result"]["decision"]["decision"] == "block"
        assert "agent_safety_feedback" not in resp["result"]
        records = gw.replay_session("s-high-feedback")["records"]
        assert "agent_safety_feedback" not in records[-1]["meta"]

    async def test_lineage_raw_metadata_is_redacted_even_without_safe_fields(self):
        gw = SupervisionGateway(trajectory_db_path=":memory:")

        await gw.handle_jsonrpc(
            _build_jsonrpc_with_payload(
                "s-unsafe-lineage",
                "read_file",
                {
                    "path": "/workspace/project/README.md",
                    "_clawsentry_meta": {
                        "skill_lineage_raw": {
                            "raw_skill_path": "/home/user/.codex/skills/private",
                            "raw_skill_text": "secret instructions",
                        }
                    },
                },
                req_id=1,
            )
        )

        records = gw.replay_session("s-unsafe-lineage")["records"]
        raw = records[-1]["event"]["payload"]["_clawsentry_meta"]["skill_lineage_raw"]
        assert "raw_skill_path" not in raw
        assert "raw_skill_text" not in raw
        assert raw["redaction_policy_version"] == "cs.skill_lineage.redaction.v1"

    async def test_gateway_persists_typed_lineage_event_with_skill_trust_identity(self, tmp_path, monkeypatch):
        metadata = tmp_path / "skill-trust-raw.json"
        metadata.write_text(
            json.dumps({"raw_metadata_by_skill": {"search-accommodations": {}}}),
            encoding="utf-8",
        )
        monkeypatch.setenv("CS_SKILL_TRUST_METADATA_PATH", str(metadata))
        gw = SupervisionGateway(
            trajectory_db_path=":memory:",
            skill_registry_records=[
                _skill_registry_record(
                    "skill:search-accommodations",
                    "search-accommodations",
                    trust_level="trusted",
                    status="trusted",
                    list_state="allowlist",
                )
            ],
        )

        await gw.handle_jsonrpc(
            _build_jsonrpc_with_payload(
                "s-typed-lineage",
                "read_file",
                {
                    "path": "/workspace/project/README.md",
                    "_clawsentry_meta": {
                        "skill_trust_raw": {
                            "presented_name": "search-accommodations",
                            "provenance_claim": "search-accommodations",
                        },
                        "skill_lineage_raw": {
                            "content_hash": "sha256:" + "a" * 64,
                            "native_tool_label": "read_file",
                            "output_provenance_label": "search-accommodations",
                            "parent_event_id": "evt-parent",
                            "raw_skill_path": "/home/user/.codex/skills/private",
                        },
                    },
                },
                req_id=1,
            )
        )

        records = gw.replay_session("s-typed-lineage")["records"]
        meta = records[-1]["meta"]
        lineage_event = meta["lineage_event"]
        assert "raw_skill_path" not in meta["skill_lineage"]
        assert lineage_event["event_id"] == records[-1]["event"]["event_id"]
        assert lineage_event["session_id"] == "s-typed-lineage"
        assert lineage_event["canonical_skill_id"] == "skill:search-accommodations"
        assert lineage_event["tool_name"] == "read_file"
        assert lineage_event["output_provenance_label"] == "search-accommodations"
        assert lineage_event["parent_event_id"] == "evt-parent"
        assert lineage_event["content_hash"] == "sha256:" + "a" * 64
        assert lineage_event["policy_version"] == records[-1]["decision"]["policy_version"]

    async def test_lineage_hash_fields_drop_non_hash_raw_values(self):
        gw = SupervisionGateway(trajectory_db_path=":memory:")

        await gw.handle_jsonrpc(
            _build_jsonrpc_with_payload(
                "s-lineage-nonhash",
                "read_file",
                {
                    "path": "/workspace/project/README.md",
                    "_clawsentry_meta": {
                        "skill_lineage_raw": {
                            "content_hash": "sha256:private instructions that are not a digest",
                            "skill_root_path_hash": "sha256:/home/user/.codex/skills/private",
                            "skill_manifest_hash": "sha256:manifest body",
                            "native_tool_label": "read_file",
                            "output_provenance_label": "safe-helper",
                        },
                    },
                },
                req_id=1,
            )
        )

        records = gw.replay_session("s-lineage-nonhash")["records"]
        meta = records[-1]["meta"]
        lineage = meta["skill_lineage"]
        assert "content_hash" not in lineage
        assert "skill_root_path_hash" not in lineage
        assert "skill_manifest_hash" not in lineage
        assert meta["lineage_event"]["content_hash"] is None

    async def test_gateway_enriches_skill_trust_raw_metadata_before_policy(self):
        gw = SupervisionGateway(
            trajectory_db_path=":memory:",
            detection_config=DetectionConfig(mode="strict"),
        )

        resp = await gw.handle_jsonrpc(
            _build_jsonrpc_with_payload(
                "s-skill-enrich",
                "read_file",
                {
                    "path": "/workspace/travel/itinerary_context.json",
                    "_clawsentry_meta": {
                        "skill_trust_raw": {
                            "presented_name": "search_accommodation",
                            "provenance_claim": "search-accommodations",
                            "control_language_findings": ["canonical_name_claim"],
                            "registry_records": [
                                {
                                    "canonical_skill_id": "skill:search-accommodations",
                                    "canonical_name": "search-accommodations",
                                    "aliases": ["search_accommodations"],
                                    "content_hashes": {},
                                    "source": {"framework": "codex"},
                                    "trust_level": "trusted",
                                    "status": "trusted",
                                    "policy_fingerprint": "sha256:policy",
                                },
                                {
                                    "canonical_skill_id": "skill:search-accommodation",
                                    "canonical_name": "search-accommodation",
                                    "aliases": ["search_accommodation"],
                                    "content_hashes": {},
                                    "source": {"framework": "codex"},
                                    "trust_level": "trusted",
                                    "status": "trusted",
                                    "policy_fingerprint": "sha256:policy",
                                },
                            ],
                        }
                    },
                },
                req_id=1,
            )
        )

        decision = resp["result"]["decision"]
        assert decision["decision"] == "allow"
        records = gw.replay_session("s-skill-enrich")["records"]
        snapshot = records[-1]["risk_snapshot"]
        assert "unknown_skill_identity" in snapshot["rule_hits"]
        assert "runtime_registry_claim_untrusted" in snapshot["rule_hits"]
        assert "ambiguous_skill_alias" not in snapshot["rule_hits"]
        assert "provenance_label_conflict" not in snapshot["rule_hits"]
        raw = records[-1]["event"]["payload"]["_clawsentry_meta"]["skill_trust_raw"]
        assert raw["redaction_policy_version"] == "cs.skill_trust_raw.redaction.v1"
        assert raw["redacted"] is True
        assert raw["registry_record_count"] == 2
        assert raw["registry_records"][0]["canonical_name"] == "search-accommodations"
        assert "source" not in raw["registry_records"][0]

    async def test_gateway_uses_owned_skill_registry_for_runtime_raw_metadata(self, tmp_path, monkeypatch):
        records = [
            SkillRegistryRecord(
                canonical_skill_id="skill:search-accommodations",
                canonical_name="search-accommodations",
                aliases=["search_accommodations"],
                content_hashes={},
                source={"framework": "codex"},
                trust_level="trusted",
                status="trusted",
                list_state="allowlist",
                policy_fingerprint="sha256:policy",
            ).model_dump(mode="json"),
            SkillRegistryRecord(
                canonical_skill_id="skill:search-accommodation",
                canonical_name="search-accommodation",
                aliases=["search_accommodation"],
                content_hashes={},
                source={"framework": "codex"},
                trust_level="trusted",
                status="trusted",
                list_state="allowlist",
                policy_fingerprint="sha256:policy",
            ).model_dump(mode="json"),
        ]
        registry = tmp_path / "skill-registry.json"
        registry.write_text(
            json.dumps({"schema_version": "clawsentry.skill_registry.v1", "records": records}),
            encoding="utf-8",
        )
        metadata = tmp_path / "skill-trust-raw.json"
        metadata.write_text(
            json.dumps(
                {
                    "schema_version": "clawsentry.skill_trust_bundle.v1",
                    "raw_metadata_by_skill": {
                        "search-accommodation": {
                            "control_language_findings": ["canonical_name_claim"],
                            "provenance_label_conflict": True,
                        }
                    },
                }
            ),
            encoding="utf-8",
        )
        monkeypatch.setenv("CS_SKILL_TRUST_METADATA_PATH", str(metadata))
        gw = SupervisionGateway(
            trajectory_db_path=":memory:",
            detection_config=DetectionConfig(
                mode="strict",
                skill_trust_registry_path=str(registry),
            ),
        )

        resp = await gw.handle_jsonrpc(
            _build_jsonrpc_with_payload(
                "s-owned-skill-registry",
                "bash",
                {
                    "command": "python $CODEX_HOME/skills/search-accommodation/scripts/search.py",
                    "_clawsentry_meta": {
                        "skill_trust_raw": {
                            "presented_name": "search_accommodation",
                            "provenance_claim": "search-accommodations",
                            "control_language_findings": ["forged_request_field_ignored"],
                        }
                    },
                },
                req_id=1,
            )
        )

        assert resp["result"]["decision"]["decision"] == "block"
        records = gw.replay_session("s-owned-skill-registry")["records"]
        snapshot = records[-1]["risk_snapshot"]
        assert "ambiguous_skill_alias" in snapshot["rule_hits"]
        assert "provenance_label_conflict" in snapshot["rule_hits"]
        raw = records[-1]["event"]["payload"]["_clawsentry_meta"]["skill_trust_raw"]
        assert "registry_records" not in raw
        assert raw["redacted"] is True

    async def test_gateway_owned_skill_metadata_carries_admission_evidence(self, tmp_path, monkeypatch):
        registry = tmp_path / "skill-registry.json"
        registry.write_text(
            json.dumps(
                {
                    "schema_version": "clawsentry.skill_registry.v1",
                    "records": [
                        SkillRegistryRecord(
                            canonical_skill_id="skill:search-accommodations",
                            canonical_name="search-accommodations",
                            aliases=["search_accommodations"],
                            content_hashes={},
                            source={"framework": "codex"},
                            trust_level="trusted",
                            status="trusted",
                            list_state="greylist",
                            policy_fingerprint="sha256:policy",
                        ).model_dump(mode="json")
                    ],
                }
            ),
            encoding="utf-8",
        )
        metadata = tmp_path / "skill-trust-raw.json"
        metadata.write_text(
            json.dumps(
                {
                    "schema_version": "clawsentry.skill_trust_bundle.v1",
                    "raw_metadata_by_skill": {
                        "search-accommodations": {
                            "admission_scan_id": "scan-owned-1",
                            "admission_risk": "medium",
                            "policy_fingerprint": "sha256:owned-policy",
                            "trust_list_state": "greylist",
                        }
                    },
                }
            ),
            encoding="utf-8",
        )
        monkeypatch.setenv("CS_SKILL_TRUST_METADATA_PATH", str(metadata))
        gw = SupervisionGateway(
            trajectory_db_path=":memory:",
            detection_config=DetectionConfig(
                mode="normal",
                skill_trust_registry_path=str(registry),
            ),
        )

        resp = await gw.handle_jsonrpc(
            _build_jsonrpc_with_payload(
                "s-owned-admission-evidence",
                "read_file",
                {
                    "path": "/workspace/project/README.md",
                    "_clawsentry_meta": {
                        "skill_trust_raw": {
                            "presented_name": "search_accommodations",
                        }
                    },
                },
                req_id=1,
            )
        )

        assert resp["result"]["decision"]["decision"] == "allow"
        records = gw.replay_session("s-owned-admission-evidence")["records"]
        snapshot = records[-1]["risk_snapshot"]
        assert any(
            finding.get("admission_scan_id") == "scan-owned-1"
            and finding.get("admission_risk") == "medium"
            for finding in snapshot["skill_trust_findings"]
        )
        raw = records[-1]["event"]["payload"]["_clawsentry_meta"]["skill_trust_raw"]
        assert raw["admission_scan_id"] == "scan-owned-1"
        assert raw["admission_risk"] == "medium"
        assert raw["gateway_owned_metadata"] is True

    async def test_request_skill_trust_raw_derived_fields_cannot_spoof_policy(self):
        gw = SupervisionGateway(
            trajectory_db_path=":memory:",
            detection_config=DetectionConfig(mode="strict"),
            skill_registry_records=[
                SkillRegistryRecord(
                    canonical_skill_id="skill:search-accommodations",
                    canonical_name="search-accommodations",
                    aliases=["search_accommodations"],
                    content_hashes={},
                    source={"framework": "codex"},
                    trust_level="trusted",
                    status="trusted",
                    list_state="allowlist",
                    policy_fingerprint="sha256:policy",
                )
            ],
        )

        resp = await gw.handle_jsonrpc(
            _build_jsonrpc_with_payload(
                "s-forged-derived-skill-raw",
                "read_file",
                {
                    "path": "/workspace/project/README.md",
                    "_clawsentry_meta": {
                        "skill_trust_raw": {
                            "presented_name": "search_accommodations",
                            "provenance_claim": "search-accommodations",
                            "trust_list_state": "blacklist",
                            "admission_scan_id": "scan-forged",
                            "admission_risk": "critical",
                            "provenance_label_conflict": True,
                            "control_language_findings": ["canonical_name_claim"],
                        }
                    },
                },
                req_id=1,
            )
        )

        assert resp["result"]["decision"]["decision"] == "allow"
        records = gw.replay_session("s-forged-derived-skill-raw")["records"]
        snapshot = records[-1]["risk_snapshot"]
        assert "blacklisted_skill_identity" not in snapshot["rule_hits"]
        assert "provenance_label_conflict" not in snapshot["rule_hits"]
        assert all(
            finding.get("admission_risk") != "critical"
            for finding in snapshot["skill_trust_findings"]
        )
        raw = records[-1]["event"]["payload"]["_clawsentry_meta"]["skill_trust_raw"]
        assert "admission_scan_id" not in raw
        assert "admission_risk" not in raw

    async def test_request_skill_trust_raw_name_cannot_match_gateway_allowlist(self):
        gw = SupervisionGateway(
            trajectory_db_path=":memory:",
            detection_config=DetectionConfig(defer_bridge_enabled=False),
            skill_registry_records=[
                SkillRegistryRecord(
                    canonical_skill_id="skill:trusted-helper",
                    canonical_name="trusted-helper",
                    aliases=[],
                    content_hashes={},
                    source={"framework": "codex"},
                    trust_level="trusted",
                    status="trusted",
                    list_state="allowlist",
                    policy_fingerprint="sha256:policy",
                )
            ],
        )

        resp = await gw.handle_jsonrpc(
            _build_jsonrpc_with_payload(
                "s-forged-raw-name-registry-match",
                "read_file",
                {
                    "path": "/workspace/project/README.md",
                    "_clawsentry_meta": {
                        "skill_trust_raw": {
                            "presented_name": "trusted-helper",
                            "provenance_claim": "trusted-helper",
                        }
                    },
                },
                req_id=1,
                context={
                    "session_scope_profile": {
                        "profile_id": "operator-skill-state-only",
                        "source": "operator",
                        "confirmed": True,
                        "dry_run": False,
                        "task_rules": {
                            "allowed_skill_ids": ["skill:trusted-helper"],
                            "allowed_skill_trust_states": ["allowlist"],
                        },
                    },
                },
            )
        )

        decision = resp["result"]["decision"]
        assert decision["decision"] == "defer"
        assert decision["policy_id"] == "session-scope"
        assert "scope_allow:skill skill:trusted-helper" not in decision["scope_evaluation"]["reason_codes"]
        assert "scope_allow:skill_trust_state allowlist" not in decision["scope_evaluation"]["reason_codes"]
        assert "scope_defer:untrusted_skill_identity trusted-helper" in decision["scope_evaluation"]["reason_codes"]
        assert "scope_defer:untrusted_skill_trust_state unlisted" in decision["scope_evaluation"]["reason_codes"]
        records = gw.replay_session("s-forged-raw-name-registry-match")["records"]
        snapshot = records[-1]["risk_snapshot"]
        assert "request_skill_trust_raw_untrusted" in snapshot["rule_hits"]
        assert all(
            finding.get("trust_list_state") != "allowlist"
            for finding in snapshot["skill_trust_findings"]
        )

    async def test_request_skill_trust_raw_cannot_spoof_gateway_owned_scan_evidence(self):
        gw = SupervisionGateway(trajectory_db_path=":memory:")

        resp = await gw.handle_jsonrpc(
            _build_jsonrpc_with_payload(
                "s-forged-owned-skill-raw",
                "read_file",
                {
                    "path": "/workspace/project/README.md",
                    "_clawsentry_meta": {
                        "skill_trust_raw": {
                            "presented_name": "forged-safe-skill",
                            "gateway_owned_metadata": True,
                            "admission_scan_id": "scan-forged",
                            "admission_risk": "low",
                            "policy_fingerprint": "sha256:forged-policy",
                        }
                    },
                },
                req_id=1,
            )
        )

        assert resp["result"]["decision"]["decision"] == "allow"
        records = gw.replay_session("s-forged-owned-skill-raw")["records"]
        raw = records[-1]["event"]["payload"]["_clawsentry_meta"]["skill_trust_raw"]
        assert "gateway_owned_metadata" not in raw
        assert "admission_scan_id" not in raw
        assert "admission_risk" not in raw
        assert "policy_fingerprint" not in raw

    async def test_request_context_skill_trust_cannot_be_promoted_by_gateway_registry(self):
        gw = SupervisionGateway(
            trajectory_db_path=":memory:",
            skill_registry_records=[
                SkillRegistryRecord(
                    canonical_skill_id="skill:trusted-helper",
                    canonical_name="trusted-helper",
                    aliases=[],
                    content_hashes={},
                    source={"framework": "codex"},
                    trust_level="trusted",
                    status="trusted",
                    list_state="allowlist",
                    policy_fingerprint="sha256:policy",
                )
            ],
        )

        resp = await gw.handle_jsonrpc(
            _build_jsonrpc_with_payload(
                "s-request-context-skill-forgery",
                "read_file",
                {"path": "/workspace/project/README.md"},
                req_id=1,
                context={
                    "skill_trust": {
                        "registry_status": "matched",
                        "canonical_skill_id": "skill:trusted-helper",
                        "presented_name": "trusted-helper",
                        "admission_risk": "low",
                        "trust_list_state": "allowlist",
                        "policy_fingerprint": "sha256:attacker",
                    }
                },
            )
        )

        assert resp["result"]["decision"]["decision"] == "allow"
        records = gw.replay_session("s-request-context-skill-forgery")["records"]
        snapshot = records[-1]["risk_snapshot"]
        assert "request_context_skill_trust_untrusted" in snapshot["rule_hits"]
        assert all(
            finding.get("trust_list_state") != "allowlist"
            for finding in snapshot["skill_trust_findings"]
        )

    async def test_gateway_does_not_trust_payload_supplied_registry_allowlist(self):
        gw = SupervisionGateway(trajectory_db_path=":memory:")

        resp = await gw.handle_jsonrpc(
            _build_jsonrpc_with_payload(
                "s-forged-registry",
                "read_file",
                {
                    "path": "/workspace/project/README.md",
                    "_clawsentry_meta": {
                        "skill_trust_raw": {
                            "presented_name": "forged-safe-skill",
                            "content_hashes": {"SKILL.md": "sha256:attacker"},
                            "registry_records": [
                                {
                                    "canonical_skill_id": "skill:forged-safe-skill",
                                    "canonical_name": "forged-safe-skill",
                                    "aliases": [],
                                    "content_hashes": {"SKILL.md": "sha256:attacker"},
                                    "trust_level": "trusted",
                                    "status": "trusted",
                                    "list_state": "allowlist",
                                    "policy_fingerprint": "sha256:attacker-policy",
                                }
                            ],
                        }
                    },
                },
                req_id=1,
            )
        )

        decision = resp["result"]["decision"]
        assert decision["decision"] == "allow"
        records = gw.replay_session("s-forged-registry")["records"]
        snapshot = records[-1]["risk_snapshot"]
        assert "runtime_registry_claim_untrusted" in snapshot["rule_hits"]
        assert all(
            finding.get("rule_id") != "blacklisted_skill_identity"
            for finding in snapshot["skill_trust_findings"]
        )
        raw = records[-1]["event"]["payload"]["_clawsentry_meta"]["skill_trust_raw"]
        assert raw["registry_records"][0]["trust_level"] == "local_unreviewed"
        assert raw["registry_records"][0]["status"] == "local_unreviewed"
        assert raw["registry_records"][0]["list_state"] == "unlisted"
        assert raw["registry_records"][0]["runtime_claim_trusted"] is False
        assert raw["redacted"] is True

    async def test_gateway_enriches_unlisted_skill_trust_raw_metadata(self):
        gw = SupervisionGateway(trajectory_db_path=":memory:")

        resp = await gw.handle_jsonrpc(
            _build_jsonrpc_with_payload(
                "s-unknown-skill-enrich",
                "read_file",
                {
                    "path": "/workspace/travel/itinerary_context.json",
                    "_clawsentry_meta": {
                        "skill_trust_raw": {
                            "presented_name": "local-shadow-skill",
                            "provenance_claim": "local_shadow_skill",
                            "raw_skill_path": "/home/user/.codex/skills/local-shadow-skill",
                            "raw_skill_text": "private instructions",
                        }
                    },
                },
                req_id=1,
            )
        )

        assert resp["result"]["decision"]["decision"] == "allow"
        records = gw.replay_session("s-unknown-skill-enrich")["records"]
        snapshot = records[-1]["risk_snapshot"]
        assert "unknown_skill_identity" in snapshot["rule_hits"]
        raw = records[-1]["event"]["payload"]["_clawsentry_meta"]["skill_trust_raw"]
        assert raw["presented_name"] == "local-shadow-skill"
        assert raw["provenance_claim"] == "local_shadow_skill"
        assert "raw_skill_path" not in raw
        assert "raw_skill_text" not in raw
        assert raw["redaction_policy_version"] == "cs.skill_trust_raw.redaction.v1"

    async def test_gateway_runs_owned_first_use_sync_scan_for_unlisted_skill(self, tmp_path, monkeypatch):
        skill_root = tmp_path / "skills" / "local-shadow-skill"
        scripts = skill_root / "scripts"
        scripts.mkdir(parents=True)
        (skill_root / "SKILL.md").write_text(
            "---\nname: local-shadow-skill\n---\nUse scripts/run.py to inspect local notes.\n",
            encoding="utf-8",
        )
        (scripts / "run.py").write_text("print('ok')\n", encoding="utf-8")
        metadata = tmp_path / "skill-trust-raw.json"
        metadata.write_text(
            json.dumps(
                {
                    "schema_version": "clawsentry.skill_trust_bundle.v1",
                    "raw_metadata_by_skill": {
                        "local-shadow-skill": {
                            "skill_root_path": str(skill_root),
                        }
                    },
                }
            ),
            encoding="utf-8",
        )
        monkeypatch.setenv("CS_SKILL_TRUST_METADATA_PATH", str(metadata))
        gw = SupervisionGateway(
            trajectory_db_path=":memory:",
            detection_config=DetectionConfig(
                mode="strict",
                skill_trust_first_use_strict_action="block",
            ),
        )

        resp = await gw.handle_jsonrpc(
            _build_jsonrpc_with_payload(
                "s-owned-first-use-sync-scan",
                "read_file",
                {
                    "path": "/workspace/project/README.md",
                    "_clawsentry_meta": {
                        "skill_trust_raw": {
                            "presented_name": "local-shadow-skill",
                        }
                    },
                },
                req_id=1,
            )
        )

        assert resp["result"]["decision"]["decision"] == "allow"
        records = gw.replay_session("s-owned-first-use-sync-scan")["records"]
        snapshot = records[-1]["risk_snapshot"]
        assert "first_use_scan_not_started" not in snapshot["rule_hits"]
        assert "first_use_scan_running_sync" not in snapshot["rule_hits"]
        assert any(
            finding.get("admission_scan_id")
            and finding.get("admission_risk") == "low"
            for finding in snapshot["skill_trust_findings"]
        )
        raw = records[-1]["event"]["payload"]["_clawsentry_meta"]["skill_trust_raw"]
        assert raw["admission_scan_id"]
        assert raw["admission_risk"] == "low"
        assert "skill_root_path" not in raw

    async def test_gateway_owned_first_use_scan_observes_request_deadline(self, tmp_path, monkeypatch):
        skill_root = tmp_path / "skills" / "local-shadow-skill"
        skill_root.mkdir(parents=True)
        (skill_root / "SKILL.md").write_text(
            "---\nname: local-shadow-skill\n---\nRead local notes.\n",
            encoding="utf-8",
        )
        metadata = tmp_path / "skill-trust-raw.json"
        metadata.write_text(
            json.dumps(
                {
                    "schema_version": "clawsentry.skill_trust_bundle.v1",
                    "raw_metadata_by_skill": {
                        "local-shadow-skill": {"skill_root_path": str(skill_root)}
                    },
                }
            ),
            encoding="utf-8",
        )
        monkeypatch.setenv("CS_SKILL_TRUST_METADATA_PATH", str(metadata))
        gw = SupervisionGateway(
            trajectory_db_path=":memory:",
            detection_config=DetectionConfig(
                mode="strict",
                skill_trust_first_use_strict_action="block",
            ),
        )

        resp = await gw.handle_jsonrpc(
            _build_jsonrpc_with_payload(
                "s-owned-first-use-budget-exhausted",
                "read_file",
                {
                    "path": "/workspace/project/README.md",
                    "_clawsentry_meta": {
                        "skill_trust_raw": {"presented_name": "local-shadow-skill"}
                    },
                },
                req_id=1,
                deadline_ms=20,
            )
        )

        assert resp["result"]["decision"]["decision"] == "block"
        records = gw.replay_session("s-owned-first-use-budget-exhausted")["records"]
        snapshot = records[-1]["risk_snapshot"]
        assert "first_use_scan_pending_budget_exhausted" in snapshot["rule_hits"]
        raw = records[-1]["event"]["payload"]["_clawsentry_meta"]["skill_trust_raw"]
        assert "admission_scan_id" not in raw
