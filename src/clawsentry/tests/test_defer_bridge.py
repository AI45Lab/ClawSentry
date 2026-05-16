"""Tests for the DEFER bridge integration in SupervisionGateway."""

from __future__ import annotations

import asyncio
import json
import uuid
from unittest.mock import MagicMock

import pytest

from clawsentry.gateway.models import (
    CanonicalDecision,
    CanonicalEvent,
    ClassifiedBy,
    DecisionSource,
    DecisionTier,
    DecisionVerdict,
    EventType,
    RiskDimensions,
    RiskLevel,
    RiskSnapshot,
    RPC_VERSION,
    utc_now_iso,
)
from clawsentry.gateway.detection_config import DetectionConfig
from clawsentry.gateway.server import SupervisionGateway


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_snapshot(risk_level=RiskLevel.MEDIUM):
    """Build a minimal RiskSnapshot for mocking."""
    return RiskSnapshot(
        risk_level=risk_level,
        composite_score=1.0,
        dimensions=RiskDimensions(d1=1, d2=0, d3=0, d4=0, d5=0),
        classified_by=ClassifiedBy.L1,
        classified_at=utc_now_iso(),
    )


def _jsonrpc_request(
    event_type="pre_action",
    tool_name="Bash",
    payload=None,
    session_id="test-session-1",
    event_id=None,
    deadline_ms=60000,
) -> bytes:
    """Build a JSON-RPC 2.0 request bytes for sync_decision."""
    eid = event_id or f"evt-{uuid.uuid4().hex[:8]}"
    return json.dumps({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "ahp/sync_decision",
        "params": {
            "rpc_version": RPC_VERSION,
            "request_id": f"req-{eid}",
            "deadline_ms": deadline_ms,
            "decision_tier": "L1",
            "event": {
                "event_id": eid,
                "trace_id": f"tr-{uuid.uuid4().hex[:8]}",
                "event_type": event_type,
                "session_id": session_id,
                "agent_id": "test-agent",
                "source_framework": "claude-code",
                "occurred_at": utc_now_iso(),
                "tool_name": tool_name,
                "payload": payload or {"command": "rm -rf /tmp/test"},
            },
        },
    }).encode()


def _force_defer(gw: SupervisionGateway, risk_level=RiskLevel.MEDIUM):
    """Mock policy_engine.evaluate to always return DEFER."""
    defer_decision = CanonicalDecision(
        decision=DecisionVerdict.DEFER,
        reason="needs review",
        policy_id="test",
        risk_level=risk_level,
        decision_source=DecisionSource.POLICY,
        final=False,
    )
    snapshot = _make_snapshot(risk_level)
    gw.policy_engine.evaluate = MagicMock(
        return_value=(defer_decision, snapshot, DecisionTier.L1)
    )


def _force_allow(gw: SupervisionGateway, risk_level=RiskLevel.MEDIUM):
    """Mock policy_engine.evaluate to return ALLOW so confirmation fast-lane can override it."""
    allow_decision = CanonicalDecision(
        decision=DecisionVerdict.ALLOW,
        reason="confirmation observed",
        policy_id="test",
        risk_level=risk_level,
        decision_source=DecisionSource.POLICY,
        final=True,
    )
    snapshot = _make_snapshot(risk_level)
    gw.policy_engine.evaluate = MagicMock(
        return_value=(allow_decision, snapshot, DecisionTier.L1)
    )


def _confirmation_jsonrpc_request(
    *,
    approval_id="approval-confirm-001",
    session_id="test-confirm-session-1",
    event_id=None,
    tool_name="Bash",
    payload=None,
    deadline_ms=60000,
) -> bytes:
    """Build a confirmation compat event routed through canonical SESSION."""
    eid = event_id or f"evt-{uuid.uuid4().hex[:8]}"
    return json.dumps({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "ahp/sync_decision",
        "params": {
            "rpc_version": RPC_VERSION,
            "request_id": f"req-{eid}",
            "deadline_ms": deadline_ms,
            "decision_tier": "L1",
            "event": {
                "event_id": eid,
                "trace_id": f"tr-{uuid.uuid4().hex[:8]}",
                "event_type": "session",
                "event_subtype": "compat:confirmation",
                "session_id": session_id,
                "agent_id": "test-agent",
                "source_framework": "a3s-code",
                "occurred_at": utc_now_iso(),
                "approval_id": approval_id,
                "tool_name": tool_name,
                "payload": payload or {
                    "command": "sudo rm -rf /tmp/test",
                    "_clawsentry_meta": {
                        "ahp_compat": {
                            "preservation_mode": "compatibility-carrying",
                            "raw_event_type": "confirmation",
                            "identity": {
                                "event_id": eid,
                                "session_id": session_id,
                                "agent_id": "test-agent",
                                "approval_id": approval_id,
                            },
                        },
                    },
                },
            },
        },
    }).encode()


# ---------------------------------------------------------------------------
# Test 1: DEFER + bridge enabled -> registers and waits (timeout -> block)
# ---------------------------------------------------------------------------

class TestDeferBridge:

    @pytest.mark.asyncio
    async def test_defer_bridge_registers_and_waits(self):
        """When bridge enabled + DEFER verdict, should register and wait.
        With short timeout and timeout_action=block, auto-resolves to block."""
        config = DetectionConfig(
            defer_bridge_enabled=True,
            defer_timeout_s=0.3,
            defer_timeout_action="block",
        )
        gw = SupervisionGateway(detection_config=config)
        _force_defer(gw, RiskLevel.HIGH)

        body = _jsonrpc_request()
        resp = await gw.handle_jsonrpc(body)

        assert "result" in resp, f"Expected success, got: {resp}"
        decision = resp["result"]["decision"]
        # Timeout -> block (system auto-resolution, not operator)
        assert decision["decision"] == "block"
        assert decision["decision_source"] == "system"
        assert decision["failure_class"] == "approval_timeout"
        assert "Operator denied" not in decision["reason"]
        assert "timeout" in decision["reason"].lower()

    # ---------------------------------------------------------------------------
    # Test 2: resolve allow-once -> ALLOW
    # ---------------------------------------------------------------------------

    @pytest.mark.asyncio
    async def test_defer_bridge_resolve_allow(self):
        """Resolving with allow-once should produce ALLOW decision."""
        config = DetectionConfig(
            defer_bridge_enabled=True,
            defer_timeout_s=10.0,
        )
        gw = SupervisionGateway(detection_config=config)
        _force_defer(gw)

        body = _jsonrpc_request()

        async def resolve_soon():
            await asyncio.sleep(0.1)
            for did in list(gw.defer_manager._pending.keys()):
                gw.defer_manager.resolve_defer(did, "allow-once", "operator approved")

        asyncio.create_task(resolve_soon())
        resp = await gw.handle_jsonrpc(body)

        assert "result" in resp, f"Expected success, got: {resp}"
        decision = resp["result"]["decision"]
        assert decision["decision"] == "allow"
        assert decision["decision_source"] == "operator"

    # ---------------------------------------------------------------------------
    # Test 3: resolve deny -> BLOCK
    # ---------------------------------------------------------------------------

    @pytest.mark.asyncio
    async def test_defer_bridge_resolve_deny(self):
        """Resolving with deny should produce BLOCK decision."""
        config = DetectionConfig(
            defer_bridge_enabled=True,
            defer_timeout_s=10.0,
        )
        gw = SupervisionGateway(detection_config=config)
        _force_defer(gw, RiskLevel.HIGH)

        body = _jsonrpc_request()

        async def resolve_soon():
            await asyncio.sleep(0.1)
            for did in list(gw.defer_manager._pending.keys()):
                gw.defer_manager.resolve_defer(did, "deny", "too risky")

        asyncio.create_task(resolve_soon())
        resp = await gw.handle_jsonrpc(body)

        assert "result" in resp, f"Expected success, got: {resp}"
        decision = resp["result"]["decision"]
        assert decision["decision"] == "block"
        assert "operator" in decision["decision_source"].lower()

    # ---------------------------------------------------------------------------
    # Test 4: timeout action=block -> BLOCK
    # ---------------------------------------------------------------------------

    @pytest.mark.asyncio
    async def test_defer_bridge_timeout_block(self):
        """When timeout_action=block, DEFER timeout -> BLOCK."""
        config = DetectionConfig(
            defer_bridge_enabled=True,
            defer_timeout_s=0.3,
            defer_timeout_action="block",
        )
        gw = SupervisionGateway(detection_config=config)
        _force_defer(gw, RiskLevel.HIGH)

        body = _jsonrpc_request()
        resp = await gw.handle_jsonrpc(body)

        assert "result" in resp, f"Expected success, got: {resp}"
        assert resp["result"]["decision"]["decision"] == "block"
        assert resp["result"]["decision"]["failure_class"] == "approval_timeout"
        assert resp["result"]["decision"]["failure_class"] == "approval_timeout"

    # ---------------------------------------------------------------------------
    # Test 5: timeout action=allow -> ALLOW
    # ---------------------------------------------------------------------------

    @pytest.mark.asyncio
    async def test_defer_bridge_timeout_allow(self):
        """When timeout_action=allow, DEFER timeout -> ALLOW."""
        config = DetectionConfig(
            defer_bridge_enabled=True,
            defer_timeout_s=0.3,
            defer_timeout_action="allow",
        )
        gw = SupervisionGateway(detection_config=config)
        _force_defer(gw, RiskLevel.MEDIUM)

        body = _jsonrpc_request()
        resp = await gw.handle_jsonrpc(body)

        assert "result" in resp, f"Expected success, got: {resp}"
        assert resp["result"]["decision"]["decision"] == "allow"
        assert resp["result"]["decision"]["failure_class"] == "approval_timeout"
        assert "Operator approved" not in resp["result"]["decision"]["reason"]
        assert "timeout" in resp["result"]["decision"]["reason"].lower()

    # ---------------------------------------------------------------------------
    # Test 6: only PRE_ACTION triggers bridge
    # ---------------------------------------------------------------------------

    @pytest.mark.asyncio
    async def test_defer_bridge_only_pre_action(self):
        """DEFER for POST_ACTION should NOT trigger bridge."""
        config = DetectionConfig(
            defer_bridge_enabled=True,
            defer_timeout_s=1.0,
        )
        gw = SupervisionGateway(detection_config=config)
        _force_defer(gw)

        # Use POST_ACTION event
        body = _jsonrpc_request(event_type="post_action")
        resp = await gw.handle_jsonrpc(body)

        assert "result" in resp, f"Expected success, got: {resp}"
        # Should return DEFER directly without blocking
        assert resp["result"]["decision"]["decision"] == "defer"
        assert gw.defer_manager.pending_count == 0

    # ---------------------------------------------------------------------------
    # Test 7: bridge disabled -> no wait
    # ---------------------------------------------------------------------------

    @pytest.mark.asyncio
    async def test_defer_bridge_disabled_no_wait(self):
        """When bridge disabled, DEFER returns immediately."""
        config = DetectionConfig(
            defer_bridge_enabled=False,
            defer_timeout_s=10.0,
        )
        gw = SupervisionGateway(detection_config=config)
        _force_defer(gw)

        body = _jsonrpc_request()
        resp = await gw.handle_jsonrpc(body)

        assert "result" in resp, f"Expected success, got: {resp}"
        assert resp["result"]["decision"]["decision"] == "defer"
        assert gw.defer_manager.pending_count == 0

    # ---------------------------------------------------------------------------
    # Test 8: broadcasts defer_pending + defer_resolved
    # ---------------------------------------------------------------------------

    @pytest.mark.asyncio
    async def test_defer_bridge_broadcasts_events(self):
        """DEFER bridge should broadcast defer_pending and defer_resolved events."""
        config = DetectionConfig(
            defer_bridge_enabled=True,
            defer_timeout_s=10.0,
        )
        gw = SupervisionGateway(detection_config=config)
        _force_defer(gw)

        # Subscribe to all events
        _, queue = gw.event_bus.subscribe(
            event_types={"decision", "defer_pending", "defer_resolved", "session_start"}
        )

        body = _jsonrpc_request()

        async def resolve_soon():
            await asyncio.sleep(0.1)
            for did in list(gw.defer_manager._pending.keys()):
                gw.defer_manager.resolve_defer(did, "allow-once", "ok")

        asyncio.create_task(resolve_soon())
        await gw.handle_jsonrpc(body)

        # Collect all broadcast events
        events = []
        while not queue.empty():
            events.append(await queue.get())

        event_types = [e["type"] for e in events]
        assert "defer_pending" in event_types
        assert "defer_resolved" in event_types

        pending = next(e for e in events if e["type"] == "defer_pending")
        assert "approval_id" in pending
        assert pending["tool_name"] == "Bash"

        resolved = next(e for e in events if e["type"] == "defer_resolved")
        assert resolved["resolved_decision"] == "allow"

    @pytest.mark.asyncio
    async def test_defer_pending_includes_operator_prompt_context(self):
        config = DetectionConfig(
            defer_bridge_enabled=True,
            defer_timeout_s=0.05,
        )
        gw = SupervisionGateway(detection_config=config)
        _force_defer(gw, RiskLevel.HIGH)
        sub_id, queue = gw.event_bus.subscribe(event_types={"defer_pending"})

        try:
            await gw.handle_jsonrpc(
                _jsonrpc_request(
                    session_id="sess-approval-prompt",
                    event_id="evt-approval-prompt",
                    tool_name="bash",
                    payload={
                        "command": "rm -rf /workspace/payments",
                        "workspace_root": "/workspace/payments",
                    },
                )
            )
            pending = queue.get_nowait()
        finally:
            gw.event_bus.unsubscribe(sub_id)

        prompt = pending["approval_prompt"]
        assert prompt["affected_target"] == "/workspace/<redacted>"
        assert prompt["operation"] == "bash"
        assert prompt["consequence"]
        assert "/workspace/payments" not in prompt["consequence"]
        assert prompt["dry_run_or_narrower_scope_suggestion"]
        assert prompt["rollback_hint"]
        assert prompt["field_sources"] == {
            "affected_target": "adapter_provided",
            "operation": "adapter_provided",
            "consequence": "generated",
            "dry_run_or_narrower_scope_suggestion": "generated",
            "rollback_hint": "generated",
        }
        assert pending["approval_affected_target"] == prompt["affected_target"]
        assert pending["approval_operation"] == prompt["operation"]
        assert pending["approval_field_sources"] == prompt["field_sources"]

    @pytest.mark.asyncio
    async def test_defer_pending_redacts_payload_supplied_operation(self):
        config = DetectionConfig(
            defer_bridge_enabled=True,
            defer_timeout_s=0.05,
        )
        gw = SupervisionGateway(detection_config=config)
        _force_defer(gw, RiskLevel.HIGH)
        sub_id, queue = gw.event_bus.subscribe(event_types={"defer_pending"})

        try:
            await gw.handle_jsonrpc(
                _jsonrpc_request(
                    session_id="sess-approval-operation-redaction",
                    event_id="evt-approval-operation-redaction",
                    tool_name="",
                    payload={
                        "operation": "write /home/user/private.txt token=abc123",
                        "workspace_root": "/workspace/payments",
                    },
                )
            )
            pending = queue.get_nowait()
        finally:
            gw.event_bus.unsubscribe(sub_id)

        prompt = pending["approval_prompt"]
        assert prompt["operation"] == "write /home/<redacted> token=<redacted>"
        assert "/home/user/private.txt" not in prompt["consequence"]
        assert "abc123" not in prompt["consequence"]

    @pytest.mark.asyncio
    async def test_defer_bridge_persists_final_resolution_record(self):
        """Final operator resolution should be replayable from trajectory storage."""
        config = DetectionConfig(
            defer_bridge_enabled=True,
            defer_timeout_s=10.0,
        )
        gw = SupervisionGateway(detection_config=config)
        _force_defer(gw)

        body = _jsonrpc_request(session_id="sess-defer-persist", event_id="evt-defer-persist")

        async def resolve_soon():
            await asyncio.sleep(0.1)
            for did in list(gw.defer_manager._pending.keys()):
                gw.defer_manager.resolve_defer(did, "allow-once", "operator approved")

        asyncio.create_task(resolve_soon())
        resp = await gw.handle_jsonrpc(body)

        assert resp["result"]["decision"]["decision"] == "allow"

        rows = gw.trajectory_store.replay_session("sess-defer-persist")
        resolution_rows = [
            row for row in rows
            if row["meta"].get("record_type") == "decision_resolution"
        ]
        assert resolution_rows, rows
        resolution = resolution_rows[-1]
        assert resolution["decision"]["decision"] == "allow"
        assert resolution["decision"]["decision_source"] == "operator"
        assert resolution["meta"]["request_id"] == "req-evt-defer-persist"
        assert resolution["meta"]["approval_id"].startswith("cs-defer-")

        summary = gw.report_summary()
        io = summary["decision_path_io"]
        assert io["record_path"]["calls"] == 2
        assert io["record_path"]["trajectory_store"]["calls"] == 2
        assert io["record_path"]["session_registry"]["calls"] == 2
        assert io["reporting"]["report_summary"]["calls"] == 1
        assert io["reporting"]["report_summary"]["trajectory_store"]["calls"] == 1

        page = gw.trajectory_store.replay_session_page("sess-defer-persist")
        assert page["records"]
        assert gw.trajectory_store.io_metrics_snapshot()["replay_session_page"]["calls"] == 1

    @pytest.mark.asyncio
    async def test_defer_bridge_updates_session_view_after_final_deny(self):
        """Session replay/report state should reflect the final resolved decision."""
        config = DetectionConfig(
            defer_bridge_enabled=True,
            defer_timeout_s=10.0,
        )
        gw = SupervisionGateway(detection_config=config)
        _force_defer(gw, RiskLevel.HIGH)

        body = _jsonrpc_request(session_id="sess-defer-deny", event_id="evt-defer-deny")

        async def resolve_soon():
            await asyncio.sleep(0.1)
            for did in list(gw.defer_manager._pending.keys()):
                gw.defer_manager.resolve_defer(did, "deny", "too risky")

        asyncio.create_task(resolve_soon())
        resp = await gw.handle_jsonrpc(body)

        assert resp["result"]["decision"]["decision"] == "block"

        session_risk = gw.report_session_risk("sess-defer-deny")
        assert session_risk["current_risk_level"] == "high"
        assert len(session_risk["risk_timeline"]) == 2
        assert session_risk["risk_timeline"][0]["decision"] == "defer"
        assert session_risk["risk_timeline"][1]["decision"] == "block"

        sessions = gw.report_sessions(limit=10)
        sess = next(item for item in sessions["sessions"] if item["session_id"] == "sess-defer-deny")
        assert sess["event_count"] == 1
        assert sess["decision_distribution"]["block"] == 1
        assert "defer" not in sess["decision_distribution"]

    @pytest.mark.asyncio
    async def test_defer_bridge_queue_full_persists_final_block(self):
        """Queue-full fallback block should also persist as a final resolution record."""
        config = DetectionConfig(
            defer_bridge_enabled=True,
            defer_timeout_s=10.0,
            defer_max_pending=1,
        )
        gw = SupervisionGateway(detection_config=config)
        _force_defer(gw, RiskLevel.HIGH)
        assert gw.defer_manager.register_defer("existing-pending") is True

        body = _jsonrpc_request(session_id="sess-defer-queue-full", event_id="evt-defer-queue-full")
        resp = await gw.handle_jsonrpc(body)

        assert resp["result"]["decision"]["decision"] == "block"

        rows = gw.trajectory_store.replay_session("sess-defer-queue-full")
        resolution_rows = [
            row for row in rows
            if row["meta"].get("record_type") == "decision_resolution"
        ]
        assert resolution_rows, rows
        resolution = resolution_rows[-1]
        assert resolution["decision"]["decision"] == "block"
        assert resolution["decision"]["decision_source"] == "policy"
        assert resolution["decision"]["failure_class"] == "approval_queue_full"

    @pytest.mark.asyncio
    async def test_confirmation_fast_lane_reuses_approval_id_and_emits_telemetry(self):
        """Confirmation compat events should enter approval bridge and emit approval telemetry."""
        config = DetectionConfig(
            defer_bridge_enabled=True,
            defer_timeout_s=10.0,
        )
        gw = SupervisionGateway(detection_config=config)
        _force_allow(gw, RiskLevel.HIGH)

        sub_id, queue = gw.event_bus.subscribe(
            event_types={"defer_pending", "defer_resolved"}
        )
        approval_id = "approval-confirm-telemetry-001"
        body = _confirmation_jsonrpc_request(
            approval_id=approval_id,
            session_id="sess-confirm-telemetry",
            event_id="evt-confirm-telemetry",
        )

        async def resolve_soon():
            await asyncio.sleep(0.1)
            gw.defer_manager.resolve_approval(
                approval_id,
                "allow-once",
                "operator approved confirmation",
            )

        asyncio.create_task(resolve_soon())
        resp = await gw.handle_jsonrpc(body)

        assert resp["result"]["decision"]["decision"] == "allow"
        assert resp["result"]["decision"]["decision_source"] == "operator"

        events = []
        while not queue.empty():
            events.append(queue.get_nowait())
        gw.event_bus.unsubscribe(sub_id)

        pending = next(evt for evt in events if evt["type"] == "defer_pending")
        assert pending["approval_id"] == approval_id
        assert pending["approval_kind"] == "confirmation"
        assert pending["approval_state"] == "pending"
        assert pending["approval_reason"] == "confirmation observed"
        assert pending["approval_reason_code"] == "approval_pending"
        assert pending["approval_timeout_s"] == 10.0

        resolved = next(evt for evt in events if evt["type"] == "defer_resolved")
        assert resolved["approval_id"] == approval_id
        assert resolved["approval_kind"] == "confirmation"
        assert resolved["approval_state"] == "resolved"
        assert resolved["approval_reason"] == "operator approved confirmation"
        assert resolved["approval_reason_code"] == "approval_allowed"
        assert resolved["approval_timeout_s"] == 10.0
        assert resolved["resolved_decision"] == "allow"

        rows = gw.trajectory_store.replay_session("sess-confirm-telemetry")
        resolution_rows = [
            row for row in rows
            if row["meta"].get("record_type") == "decision_resolution"
        ]
        assert resolution_rows
        resolution = resolution_rows[-1]
        assert resolution["meta"]["approval_id"] == approval_id
        assert resolution["meta"]["approval_kind"] == "confirmation"
        assert resolution["meta"]["approval_state"] == "resolved"
        assert resolution["meta"]["approval_reason"] == "operator approved confirmation"
        assert resolution["meta"]["approval_reason_code"] == "approval_allowed"
        assert resolution["meta"]["approval_timeout_s"] == 10.0

        session_risk = gw.report_session_risk("sess-confirm-telemetry")
        assert session_risk["approval_id"] == approval_id
        assert session_risk["approval_kind"] == "confirmation"
        assert session_risk["approval_state"] == "resolved"
        assert session_risk["approval_reason"] == "operator approved confirmation"
        assert session_risk["approval_reason_code"] == "approval_allowed"
        assert session_risk["approval_timeout_s"] == 10.0
        assert session_risk["risk_timeline"][-1]["approval_state"] == "resolved"
        assert session_risk["risk_timeline"][-1]["approval_reason_code"] == "approval_allowed"

    @pytest.mark.asyncio
    async def test_confirmation_fast_lane_timeout_has_explicit_terminal_reason_code(self):
        config = DetectionConfig(
            defer_bridge_enabled=True,
            defer_timeout_s=0.05,
            defer_timeout_action="block",
        )
        gw = SupervisionGateway(detection_config=config)
        _force_allow(gw, RiskLevel.MEDIUM)

        body = _confirmation_jsonrpc_request(
            approval_id="approval-confirm-timeout-001",
            session_id="sess-confirm-timeout",
            event_id="evt-confirm-timeout",
        )
        resp = await gw.handle_jsonrpc(body)

        assert resp["result"]["decision"]["decision"] == "block"

        rows = gw.trajectory_store.replay_session("sess-confirm-timeout")
        resolution = [
            row for row in rows
            if row["meta"].get("record_type") == "decision_resolution"
        ][-1]
        assert resolution["meta"]["approval_kind"] == "confirmation"
        assert resolution["meta"]["approval_state"] == "timeout"
        assert resolution["meta"]["approval_reason_code"] == "approval_timeout"
        assert resolution["meta"]["approval_timeout_s"] == 0.05
        assert "timeout" in resolution["meta"]["approval_reason"].lower()

    @pytest.mark.asyncio
    async def test_confirmation_fast_lane_queue_full_is_explicit_terminal_state(self):
        config = DetectionConfig(
            defer_bridge_enabled=True,
            defer_timeout_s=10.0,
            defer_max_pending=1,
        )
        gw = SupervisionGateway(detection_config=config)
        _force_allow(gw, RiskLevel.HIGH)
        assert gw.defer_manager.register_defer("existing-pending") is True

        body = _confirmation_jsonrpc_request(
            approval_id="approval-confirm-queue-full-001",
            session_id="sess-confirm-queue-full",
            event_id="evt-confirm-queue-full",
        )
        resp = await gw.handle_jsonrpc(body)

        assert resp["result"]["decision"]["decision"] == "block"
        assert resp["result"]["decision"]["failure_class"] == "approval_queue_full"

        rows = gw.trajectory_store.replay_session("sess-confirm-queue-full")
        resolution = [
            row for row in rows
            if row["meta"].get("record_type") == "decision_resolution"
        ][-1]
        assert resolution["meta"]["approval_kind"] == "confirmation"
        assert resolution["meta"]["approval_state"] == "queue_full"
        assert resolution["meta"]["approval_reason_code"] == "approval_queue_full"
        assert "queue full" in resolution["meta"]["approval_reason"].lower()

    @pytest.mark.asyncio
    async def test_confirmation_queue_full_promotes_pending_effect_hold(self):
        config = DetectionConfig(
            defer_bridge_enabled=True,
            defer_timeout_s=10.0,
            defer_max_pending=1,
            anti_bypass_guard_enabled=True,
        )
        gw = SupervisionGateway(detection_config=config)
        _force_allow(gw, RiskLevel.HIGH)
        assert gw.defer_manager.register_defer("existing-pending") is True
        event_id = "evt-confirm-effect-queue-full"
        session_id = "sess-confirm-effect-queue-full"
        payload = {"command": "printf '%s' payload > build/loader.sh"}
        gw.anti_bypass_guard.record_final_decision(
            CanonicalEvent(
                event_id=event_id,
                trace_id="trace-confirm-effect-queue-full",
                event_type=EventType.PRE_ACTION,
                session_id=session_id,
                agent_id="test-agent",
                source_framework="test",
                occurred_at=utc_now_iso(),
                tool_name="Bash",
                payload=payload,
            ),
            CanonicalDecision(
                decision=DecisionVerdict.DEFER,
                reason="pending review",
                policy_id="test",
                risk_level=RiskLevel.HIGH,
                decision_source=DecisionSource.POLICY,
                final=False,
            ),
            None,
            {},
            1,
            config,
        )

        body = _confirmation_jsonrpc_request(
            approval_id="approval-confirm-effect-queue-full",
            session_id=session_id,
            event_id=event_id,
            payload=payload,
        )
        resp = await gw.handle_jsonrpc(body)

        assert resp["result"]["decision"]["decision"] == "block"
        assert gw.anti_bypass_guard.pending_effect_holds_for_session(session_id) == []
        assert gw.anti_bypass_guard.denied_effect_records_for_session(session_id)

    @pytest.mark.asyncio
    async def test_confirmation_resolution_deny_promotes_pending_effect_hold(self):
        config = DetectionConfig(
            defer_bridge_enabled=True,
            defer_timeout_s=10.0,
            anti_bypass_guard_enabled=True,
        )
        gw = SupervisionGateway(detection_config=config)
        _force_allow(gw, RiskLevel.HIGH)
        event_id = "evt-confirm-effect-deny"
        session_id = "sess-confirm-effect-deny"
        payload = {"command": "printf '%s' payload > build/loader.sh"}
        gw.anti_bypass_guard.record_final_decision(
            CanonicalEvent(
                event_id=event_id,
                trace_id="trace-confirm-effect-deny",
                event_type=EventType.PRE_ACTION,
                session_id=session_id,
                agent_id="test-agent",
                source_framework="test",
                occurred_at=utc_now_iso(),
                tool_name="Bash",
                payload=payload,
            ),
            CanonicalDecision(
                decision=DecisionVerdict.DEFER,
                reason="pending review",
                policy_id="test",
                risk_level=RiskLevel.HIGH,
                decision_source=DecisionSource.POLICY,
                final=False,
            ),
            None,
            {},
            1,
            config,
        )

        async def resolve_soon():
            await asyncio.sleep(0.1)
            gw.defer_manager.resolve_approval(
                "approval-confirm-effect-deny",
                "deny",
                "operator denied confirmation",
            )

        asyncio.create_task(resolve_soon())
        body = _confirmation_jsonrpc_request(
            approval_id="approval-confirm-effect-deny",
            session_id=session_id,
            event_id=event_id,
            payload=payload,
        )
        resp = await gw.handle_jsonrpc(body)

        assert resp["result"]["decision"]["decision"] == "block"
        assert gw.anti_bypass_guard.pending_effect_holds_for_session(session_id) == []
        assert gw.anti_bypass_guard.denied_effect_records_for_session(session_id)

    @pytest.mark.asyncio
    async def test_confirmation_resolution_allow_clears_pending_effect_hold(self):
        config = DetectionConfig(
            defer_bridge_enabled=True,
            defer_timeout_s=10.0,
            anti_bypass_guard_enabled=True,
        )
        gw = SupervisionGateway(detection_config=config)
        _force_allow(gw, RiskLevel.HIGH)
        event_id = "evt-confirm-effect-allow"
        session_id = "sess-confirm-effect-allow"
        payload = {"command": "printf '%s' payload > build/loader.sh"}
        gw.anti_bypass_guard.record_final_decision(
            CanonicalEvent(
                event_id=event_id,
                trace_id="trace-confirm-effect-allow",
                event_type=EventType.PRE_ACTION,
                session_id=session_id,
                agent_id="test-agent",
                source_framework="test",
                occurred_at=utc_now_iso(),
                tool_name="Bash",
                payload=payload,
            ),
            CanonicalDecision(
                decision=DecisionVerdict.DEFER,
                reason="pending review",
                policy_id="test",
                risk_level=RiskLevel.HIGH,
                decision_source=DecisionSource.POLICY,
                final=False,
            ),
            None,
            {},
            1,
            config,
        )

        async def resolve_soon():
            await asyncio.sleep(0.1)
            gw.defer_manager.resolve_approval(
                "approval-confirm-effect-allow",
                "allow-once",
                "operator approved confirmation",
            )

        asyncio.create_task(resolve_soon())
        body = _confirmation_jsonrpc_request(
            approval_id="approval-confirm-effect-allow",
            session_id=session_id,
            event_id=event_id,
            payload=payload,
        )
        resp = await gw.handle_jsonrpc(body)

        assert resp["result"]["decision"]["decision"] == "allow"
        assert gw.anti_bypass_guard.pending_effect_holds_for_session(session_id) == []
        assert gw.anti_bypass_guard.denied_effect_records_for_session(session_id) == []

    @pytest.mark.asyncio
    async def test_confirmation_fast_lane_no_route_is_explicit_terminal_state(self):
        config = DetectionConfig(
            defer_bridge_enabled=False,
            defer_timeout_s=10.0,
        )
        gw = SupervisionGateway(detection_config=config)
        _force_allow(gw, RiskLevel.MEDIUM)

        body = _confirmation_jsonrpc_request(
            approval_id="approval-confirm-no-route-001",
            session_id="sess-confirm-no-route",
            event_id="evt-confirm-no-route",
        )
        resp = await gw.handle_jsonrpc(body)

        assert resp["result"]["decision"]["decision"] == "block"
        assert resp["result"]["decision"]["failure_class"] == "approval_no_route"

        rows = gw.trajectory_store.replay_session("sess-confirm-no-route")
        resolution = [
            row for row in rows
            if row["meta"].get("record_type") == "decision_resolution"
        ][-1]
        assert resolution["meta"]["approval_kind"] == "confirmation"
        assert resolution["meta"]["approval_state"] == "no_route"
        assert resolution["meta"]["approval_reason_code"] == "approval_no_route"
        assert "no route" in resolution["meta"]["approval_reason"].lower()
