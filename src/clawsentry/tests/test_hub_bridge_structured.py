"""Tests for LatchHubBridge structured messages and gateway registration."""
from __future__ import annotations

import os
from unittest.mock import AsyncMock, patch

import pytest

from clawsentry.latch.hub_bridge import LatchHubBridge


@pytest.fixture
def bridge():
    return LatchHubBridge(
        hub_url="http://localhost:3006",
        token="test-token",
        gateway_url="http://localhost:8080",
        gateway_token="gw-token",
    )


class TestStructuredMessages:
    """LatchHubBridge should send structured JSON content alongside text."""

    def test_decision_event(self, bridge):
        event = {
            "type": "decision",
            "decision": "block",
            "tool_name": "write_file",
            "risk_level": "high",
            "reason": "dangerous operation",
            "session_id": "sess-1",
        }
        body = bridge._build_message_body(event)
        content = body["content"]
        assert content["type"] == "event"
        assert content["data"]["type"] == "decision"
        assert content["data"]["tool_name"] == "write_file"
        assert content["data"]["risk_level"] == "high"
        assert content["data"]["decision"] == "block"
        assert "text" in content
        assert "BLOCK" in content["text"]
        assert body["metadata"]["clawsentry"] is True
        assert body["metadata"]["event_type"] == "decision"

    def test_defer_pending_event(self, bridge):
        event = {
            "type": "defer_pending",
            "tool_name": "execute_bash",
            "approval_id": "cs-defer-abc123",
            "timeout_s": 300,
            "risk_level": "high",
            "session_id": "sess-1",
        }
        body = bridge._build_message_body(event)
        content = body["content"]
        assert content["data"]["type"] == "defer_pending"
        assert content["data"]["approval_id"] == "cs-defer-abc123"
        assert content["data"]["timeout_s"] == 300
        assert "DEFER PENDING" in content["text"]

    def test_defer_resolved_event(self, bridge):
        event = {
            "type": "defer_resolved",
            "resolved_decision": "allow",
            "approval_id": "cs-defer-abc123",
            "session_id": "sess-1",
        }
        body = bridge._build_message_body(event)
        content = body["content"]
        assert content["data"]["type"] == "defer_resolved"
        assert content["data"]["resolved_decision"] == "allow"
        assert "DEFER RESOLVED" in content["text"]

    def test_alert_event(self, bridge):
        event = {
            "type": "alert",
            "severity": "critical",
            "message": "Secret leak detected",
            "session_id": "sess-1",
        }
        body = bridge._build_message_body(event)
        content = body["content"]
        assert content["data"]["type"] == "alert"
        assert content["data"]["severity"] == "critical"
        assert "ALERT" in content["text"]

    def test_session_id_excluded_from_data(self, bridge):
        event = {"type": "decision", "decision": "allow", "session_id": "sess-1"}
        body = bridge._build_message_body(event)
        assert "session_id" not in body["content"]["data"]

    def test_all_web_fields_in_defer_pending(self, bridge):
        """Verify defer_pending has all fields Latch Web needs."""
        event = {
            "type": "defer_pending",
            "tool_name": "write_file",
            "approval_id": "cs-defer-xyz",
            "timeout_s": 300,
            "risk_level": "high",
            "reason": "writes to sensitive path",
            "session_id": "sess-abc",
            "expires_at": "2026-03-30T12:00:00Z",
            "approval_prompt": {
                "affected_target": "/workspace/payments",
                "operation": "write_file",
                "consequence": "Approving writes the file.",
                "dry_run_or_narrower_scope_suggestion": "Preview a diff first.",
                "rollback_hint": "Restore from VCS if needed.",
            },
        }
        body = bridge._build_message_body(event)
        data = body["content"]["data"]
        assert data["approval_id"] == "cs-defer-xyz"
        assert data["tool_name"] == "write_file"
        assert data["timeout_s"] == 300
        assert data["risk_level"] == "high"
        assert data["expires_at"] == "2026-03-30T12:00:00Z"
        assert data["approval_prompt"]["affected_target"] == "/workspace/payments"
        assert "Target: /workspace/<redacted>" in body["content"]["text"]


class TestGatewayRegistration:
    """LatchHubBridge should register Gateway URL with Hub at startup."""

    @pytest.mark.asyncio
    async def test_register_gateway_called(self, bridge):
        with patch.object(bridge, "_hub_request", new_callable=AsyncMock) as mock_req:
            mock_req.return_value = {"ok": True}
            await bridge._register_gateway()
            mock_req.assert_called_once_with(
                "POST",
                "/cli/clawsentry/config",
                {
                    "gateway_url": "http://localhost:8080",
                    "auth_token": "gw-token",
                },
            )

    @pytest.mark.asyncio
    async def test_register_gateway_failure_logged(self, bridge):
        with patch.object(bridge, "_hub_request", new_callable=AsyncMock) as mock_req:
            mock_req.return_value = None
            await bridge._register_gateway()  # should not raise

    def test_gateway_url_from_env(self):
        with patch.dict(os.environ, {"CS_GATEWAY_URL": "http://gw:9090"}):
            b = LatchHubBridge(hub_url="http://localhost:3006", token="t")
            assert b._gateway_url == "http://gw:9090"

    def test_gateway_url_default(self):
        env = {k: v for k, v in os.environ.items() if k != "CS_GATEWAY_URL"}
        with patch.dict(os.environ, env, clear=True):
            b = LatchHubBridge(hub_url="http://localhost:3006", token="t")
            assert b._gateway_url == "http://127.0.0.1:8080"

    def test_explicit_gateway_url_overrides_env(self):
        with patch.dict(os.environ, {"CS_GATEWAY_URL": "http://env:1111"}):
            b = LatchHubBridge(
                hub_url="http://localhost:3006",
                token="t",
                gateway_url="http://explicit:2222",
            )
            assert b._gateway_url == "http://explicit:2222"


class TestForwardEventStructured:
    """Forward loop should use structured messages."""

    @pytest.mark.asyncio
    async def test_forward_sends_structured_content(self, bridge):
        bridge._session_map["sess-1"] = "hub-session-id"
        sent_bodies: list = []

        async def mock_request(method, path, body):
            sent_bodies.append((method, path, body))
            return {}

        with patch.object(bridge, "_hub_request", side_effect=mock_request):
            await bridge._forward_event({
                "type": "decision",
                "decision": "allow",
                "tool_name": "read_file",
                "risk_level": "low",
                "session_id": "sess-1",
            })

        assert len(sent_bodies) == 1
        _, path, body = sent_bodies[0]
        assert path == "/cli/sessions/hub-session-id/messages"
        assert body["content"]["type"] == "event"
        assert body["content"]["data"]["type"] == "decision"
        assert body["metadata"]["clawsentry"] is True
