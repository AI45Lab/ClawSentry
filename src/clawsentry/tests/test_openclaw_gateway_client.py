"""
Tests for OpenClaw Gateway Client — Gate 5 verification.

Covers: HTTP + UDS client, retry/fallback logic, fallback decision matrix.
"""

import asyncio
import json
import os
import struct
import pytest
import pytest_asyncio
from clawsentry.adapters.openclaw_gateway_client import OpenClawGatewayClient
from clawsentry.gateway.models import (
    CanonicalEvent,
    DecisionContext,
    DecisionVerdict,
    DecisionSource,
    DecisionTier,
    EventType,
    AgentTrustLevel,
)
from clawsentry.gateway.server import SupervisionGateway, start_uds_server


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

TEST_UDS_PATH = "/tmp/ahp-oc-client-test.sock"


def _make_event(**overrides) -> CanonicalEvent:
    defaults = dict(
        event_id="evt-001",
        trace_id="trace-001",
        event_type=EventType.PRE_ACTION,
        session_id="s1",
        agent_id="a1",
        source_framework="openclaw",
        occurred_at="2026-03-19T12:00:00+00:00",
        payload={"tool": "bash", "command": "ls"},
        event_subtype="exec.approval.requested",
        source_protocol_version="1.0",
        mapping_profile="openclaw@abc1234/protocol.v1.0/profile.v1",
        tool_name="bash",
    )
    defaults.update(overrides)
    return CanonicalEvent(**defaults)


@pytest.fixture
def client():
    return OpenClawGatewayClient(
        http_url="http://127.0.0.1:8080/ahp",
        uds_path=TEST_UDS_PATH,
        default_deadline_ms=500,
    )


@pytest_asyncio.fixture
async def gateway_and_client():
    gw = SupervisionGateway()
    server = await start_uds_server(gw, TEST_UDS_PATH)
    client = OpenClawGatewayClient(
        http_url="http://127.0.0.1:8080/ahp",
        uds_path=TEST_UDS_PATH,
        default_deadline_ms=500,
    )
    yield gw, client
    server.close()
    await server.wait_closed()
    if os.path.exists(TEST_UDS_PATH):
        os.unlink(TEST_UDS_PATH)


# ===========================================================================
# UDS Communication
# ===========================================================================

class TestUDSCommunication:
    @pytest.mark.asyncio
    async def test_safe_command_via_uds(self, gateway_and_client):
        gw, client = gateway_and_client
        evt = _make_event(
            tool_name="read_file",
            payload={"tool": "read_file", "path": "/tmp/x"},
        )
        decision = await client.request_decision(evt)
        assert decision.decision == DecisionVerdict.ALLOW

    @pytest.mark.asyncio
    async def test_dangerous_command_via_uds(self, gateway_and_client):
        gw, client = gateway_and_client
        evt = _make_event(
            tool_name="bash",
            payload={"tool": "bash", "command": "rm -rf /"},
        )
        decision = await client.request_decision(evt)
        assert decision.decision == DecisionVerdict.BLOCK


# ===========================================================================
# Fallback
# ===========================================================================

class TestFallback:
    @pytest.mark.asyncio
    async def test_fallback_dangerous_tool_blocks(self):
        client = OpenClawGatewayClient(
            http_url="http://127.0.0.1:19999/ahp",
            uds_path="/tmp/nonexistent-oc.sock",
        )
        evt = _make_event(
            tool_name="bash",
            payload={"tool": "bash", "command": "rm -rf /"},
            risk_hints=["destructive_pattern", "shell_execution"],
        )
        decision = await client.request_decision(evt)
        assert decision.decision == DecisionVerdict.BLOCK
        assert decision.decision_source == DecisionSource.SYSTEM

    @pytest.mark.asyncio
    async def test_fallback_safe_tool_defers(self):
        client = OpenClawGatewayClient(
            http_url="http://127.0.0.1:19999/ahp",
            uds_path="/tmp/nonexistent-oc.sock",
        )
        evt = _make_event(
            tool_name="read_file",
            event_type=EventType.PRE_ACTION,
            payload={"tool": "read_file", "path": "/tmp/x"},
            risk_hints=[],
        )
        decision = await client.request_decision(evt)
        assert decision.decision == DecisionVerdict.DEFER

    @pytest.mark.asyncio
    async def test_fallback_post_action_allows(self):
        client = OpenClawGatewayClient(
            http_url="http://127.0.0.1:19999/ahp",
            uds_path="/tmp/nonexistent-oc.sock",
        )
        evt = _make_event(event_type=EventType.POST_ACTION, event_subtype="exec.approval.resolved")
        decision = await client.request_decision(evt)
        assert decision.decision == DecisionVerdict.ALLOW


class TestRetryBehavior:
    @pytest.mark.asyncio
    async def test_retry_eligible_error_triggers_next_attempt(self):
        client = OpenClawGatewayClient(
            http_url="http://127.0.0.1:19999/ahp",
            uds_path="/tmp/nonexistent-oc.sock",
            default_deadline_ms=500,
            max_rpc_retries=1,
            retry_backoff_ms=0,
        )
        evt = _make_event(
            tool_name="read_file",
            payload={"tool": "read_file", "path": "/tmp/retry"},
            risk_hints=[],
        )
        calls = {"uds": 0}

        async def fake_uds(_req):
            calls["uds"] += 1
            if calls["uds"] == 1:
                return {
                    "error": {
                        "code": -32603,
                        "message": "temporary error",
                        "data": {"retry_eligible": True},
                    }
                }
            return {
                "result": {
                    "rpc_status": "ok",
                    "decision": {
                        "decision": "allow",
                        "reason": "retry success",
                        "policy_id": "retry-test",
                        "risk_level": "low",
                        "decision_source": "policy",
                        "policy_version": "1.0",
                        "failure_class": "none",
                        "final": True,
                    },
                }
            }

        async def fake_http(_req):
            raise AssertionError("HTTP transport should not be used in this retry path")

        client._send_uds_request = fake_uds
        client._send_http_request = fake_http

        decision = await client.request_decision(evt)
        assert calls["uds"] == 2
        assert decision.decision == DecisionVerdict.ALLOW


class TestDecisionTier:
    @pytest.mark.asyncio
    async def test_agent_safety_feedback_openclaw_response_metadata(self, client):
        async def fake_send_uds(_req):
            return {
                "result": {
                    "rpc_status": "ok",
                    "decision": {
                        "decision": "block",
                        "reason": "critical block",
                        "policy_id": "test-policy",
                        "risk_level": "critical",
                        "decision_source": "policy",
                        "policy_version": "1.0",
                        "failure_class": "none",
                        "final": True,
                    },
                    "agent_safety_feedback": {
                        "schema": "clawsentry.agent_safety_feedback.v1",
                        "delivery": "response",
                        "risk_level": "critical",
                        "decision_id": "evt-001",
                        "blocked_surface": "command",
                        "reason_summary": "redacted",
                        "safe_next_step": "Ask the operator to review.",
                        "redaction_policy_version": "cs.agent_safety_feedback.v1",
                        "evidence_refs": ["policy:test-policy"],
                    },
                }
            }

        client._send_uds_request = fake_send_uds
        evt = _make_event(
            tool_name="bash",
            payload={"tool": "bash", "command": "rm -rf /tmp/openclaw-feedback"},
        )

        decision = await client.request_decision(evt)

        assert decision.decision == DecisionVerdict.BLOCK
        assert client.last_decision_response_metadata["agent_safety_feedback"]["delivery"] == "response"
        assert client.last_decision_response_metadata["agent_safety_feedback"]["blocked_surface"] == "command"

    @pytest.mark.asyncio
    async def test_request_decision_defaults_to_l1_tier(self, client):
        captured = {}

        async def fake_send_uds(req):
            captured["tier"] = req.decision_tier.value
            return {
                "result": {
                    "rpc_status": "ok",
                    "decision": {
                        "decision": "allow",
                        "reason": "ok",
                        "policy_id": "test-policy",
                        "risk_level": "low",
                        "decision_source": "policy",
                        "policy_version": "1.0",
                        "failure_class": "none",
                        "final": True,
                    },
                }
            }

        client._send_uds_request = fake_send_uds
        evt = _make_event(
            tool_name="read_file",
            payload={"tool": "read_file", "path": "/tmp/default-tier"},
        )
        decision = await client.request_decision(evt)
        assert captured["tier"] == "L1"
        assert decision.decision == DecisionVerdict.ALLOW

    @pytest.mark.asyncio
    async def test_request_decision_supports_explicit_l2_tier(self, client):
        captured = {}

        async def fake_send_uds(req):
            captured["tier"] = req.decision_tier.value
            return {
                "result": {
                    "rpc_status": "ok",
                    "decision": {
                        "decision": "allow",
                        "reason": "ok",
                        "policy_id": "test-policy",
                        "risk_level": "low",
                        "decision_source": "policy",
                        "policy_version": "1.0",
                        "failure_class": "none",
                        "final": True,
                    },
                }
            }

        client._send_uds_request = fake_send_uds
        evt = _make_event(
            tool_name="read_file",
            payload={"tool": "read_file", "path": "/tmp/l2-tier"},
        )
        decision = await client.request_decision(evt, decision_tier=DecisionTier.L2)
        assert captured["tier"] == "L2"
        assert decision.decision == DecisionVerdict.ALLOW

    @pytest.mark.asyncio
    async def test_request_decision_sets_default_caller_adapter(self, client):
        captured = {}

        async def fake_send_uds(req):
            captured["caller_adapter"] = (
                req.context.caller_adapter if req.context else None
            )
            return {
                "result": {
                    "rpc_status": "ok",
                    "decision": {
                        "decision": "allow",
                        "reason": "ok",
                        "policy_id": "test-policy",
                        "risk_level": "low",
                        "decision_source": "policy",
                        "policy_version": "1.0",
                        "failure_class": "none",
                        "final": True,
                    },
                }
            }

        client._send_uds_request = fake_send_uds
        evt = _make_event(
            tool_name="read_file",
            payload={"tool": "read_file", "path": "/tmp/default-caller"},
        )
        decision = await client.request_decision(evt)
        assert captured["caller_adapter"] == "openclaw-adapter.v1"
        assert decision.decision == DecisionVerdict.ALLOW

    @pytest.mark.asyncio
    async def test_request_decision_keeps_explicit_caller_adapter(self, client):
        captured = {}

        async def fake_send_uds(req):
            captured["caller_adapter"] = (
                req.context.caller_adapter if req.context else None
            )
            return {
                "result": {
                    "rpc_status": "ok",
                    "decision": {
                        "decision": "allow",
                        "reason": "ok",
                        "policy_id": "test-policy",
                        "risk_level": "low",
                        "decision_source": "policy",
                        "policy_version": "1.0",
                        "failure_class": "none",
                        "final": True,
                    },
                }
            }

        client._send_uds_request = fake_send_uds
        evt = _make_event(
            tool_name="read_file",
            payload={"tool": "read_file", "path": "/tmp/explicit-caller"},
        )
        context = DecisionContext(
            caller_adapter="custom-openclaw-adapter.v9",
            agent_trust_level=AgentTrustLevel.STANDARD,
        )
        decision = await client.request_decision(evt, context=context)
        assert captured["caller_adapter"] == "custom-openclaw-adapter.v9"
        assert decision.decision == DecisionVerdict.ALLOW


# ===========================================================================
# Transport Preference
# ===========================================================================

class TestTransportPreference:
    @pytest.mark.asyncio
    async def test_default_prefers_uds(self):
        client = OpenClawGatewayClient()
        evt = _make_event(
            tool_name="read_file",
            payload={"tool": "read_file", "path": "/tmp/default-pref"},
        )
        order = []

        async def fake_uds(_req):
            order.append("uds")
            return {
                "result": {
                    "rpc_status": "ok",
                    "decision": {
                        "decision": "allow",
                        "reason": "uds-first",
                        "policy_id": "test-policy",
                        "risk_level": "low",
                        "decision_source": "policy",
                        "policy_version": "1.0",
                        "failure_class": "none",
                        "final": True,
                    },
                }
            }

        async def fake_http(_req):
            order.append("http")
            raise AssertionError("HTTP should not be called when UDS already succeeded")

        client._send_uds_request = fake_uds
        client._send_http_request = fake_http
        decision = await client.request_decision(evt)
        assert decision.decision == DecisionVerdict.ALLOW
        assert order == ["uds"]

    @pytest.mark.asyncio
    async def test_http_first_uses_http_before_uds(self):
        client = OpenClawGatewayClient(transport_preference="http_first")
        evt = _make_event(
            tool_name="read_file",
            payload={"tool": "read_file", "path": "/tmp/http-first"},
        )
        order = []

        async def fake_http(_req):
            order.append("http")
            return {
                "result": {
                    "rpc_status": "ok",
                    "decision": {
                        "decision": "allow",
                        "reason": "http-first",
                        "policy_id": "test-policy",
                        "risk_level": "low",
                        "decision_source": "policy",
                        "policy_version": "1.0",
                        "failure_class": "none",
                        "final": True,
                    },
                }
            }

        async def fake_uds(_req):
            order.append("uds")
            raise AssertionError("UDS should not be called when HTTP already succeeded")

        client._send_http_request = fake_http
        client._send_uds_request = fake_uds
        decision = await client.request_decision(evt)
        assert decision.decision == DecisionVerdict.ALLOW
        assert order == ["http"]

    @pytest.mark.asyncio
    async def test_http_first_falls_back_to_uds_when_http_fails(self):
        client = OpenClawGatewayClient(transport_preference="http_first")
        evt = _make_event(
            tool_name="read_file",
            payload={"tool": "read_file", "path": "/tmp/http-first-fallback"},
        )
        order = []

        async def fake_http(_req):
            order.append("http")
            raise RuntimeError("http down")

        async def fake_uds(_req):
            order.append("uds")
            return {
                "result": {
                    "rpc_status": "ok",
                    "decision": {
                        "decision": "allow",
                        "reason": "uds-fallback",
                        "policy_id": "test-policy",
                        "risk_level": "low",
                        "decision_source": "policy",
                        "policy_version": "1.0",
                        "failure_class": "none",
                        "final": True,
                    },
                }
            }

        client._send_http_request = fake_http
        client._send_uds_request = fake_uds
        decision = await client.request_decision(evt)
        assert decision.decision == DecisionVerdict.ALLOW
        assert order == ["http", "uds"]

    def test_invalid_transport_preference_raises(self):
        with pytest.raises(ValueError):
            OpenClawGatewayClient(transport_preference="invalid")


# ===========================================================================
# Auth Token in HTTP Requests
# ===========================================================================

class _FakeWriter:
    """Capture written data for request inspection."""
    def __init__(self, capture: dict):
        self._capture = capture
        self._buffer = b""

    def write(self, data: bytes):
        self._buffer += data
        self._capture["data"] = self._buffer.decode("utf-8", errors="replace")

    async def drain(self):
        pass

    def close(self):
        pass

    async def wait_closed(self):
        pass


class TestAuthTokenInHttpRequests:
    """Gateway client should include Bearer token in HTTP requests when configured."""

    @pytest.mark.asyncio
    async def test_http_request_includes_auth_header(self, monkeypatch):
        """When auth_token is set, HTTP requests include Authorization header."""
        client = OpenClawGatewayClient(
            uds_path="/nonexistent.sock",
            auth_token="test-token-32chars-padding-xxxxx",
        )
        event = _make_event()

        captured_headers = {}

        async def fake_open_connection(host, port):
            reader = asyncio.StreamReader()
            reader.feed_data(
                b"HTTP/1.1 200 OK\r\n"
                b"Content-Length: 2\r\n"
                b"\r\n"
                b"{}"
            )
            reader.feed_eof()
            writer = _FakeWriter(captured_headers)
            return reader, writer

        monkeypatch.setattr(asyncio, "open_connection", fake_open_connection)
        # Will fall through to fallback since response is not valid JSON-RPC
        await client.request_decision(event)
        # Verify the Authorization header was sent
        assert "Authorization: Bearer test-token-32chars-padding-xxxxx" in captured_headers.get("data", "")

    @pytest.mark.asyncio
    async def test_http_request_no_auth_header_when_no_token(self, monkeypatch):
        """When no auth_token, HTTP requests do not include Authorization header."""
        monkeypatch.delenv("CS_AUTH_TOKEN", raising=False)
        client = OpenClawGatewayClient(uds_path="/nonexistent.sock")
        event = _make_event()

        captured_headers = {}

        async def fake_open_connection(host, port):
            reader = asyncio.StreamReader()
            reader.feed_data(
                b"HTTP/1.1 200 OK\r\n"
                b"Content-Length: 2\r\n"
                b"\r\n"
                b"{}"
            )
            reader.feed_eof()
            writer = _FakeWriter(captured_headers)
            return reader, writer

        monkeypatch.setattr(asyncio, "open_connection", fake_open_connection)
        await client.request_decision(event)
        assert "Authorization:" not in captured_headers.get("data", "")
