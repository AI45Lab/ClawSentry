"""Tests for OpenClawApprovalClient WebSocket client."""
from __future__ import annotations

import asyncio
import json
from typing import Any

import pytest

from clawsentry.adapters.openclaw_ws_client import (
    OpenClawApprovalClient,
    OpenClawApprovalClientConfig,
    map_verdict_to_openclaw,
)
from clawsentry.gateway.models import DecisionVerdict


class TestOpenClawApprovalClientConfig:
    def test_defaults(self):
        cfg = OpenClawApprovalClientConfig()
        assert cfg.ws_url == "ws://127.0.0.1:18789"
        assert cfg.operator_token == ""
        assert cfg.enabled is False
        assert cfg.connect_timeout_s == 10.0
        assert cfg.resolve_timeout_s == 5.0
        assert cfg.max_reconnect_attempts == 5
        assert cfg.reconnect_base_delay_s == 0.1

    def test_from_env(self, monkeypatch):
        monkeypatch.setenv("OPENCLAW_WS_URL", "ws://10.0.0.1:9999")
        monkeypatch.setenv("OPENCLAW_OPERATOR_TOKEN", "secret-token")
        monkeypatch.setenv("OPENCLAW_ENFORCEMENT_ENABLED", "true")
        cfg = OpenClawApprovalClientConfig.from_env()
        assert cfg.ws_url == "ws://10.0.0.1:9999"
        assert cfg.operator_token == "secret-token"
        assert cfg.enabled is True

    def test_from_env_disabled_by_default(self):
        cfg = OpenClawApprovalClientConfig.from_env()
        assert cfg.enabled is False

    def test_from_env_with_overrides(self, monkeypatch):
        monkeypatch.setenv("OPENCLAW_ENFORCEMENT_ENABLED", "true")
        cfg = OpenClawApprovalClientConfig.from_env(ws_url="ws://custom:1234")
        assert cfg.ws_url == "ws://custom:1234"
        assert cfg.enabled is True

    def test_from_env_unknown_field_raises(self):
        with pytest.raises(TypeError, match="Unknown config field"):
            OpenClawApprovalClientConfig.from_env(nonexistent="value")


class TestDecisionMapping:
    def test_allow_maps_to_allow_once(self):
        assert map_verdict_to_openclaw(DecisionVerdict.ALLOW) == "allow-once"

    def test_block_maps_to_deny(self):
        assert map_verdict_to_openclaw(DecisionVerdict.BLOCK) == "deny"

    def test_defer_maps_to_none(self):
        assert map_verdict_to_openclaw(DecisionVerdict.DEFER) is None

    def test_modify_maps_to_none(self):
        assert map_verdict_to_openclaw(DecisionVerdict.MODIFY) is None


class TestResolveApproval:
    @pytest.fixture
    def client(self):
        cfg = OpenClawApprovalClientConfig(
            ws_url="ws://127.0.0.1:19999",
            operator_token="test-token",
            enabled=True,
        )
        return OpenClawApprovalClient(cfg)

    async def test_resolve_success(self, client):
        async def mock_send(method, params):
            assert method == "exec.approval.resolve"
            assert params == {"id": "ap-123", "decision": "deny"}
            return True

        client._send_request = mock_send
        result = await client.resolve("ap-123", "deny")
        assert result is True

    async def test_resolve_error_returns_false(self, client):
        async def mock_send(method, params):
            raise RuntimeError("unknown or expired approval id")

        client._send_request = mock_send
        result = await client.resolve("ap-expired", "allow-once")
        assert result is False

    async def test_resolve_disabled_is_noop(self):
        cfg = OpenClawApprovalClientConfig(enabled=False)
        client = OpenClawApprovalClient(cfg)
        result = await client.resolve("ap-123", "deny")
        assert result is False

    async def test_resolve_invalid_decision_raises(self, client):
        with pytest.raises(ValueError, match="Invalid decision"):
            await client.resolve("ap-123", "invalid-decision")

    async def test_resolve_all_valid_decisions(self, client):
        for decision in ("allow-once", "allow-always", "deny"):
            async def mock_send(method, params):
                return True
            client._send_request = mock_send
            result = await client.resolve("ap-x", decision)
            assert result is True


class TestConnectionLifecycle:
    async def test_close_when_not_connected(self):
        cfg = OpenClawApprovalClientConfig(enabled=True)
        client = OpenClawApprovalClient(cfg)
        await client.close()
        assert client.connected is False

    async def test_connected_property_default_false(self):
        cfg = OpenClawApprovalClientConfig(enabled=True)
        client = OpenClawApprovalClient(cfg)
        assert client.connected is False

    async def test_connect_when_disabled_is_noop(self):
        cfg = OpenClawApprovalClientConfig(enabled=False)
        client = OpenClawApprovalClient(cfg)
        await client.connect()
        assert client.connected is False

    async def test_send_request_when_not_connected(self):
        cfg = OpenClawApprovalClientConfig(enabled=True)
        client = OpenClawApprovalClient(cfg)
        result = await client._send_request("test", {})
        assert result is False


# ===========================================================================
# Integration tests with MockOpenClawGateway
# ===========================================================================

class TestWithMockGateway:
    """Integration tests using a real WebSocket server."""

    @pytest.fixture
    async def mock_gateway(self):
        from clawsentry.tests.helpers.mock_openclaw_gateway import (
            MockOpenClawGateway,
        )

        gw = MockOpenClawGateway(require_token="integration-token")
        await gw.start()
        yield gw
        await gw.stop()

    async def test_full_connect_and_resolve(self, mock_gateway):
        cfg = OpenClawApprovalClientConfig(
            ws_url=mock_gateway.ws_url,
            operator_token="integration-token",
            enabled=True,
        )
        client = OpenClawApprovalClient(cfg)
        await client.connect()
        assert client.connected is True

        result = await client.resolve("ap-test-1", "deny")
        assert result is True
        assert len(mock_gateway.resolved_approvals) == 1
        assert mock_gateway.resolved_approvals[0] == {
            "id": "ap-test-1",
            "decision": "deny",
        }

        await client.close()
        assert client.connected is False

    async def test_auth_failure(self, mock_gateway):
        cfg = OpenClawApprovalClientConfig(
            ws_url=mock_gateway.ws_url,
            operator_token="wrong-token",
            enabled=True,
        )
        client = OpenClawApprovalClient(cfg)
        await client.connect()
        assert client.connected is False
        await client.close()

    async def test_multiple_resolves(self, mock_gateway):
        cfg = OpenClawApprovalClientConfig(
            ws_url=mock_gateway.ws_url,
            operator_token="integration-token",
            enabled=True,
        )
        client = OpenClawApprovalClient(cfg)
        await client.connect()
        assert client.connected is True

        await client.resolve("ap-1", "allow-once")
        await client.resolve("ap-2", "deny")
        await client.resolve("ap-3", "allow-always")

        assert len(mock_gateway.resolved_approvals) == 3
        assert mock_gateway.resolved_approvals[0]["decision"] == "allow-once"
        assert mock_gateway.resolved_approvals[1]["decision"] == "deny"
        assert mock_gateway.resolved_approvals[2]["decision"] == "allow-always"

        await client.close()

    async def test_resolve_after_close_returns_false(self, mock_gateway):
        cfg = OpenClawApprovalClientConfig(
            ws_url=mock_gateway.ws_url,
            operator_token="integration-token",
            enabled=True,
        )
        client = OpenClawApprovalClient(cfg)
        await client.connect()
        await client.close()

        result = await client.resolve("ap-after-close", "deny")
        assert result is False


# ===========================================================================
# Event listener tests with MockOpenClawGateway
# ===========================================================================

class TestWSEventListener:
    """Tests for the WS event listening functionality."""

    @pytest.fixture
    async def mock_gateway(self):
        from clawsentry.tests.helpers.mock_openclaw_gateway import (
            MockOpenClawGateway,
        )

        gw = MockOpenClawGateway(require_token="listener-token")
        await gw.start()
        yield gw
        await gw.stop()

    async def test_listener_receives_approval_event(self, mock_gateway):
        """Mock gateway broadcasts an event, client listener receives it."""
        cfg = OpenClawApprovalClientConfig(
            ws_url=mock_gateway.ws_url,
            operator_token="listener-token",
            enabled=True,
        )
        client = OpenClawApprovalClient(cfg)
        await client.connect()
        assert client.connected is True

        received_events: list[dict] = []

        async def on_event(payload):
            received_events.append(payload)

        await client.start_listening(on_event)
        assert client.listening is True

        # Give listener a moment to start reading
        await asyncio.sleep(0.05)

        # Broadcast approval event from mock gateway
        await mock_gateway.broadcast_approval_request(
            approval_id="ap-ws-001",
            tool="bash",
            command="rm -rf /important",
        )

        # Wait for event to be received
        for _ in range(20):
            if received_events:
                break
            await asyncio.sleep(0.05)

        assert len(received_events) == 1
        assert received_events[0]["id"] == "ap-ws-001"
        assert received_events[0]["tool"] == "bash"
        assert received_events[0]["command"] == "rm -rf /important"

        await client.close()
        assert client.listening is False

    async def test_listener_concurrent_resolve_and_listen(self, mock_gateway):
        """Resolve RPC and event listening work concurrently without conflicts."""
        cfg = OpenClawApprovalClientConfig(
            ws_url=mock_gateway.ws_url,
            operator_token="listener-token",
            enabled=True,
        )
        client = OpenClawApprovalClient(cfg)
        await client.connect()

        received_events: list[dict] = []

        async def on_event(payload):
            received_events.append(payload)

        await client.start_listening(on_event)
        await asyncio.sleep(0.05)

        # Resolve an approval while listener is active
        result = await client.resolve("ap-rpc-001", "deny")
        assert result is True
        assert len(mock_gateway.resolved_approvals) == 1
        assert mock_gateway.resolved_approvals[0]["decision"] == "deny"

        # Also receive an event
        await mock_gateway.broadcast_approval_request(
            approval_id="ap-ws-002",
            tool="read",
            command="cat /etc/passwd",
        )

        for _ in range(20):
            if received_events:
                break
            await asyncio.sleep(0.05)

        assert len(received_events) == 1
        assert received_events[0]["id"] == "ap-ws-002"

        # Another resolve
        result = await client.resolve("ap-rpc-002", "allow-once")
        assert result is True
        assert len(mock_gateway.resolved_approvals) == 2

        await client.close()

    async def test_listener_multiple_events(self, mock_gateway):
        """Listener receives multiple events in sequence."""
        cfg = OpenClawApprovalClientConfig(
            ws_url=mock_gateway.ws_url,
            operator_token="listener-token",
            enabled=True,
        )
        client = OpenClawApprovalClient(cfg)
        await client.connect()

        received_events: list[dict] = []

        async def on_event(payload):
            received_events.append(payload)

        await client.start_listening(on_event)
        await asyncio.sleep(0.05)

        # Broadcast 3 events
        for i in range(3):
            await mock_gateway.broadcast_approval_request(
                approval_id=f"ap-multi-{i}",
                tool="bash",
                command=f"cmd-{i}",
            )

        for _ in range(40):
            if len(received_events) >= 3:
                break
            await asyncio.sleep(0.05)

        assert len(received_events) == 3
        for i in range(3):
            assert received_events[i]["id"] == f"ap-multi-{i}"

        await client.close()

    async def test_start_listening_when_not_connected(self):
        """start_listening when not connected is a no-op."""
        cfg = OpenClawApprovalClientConfig(enabled=True)
        client = OpenClawApprovalClient(cfg)

        async def on_event(payload):
            pass

        await client.start_listening(on_event)
        assert client.listening is False

    async def test_stop_listening(self, mock_gateway):
        """stop_listening cancels the listener task."""
        cfg = OpenClawApprovalClientConfig(
            ws_url=mock_gateway.ws_url,
            operator_token="listener-token",
            enabled=True,
        )
        client = OpenClawApprovalClient(cfg)
        await client.connect()

        async def on_event(payload):
            pass

        await client.start_listening(on_event)
        assert client.listening is True

        await client.stop_listening()
        assert client.listening is False

        await client.close()

    async def test_listening_property_default_false(self):
        """listening property defaults to False."""
        cfg = OpenClawApprovalClientConfig(enabled=True)
        client = OpenClawApprovalClient(cfg)
        assert client.listening is False


class TestFutureRegistrationOrder:
    """H-5: Future must be registered before WS frame is sent."""

    async def test_pending_request_exists_when_send_called(self):
        """_pending_requests should have the future before ws.send() executes."""
        config = OpenClawApprovalClientConfig(enabled=True, ws_url="ws://localhost:0")
        client = OpenClawApprovalClient(config)
        send_time_pending_count: list[int] = []

        class FakeWS:
            async def send(self, data: str) -> None:
                send_time_pending_count.append(len(client._pending_requests))

        client._ws = FakeWS()
        client._connected = True
        client._listening = True

        # Create a non-done task to satisfy the listener check
        client._listener_task = asyncio.ensure_future(asyncio.sleep(999))

        # Set up auto-resolution so _send_request can complete
        async def resolve_soon() -> None:
            await asyncio.sleep(0.01)
            for rid, fut in list(client._pending_requests.items()):
                if not fut.done():
                    fut.set_result({"type": "res", "id": rid, "ok": True, "result": {}})

        asyncio.create_task(resolve_soon())
        await client._send_request("test.method", {})

        assert send_time_pending_count == [1], (
            f"Expected 1 pending request at send time, got {send_time_pending_count}"
        )
        client._listener_task.cancel()


class TestResolveWithReason:
    """Tests for the optional reason parameter on resolve()."""

    @pytest.fixture
    def client(self):
        cfg = OpenClawApprovalClientConfig(
            ws_url="ws://127.0.0.1:19999",
            operator_token="test-token",
            enabled=True,
        )
        return OpenClawApprovalClient(cfg)

    async def test_resolve_with_reason_includes_in_params(self, client):
        """reason kwarg is included in RPC params."""
        captured_params = {}

        async def mock_send(method, params):
            captured_params.update(params)
            return True

        client._send_request = mock_send
        await client.resolve("ap-r1", "deny", reason="blocked: destructive pattern")
        assert captured_params["reason"] == "blocked: destructive pattern"

    async def test_resolve_without_reason_omits_field(self, client):
        """When reason is None, 'reason' key is absent from params."""
        captured_params = {}

        async def mock_send(method, params):
            captured_params.update(params)
            return True

        client._send_request = mock_send
        await client.resolve("ap-r2", "deny")
        assert "reason" not in captured_params

    async def test_resolve_with_empty_reason_includes_field(self, client):
        """Even empty string reason is included (explicit empty is different from None)."""
        captured_params = {}

        async def mock_send(method, params):
            captured_params.update(params)
            return True

        client._send_request = mock_send
        await client.resolve("ap-r3", "allow-once", reason="")
        assert "reason" in captured_params
        assert captured_params["reason"] == ""

    async def test_resolve_retries_without_reason_on_additional_properties_error(
        self, client
    ):
        """When OpenClaw rejects the reason field (additionalProperties), retry without it."""
        call_log: list[dict] = []

        async def mock_send(method, params):
            call_log.append(dict(params))
            if "reason" in params:
                raise RuntimeError(
                    "data must NOT have additional properties: reason"
                )
            return True

        client._send_request = mock_send
        result = await client.resolve(
            "ap-degrade", "deny", reason="blocked: destructive"
        )
        assert result is True
        # First call includes reason, second retries without it
        assert len(call_log) == 2
        assert "reason" in call_log[0]
        assert "reason" not in call_log[1]
        assert call_log[1] == {"id": "ap-degrade", "decision": "deny"}

    async def test_resolve_retries_on_unexpected_property_error(self, client):
        """Real OpenClaw uses 'unexpected property' wording — retry must also match."""
        call_log: list[dict] = []

        async def mock_send(method, params):
            call_log.append(dict(params))
            if "reason" in params:
                raise RuntimeError(
                    "invalid exec.approval.resolve params: at root: unexpected property 'reason'"
                )
            return True

        client._send_request = mock_send
        result = await client.resolve(
            "ap-real-oc", "deny", reason="blocked: policy"
        )
        assert result is True
        assert len(call_log) == 2
        assert "reason" in call_log[0]
        assert "reason" not in call_log[1]

    async def test_resolve_does_not_retry_on_unrelated_error(self, client):
        """Non-additional-properties errors do NOT trigger a retry."""
        call_count = 0

        async def mock_send(method, params):
            nonlocal call_count
            call_count += 1
            raise RuntimeError("connection timeout")

        client._send_request = mock_send
        result = await client.resolve(
            "ap-fail", "deny", reason="blocked: something"
        )
        assert result is False
        assert call_count == 1  # no retry


class TestResolveReasonFallbackE2E:
    """CS-011: End-to-end test that resolve() retries without reason when
    OpenClaw responds with an error about additional properties.

    This exercises the REAL _send_request code path (no mock of _send_request).
    """

    @pytest.fixture
    async def reason_rejecting_gateway(self):
        """MockOpenClawGateway that rejects the 'reason' field on first call."""
        from clawsentry.tests.helpers.mock_openclaw_gateway import (
            MockOpenClawGateway,
        )

        gw = _ReasonRejectingGateway(require_token="cs011-token")
        await gw.start()
        yield gw
        await gw.stop()

    async def test_resolve_retries_via_real_send_request(
        self, reason_rejecting_gateway
    ):
        """When real _send_request receives {"ok": false, "error": ...additional properties...},
        resolve() should catch the error and retry without the reason field."""
        gw = reason_rejecting_gateway
        cfg = OpenClawApprovalClientConfig(
            ws_url=gw.ws_url,
            operator_token="cs011-token",
            enabled=True,
        )
        client = OpenClawApprovalClient(cfg)
        await client.connect()
        assert client.connected is True

        result = await client.resolve(
            "ap-cs011", "deny", reason="blocked: destructive pattern"
        )
        # The retry should succeed
        assert result is True

        # Gateway should have received 2 calls: first rejected, second accepted
        assert len(gw.resolved_approvals) == 1
        assert gw.resolved_approvals[0] == {"id": "ap-cs011", "decision": "deny"}
        assert "reason" not in gw.resolved_approvals[0]

        # The rejected call count should be 1
        assert gw.rejected_count == 1

        await client.close()

    async def test_resolve_without_reason_no_retry_needed(
        self, reason_rejecting_gateway
    ):
        """When reason is None, no retry is needed — first call succeeds."""
        gw = reason_rejecting_gateway
        cfg = OpenClawApprovalClientConfig(
            ws_url=gw.ws_url,
            operator_token="cs011-token",
            enabled=True,
        )
        client = OpenClawApprovalClient(cfg)
        await client.connect()
        assert client.connected is True

        result = await client.resolve("ap-ok", "allow-once")
        assert result is True
        assert len(gw.resolved_approvals) == 1
        assert gw.rejected_count == 0

        await client.close()

    async def test_resolve_retry_also_fails_returns_false(
        self, reason_rejecting_gateway
    ):
        """When the retry itself fails, resolve() should return False."""
        gw = reason_rejecting_gateway
        gw.reject_all = True  # Make ALL calls fail
        cfg = OpenClawApprovalClientConfig(
            ws_url=gw.ws_url,
            operator_token="cs011-token",
            enabled=True,
        )
        client = OpenClawApprovalClient(cfg)
        await client.connect()
        assert client.connected is True

        result = await client.resolve(
            "ap-fail-both", "deny", reason="will fail"
        )
        assert result is False

        await client.close()


class _ReasonRejectingGateway:
    """Mock gateway that rejects resolve calls with a 'reason' field,
    simulating real OpenClaw behavior for CS-011."""

    def __init__(self, *, require_token: str = "test-token") -> None:
        self.require_token = require_token
        self.resolved_approvals: list[dict[str, Any]] = []
        self.rejected_count = 0
        self.reject_all = False
        self._server: Any = None
        self._port: int = 0

    @property
    def ws_url(self) -> str:
        return f"ws://127.0.0.1:{self._port}"

    async def start(self) -> None:
        import websockets as ws_lib

        self._server = await ws_lib.serve(self._handler, "127.0.0.1", 0)
        for sock in self._server.sockets:
            self._port = sock.getsockname()[1]
            break

    async def stop(self) -> None:
        if self._server:
            self._server.close()
            await self._server.wait_closed()

    async def _handler(self, websocket: Any) -> None:
        import websockets as ws_lib

        # Handshake: challenge → connect → hello-ok
        challenge = {
            "type": "event",
            "event": "connect.challenge",
            "payload": {"nonce": "abc123", "ts": 1234567890000},
        }
        await websocket.send(json.dumps(challenge))

        connect_raw = await websocket.recv()
        connect_msg = json.loads(connect_raw)
        token = connect_msg.get("params", {}).get("auth", {}).get("token", "")
        if token != self.require_token:
            await websocket.send(json.dumps({
                "type": "res", "id": connect_msg.get("id"),
                "ok": False, "error": {"message": "invalid token"},
            }))
            await websocket.close()
            return

        await websocket.send(json.dumps({
            "type": "res", "id": connect_msg.get("id"),
            "ok": True, "payload": {"type": "hello-ok", "protocol": 3},
        }))

        # Handle requests
        try:
            async for message in websocket:
                msg = json.loads(message)
                if msg.get("method") == "exec.approval.resolve":
                    params = msg.get("params", {})
                    if self.reject_all or "reason" in params:
                        # Reject with "additional properties" error
                        self.rejected_count += 1
                        resp = {
                            "type": "res",
                            "id": msg.get("id"),
                            "ok": False,
                            "error": {
                                "message": (
                                    "invalid exec.approval.resolve params: "
                                    "unexpected property 'reason' — "
                                    "data must NOT have additional properties"
                                ),
                            },
                        }
                    else:
                        # Accept
                        self.resolved_approvals.append(params)
                        resp = {
                            "type": "res",
                            "id": msg.get("id"),
                            "ok": True,
                            "payload": {"ok": True},
                        }
                    await websocket.send(json.dumps(resp))
        except ws_lib.exceptions.ConnectionClosed:
            pass
