"""Tests for POST /ahp/resolve endpoint."""
from __future__ import annotations

import asyncio
import os
from unittest.mock import AsyncMock

import pytest
from httpx import ASGITransport, AsyncClient

from clawsentry.gateway.defer_manager import DeferManager
from clawsentry.gateway.server import SupervisionGateway, create_http_app
from clawsentry.gateway.stack import add_resolve_endpoint, _build_openclaw_runtime


class TestResolveEndpoint:
    """POST /ahp/resolve proxies to OpenClaw approval client."""

    @pytest.fixture
    def gateway(self, tmp_path):
        return SupervisionGateway(trajectory_db_path=str(tmp_path / "traj.db"))

    @pytest.fixture
    def mock_approval_client(self):
        client = AsyncMock()
        client.resolve = AsyncMock(return_value=True)
        return client

    @pytest.fixture
    def app_with_resolve(self, gateway, mock_approval_client):
        app = create_http_app(gateway)
        add_resolve_endpoint(app, mock_approval_client)
        return app

    @pytest.fixture
    def app_without_resolve(self, gateway):
        app = create_http_app(gateway)
        add_resolve_endpoint(app, None)
        return app

    @pytest.mark.asyncio
    async def test_resolve_allow(self, app_with_resolve, mock_approval_client):
        async with AsyncClient(
            transport=ASGITransport(app=app_with_resolve),
            base_url="http://test",
        ) as client:
            resp = await client.post("/ahp/resolve", json={
                "approval_id": "ap-123",
                "decision": "allow-once",
            })
        assert resp.status_code == 200
        body = resp.json()
        assert body["status"] == "ok"
        mock_approval_client.resolve.assert_awaited_once_with(
            "ap-123", "allow-once", reason="",
        )

    @pytest.mark.asyncio
    async def test_resolve_deny_with_reason(self, app_with_resolve, mock_approval_client):
        async with AsyncClient(
            transport=ASGITransport(app=app_with_resolve),
            base_url="http://test",
        ) as client:
            resp = await client.post("/ahp/resolve", json={
                "approval_id": "ap-456",
                "decision": "deny",
                "reason": "operator denied via dashboard",
            })
        assert resp.status_code == 200
        mock_approval_client.resolve.assert_awaited_once_with(
            "ap-456", "deny", reason="operator denied via dashboard",
        )

    @pytest.mark.asyncio
    async def test_resolve_unavailable_without_client(self, app_without_resolve):
        async with AsyncClient(
            transport=ASGITransport(app=app_without_resolve),
            base_url="http://test",
        ) as client:
            resp = await client.post("/ahp/resolve", json={
                "approval_id": "ap-789",
                "decision": "deny",
            })
        assert resp.status_code == 503
        assert "not available" in resp.json()["error"]

    @pytest.mark.asyncio
    async def test_resolve_missing_fields(self, app_with_resolve):
        async with AsyncClient(
            transport=ASGITransport(app=app_with_resolve),
            base_url="http://test",
        ) as client:
            resp = await client.post("/ahp/resolve", json={"approval_id": "ap-1"})
        assert resp.status_code == 400

    @pytest.mark.asyncio
    async def test_resolve_invalid_decision(self, app_with_resolve):
        async with AsyncClient(
            transport=ASGITransport(app=app_with_resolve),
            base_url="http://test",
        ) as client:
            resp = await client.post("/ahp/resolve", json={
                "approval_id": "ap-1",
                "decision": "invalid-value",
            })
        assert resp.status_code == 400

    @pytest.mark.asyncio
    async def test_resolve_returns_503_when_ws_unavailable(self, gateway):
        """When resolve() returns False (WS down), endpoint should return 503."""
        client = AsyncMock()
        client.resolve = AsyncMock(return_value=False)
        app = create_http_app(gateway)
        add_resolve_endpoint(app, client)
        async with AsyncClient(
            transport=ASGITransport(app=app),
            base_url="http://test",
        ) as ac:
            resp = await ac.post("/ahp/resolve", json={
                "approval_id": "ap-ws-down",
                "decision": "allow-once",
            })
        assert resp.status_code == 503
        assert "not delivered" in resp.json()["error"]

    @pytest.mark.asyncio
    async def test_resolve_requires_auth(self, gateway, mock_approval_client):
        """When auth is enabled, resolve requires a token."""
        original = os.environ.get("CS_AUTH_TOKEN")
        os.environ["CS_AUTH_TOKEN"] = "secret-token-for-resolve-test-1234"
        try:
            app = create_http_app(gateway)
            add_resolve_endpoint(app, mock_approval_client)
            async with AsyncClient(
                transport=ASGITransport(app=app),
                base_url="http://test",
            ) as client:
                resp = await client.post("/ahp/resolve", json={
                    "approval_id": "ap-1", "decision": "deny",
                })
            assert resp.status_code == 401
        finally:
            if original is None:
                os.environ.pop("CS_AUTH_TOKEN", None)
            else:
                os.environ["CS_AUTH_TOKEN"] = original


class TestResolveDeferManager:
    """POST /ahp/resolve with DeferManager integration."""

    @pytest.fixture
    def gateway(self, tmp_path):
        return SupervisionGateway(trajectory_db_path=str(tmp_path / "traj.db"))

    @pytest.fixture
    def defer_manager(self):
        return DeferManager(timeout_action="block", timeout_s=5.0)

    @pytest.fixture
    def mock_approval_client(self):
        client = AsyncMock()
        client.resolve = AsyncMock(return_value=True)
        return client

    @pytest.mark.asyncio
    async def test_resolve_defer_manager_pending(
        self, gateway, defer_manager, mock_approval_client,
    ):
        """When DeferManager has a pending request, resolving it returns ok."""
        defer_manager.register_defer("cs-defer-001")
        app = create_http_app(gateway)
        add_resolve_endpoint(app, mock_approval_client, defer_manager=defer_manager)

        async with AsyncClient(
            transport=ASGITransport(app=app),
            base_url="http://test",
        ) as client:
            resp = await client.post("/ahp/resolve", json={
                "approval_id": "cs-defer-001",
                "decision": "allow-once",
                "reason": "operator approved",
            })
        assert resp.status_code == 200
        body = resp.json()
        assert body["status"] == "ok"
        assert body["approval_id"] == "cs-defer-001"
        # Should no longer be pending
        assert not defer_manager.is_pending("cs-defer-001")
        mock_approval_client.resolve.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_resolve_confirmation_pending_prefers_local_bridge(
        self, gateway, defer_manager, mock_approval_client,
    ):
        """Confirmation-kind pending approvals should resolve locally before fallback."""
        assert defer_manager.register_approval(
            "approval-confirm-001",
            approval_kind="confirmation",
            session_id="sess-1",
            tool_name="delete_file",
            summary="Delete a sensitive file",
        ) is True
        app = create_http_app(gateway)
        add_resolve_endpoint(app, mock_approval_client, defer_manager=defer_manager)

        async with AsyncClient(
            transport=ASGITransport(app=app),
            base_url="http://test",
        ) as client:
            resp = await client.post("/ahp/resolve", json={
                "approval_id": "approval-confirm-001",
                "decision": "allow-once",
                "reason": "operator approved confirmation",
            })
        assert resp.status_code == 200
        assert resp.json() == {"status": "ok", "approval_id": "approval-confirm-001"}
        assert defer_manager.get_approval("approval-confirm-001").approval_state == "resolved"
        mock_approval_client.resolve.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_resolve_local_bridge_passes_resolution_binding(
        self, gateway, defer_manager, mock_approval_client,
    ):
        binding = {
            "effect_hash": "sha256:effect",
            "canonical_argv_hash": "sha256:argv",
            "profile_fingerprint": "sha256:profile",
        }
        assert defer_manager.register_approval(
            "approval-bound-001",
            approval_kind="defer",
            approval_binding=binding,
        ) is True
        app = create_http_app(gateway)
        add_resolve_endpoint(app, mock_approval_client, defer_manager=defer_manager)

        async with AsyncClient(
            transport=ASGITransport(app=app),
            base_url="http://test",
        ) as client:
            resp = await client.post("/ahp/resolve", json={
                "approval_id": "approval-bound-001",
                "decision": "allow-once",
                "reason": "operator approved",
                "resolution_binding": {
                    **binding,
                    "effect_hash": "sha256:mutated",
                },
            })

        assert resp.status_code == 200
        approval = defer_manager.get_approval("approval-bound-001")
        assert approval.decision == "block"
        assert approval.reason_code == "approval_binding_drift"
        mock_approval_client.resolve.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_resolve_local_bridge_rejects_missing_resolution_binding_for_bound_approval(
        self, gateway, defer_manager, mock_approval_client,
    ):
        assert defer_manager.register_approval(
            "approval-bound-missing-001",
            approval_kind="defer",
            approval_binding={"effect_hash": "sha256:effect"},
        ) is True
        app = create_http_app(gateway)
        add_resolve_endpoint(app, mock_approval_client, defer_manager=defer_manager)

        async with AsyncClient(
            transport=ASGITransport(app=app),
            base_url="http://test",
        ) as client:
            resp = await client.post("/ahp/resolve", json={
                "approval_id": "approval-bound-missing-001",
                "decision": "allow-once",
                "reason": "operator approved",
            })

        assert resp.status_code == 200
        approval = defer_manager.get_approval("approval-bound-missing-001")
        assert approval.decision == "block"
        assert approval.reason_code == "approval_binding_drift"
        mock_approval_client.resolve.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_resolve_defer_manager_not_pending_fallback(
        self, gateway, defer_manager, mock_approval_client,
    ):
        """When DeferManager has no pending request, falls back to approval_client."""
        app = create_http_app(gateway)
        add_resolve_endpoint(app, mock_approval_client, defer_manager=defer_manager)

        async with AsyncClient(
            transport=ASGITransport(app=app),
            base_url="http://test",
        ) as client:
            resp = await client.post("/ahp/resolve", json={
                "approval_id": "ap-openclaw-123",
                "decision": "deny",
                "reason": "not in defer manager",
            })
        assert resp.status_code == 200
        mock_approval_client.resolve.assert_awaited_once_with(
            "ap-openclaw-123", "deny", reason="not in defer manager",
        )

    @pytest.mark.asyncio
    async def test_resolve_defer_manager_no_approval_client(self, gateway, defer_manager):
        """When approval_client is None but DeferManager resolves, returns ok."""
        defer_manager.register_defer("cs-defer-002")
        app = create_http_app(gateway)
        add_resolve_endpoint(app, None, defer_manager=defer_manager)

        async with AsyncClient(
            transport=ASGITransport(app=app),
            base_url="http://test",
        ) as client:
            resp = await client.post("/ahp/resolve", json={
                "approval_id": "cs-defer-002",
                "decision": "deny",
            })
        assert resp.status_code == 200
        assert resp.json()["status"] == "ok"

    @pytest.mark.asyncio
    async def test_resolve_defer_manager_none(self, gateway, mock_approval_client):
        """When defer_manager is None, behaves like before (fallback to approval_client)."""
        app = create_http_app(gateway)
        add_resolve_endpoint(app, mock_approval_client, defer_manager=None)

        async with AsyncClient(
            transport=ASGITransport(app=app),
            base_url="http://test",
        ) as client:
            resp = await client.post("/ahp/resolve", json={
                "approval_id": "ap-legacy-1",
                "decision": "allow-once",
            })
        assert resp.status_code == 200
        mock_approval_client.resolve.assert_awaited_once_with(
            "ap-legacy-1", "allow-once", reason="",
        )

    @pytest.mark.asyncio
    async def test_resolve_defer_manager_resolves_correctly(self, gateway, defer_manager):
        """The resolution actually unblocks the waiting coroutine with correct decision/reason."""
        defer_manager.register_defer("cs-defer-003")
        app = create_http_app(gateway)
        add_resolve_endpoint(app, None, defer_manager=defer_manager)

        # Start waiting for resolution in background
        wait_task = asyncio.create_task(
            defer_manager.wait_for_resolution("cs-defer-003"),
        )
        # Yield control so wait_for_resolution grabs its _pending reference
        await asyncio.sleep(0)

        # Resolve via HTTP endpoint
        async with AsyncClient(
            transport=ASGITransport(app=app),
            base_url="http://test",
        ) as client:
            resp = await client.post("/ahp/resolve", json={
                "approval_id": "cs-defer-003",
                "decision": "deny",
                "reason": "unsafe operation",
            })
        assert resp.status_code == 200

        # The waiting coroutine should now be resolved
        decision, reason = await asyncio.wait_for(wait_task, timeout=2.0)
        assert decision == "deny"
        assert reason == "unsafe operation"


class TestBuildOpenclawRuntimeEnforcement:
    """CS-010: _build_openclaw_runtime must forward enforcement fields."""

    def test_enforcement_fields_passed_to_config(self):
        runtime = _build_openclaw_runtime(
            webhook_token="tok",
            webhook_secret=None,
            webhook_require_https=False,
            webhook_max_body_bytes=1_000_000,
            source_protocol_version="1.0",
            git_short_sha="abc1234",
            profile_version=1,
            uds_path="/tmp/test.sock",
            gateway_host="127.0.0.1",
            gateway_port=8080,
            gateway_transport_preference="uds_first",
            enforcement_enabled=True,
            openclaw_ws_url="ws://127.0.0.1:19999",
            openclaw_operator_token="test-op-token",
        )
        assert runtime.config.enforcement_enabled is True
        assert runtime.config.openclaw_ws_url == "ws://127.0.0.1:19999"
        assert runtime.config.openclaw_operator_token == "test-op-token"
        assert runtime.approval_client._config.enabled is True
        assert runtime.approval_client._config.ws_url == "ws://127.0.0.1:19999"
        assert runtime.approval_client._config.operator_token == "test-op-token"

    def test_enforcement_defaults_when_omitted(self):
        runtime = _build_openclaw_runtime(
            webhook_token="tok",
            webhook_secret=None,
            webhook_require_https=False,
            webhook_max_body_bytes=1_000_000,
            source_protocol_version="1.0",
            git_short_sha="abc1234",
            profile_version=1,
            uds_path="/tmp/test.sock",
            gateway_host="127.0.0.1",
            gateway_port=8080,
            gateway_transport_preference="uds_first",
        )
        assert runtime.config.enforcement_enabled is False
        assert runtime.approval_client._config.enabled is False
