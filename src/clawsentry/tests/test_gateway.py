"""
Tests for Gateway server — Gate 4 verification.

Covers: JSON-RPC 2.0 dispatch, SyncDecision v1 protocol,
health endpoint, error codes, idempotency, HTTP transport,
UDS transport edge cases (#33).
"""

import asyncio
import json
import os
import struct
import time
import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport

from clawsentry.gateway.server import SupervisionGateway, create_http_app, start_uds_server
from clawsentry.gateway.models import RPC_VERSION


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _jsonrpc_request(method: str, params: dict, rpc_id: int = 1) -> bytes:
    return json.dumps({
        "jsonrpc": "2.0",
        "id": rpc_id,
        "method": method,
        "params": params,
    }).encode()


def _sync_decision_params(**overrides) -> dict:
    base = {
        "rpc_version": RPC_VERSION,
        "request_id": "req-test-001",
        "deadline_ms": 100,
        "decision_tier": "L1",
        "event": {
            "event_id": "evt-001",
            "trace_id": "trace-001",
            "event_type": "pre_action",
            "session_id": "sess-001",
            "agent_id": "agent-001",
            "source_framework": "test",
            "occurred_at": "2026-03-19T12:00:00+00:00",
            "payload": {"tool": "read_file", "path": "/tmp/readme.txt"},
            "tool_name": "read_file",
        },
    }
    base.update(overrides)
    return base


# ===========================================================================
# Gateway Core Tests
# ===========================================================================

class TestGatewayCore:
    @pytest.fixture
    def gw(self):
        return SupervisionGateway()

    @pytest.mark.asyncio
    async def test_valid_sync_decision(self, gw):
        body = _jsonrpc_request("ahp/sync_decision", _sync_decision_params())
        result = await gw.handle_jsonrpc(body)
        assert result["jsonrpc"] == "2.0"
        assert "result" in result
        assert result["result"]["rpc_status"] == "ok"
        assert result["result"]["request_id"] == "req-test-001"

    @pytest.mark.asyncio
    async def test_safe_read_returns_allow(self, gw):
        params = _sync_decision_params()
        body = _jsonrpc_request("ahp/sync_decision", params)
        result = await gw.handle_jsonrpc(body)
        decision = result["result"]["decision"]
        assert decision["decision"] == "allow"

    @pytest.mark.asyncio
    async def test_dangerous_command_returns_block(self, gw):
        params = _sync_decision_params(event={
            "event_id": "evt-002",
            "trace_id": "trace-002",
            "event_type": "pre_action",
            "session_id": "sess-001",
            "agent_id": "agent-001",
            "source_framework": "test",
            "occurred_at": "2026-03-19T12:00:00+00:00",
            "payload": {"command": "rm -rf /"},
            "tool_name": "bash",
        }, request_id="req-dangerous")
        body = _jsonrpc_request("ahp/sync_decision", params)
        result = await gw.handle_jsonrpc(body)
        decision = result["result"]["decision"]
        assert decision["decision"] == "block"

    @pytest.mark.asyncio
    async def test_idempotency_cache_hit(self, gw):
        params = _sync_decision_params(request_id="req-idem-001")
        body = _jsonrpc_request("ahp/sync_decision", params)
        r1 = await gw.handle_jsonrpc(body)
        r2 = await gw.handle_jsonrpc(body)
        assert r1["result"] == r2["result"]
        assert r1["result"]["request_id"] == "req-idem-001"

    @pytest.mark.asyncio
    async def test_trajectory_recorded(self, gw):
        assert gw.trajectory_store.count() == 0
        params = _sync_decision_params(request_id="req-traj-001")
        body = _jsonrpc_request("ahp/sync_decision", params)
        await gw.handle_jsonrpc(body)
        assert gw.trajectory_store.count() == 1
        rec = gw.trajectory_store.records[0]
        assert rec["meta"]["request_id"] == "req-traj-001"

    @pytest.mark.asyncio
    async def test_trajectory_records_caller_adapter_in_meta(self, gw):
        params = _sync_decision_params(
            request_id="req-traj-caller-001",
            context={"caller_adapter": "openclaw-adapter.v1"},
        )
        body = _jsonrpc_request("ahp/sync_decision", params)
        await gw.handle_jsonrpc(body)
        rec = gw.trajectory_store.records[-1]
        assert rec["meta"]["caller_adapter"] == "openclaw-adapter.v1"

    @pytest.mark.asyncio
    async def test_health(self, gw):
        h = gw.health()
        assert h["status"] == "healthy"
        assert h["policy_engine"] == "L1+L2"
        assert h["rpc_version"] == RPC_VERSION

    @pytest.mark.asyncio
    async def test_requested_l2_returns_actual_tier_l2(self, gw):
        params = _sync_decision_params(
            request_id="req-l2-explicit",
            decision_tier="L2",
            deadline_ms=1000,  # L2 needs budget > _L2_OVERHEAD_MARGIN_MS (200ms)
            event={
                "event_id": "evt-l2-explicit",
                "trace_id": "trace-l2-explicit",
                "event_type": "pre_action",
                "session_id": "sess-l2-explicit",
                "agent_id": "agent-001",
                "source_framework": "test",
                "occurred_at": "2026-03-19T12:00:00+00:00",
                "payload": {"tool": "read_file", "path": "/tmp/readme.txt"},
                "tool_name": "read_file",
            },
        )
        body = _jsonrpc_request("ahp/sync_decision", params)
        result = await gw.handle_jsonrpc(body)
        assert result["result"]["actual_tier"] == "L2"
        assert result["result"]["decision"]["decision"] == "allow"

    @pytest.mark.asyncio
    async def test_medium_pre_action_auto_escalates_to_l2(self, gw):
        params = _sync_decision_params(
            request_id="req-l2-auto",
            decision_tier="L1",
            deadline_ms=1000,  # L2 auto-escalation needs budget > _L2_OVERHEAD_MARGIN_MS
            event={
                "event_id": "evt-l2-auto",
                "trace_id": "trace-l2-auto",
                "event_type": "pre_action",
                "session_id": "sess-l2-auto",
                "agent_id": "agent-001",
                "source_framework": "test",
                "occurred_at": "2026-03-19T12:00:00+00:00",
                "payload": {"url": "https://example.com"},
                "tool_name": "http_request",
                "risk_hints": ["credential_exfiltration"],
            },
        )
        body = _jsonrpc_request("ahp/sync_decision", params)
        result = await gw.handle_jsonrpc(body)
        assert result["result"]["actual_tier"] == "L2"
        assert result["result"]["decision"]["decision"] == "block"
        record = gw.trajectory_store.records[-1]
        assert record["meta"]["actual_tier"] == "L2"
        assert record["risk_snapshot"]["classified_by"] == "L2"

    @pytest.mark.asyncio
    async def test_report_summary_counts(self, gw):
        body1 = _jsonrpc_request("ahp/sync_decision", _sync_decision_params(request_id="req-rpt-1"))
        body2 = _jsonrpc_request("ahp/sync_decision", _sync_decision_params(
            request_id="req-rpt-2",
            event={
                "event_id": "evt-rpt-2",
                "trace_id": "trace-rpt-2",
                "event_type": "pre_action",
                "session_id": "sess-report",
                "agent_id": "agent-001",
                "source_framework": "openclaw",
                "occurred_at": "2026-03-19T12:00:00+00:00",
                "payload": {"command": "rm -rf /"},
                "tool_name": "bash",
                "event_subtype": "exec.approval.requested",
                "source_protocol_version": "1.0",
                "mapping_profile": "openclaw@abc1234/protocol.v1.0/profile.v1",
            },
        ))
        await gw.handle_jsonrpc(body1)
        await gw.handle_jsonrpc(body2)

        summary = gw.report_summary()
        assert summary["total_records"] >= 2
        assert summary["by_source_framework"]["test"] >= 1
        assert summary["by_source_framework"]["openclaw"] >= 1

    @pytest.mark.asyncio
    async def test_replay_session_filters_records(self, gw):
        body1 = _jsonrpc_request("ahp/sync_decision", _sync_decision_params(
            request_id="req-sess-1",
            event={
                "event_id": "evt-sess-1",
                "trace_id": "trace-sess-1",
                "event_type": "pre_action",
                "session_id": "sess-target",
                "agent_id": "agent-001",
                "source_framework": "test",
                "occurred_at": "2026-03-19T12:00:00+00:00",
                "payload": {"tool": "read_file", "path": "/tmp/readme.txt"},
                "tool_name": "read_file",
            },
        ))
        body2 = _jsonrpc_request("ahp/sync_decision", _sync_decision_params(
            request_id="req-sess-2",
            event={
                "event_id": "evt-sess-2",
                "trace_id": "trace-sess-2",
                "event_type": "pre_action",
                "session_id": "sess-other",
                "agent_id": "agent-001",
                "source_framework": "test",
                "occurred_at": "2026-03-19T12:00:00+00:00",
                "payload": {"tool": "read_file", "path": "/tmp/readme.txt"},
                "tool_name": "read_file",
            },
        ))
        await gw.handle_jsonrpc(body1)
        await gw.handle_jsonrpc(body2)

        replay = gw.replay_session("sess-target")
        assert replay["session_id"] == "sess-target"
        assert replay["record_count"] == 1
        assert replay["records"][0]["event"]["session_id"] == "sess-target"

    @pytest.mark.asyncio
    async def test_trajectory_persists_across_gateway_instances(self, tmp_path):
        db_path = tmp_path / "trajectory.db"
        gw1 = SupervisionGateway(trajectory_db_path=str(db_path))
        body = _jsonrpc_request("ahp/sync_decision", _sync_decision_params(request_id="req-persist-1"))
        await gw1.handle_jsonrpc(body)
        assert gw1.trajectory_store.count() == 1

        gw2 = SupervisionGateway(trajectory_db_path=str(db_path))
        assert gw2.trajectory_store.count() == 1
        summary = gw2.report_summary()
        assert summary["total_records"] == 1

    def test_trajectory_retention_prunes_expired_records(self, tmp_path):
        db_path = tmp_path / "trajectory-retention.db"
        gw = SupervisionGateway(
            trajectory_db_path=str(db_path),
            trajectory_retention_seconds=1,
        )
        now = time.time()
        gw.trajectory_store.record(
            event={"event_id": "evt-old", "session_id": "s1", "source_framework": "test", "event_type": "pre_action"},
            decision={"decision": "allow", "risk_level": "low"},
            snapshot={},
            meta={},
            recorded_at_ts=now - 10,
        )
        gw.trajectory_store.record(
            event={"event_id": "evt-new", "session_id": "s1", "source_framework": "test", "event_type": "pre_action"},
            decision={"decision": "block", "risk_level": "high"},
            snapshot={},
            meta={},
            recorded_at_ts=now,
        )
        assert gw.trajectory_store.count() == 1
        assert gw.trajectory_store.records[0]["event"]["event_id"] == "evt-new"

    def test_report_summary_with_window_seconds(self, tmp_path):
        db_path = tmp_path / "trajectory-window.db"
        gw = SupervisionGateway(trajectory_db_path=str(db_path))
        now = time.time()
        gw.trajectory_store.record(
            event={"event_id": "evt-old", "session_id": "s1", "source_framework": "test", "event_type": "pre_action"},
            decision={"decision": "allow", "risk_level": "low"},
            snapshot={},
            meta={},
            recorded_at_ts=now - 120,
        )
        gw.trajectory_store.record(
            event={"event_id": "evt-new", "session_id": "s1", "source_framework": "test", "event_type": "pre_action"},
            decision={"decision": "block", "risk_level": "high"},
            snapshot={},
            meta={},
            recorded_at_ts=now,
        )
        summary = gw.report_summary(window_seconds=60)
        assert summary["total_records"] == 1
        assert summary["by_decision"]["block"] == 1

    @pytest.mark.asyncio
    async def test_report_summary_includes_actual_tier_distribution(self, gw):
        l1_body = _jsonrpc_request("ahp/sync_decision", _sync_decision_params(
            request_id="req-tier-l1",
            decision_tier="L1",
            event={
                "event_id": "evt-tier-l1",
                "trace_id": "trace-tier-l1",
                "event_type": "pre_action",
                "session_id": "sess-tier",
                "agent_id": "agent-001",
                "source_framework": "test",
                "occurred_at": "2026-03-19T12:00:00+00:00",
                "payload": {"tool": "read_file", "path": "/tmp/x"},
                "tool_name": "read_file",
            },
        ))
        l2_body = _jsonrpc_request("ahp/sync_decision", _sync_decision_params(
            request_id="req-tier-l2",
            decision_tier="L2",
            deadline_ms=1000,  # L2 needs budget > _L2_OVERHEAD_MARGIN_MS (200ms)
            event={
                "event_id": "evt-tier-l2",
                "trace_id": "trace-tier-l2",
                "event_type": "pre_action",
                "session_id": "sess-tier",
                "agent_id": "agent-001",
                "source_framework": "test",
                "occurred_at": "2026-03-19T12:00:00+00:00",
                "payload": {"tool": "read_file", "path": "/tmp/y"},
                "tool_name": "read_file",
            },
        ))
        await gw.handle_jsonrpc(l1_body)
        await gw.handle_jsonrpc(l2_body)

        summary = gw.report_summary()
        assert summary["by_actual_tier"]["L1"] >= 1
        assert summary["by_actual_tier"]["L2"] >= 1

    @pytest.mark.asyncio
    async def test_report_summary_includes_caller_adapter_distribution(self, gw):
        body1 = _jsonrpc_request(
            "ahp/sync_decision",
            _sync_decision_params(
                request_id="req-caller-dist-1",
                context={"caller_adapter": "a3s-adapter.v1"},
            ),
        )
        body2 = _jsonrpc_request(
            "ahp/sync_decision",
            _sync_decision_params(
                request_id="req-caller-dist-2",
                context={"caller_adapter": "openclaw-adapter.v1"},
                event={
                    "event_id": "evt-caller-dist-2",
                    "trace_id": "trace-caller-dist-2",
                    "event_type": "pre_action",
                    "session_id": "sess-caller-dist",
                    "agent_id": "agent-001",
                    "source_framework": "openclaw",
                    "occurred_at": "2026-03-19T12:00:00+00:00",
                    "payload": {"tool": "read_file", "path": "/tmp/x"},
                    "tool_name": "read_file",
                    "event_subtype": "exec.approval.requested",
                    "source_protocol_version": "1.0",
                    "mapping_profile": "openclaw@abc1234/protocol.v1.0/profile.v1",
                },
            ),
        )
        await gw.handle_jsonrpc(body1)
        await gw.handle_jsonrpc(body2)

        summary = gw.report_summary()
        assert summary["by_caller_adapter"]["a3s-adapter.v1"] >= 1
        assert summary["by_caller_adapter"]["openclaw-adapter.v1"] >= 1

    def test_replay_session_with_window_seconds(self, tmp_path):
        db_path = tmp_path / "trajectory-replay-window.db"
        gw = SupervisionGateway(trajectory_db_path=str(db_path))
        now = time.time()
        gw.trajectory_store.record(
            event={"event_id": "evt-old", "session_id": "sess-win", "source_framework": "test", "event_type": "pre_action"},
            decision={"decision": "allow", "risk_level": "low"},
            snapshot={},
            meta={},
            recorded_at_ts=now - 120,
        )
        gw.trajectory_store.record(
            event={"event_id": "evt-new", "session_id": "sess-win", "source_framework": "test", "event_type": "pre_action"},
            decision={"decision": "block", "risk_level": "high"},
            snapshot={},
            meta={},
            recorded_at_ts=now,
        )
        replay = gw.replay_session("sess-win", window_seconds=60)
        assert replay["record_count"] == 1
        assert replay["records"][0]["event"]["event_id"] == "evt-new"

    def test_report_summary_includes_invalid_event_threshold_alerts(self, tmp_path):
        db_path = tmp_path / "trajectory-invalid-alerts.db"
        gw = SupervisionGateway(trajectory_db_path=str(db_path))
        now = time.time()

        # 25 invalid events in last minute should trigger count and 5m rate alerts.
        for i in range(25):
            gw.trajectory_store.record(
                event={
                    "event_id": f"evt-invalid-{i}",
                    "session_id": "sess-invalid",
                    "source_framework": "openclaw",
                    "event_type": "error",
                    "event_subtype": "invalid_event",
                },
                decision={
                    "decision": "block",
                    "risk_level": "high",
                    "failure_class": "input_invalid",
                },
                snapshot={},
                meta={},
                recorded_at_ts=now - 5,
            )

        # Add normal traffic as denominator for rate checks.
        for i in range(200):
            gw.trajectory_store.record(
                event={
                    "event_id": f"evt-normal-{i}",
                    "session_id": "sess-normal",
                    "source_framework": "openclaw",
                    "event_type": "pre_action",
                    "event_subtype": "exec.approval.requested",
                },
                decision={"decision": "allow", "risk_level": "low"},
                snapshot={},
                meta={},
                recorded_at_ts=now - 10,
            )

        summary = gw.report_summary()
        invalid_metrics = summary["invalid_event"]
        assert invalid_metrics["count_1m"] == 25
        assert invalid_metrics["rate_5m"] > 0.01

        alert_metrics = {item["metric"] for item in invalid_metrics["alerts"]}
        assert "invalid_event_count_1m" in alert_metrics
        assert "invalid_event_rate_5m" in alert_metrics

    def test_report_summary_includes_high_risk_trend_aggregation(self, tmp_path):
        db_path = tmp_path / "trajectory-risk-trend.db"
        gw = SupervisionGateway(trajectory_db_path=str(db_path))
        now = time.time()

        # Previous 5m bucket: low high-risk pressure (1/10).
        for i in range(10):
            gw.trajectory_store.record(
                event={
                    "event_id": f"evt-prev-{i}",
                    "session_id": "sess-trend",
                    "source_framework": "test",
                    "event_type": "pre_action",
                },
                decision={
                    "decision": "allow",
                    "risk_level": "high" if i == 0 else "low",
                },
                snapshot={},
                meta={},
                recorded_at_ts=now - 450 + i,
            )

        # Recent 5m bucket: elevated high-risk pressure (6/10).
        for i in range(10):
            gw.trajectory_store.record(
                event={
                    "event_id": f"evt-recent-{i}",
                    "session_id": "sess-trend",
                    "source_framework": "test",
                    "event_type": "pre_action",
                },
                decision={
                    "decision": "block" if i < 6 else "allow",
                    "risk_level": "high" if i < 6 else "low",
                },
                snapshot={},
                meta={},
                recorded_at_ts=now - 120 + i,
            )

        summary = gw.report_summary()
        trend = summary["high_risk_trend"]
        assert trend["windows"]["5m"]["count"] == 6
        assert trend["windows"]["5m"]["ratio"] == pytest.approx(0.6)
        assert trend["direction_5m"] == "up"
        assert trend["series_5m"][-1]["high_or_critical_count"] == 6


# ===========================================================================
# JSON-RPC Error Tests
# ===========================================================================

class TestJsonRpcErrors:
    @pytest.fixture
    def gw(self):
        return SupervisionGateway()

    @pytest.mark.asyncio
    async def test_parse_error(self, gw):
        result = await gw.handle_jsonrpc(b"not json{{{")
        assert "error" in result
        assert result["error"]["code"] == -32700

    @pytest.mark.asyncio
    async def test_invalid_jsonrpc_version(self, gw):
        body = json.dumps({
            "jsonrpc": "1.0",
            "id": 1,
            "method": "ahp/sync_decision",
            "params": {},
        }).encode()
        result = await gw.handle_jsonrpc(body)
        assert "error" in result
        assert result["error"]["code"] == -32600

    @pytest.mark.asyncio
    async def test_method_not_found(self, gw):
        body = _jsonrpc_request("unknown/method", {})
        result = await gw.handle_jsonrpc(body)
        assert "error" in result
        assert result["error"]["code"] == -32601

    @pytest.mark.asyncio
    async def test_invalid_request_missing_fields(self, gw):
        body = _jsonrpc_request("ahp/sync_decision", {"request_id": "x"})
        result = await gw.handle_jsonrpc(body)
        assert "error" in result
        error_data = result["error"]["data"]
        assert error_data["rpc_error_code"] == "INVALID_REQUEST"
        assert error_data["retry_eligible"] is False

    @pytest.mark.asyncio
    async def test_schema_mismatch_invalid_event_type(self, gw):
        params = _sync_decision_params()
        params["event"]["event_type"] = "invalid_type"
        body = _jsonrpc_request("ahp/sync_decision", params)
        result = await gw.handle_jsonrpc(body)
        assert "error" in result
        assert result["error"]["data"]["rpc_error_code"] == "INVALID_REQUEST"


# ===========================================================================
# HTTP Transport Tests
# ===========================================================================

class TestHttpTransport:
    @pytest.fixture
    def gw(self):
        return SupervisionGateway()

    @pytest.fixture
    def app(self, gw):
        return create_http_app(gw)

    @pytest.mark.asyncio
    async def test_http_ahp_endpoint(self, app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            body = _jsonrpc_request("ahp/sync_decision", _sync_decision_params())
            resp = await client.post("/ahp", content=body)
            assert resp.status_code == 200
            data = resp.json()
            assert "result" in data
            assert data["result"]["rpc_status"] == "ok"

    @pytest.mark.asyncio
    async def test_http_health_endpoint(self, app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/health")
            assert resp.status_code == 200
            data = resp.json()
            assert data["status"] == "healthy"

    @pytest.mark.asyncio
    async def test_http_dangerous_block(self, app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            params = _sync_decision_params(
                request_id="req-http-block",
                event={
                    "event_id": "evt-http-block",
                    "trace_id": "trace-http",
                    "event_type": "pre_action",
                    "session_id": "sess-http",
                    "agent_id": "agent-http",
                    "source_framework": "test",
                    "occurred_at": "2026-03-19T12:00:00+00:00",
                    "payload": {"command": "sudo rm -rf /"},
                    "tool_name": "bash",
                },
            )
            body = _jsonrpc_request("ahp/sync_decision", params)
            resp = await client.post("/ahp", content=body)
            data = resp.json()
            assert data["result"]["decision"]["decision"] == "block"

    @pytest.mark.asyncio
    async def test_http_report_summary_endpoint(self, app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            body = _jsonrpc_request("ahp/sync_decision", _sync_decision_params(request_id="req-rpt-http"))
            await client.post("/ahp", content=body)

            resp = await client.get("/report/summary")
            assert resp.status_code == 200
            data = resp.json()
            assert data["total_records"] >= 1
            assert "by_source_framework" in data

    @pytest.mark.asyncio
    async def test_http_report_session_endpoint(self, app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            body = _jsonrpc_request("ahp/sync_decision", _sync_decision_params(
                request_id="req-rpt-sess-http",
                event={
                    "event_id": "evt-rpt-sess-http",
                    "trace_id": "trace-rpt-sess-http",
                    "event_type": "pre_action",
                    "session_id": "sess-http-replay",
                    "agent_id": "agent-001",
                    "source_framework": "test",
                    "occurred_at": "2026-03-19T12:00:00+00:00",
                    "payload": {"tool": "read_file", "path": "/tmp/readme.txt"},
                    "tool_name": "read_file",
                },
            ))
            await client.post("/ahp", content=body)

            resp = await client.get("/report/session/sess-http-replay")
            assert resp.status_code == 200
            data = resp.json()
            assert data["session_id"] == "sess-http-replay"
            assert data["record_count"] >= 1

    @pytest.mark.asyncio
    async def test_http_payload_over_10mb_returns_413(self, app):
        """HTTP POST /ahp with payload > 10MB should return 413."""
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            huge_body = b"x" * (10 * 1024 * 1024 + 1)
            resp = await client.post("/ahp", content=huge_body)
            assert resp.status_code == 413

    @pytest.mark.asyncio
    async def test_http_session_replay_limit_capped_at_1000(self, gw, app):
        """GET /report/session with limit > 1000 should be capped (no error)."""
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            body = _jsonrpc_request("ahp/sync_decision", _sync_decision_params(
                request_id="req-limit-cap",
                event={
                    "event_id": "evt-limit-cap",
                    "trace_id": "trace-limit-cap",
                    "event_type": "pre_action",
                    "session_id": "sess-limit-cap",
                    "agent_id": "agent-001",
                    "source_framework": "test",
                    "occurred_at": "2026-03-19T12:00:00+00:00",
                    "payload": {"tool": "read_file", "path": "/tmp/x"},
                    "tool_name": "read_file",
                },
            ))
            await client.post("/ahp", content=body)

            resp = await client.get("/report/session/sess-limit-cap?limit=9999")
            assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_http_session_replay_limit_floor_at_1(self, gw, app):
        """GET /report/session with limit=0 should be floored to 1."""
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            body = _jsonrpc_request("ahp/sync_decision", _sync_decision_params(
                request_id="req-limit-floor",
                event={
                    "event_id": "evt-limit-floor",
                    "trace_id": "trace-limit-floor",
                    "event_type": "pre_action",
                    "session_id": "sess-limit-floor",
                    "agent_id": "agent-001",
                    "source_framework": "test",
                    "occurred_at": "2026-03-19T12:00:00+00:00",
                    "payload": {"tool": "read_file", "path": "/tmp/x"},
                    "tool_name": "read_file",
                },
            ))
            await client.post("/ahp", content=body)

            resp = await client.get("/report/session/sess-limit-floor?limit=0")
            assert resp.status_code == 200
            data = resp.json()
            assert data["record_count"] >= 1

    @pytest.mark.asyncio
    async def test_http_report_summary_with_window_param(self, gw, app):
        """GET /report/summary?window_seconds=X should filter via HTTP."""
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            body = _jsonrpc_request("ahp/sync_decision", _sync_decision_params(
                request_id="req-http-window",
            ))
            await client.post("/ahp", content=body)

            resp = await client.get("/report/summary?window_seconds=300")
            assert resp.status_code == 200
            data = resp.json()
            assert data["total_records"] >= 1

    @pytest.mark.asyncio
    async def test_http_report_sessions_endpoint(self, app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            await client.post("/ahp", content=_jsonrpc_request(
                "ahp/sync_decision",
                _sync_decision_params(
                    request_id="req-sessions-1",
                    event={
                        "event_id": "evt-sessions-1",
                        "trace_id": "trace-sessions-1",
                        "event_type": "pre_action",
                        "session_id": "sess-sessions-1",
                        "agent_id": "agent-001",
                        "source_framework": "test",
                        "occurred_at": "2026-03-21T12:00:00+00:00",
                        "payload": {"path": "/tmp/a"},
                        "tool_name": "read_file",
                    },
                ),
            ))

            resp = await client.get("/report/sessions")
            assert resp.status_code == 200
            data = resp.json()
            assert data["total_active"] >= 1
            assert any(s["session_id"] == "sess-sessions-1" for s in data["sessions"])

    @pytest.mark.asyncio
    async def test_http_report_sessions_respects_limit(self, app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            for idx in range(3):
                await client.post("/ahp", content=_jsonrpc_request(
                    "ahp/sync_decision",
                    _sync_decision_params(
                        request_id=f"req-sessions-limit-{idx}",
                        event={
                            "event_id": f"evt-sessions-limit-{idx}",
                            "trace_id": f"trace-sessions-limit-{idx}",
                            "event_type": "pre_action",
                            "session_id": f"sess-sessions-limit-{idx}",
                            "agent_id": "agent-001",
                            "source_framework": "test",
                            "occurred_at": f"2026-03-21T12:00:0{idx}+00:00",
                            "payload": {"path": f"/tmp/{idx}"},
                            "tool_name": "read_file",
                        },
                    ),
                ))

            resp = await client.get("/report/sessions?limit=2")
            assert resp.status_code == 200
            data = resp.json()
            assert len(data["sessions"]) == 2

    @pytest.mark.asyncio
    async def test_http_report_sessions_filters_by_min_risk(self, app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            await client.post("/ahp", content=_jsonrpc_request(
                "ahp/sync_decision",
                _sync_decision_params(
                    request_id="req-sessions-min-risk-low",
                    event={
                        "event_id": "evt-sessions-min-risk-low",
                        "trace_id": "trace-sessions-min-risk-low",
                        "event_type": "pre_action",
                        "session_id": "sess-sessions-min-risk-low",
                        "agent_id": "agent-001",
                        "source_framework": "test",
                        "occurred_at": "2026-03-21T12:00:00+00:00",
                        "payload": {"path": "/tmp/low"},
                        "tool_name": "read_file",
                    },
                ),
            ))
            await client.post("/ahp", content=_jsonrpc_request(
                "ahp/sync_decision",
                _sync_decision_params(
                    request_id="req-sessions-min-risk-high",
                    event={
                        "event_id": "evt-sessions-min-risk-high",
                        "trace_id": "trace-sessions-min-risk-high",
                        "event_type": "pre_action",
                        "session_id": "sess-sessions-min-risk-high",
                        "agent_id": "agent-001",
                        "source_framework": "test",
                        "occurred_at": "2026-03-21T12:00:01+00:00",
                        "payload": {"command": "sudo rm -rf /tmp/demo"},
                        "tool_name": "bash",
                    },
                ),
            ))

            resp = await client.get("/report/sessions?min_risk=high")
            assert resp.status_code == 200
            data = resp.json()
            assert data["sessions"]
            assert all(s["current_risk_level"] in {"high", "critical"} for s in data["sessions"])

    @pytest.mark.asyncio
    async def test_http_report_sessions_sorts_by_last_event(self, app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            await client.post("/ahp", content=_jsonrpc_request(
                "ahp/sync_decision",
                _sync_decision_params(
                    request_id="req-sessions-sort-old",
                    event={
                        "event_id": "evt-sessions-sort-old",
                        "trace_id": "trace-sessions-sort-old",
                        "event_type": "pre_action",
                        "session_id": "sess-sessions-sort-old",
                        "agent_id": "agent-001",
                        "source_framework": "test",
                        "occurred_at": "2026-03-21T12:00:00+00:00",
                        "payload": {"path": "/tmp/old"},
                        "tool_name": "read_file",
                    },
                ),
            ))
            await client.post("/ahp", content=_jsonrpc_request(
                "ahp/sync_decision",
                _sync_decision_params(
                    request_id="req-sessions-sort-new",
                    event={
                        "event_id": "evt-sessions-sort-new",
                        "trace_id": "trace-sessions-sort-new",
                        "event_type": "pre_action",
                        "session_id": "sess-sessions-sort-new",
                        "agent_id": "agent-001",
                        "source_framework": "test",
                        "occurred_at": "2026-03-21T12:00:10+00:00",
                        "payload": {"path": "/tmp/new"},
                        "tool_name": "read_file",
                    },
                ),
            ))

            resp = await client.get("/report/sessions?sort=last_event")
            assert resp.status_code == 200
            data = resp.json()
            assert len(data["sessions"]) >= 2
            assert data["sessions"][0]["session_id"] == "sess-sessions-sort-new"

    @pytest.mark.asyncio
    async def test_http_report_sessions_window_validation(self, app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/report/sessions", params={"window_seconds": -1})
            assert resp.status_code == 400
            assert "window_seconds" in resp.json()["error"]

    @pytest.mark.asyncio
    async def test_http_report_session_risk_endpoint(self, app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            await client.post("/ahp", content=_jsonrpc_request(
                "ahp/sync_decision",
                _sync_decision_params(
                    request_id="req-risk-1",
                    event={
                        "event_id": "evt-risk-1",
                        "trace_id": "trace-risk-1",
                        "event_type": "pre_action",
                        "session_id": "sess-risk-1",
                        "agent_id": "agent-001",
                        "source_framework": "test",
                        "occurred_at": "2026-03-21T12:00:00+00:00",
                        "payload": {"command": "sudo rm -rf /tmp/demo"},
                        "tool_name": "bash",
                    },
                ),
            ))

            resp = await client.get("/report/session/sess-risk-1/risk")
            assert resp.status_code == 200
            data = resp.json()
            assert data["session_id"] == "sess-risk-1"
            assert data["current_risk_level"] in {"high", "critical"}
            assert len(data["risk_timeline"]) >= 1

    @pytest.mark.asyncio
    async def test_http_report_session_risk_limit_capped_at_1000(self, app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            await client.post("/ahp", content=_jsonrpc_request(
                "ahp/sync_decision",
                _sync_decision_params(
                    request_id="req-risk-cap",
                    event={
                        "event_id": "evt-risk-cap",
                        "trace_id": "trace-risk-cap",
                        "event_type": "pre_action",
                        "session_id": "sess-risk-cap",
                        "agent_id": "agent-001",
                        "source_framework": "test",
                        "occurred_at": "2026-03-21T12:00:00+00:00",
                        "payload": {"command": "sudo rm -rf /tmp/demo"},
                        "tool_name": "bash",
                    },
                ),
            ))

            resp = await client.get("/report/session/sess-risk-cap/risk?limit=9999")
            assert resp.status_code == 200
            data = resp.json()
            assert len(data["risk_timeline"]) >= 1

    @pytest.mark.asyncio
    async def test_http_report_session_risk_limit_floor_at_1(self, app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            await client.post("/ahp", content=_jsonrpc_request(
                "ahp/sync_decision",
                _sync_decision_params(
                    request_id="req-risk-floor",
                    event={
                        "event_id": "evt-risk-floor",
                        "trace_id": "trace-risk-floor",
                        "event_type": "pre_action",
                        "session_id": "sess-risk-floor",
                        "agent_id": "agent-001",
                        "source_framework": "test",
                        "occurred_at": "2026-03-21T12:00:00+00:00",
                        "payload": {"command": "sudo rm -rf /tmp/demo"},
                        "tool_name": "bash",
                    },
                ),
            ))

            resp = await client.get("/report/session/sess-risk-floor/risk?limit=0")
            assert resp.status_code == 200
            data = resp.json()
            assert len(data["risk_timeline"]) == 1

    @pytest.mark.asyncio
    async def test_http_report_session_risk_window_validation(self, app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/report/session/sess-risk-window/risk", params={"window_seconds": -1})
            assert resp.status_code == 400
            assert "window_seconds" in resp.json()["error"]

    @pytest.mark.asyncio
    async def test_http_report_session_risk_unknown_session_returns_empty_detail(self, app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/report/session/sess-risk-unknown/risk")
            assert resp.status_code == 200
            data = resp.json()
            assert data["session_id"] == "sess-risk-unknown"
            assert data["risk_timeline"] == []


# ===========================================================================
# UDS Transport Tests (#33)
# ===========================================================================

UDS_TEST_PATH = "/tmp/ahp-uds-edge-test.sock"


class TestUdsTransport:
    @pytest_asyncio.fixture
    async def uds_gateway(self):
        gw = SupervisionGateway()
        server = await start_uds_server(gw, UDS_TEST_PATH)
        yield gw, server
        server.close()
        await server.wait_closed()
        if os.path.exists(UDS_TEST_PATH):
            os.unlink(UDS_TEST_PATH)

    @pytest.mark.asyncio
    async def test_uds_valid_request_response(self, uds_gateway):
        """UDS transport should handle a valid JSON-RPC request end-to-end."""
        gw, server = uds_gateway
        params = _sync_decision_params(request_id="req-uds-valid")
        body = _jsonrpc_request("ahp/sync_decision", params)

        reader, writer = await asyncio.open_unix_connection(UDS_TEST_PATH)
        try:
            writer.write(struct.pack("!I", len(body)))
            writer.write(body)
            await writer.drain()

            resp_len_bytes = await reader.readexactly(4)
            resp_len = struct.unpack("!I", resp_len_bytes)[0]
            resp_data = await reader.readexactly(resp_len)
            result = json.loads(resp_data)

            assert "result" in result
            assert result["result"]["rpc_status"] == "ok"
            assert result["result"]["decision"]["decision"] == "allow"
        finally:
            writer.close()
            await writer.wait_closed()

    @pytest.mark.asyncio
    async def test_uds_oversized_frame_rejected(self, uds_gateway):
        """UDS should reject frames claiming > 10MB."""
        gw, server = uds_gateway

        reader, writer = await asyncio.open_unix_connection(UDS_TEST_PATH)
        try:
            writer.write(struct.pack("!I", 11 * 1024 * 1024))
            await writer.drain()

            try:
                data = await asyncio.wait_for(reader.read(1024), timeout=2.0)
                assert data == b""
            except (asyncio.IncompleteReadError, ConnectionResetError):
                pass
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    @pytest.mark.asyncio
    async def test_uds_zero_length_frame_rejected(self, uds_gateway):
        """UDS should reject zero-length frames."""
        gw, server = uds_gateway

        reader, writer = await asyncio.open_unix_connection(UDS_TEST_PATH)
        try:
            writer.write(struct.pack("!I", 0))
            await writer.drain()

            try:
                data = await asyncio.wait_for(reader.read(1024), timeout=2.0)
                assert data == b""
            except (asyncio.IncompleteReadError, ConnectionResetError):
                pass
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    @pytest.mark.asyncio
    async def test_uds_multiple_requests_on_same_connection(self, uds_gateway):
        """UDS should handle multiple sequential requests on one connection."""
        gw, server = uds_gateway

        reader, writer = await asyncio.open_unix_connection(UDS_TEST_PATH)
        try:
            for i in range(3):
                params = _sync_decision_params(request_id=f"req-uds-multi-{i}")
                body = _jsonrpc_request("ahp/sync_decision", params)
                writer.write(struct.pack("!I", len(body)))
                writer.write(body)
                await writer.drain()

                resp_len_bytes = await reader.readexactly(4)
                resp_len = struct.unpack("!I", resp_len_bytes)[0]
                resp_data = await reader.readexactly(resp_len)
                result = json.loads(resp_data)
                assert result["result"]["rpc_status"] == "ok"
        finally:
            writer.close()
            await writer.wait_closed()

    @pytest.mark.asyncio
    async def test_uds_malformed_json_returns_parse_error(self, uds_gateway):
        """UDS should return JSON-RPC parse error for malformed JSON."""
        gw, server = uds_gateway

        reader, writer = await asyncio.open_unix_connection(UDS_TEST_PATH)
        try:
            bad_body = b"not valid json{{"
            writer.write(struct.pack("!I", len(bad_body)))
            writer.write(bad_body)
            await writer.drain()

            resp_len_bytes = await reader.readexactly(4)
            resp_len = struct.unpack("!I", resp_len_bytes)[0]
            resp_data = await reader.readexactly(resp_len)
            result = json.loads(resp_data)
            assert "error" in result
            assert result["error"]["code"] == -32700
        finally:
            writer.close()
            await writer.wait_closed()


# ===========================================================================
# Report Endpoint window_seconds Validation Tests (W-5)
# ===========================================================================

class TestReportWindowSecondsValidation:
    @pytest.fixture
    def gw(self):
        return SupervisionGateway()

    @pytest.fixture
    def app(self, gw):
        return create_http_app(gw)

    @pytest.mark.asyncio
    async def test_summary_negative_window_returns_400(self, app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/report/summary", params={"window_seconds": -1})
            assert resp.status_code == 400
            assert "window_seconds" in resp.json()["error"]

    @pytest.mark.asyncio
    async def test_summary_too_large_window_returns_400(self, app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/report/summary", params={"window_seconds": 999999999})
            assert resp.status_code == 400

    @pytest.mark.asyncio
    async def test_summary_max_boundary_returns_200(self, app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/report/summary", params={"window_seconds": 604800})
            assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_session_negative_window_returns_400(self, app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/report/session/sess-001", params={"window_seconds": -1})
            assert resp.status_code == 400

    @pytest.mark.asyncio
    async def test_session_too_large_window_returns_400(self, app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/report/session/s1", params={"window_seconds": 999999999})
            assert resp.status_code == 400

    @pytest.mark.asyncio
    async def test_session_valid_window_returns_200(self, app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/report/session/s1", params={"window_seconds": 3600})
            assert resp.status_code == 200


# ===========================================================================
# SSE Stream Tests (Phase 5.6b)
# ===========================================================================

class TestSseStream:
    """Tests for GET /report/stream SSE endpoint and EventBus.

    NOTE: httpx ASGITransport collects all response body chunks before returning,
    so streaming (SSE) endpoints cannot be tested end-to-end with client.stream().
    HTTP-level tests cover: auth enforcement, 503 on capacity, 400 on bad params.
    EventBus unit tests cover: subscribe/broadcast/filter logic.
    """

    @pytest.fixture
    def gw(self):
        return SupervisionGateway()

    @pytest.fixture
    def app(self, gw):
        return create_http_app(gw)


    # -----------------------------------------------------------------------
    # EventBus unit tests (no HTTP layer — avoid ASGITransport SSE limitation)
    # -----------------------------------------------------------------------

    @pytest.mark.asyncio
    async def test_eventbus_subscribe_and_receive(self, gw):
        """subscribe() returns a queue; broadcast() puts matching events in it."""
        sub_id, queue = gw.event_bus.subscribe()
        assert sub_id is not None
        assert queue is not None
        gw.event_bus.broadcast({
            "type": "decision",
            "session_id": "sess-1",
            "event_id": "evt-1",
            "risk_level": "medium",
            "decision": "allow",
            "tool_name": "Read",
            "actual_tier": "L1",
            "timestamp": "2026-03-21T12:00:00+00:00",
        })
        event = queue.get_nowait()
        assert event["session_id"] == "sess-1"
        assert event["risk_level"] == "medium"
        gw.event_bus.unsubscribe(sub_id)

    @pytest.mark.asyncio
    async def test_eventbus_filters_by_session_id(self, gw):
        """Subscriber with session_id filter ignores events for other sessions."""
        sub_id, queue = gw.event_bus.subscribe(session_id="sess-target")
        gw.event_bus.broadcast({
            "type": "decision", "session_id": "sess-other",
            "risk_level": "low", "decision": "allow",
            "event_id": "e1", "tool_name": "Read", "actual_tier": "L1",
            "timestamp": "2026-03-21T12:00:00+00:00",
        })
        assert queue.empty()  # filtered out
        gw.event_bus.broadcast({
            "type": "decision", "session_id": "sess-target",
            "risk_level": "low", "decision": "allow",
            "event_id": "e2", "tool_name": "Read", "actual_tier": "L1",
            "timestamp": "2026-03-21T12:00:01+00:00",
        })
        event = queue.get_nowait()
        assert event["session_id"] == "sess-target"
        gw.event_bus.unsubscribe(sub_id)

    @pytest.mark.asyncio
    async def test_eventbus_filters_by_min_risk(self, gw):
        """Subscriber with min_risk=high drops low/medium events."""
        sub_id, queue = gw.event_bus.subscribe(min_risk="high")
        gw.event_bus.broadcast({
            "type": "decision", "session_id": "sess-1",
            "risk_level": "low", "decision": "allow",
            "event_id": "e-low", "tool_name": "Read", "actual_tier": "L1",
            "timestamp": "2026-03-21T12:00:00+00:00",
        })
        assert queue.empty()  # low risk filtered
        gw.event_bus.broadcast({
            "type": "decision", "session_id": "sess-1",
            "risk_level": "high", "decision": "block",
            "event_id": "e-high", "tool_name": "Bash", "actual_tier": "L1",
            "timestamp": "2026-03-21T12:00:01+00:00",
        })
        event = queue.get_nowait()
        assert event["risk_level"] == "high"
        gw.event_bus.unsubscribe(sub_id)

    @pytest.mark.asyncio
    async def test_eventbus_filters_by_event_type(self, gw):
        """Subscriber with types={session_start} drops decision events."""
        sub_id, queue = gw.event_bus.subscribe(event_types={"session_start"})
        gw.event_bus.broadcast({
            "type": "decision", "session_id": "sess-1",
            "risk_level": "low", "decision": "allow",
            "event_id": "e1", "tool_name": "Read", "actual_tier": "L1",
            "timestamp": "2026-03-21T12:00:00+00:00",
        })
        assert queue.empty()
        gw.event_bus.broadcast({
            "type": "session_start", "session_id": "sess-2",
            "agent_id": "agent-1", "source_framework": "test",
            "timestamp": "2026-03-21T12:00:01+00:00",
        })
        event = queue.get_nowait()
        assert event["session_id"] == "sess-2"
        gw.event_bus.unsubscribe(sub_id)

    @pytest.mark.asyncio
    async def test_eventbus_unsubscribe_stops_delivery(self, gw):
        """After unsubscribe, broadcast no longer delivers to that subscriber."""
        sub_id, queue = gw.event_bus.subscribe()
        gw.event_bus.unsubscribe(sub_id)
        gw.event_bus.broadcast({
            "type": "decision", "session_id": "sess-1",
            "risk_level": "low", "decision": "allow",
            "event_id": "e1", "tool_name": "Read", "actual_tier": "L1",
            "timestamp": "2026-03-21T12:00:00+00:00",
        })
        assert queue.empty()

    @pytest.mark.asyncio
    async def test_eventbus_session_risk_change_broadcast_on_escalation(self, gw, app):
        """Gateway broadcasts session_risk_change when risk escalates."""
        sub_id, queue = gw.event_bus.subscribe(event_types={"session_risk_change"})
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            # First event: low risk
            body1 = _jsonrpc_request("ahp/sync_decision", _sync_decision_params(
                request_id="req-risk-change-1",
                event={
                    "event_id": "evt-risk-1",
                    "trace_id": "trace-rc-1",
                    "event_type": "pre_action",
                    "session_id": "sess-risk-change",
                    "agent_id": "agent-rc",
                    "source_framework": "test",
                    "occurred_at": "2026-03-21T12:00:00+00:00",
                    "payload": {"tool": "Read"},
                    "tool_name": "Read",
                },
            ))
            await client.post("/ahp", content=body1)
            # Second event: high risk (sudo rm)
            body2 = _jsonrpc_request("ahp/sync_decision", _sync_decision_params(
                request_id="req-risk-change-2",
                event={
                    "event_id": "evt-risk-2",
                    "trace_id": "trace-rc-2",
                    "event_type": "pre_action",
                    "session_id": "sess-risk-change",
                    "agent_id": "agent-rc",
                    "source_framework": "test",
                    "occurred_at": "2026-03-21T12:00:01+00:00",
                    "payload": {"command": "sudo rm -rf /etc"},
                    "tool_name": "Bash",
                },
            ))
            await client.post("/ahp", content=body2)
        # Should have received a risk_change event
        assert not queue.empty()
        evt = queue.get_nowait()
        assert evt["session_id"] == "sess-risk-change"
        assert evt["previous_risk"] in {"low", "medium"}
        assert evt["current_risk"] in {"high", "critical"}
        gw.event_bus.unsubscribe(sub_id)

    @pytest.mark.asyncio
    async def test_decision_broadcast_includes_reason_command_approval_id(self, gw, app):
        """Decision broadcast includes reason, command, approval_id, expires_at."""
        sub_id, queue = gw.event_bus.subscribe(event_types={"decision"})
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            body = _jsonrpc_request("ahp/sync_decision", _sync_decision_params(
                request_id="req-sse-fields-1",
                event={
                    "event_id": "evt-sse-fields-1",
                    "trace_id": "trace-sse-fields-1",
                    "event_type": "pre_action",
                    "session_id": "sess-sse-fields",
                    "agent_id": "agent-sse",
                    "source_framework": "test",
                    "occurred_at": "2026-03-22T10:00:00+00:00",
                    "payload": {"command": "sudo rm -rf /"},
                    "tool_name": "Bash",
                    "approval_id": "appr-999",
                },
            ))
            resp = await client.post("/ahp", content=body)
            assert resp.status_code == 200
        # Drain to find the decision event (skip session_start if present)
        decision_evt = None
        while not queue.empty():
            evt = queue.get_nowait()
            if evt.get("type") == "decision":
                decision_evt = evt
                break
        assert decision_evt is not None, "No decision event broadcast received"
        # New fields
        assert "reason" in decision_evt and decision_evt["reason"] != ""
        assert decision_evt["command"] == "sudo rm -rf /"
        assert decision_evt["approval_id"] == "appr-999"
        # expires_at: not set in this request, so should be None
        assert "expires_at" in decision_evt
        gw.event_bus.unsubscribe(sub_id)

    # -----------------------------------------------------------------------
    # HTTP-level tests (status code / headers / error responses)
    # -----------------------------------------------------------------------

    @pytest.mark.asyncio
    async def test_sse_stream_max_subscribers_returns_503(self, gw, app):
        """When MAX_SUBSCRIBERS is reached, new connections return 503."""
        from clawsentry.gateway.server import EventBus
        original_max = EventBus.MAX_SUBSCRIBERS
        EventBus.MAX_SUBSCRIBERS = 1
        transport = ASGITransport(app=app)
        try:
            # Occupy the one slot directly via bus
            sub_id, _ = gw.event_bus.subscribe()
            assert sub_id is not None
            # HTTP request should now get 503 (non-streaming response)
            async with AsyncClient(transport=transport, base_url="http://test", timeout=3.0) as client:
                resp = await client.get("/report/stream")
                assert resp.status_code == 503
        finally:
            gw.event_bus.unsubscribe(sub_id)
            EventBus.MAX_SUBSCRIBERS = original_max

    @pytest.mark.asyncio
    async def test_sse_stream_invalid_min_risk_returns_400(self, app):
        """Invalid min_risk param returns 400."""
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test", timeout=3.0) as client:
            resp = await client.get("/report/stream", params={"min_risk": "extreme"})
            assert resp.status_code == 400
            assert "min_risk" in resp.json()["error"]

    @pytest.mark.asyncio
    async def test_sse_stream_invalid_types_returns_400(self, app):
        """Unknown event type in types param returns 400."""
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test", timeout=3.0) as client:
            resp = await client.get("/report/stream", params={"types": "decision,unknown_type"})
            assert resp.status_code == 400

    @pytest.mark.asyncio
    async def test_sse_stream_alert_type_accepted(self, app):
        """'alert' is a valid types value and should not return 400."""
        from clawsentry.gateway.server import EventBus
        original_max = EventBus.MAX_SUBSCRIBERS
        EventBus.MAX_SUBSCRIBERS = 0  # force 503 immediately, avoiding hanging stream
        transport = ASGITransport(app=app)
        try:
            async with AsyncClient(transport=transport, base_url="http://test", timeout=3.0) as client:
                resp = await client.get("/report/stream", params={"types": "alert"})
                # 503 means we passed validation (not 400)
                assert resp.status_code == 503
        finally:
            EventBus.MAX_SUBSCRIBERS = original_max


class TestAlertRegistry:
    """Unit tests for AlertRegistry."""

    def test_add_and_list(self):
        from clawsentry.gateway.server import AlertRegistry
        reg = AlertRegistry()
        alert = {
            "alert_id": "alert-001",
            "severity": "high",
            "metric": "session_risk_escalation",
            "session_id": "sess-1",
            "message": "Risk escalated",
            "details": {},
            "triggered_at": "2026-03-21T12:00:00+00:00",
            "triggered_at_ts": 1000.0,
            "acknowledged": False,
            "acknowledged_by": None,
            "acknowledged_at": None,
        }
        reg.add(alert)
        result = reg.list_alerts()
        assert result["total_unacknowledged"] == 1
        assert len(result["alerts"]) == 1
        assert result["alerts"][0]["alert_id"] == "alert-001"

    def test_acknowledge(self):
        from clawsentry.gateway.server import AlertRegistry
        reg = AlertRegistry()
        alert = {
            "alert_id": "alert-002",
            "severity": "critical",
            "metric": "session_risk_escalation",
            "session_id": "sess-2",
            "message": "Critical risk",
            "details": {},
            "triggered_at": "2026-03-21T12:00:00+00:00",
            "triggered_at_ts": 1000.0,
            "acknowledged": False,
            "acknowledged_by": None,
            "acknowledged_at": None,
        }
        reg.add(alert)
        result = reg.acknowledge("alert-002", "operator-kai")
        assert result is not None
        assert result["acknowledged"] is True
        assert result["acknowledged_by"] == "operator-kai"
        # Should no longer appear in unacknowledged count
        listing = reg.list_alerts()
        assert listing["total_unacknowledged"] == 0

    def test_acknowledge_not_found_returns_none(self):
        from clawsentry.gateway.server import AlertRegistry
        reg = AlertRegistry()
        assert reg.acknowledge("nonexistent", "op") is None

    def test_filter_by_severity(self):
        from clawsentry.gateway.server import AlertRegistry
        reg = AlertRegistry()
        for sev, aid in [("high", "a1"), ("critical", "a2"), ("high", "a3")]:
            reg.add({
                "alert_id": aid, "severity": sev, "metric": "m",
                "session_id": "s", "message": "msg", "details": {},
                "triggered_at": "2026-01-01T00:00:00+00:00",
                "triggered_at_ts": 1.0,
                "acknowledged": False, "acknowledged_by": None, "acknowledged_at": None,
            })
        result = reg.list_alerts(severity="critical")
        assert len(result["alerts"]) == 1
        assert result["alerts"][0]["alert_id"] == "a2"

    def test_filter_acknowledged(self):
        from clawsentry.gateway.server import AlertRegistry
        reg = AlertRegistry()
        for aid in ["b1", "b2"]:
            reg.add({
                "alert_id": aid, "severity": "high", "metric": "m",
                "session_id": "s", "message": "msg", "details": {},
                "triggered_at": "2026-01-01T00:00:00+00:00",
                "triggered_at_ts": 1.0,
                "acknowledged": False, "acknowledged_by": None, "acknowledged_at": None,
            })
        reg.acknowledge("b1", "op")
        unacked = reg.list_alerts(acknowledged=False)
        acked = reg.list_alerts(acknowledged=True)
        assert len(unacked["alerts"]) == 1 and unacked["alerts"][0]["alert_id"] == "b2"
        assert len(acked["alerts"]) == 1 and acked["alerts"][0]["alert_id"] == "b1"

    def test_eviction_at_max(self):
        from clawsentry.gateway.server import AlertRegistry
        reg = AlertRegistry()
        reg.MAX_ALERTS = 3
        for i in range(4):
            reg.add({
                "alert_id": f"ev-{i}", "severity": "high", "metric": "m",
                "session_id": "s", "message": "msg", "details": {},
                "triggered_at": "2026-01-01T00:00:00+00:00",
                "triggered_at_ts": float(i),
                "acknowledged": False, "acknowledged_by": None, "acknowledged_at": None,
            })
        assert len(reg._alerts) == 3
        assert "ev-0" not in reg._alerts  # oldest evicted


class TestAlertHttpEndpoints:
    """HTTP-level tests for /report/alerts and /report/alerts/{id}/acknowledge."""

    @pytest.fixture
    def gw(self):
        return SupervisionGateway()

    @pytest.fixture
    def app(self, gw):
        return create_http_app(gw)

    @pytest.mark.asyncio
    async def test_list_alerts_empty(self, app):
        """GET /report/alerts returns empty list when no alerts exist."""
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/report/alerts")
        assert resp.status_code == 200
        data = resp.json()
        assert data["alerts"] == []
        assert data["total_unacknowledged"] == 0
        assert "generated_at" in data

    @pytest.mark.asyncio
    async def test_list_alerts_invalid_severity_returns_400(self, app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/report/alerts", params={"severity": "extreme"})
        assert resp.status_code == 400
        assert "severity" in resp.json()["error"]

    @pytest.mark.asyncio
    async def test_list_alerts_invalid_acknowledged_returns_400(self, app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/report/alerts", params={"acknowledged": "maybe"})
        assert resp.status_code == 400
        assert "acknowledged" in resp.json()["error"]

    @pytest.mark.asyncio
    async def test_acknowledge_not_found_returns_404(self, app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.post(
                "/report/alerts/nonexistent/acknowledge",
                json={"acknowledged_by": "op"},
            )
        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_alert_triggered_on_high_risk_event(self, gw, app):
        """A high-risk decision should create an alert in AlertRegistry."""
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            body = _jsonrpc_request("ahp/sync_decision", _sync_decision_params(
                request_id="req-alert-trigger",
                event={
                    "event_id": "evt-alert-1",
                    "trace_id": "trace-alert-1",
                    "event_type": "pre_action",
                    "session_id": "sess-alert-test",
                    "agent_id": "agent-alert",
                    "source_framework": "test",
                    "occurred_at": "2026-03-21T12:00:00+00:00",
                    "payload": {"command": "sudo rm -rf /etc"},
                    "tool_name": "Bash",
                },
            ))
            await client.post("/ahp", content=body)
            # Check alerts endpoint
            resp = await client.get("/report/alerts")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total_unacknowledged"] >= 1
        assert any(a["session_id"] == "sess-alert-test" for a in data["alerts"])

    @pytest.mark.asyncio
    async def test_acknowledge_alert_lifecycle(self, gw, app):
        """Create alert via high-risk event then acknowledge it via HTTP."""
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            # Trigger alert
            body = _jsonrpc_request("ahp/sync_decision", _sync_decision_params(
                request_id="req-alert-ack",
                event={
                    "event_id": "evt-ack-1",
                    "trace_id": "trace-ack-1",
                    "event_type": "pre_action",
                    "session_id": "sess-ack-test",
                    "agent_id": "agent-ack",
                    "source_framework": "test",
                    "occurred_at": "2026-03-21T12:00:00+00:00",
                    "payload": {"command": "sudo rm -rf /var"},
                    "tool_name": "Bash",
                },
            ))
            await client.post("/ahp", content=body)
            # Get alert_id
            list_resp = await client.get("/report/alerts")
            alerts = list_resp.json()["alerts"]
            assert len(alerts) >= 1
            alert_id = alerts[0]["alert_id"]
            # Acknowledge
            ack_resp = await client.post(
                f"/report/alerts/{alert_id}/acknowledge",
                json={"acknowledged_by": "operator-kai"},
            )
            assert ack_resp.status_code == 200
            ack_data = ack_resp.json()
            assert ack_data["acknowledged"] is True
            assert ack_data["acknowledged_by"] == "operator-kai"
            # Verify unacknowledged count drops
            list_resp2 = await client.get("/report/alerts", params={"acknowledged": "false"})
            unacked = [a for a in list_resp2.json()["alerts"] if a["alert_id"] == alert_id]
            assert len(unacked) == 0


# ---------------------------------------------------------------------------
# L3 Trace — TrajectoryStore l3_trace_json column (#Task3)
# ---------------------------------------------------------------------------


def test_trajectory_store_records_l3_trace(tmp_path):
    from clawsentry.gateway.server import TrajectoryStore
    store = TrajectoryStore(db_path=str(tmp_path / "test.db"))
    trace = {"trigger_reason": "manual_l3_escalate", "skill_selected": "credential-audit", "turns": []}
    store.record(
        event={"session_id": "s1", "source_framework": "test", "event_type": "pre_action"},
        decision={"decision": "block", "risk_level": "high"},
        snapshot={"risk_level": "high"},
        meta={"actual_tier": "L3", "request_id": "r1"},
        l3_trace=trace,
    )
    records = store.records
    assert len(records) == 1
    assert records[0]["l3_trace"] == trace
    assert records[0]["l3_trace"]["trigger_reason"] == "manual_l3_escalate"


def test_trajectory_store_l3_trace_none_for_l1(tmp_path):
    from clawsentry.gateway.server import TrajectoryStore
    store = TrajectoryStore(db_path=str(tmp_path / "test.db"))
    store.record(
        event={"session_id": "s1", "source_framework": "test", "event_type": "pre_action"},
        decision={"decision": "allow", "risk_level": "low"},
        snapshot={"risk_level": "low"},
        meta={"actual_tier": "L1", "request_id": "r1"},
    )
    records = store.records
    assert len(records) == 1
    assert records[0]["l3_trace"] is None


def test_trajectory_store_replay_includes_l3_trace(tmp_path):
    from clawsentry.gateway.server import TrajectoryStore
    store = TrajectoryStore(db_path=str(tmp_path / "test.db"))
    trace = {"trigger_reason": "cumulative_risk", "turns": [{"turn": 1, "type": "llm_call"}]}
    store.record(
        event={"session_id": "s1", "source_framework": "test", "event_type": "pre_action"},
        decision={"decision": "block", "risk_level": "critical"},
        snapshot={"risk_level": "critical"},
        meta={"actual_tier": "L3", "request_id": "r1"},
        l3_trace=trace,
    )
    replayed = store.replay_session("s1")
    assert len(replayed) == 1
    assert replayed[0]["l3_trace"] == trace


def test_policy_engine_carries_l3_trace_to_snapshot():
    """L2Result.trace flows from analyzer through policy_engine to RiskSnapshot.l3_trace."""
    from unittest.mock import AsyncMock, MagicMock
    from clawsentry.gateway.policy_engine import L1PolicyEngine
    from clawsentry.gateway.semantic_analyzer import L2Result
    from clawsentry.gateway.models import (
        CanonicalEvent, DecisionContext, DecisionTier, EventType, RiskLevel,
    )

    # Create a mock analyzer that returns L2Result with trace
    mock_analyzer = MagicMock()
    mock_analyzer.analyzer_id = "test-analyzer"
    trace_data = {"trigger_reason": "test", "mode": "single_turn", "turns": [], "degraded": False}

    async def mock_analyze(event, context, l1_snapshot, budget_ms):
        return L2Result(
            target_level=RiskLevel.HIGH,
            reasons=["test escalation"],
            confidence=0.9,
            analyzer_id="test-analyzer",
            latency_ms=100.0,
            trace=trace_data,
        )

    mock_analyzer.analyze = mock_analyze

    engine = L1PolicyEngine(analyzer=mock_analyzer)

    event = CanonicalEvent(
        event_id="evt-test",
        trace_id="trace-test",
        event_type=EventType.PRE_ACTION,
        session_id="sess-test",
        agent_id="agent-test",
        source_framework="test",
        occurred_at="2026-03-21T00:00:00+00:00",
        payload={"command": "cat /etc/passwd"},
        tool_name="bash",
        risk_hints=["credential_exfiltration"],
    )
    ctx = DecisionContext(session_risk_summary={"l2_escalate": True})

    decision, snapshot, tier = engine.evaluate(event, ctx, DecisionTier.L2)

    assert tier == DecisionTier.L2
    assert snapshot.l3_trace == trace_data
    assert snapshot.l3_trace["trigger_reason"] == "test"
    # Verify l3_trace is NOT in model_dump
    dumped = snapshot.model_dump(mode="json")
    assert "l3_trace" not in dumped


# ---------------------------------------------------------------------------
# CS-009: L2 budget capped by deadline
# ---------------------------------------------------------------------------

def test_l2_budget_capped_by_deadline():
    """CS-009: L2 budget must not exceed remaining deadline."""
    from clawsentry.gateway.policy_engine import L1PolicyEngine
    from clawsentry.gateway.semantic_analyzer import L2Result
    from clawsentry.gateway.models import (
        CanonicalEvent, DecisionContext, DecisionTier, EventType, RiskLevel,
    )

    captured_budget = []

    class SpyAnalyzer:
        analyzer_id = "spy"

        async def analyze(self, event, context, l1_snapshot, budget_ms):
            captured_budget.append(budget_ms)
            return L2Result(
                target_level=RiskLevel.LOW,
                reasons=["ok"],
                confidence=0.8,
                analyzer_id="spy",
                latency_ms=1.0,
            )

    engine = L1PolicyEngine(analyzer=SpyAnalyzer())

    event = CanonicalEvent(
        event_id="evt-dl",
        trace_id="trace-dl",
        event_type=EventType.PRE_ACTION,
        session_id="sess-dl",
        agent_id="agent-dl",
        source_framework="test",
        occurred_at="2026-03-26T00:00:00+00:00",
        payload={"command": "cat /etc/passwd"},
        tool_name="bash",
        risk_hints=["credential_exfiltration"],
    )
    ctx = DecisionContext(session_risk_summary={"l2_escalate": True})

    # default l2_budget_ms is 5000; pass deadline_budget_ms=1500 → should cap
    # With overhead margin: budget = min(5000, max(0, 1500 - 200)) = 1300
    from clawsentry.gateway.policy_engine import _L2_OVERHEAD_MARGIN_MS
    _, _, _ = engine.evaluate(event, ctx, DecisionTier.L2, deadline_budget_ms=1500.0)
    assert len(captured_budget) == 1
    expected = 1500.0 - _L2_OVERHEAD_MARGIN_MS  # 1300.0
    assert captured_budget[0] == expected, (
        f"L2 budget {captured_budget[0]} should be {expected} (deadline 1500 - margin {_L2_OVERHEAD_MARGIN_MS})"
    )


def test_l2_budget_uncapped_without_deadline():
    """CS-009: Without deadline, L2 budget should use default config value."""
    from clawsentry.gateway.policy_engine import L1PolicyEngine
    from clawsentry.gateway.semantic_analyzer import L2Result
    from clawsentry.gateway.models import (
        CanonicalEvent, DecisionContext, DecisionTier, EventType, RiskLevel,
    )

    captured_budget = []

    class SpyAnalyzer:
        analyzer_id = "spy"

        async def analyze(self, event, context, l1_snapshot, budget_ms):
            captured_budget.append(budget_ms)
            return L2Result(
                target_level=RiskLevel.LOW,
                reasons=["ok"],
                confidence=0.8,
                analyzer_id="spy",
                latency_ms=1.0,
            )

    engine = L1PolicyEngine(analyzer=SpyAnalyzer())

    event = CanonicalEvent(
        event_id="evt-dl2",
        trace_id="trace-dl2",
        event_type=EventType.PRE_ACTION,
        session_id="sess-dl2",
        agent_id="agent-dl2",
        source_framework="test",
        occurred_at="2026-03-26T00:00:00+00:00",
        payload={"command": "cat /etc/passwd"},
        tool_name="bash",
        risk_hints=["credential_exfiltration"],
    )
    ctx = DecisionContext(session_risk_summary={"l2_escalate": True})

    # No deadline → should use full default budget (5000ms from DetectionConfig)
    _, _, _ = engine.evaluate(event, ctx, DecisionTier.L2)
    assert len(captured_budget) == 1
    assert captured_budget[0] == 5000.0


def test_l2_budget_reserves_overhead_margin():
    """CS-009: L2 budget must subtract _L2_OVERHEAD_MARGIN_MS when deadline is set."""
    from clawsentry.gateway.policy_engine import L1PolicyEngine, _L2_OVERHEAD_MARGIN_MS
    from clawsentry.gateway.semantic_analyzer import L2Result
    from clawsentry.gateway.models import (
        CanonicalEvent, DecisionContext, DecisionTier, EventType, RiskLevel,
    )

    captured_budget = []

    class SpyAnalyzer:
        analyzer_id = "spy"

        async def analyze(self, event, context, l1_snapshot, budget_ms):
            captured_budget.append(budget_ms)
            return L2Result(
                target_level=RiskLevel.LOW,
                reasons=["ok"],
                confidence=0.8,
                analyzer_id="spy",
                latency_ms=1.0,
            )

    engine = L1PolicyEngine(analyzer=SpyAnalyzer())

    event = CanonicalEvent(
        event_id="evt-margin",
        trace_id="trace-margin",
        event_type=EventType.PRE_ACTION,
        session_id="sess-margin",
        agent_id="agent-margin",
        source_framework="test",
        occurred_at="2026-03-26T00:00:00+00:00",
        payload={"command": "cat /etc/passwd"},
        tool_name="bash",
        risk_hints=["credential_exfiltration"],
    )
    ctx = DecisionContext(session_risk_summary={"l2_escalate": True})

    # deadline_budget_ms=5000 → budget should be 5000 - _L2_OVERHEAD_MARGIN_MS
    _, _, _ = engine.evaluate(event, ctx, DecisionTier.L2, deadline_budget_ms=5000.0)
    assert len(captured_budget) == 1
    expected_max = 5000.0 - _L2_OVERHEAD_MARGIN_MS
    assert captured_budget[0] <= expected_max, (
        f"L2 budget {captured_budget[0]} should be <= {expected_max} (with overhead margin)"
    )
    assert captured_budget[0] >= 0, "Budget must not be negative"


def test_l2_budget_margin_does_not_go_negative():
    """CS-009: When deadline < margin, budget is clamped to 0 and L2 falls back to L1."""
    from clawsentry.gateway.policy_engine import L1PolicyEngine, _L2_OVERHEAD_MARGIN_MS
    from clawsentry.gateway.semantic_analyzer import L2Result
    from clawsentry.gateway.models import (
        CanonicalEvent, DecisionContext, DecisionTier, EventType, RiskLevel,
    )

    captured_budget = []

    class SpyAnalyzer:
        analyzer_id = "spy"

        async def analyze(self, event, context, l1_snapshot, budget_ms):
            captured_budget.append(budget_ms)
            return L2Result(
                target_level=RiskLevel.LOW,
                reasons=["ok"],
                confidence=0.8,
                analyzer_id="spy",
                latency_ms=1.0,
            )

    engine = L1PolicyEngine(analyzer=SpyAnalyzer())

    event = CanonicalEvent(
        event_id="evt-neg",
        trace_id="trace-neg",
        event_type=EventType.PRE_ACTION,
        session_id="sess-neg",
        agent_id="agent-neg",
        source_framework="test",
        occurred_at="2026-03-26T00:00:00+00:00",
        payload={"command": "cat /etc/passwd"},
        tool_name="bash",
        risk_hints=["credential_exfiltration"],
    )
    ctx = DecisionContext(session_risk_summary={"l2_escalate": True})

    # deadline_budget_ms=100 < margin=200 → budget clamped to 0 → L2 times out immediately
    # L2 failure falls back to L1, so actual_tier should be L1
    _, _, actual_tier = engine.evaluate(event, ctx, DecisionTier.L2, deadline_budget_ms=100.0)

    # Budget is 0ms → asyncio.wait_for timeout immediately → L2 fails → fallback to L1.
    # The spy analyzer may or may not be called (timeout=0 races with coroutine start).
    # The key invariant: budget is never negative, and the system degrades gracefully.
    if len(captured_budget) == 1:
        assert captured_budget[0] == 0.0, (
            f"L2 budget should be 0 when deadline ({100.0}) < margin ({_L2_OVERHEAD_MARGIN_MS})"
        )
    else:
        # L2 timed out before analyzer was called → fell back to L1
        from clawsentry.gateway.models import DecisionTier as DT
        assert actual_tier == DT.L1, "Should fall back to L1 when budget is exhausted"


# ---------------------------------------------------------------------------
# G-2: _gateway_args_from_env() respects environment variables
# ---------------------------------------------------------------------------

class TestGatewayMainEnvVars:
    """G-2: gateway main() should read configuration from env vars."""

    def test_run_gateway_respects_env_port(self, monkeypatch):
        from clawsentry.gateway.server import _gateway_args_from_env
        monkeypatch.setenv("CS_HTTP_PORT", "9999")
        args = _gateway_args_from_env()
        assert args["http_port"] == 9999

    def test_run_gateway_default_without_env(self, monkeypatch):
        from clawsentry.gateway.server import _gateway_args_from_env
        for key in ["CS_HTTP_PORT", "CS_HTTP_HOST", "CS_UDS_PATH"]:
            monkeypatch.delenv(key, raising=False)
        args = _gateway_args_from_env()
        assert args["http_port"] == 8080
        assert args["http_host"] == "127.0.0.1"

    def test_run_gateway_env_uds_path(self, monkeypatch):
        from clawsentry.gateway.server import _gateway_args_from_env
        monkeypatch.setenv("CS_UDS_PATH", "/tmp/custom.sock")
        args = _gateway_args_from_env()
        assert args["uds_path"] == "/tmp/custom.sock"


# ---------------------------------------------------------------------------
# CS-012: Record decision before deadline check
# ---------------------------------------------------------------------------

class TestCS012RecordBeforeDeadline:
    """CS-012: When deadline is exceeded, the decision must still be recorded
    in trajectory_store and session_registry before the error is returned."""

    @pytest.fixture
    def gw(self):
        return SupervisionGateway()

    @pytest.mark.asyncio
    async def test_deadline_exceeded_still_records_trajectory(self, gw, monkeypatch):
        """When deadline is exceeded, trajectory_store should still have the record."""
        call_count = 0
        base_time = 1000.0

        def fake_monotonic():
            nonlocal call_count
            call_count += 1
            # First call: start time (line 1106) → 1000.0
            # Second call: remaining_ms calc (line 1134) → 1000.0 (within deadline)
            # Third call onward: deadline check → way past deadline
            if call_count <= 2:
                return base_time
            return base_time + 10.0  # 10 seconds past start, way past 100ms deadline

        monkeypatch.setattr(time, "monotonic", fake_monotonic)

        params = _sync_decision_params(
            request_id="req-deadline-record-001",
            deadline_ms=100,
        )
        body = _jsonrpc_request("ahp/sync_decision", params)
        result = await gw.handle_jsonrpc(body)

        # Should return DEADLINE_EXCEEDED error
        assert "error" in result, "Expected DEADLINE_EXCEEDED error response"
        error_data = result["error"]["data"]
        assert error_data["rpc_error_code"] == "DEADLINE_EXCEEDED"

        # But trajectory should still be recorded (CS-012 fix)
        assert gw.trajectory_store.count() == 1, (
            "CS-012: trajectory_store must record even on DEADLINE_EXCEEDED"
        )
        rec = gw.trajectory_store.records[0]
        assert rec["meta"]["request_id"] == "req-deadline-record-001"

    @pytest.mark.asyncio
    async def test_deadline_exceeded_still_records_session(self, gw, monkeypatch):
        """When deadline is exceeded, session_registry should still have the record."""
        call_count = 0
        base_time = 1000.0

        def fake_monotonic():
            nonlocal call_count
            call_count += 1
            if call_count <= 2:
                return base_time
            return base_time + 10.0

        monkeypatch.setattr(time, "monotonic", fake_monotonic)

        params = _sync_decision_params(
            request_id="req-deadline-session-001",
            deadline_ms=100,
            event={
                "event_id": "evt-dl-sess",
                "trace_id": "trace-dl-sess",
                "event_type": "pre_action",
                "session_id": "sess-deadline-001",
                "agent_id": "agent-001",
                "source_framework": "test",
                "occurred_at": "2026-03-19T12:00:00+00:00",
                "payload": {"tool": "read_file", "path": "/tmp/readme.txt"},
                "tool_name": "read_file",
            },
        )
        body = _jsonrpc_request("ahp/sync_decision", params)
        result = await gw.handle_jsonrpc(body)

        # Should return DEADLINE_EXCEEDED error
        assert "error" in result
        assert result["error"]["data"]["rpc_error_code"] == "DEADLINE_EXCEEDED"

        # Session should still be recorded (CS-012 fix)
        stats = gw.session_registry.get_session_stats("sess-deadline-001")
        assert stats.get("event_count", 0) >= 1, (
            "CS-012: session_registry must record even on DEADLINE_EXCEEDED"
        )

    @pytest.mark.asyncio
    async def test_deadline_exceeded_returns_fallback_decision(self, gw, monkeypatch):
        """DEADLINE_EXCEEDED response should still contain fallback_decision."""
        call_count = 0
        base_time = 1000.0

        def fake_monotonic():
            nonlocal call_count
            call_count += 1
            if call_count <= 2:
                return base_time
            return base_time + 10.0

        monkeypatch.setattr(time, "monotonic", fake_monotonic)

        params = _sync_decision_params(
            request_id="req-deadline-fallback-001",
            deadline_ms=100,
        )
        body = _jsonrpc_request("ahp/sync_decision", params)
        result = await gw.handle_jsonrpc(body)

        assert "error" in result
        error_data = result["error"]["data"]
        assert error_data["rpc_error_code"] == "DEADLINE_EXCEEDED"
        assert "fallback_decision" in error_data
        assert error_data["fallback_decision"] is not None


# ---------------------------------------------------------------------------
# L3 budget configuration tests
# ---------------------------------------------------------------------------

def test_l3_budget_overrides_l2_budget():
    """CS_L3_BUDGET_MS should increase L2 analysis budget when L3 is present."""
    from clawsentry.gateway.policy_engine import L1PolicyEngine, _L2_OVERHEAD_MARGIN_MS
    from clawsentry.gateway.semantic_analyzer import L2Result
    from clawsentry.gateway.detection_config import DetectionConfig
    from clawsentry.gateway.models import (
        CanonicalEvent, DecisionContext, DecisionTier, EventType, RiskLevel,
    )

    captured_budget = []

    class SpyAnalyzer:
        analyzer_id = "spy"

        async def analyze(self, event, context, l1_snapshot, budget_ms):
            captured_budget.append(budget_ms)
            return L2Result(
                target_level=RiskLevel.LOW,
                reasons=["ok"],
                confidence=0.8,
                analyzer_id="spy",
                latency_ms=1.0,
            )

    config = DetectionConfig(l2_budget_ms=5000.0, l3_budget_ms=15000.0)
    engine = L1PolicyEngine(analyzer=SpyAnalyzer(), config=config)

    event = CanonicalEvent(
        event_id="evt-l3b",
        trace_id="trace-l3b",
        event_type=EventType.PRE_ACTION,
        session_id="sess-l3b",
        agent_id="agent-l3b",
        source_framework="test",
        occurred_at="2026-03-26T00:00:00+00:00",
        payload={"command": "cat /etc/passwd"},
        tool_name="bash",
        risk_hints=["credential_exfiltration"],
    )
    ctx = DecisionContext(session_risk_summary={"l2_escalate": True})

    # No deadline → budget should be max(5000, 15000) = 15000
    _, _, _ = engine.evaluate(event, ctx, DecisionTier.L2)
    assert len(captured_budget) == 1
    assert captured_budget[0] == 15000.0, (
        f"L3 budget should override L2: expected 15000, got {captured_budget[0]}"
    )


def test_l3_budget_still_capped_by_deadline():
    """L3 budget is still capped by the request deadline."""
    from clawsentry.gateway.policy_engine import L1PolicyEngine, _L2_OVERHEAD_MARGIN_MS
    from clawsentry.gateway.semantic_analyzer import L2Result
    from clawsentry.gateway.detection_config import DetectionConfig
    from clawsentry.gateway.models import (
        CanonicalEvent, DecisionContext, DecisionTier, EventType, RiskLevel,
    )

    captured_budget = []

    class SpyAnalyzer:
        analyzer_id = "spy"

        async def analyze(self, event, context, l1_snapshot, budget_ms):
            captured_budget.append(budget_ms)
            return L2Result(
                target_level=RiskLevel.LOW,
                reasons=["ok"],
                confidence=0.8,
                analyzer_id="spy",
                latency_ms=1.0,
            )

    config = DetectionConfig(l2_budget_ms=5000.0, l3_budget_ms=15000.0)
    engine = L1PolicyEngine(analyzer=SpyAnalyzer(), config=config)

    event = CanonicalEvent(
        event_id="evt-l3bc",
        trace_id="trace-l3bc",
        event_type=EventType.PRE_ACTION,
        session_id="sess-l3bc",
        agent_id="agent-l3bc",
        source_framework="test",
        occurred_at="2026-03-26T00:00:00+00:00",
        payload={"command": "cat /etc/passwd"},
        tool_name="bash",
        risk_hints=["credential_exfiltration"],
    )
    ctx = DecisionContext(session_risk_summary={"l2_escalate": True})

    # deadline=10000 → budget = min(15000, 10000-200) = 9800
    _, _, _ = engine.evaluate(event, ctx, DecisionTier.L2, deadline_budget_ms=10000.0)
    assert len(captured_budget) == 1
    expected = 10000.0 - _L2_OVERHEAD_MARGIN_MS
    assert captured_budget[0] == expected, (
        f"L3 budget should be capped by deadline: expected {expected}, got {captured_budget[0]}"
    )


def test_l3_budget_none_uses_l2_budget():
    """When l3_budget_ms is None (default), L2 budget is used."""
    from clawsentry.gateway.policy_engine import L1PolicyEngine
    from clawsentry.gateway.semantic_analyzer import L2Result
    from clawsentry.gateway.detection_config import DetectionConfig
    from clawsentry.gateway.models import (
        CanonicalEvent, DecisionContext, DecisionTier, EventType, RiskLevel,
    )

    captured_budget = []

    class SpyAnalyzer:
        analyzer_id = "spy"

        async def analyze(self, event, context, l1_snapshot, budget_ms):
            captured_budget.append(budget_ms)
            return L2Result(
                target_level=RiskLevel.LOW,
                reasons=["ok"],
                confidence=0.8,
                analyzer_id="spy",
                latency_ms=1.0,
            )

    config = DetectionConfig(l2_budget_ms=5000.0, l3_budget_ms=None)
    engine = L1PolicyEngine(analyzer=SpyAnalyzer(), config=config)

    event = CanonicalEvent(
        event_id="evt-l3n",
        trace_id="trace-l3n",
        event_type=EventType.PRE_ACTION,
        session_id="sess-l3n",
        agent_id="agent-l3n",
        source_framework="test",
        occurred_at="2026-03-26T00:00:00+00:00",
        payload={"command": "cat /etc/passwd"},
        tool_name="bash",
        risk_hints=["credential_exfiltration"],
    )
    ctx = DecisionContext(session_risk_summary={"l2_escalate": True})

    _, _, _ = engine.evaluate(event, ctx, DecisionTier.L2)
    assert len(captured_budget) == 1
    assert captured_budget[0] == 5000.0
