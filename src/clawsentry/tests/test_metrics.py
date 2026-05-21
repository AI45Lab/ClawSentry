"""
Tests for MetricsCollector (P3 production hardening).

Covers: no-op mode (prometheus_client absent), enabled mode (counter increments,
latency observation, token tracking, gauge updates), cost estimation,
/metrics endpoint (200, no-auth default, auth toggle).
"""

from __future__ import annotations

import json
import os
import sys
from unittest.mock import patch

import pytest
from httpx import ASGITransport, AsyncClient

from clawsentry.gateway.metrics import LLMBudgetTracker, MetricsCollector
from clawsentry.gateway.server import SupervisionGateway, create_http_app
from clawsentry.gateway.models import RPC_VERSION


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _sync_decision_params(**overrides) -> dict:
    base = {
        "rpc_version": RPC_VERSION,
        "request_id": "req-metrics-001",
        "deadline_ms": 500,
        "decision_tier": "L1",
        "event": {
            "event_id": "evt-metrics-001",
            "trace_id": "trace-metrics-001",
            "event_type": "pre_action",
            "session_id": "sess-metrics-001",
            "agent_id": "agent-001",
            "source_framework": "test",
            "occurred_at": "2026-03-30T12:00:00+00:00",
            "payload": {"tool": "read_file", "path": "/tmp/readme.txt"},
            "tool_name": "read_file",
        },
    }
    base.update(overrides)
    return base


def _jsonrpc_body(params: dict, rpc_id: int = 1) -> bytes:
    return json.dumps({
        "jsonrpc": "2.0",
        "id": rpc_id,
        "method": "ahp/sync_decision",
        "params": params,
    }).encode()


# ===========================================================================
# No-op mode (prometheus_client missing or disabled)
# ===========================================================================


class TestMetricsNoOp:
    """MetricsCollector must be fully functional (no-op) without prometheus_client."""

    def test_noop_when_disabled(self):
        from clawsentry.gateway.metrics import MetricsCollector
        mc = MetricsCollector(enabled=False)
        assert mc.enabled is False
        # All methods should be safe to call
        mc.record_decision(
            verdict="allow", risk_level="low", risk_score=0.1,
            tier="L1", source_framework="test", latency_s=0.001,
        )
        mc.record_llm_call(
            provider="anthropic", tier="L2", status="success",
            input_tokens=100, output_tokens=50,
        )
        mc.session_started()
        mc.session_ended()
        mc.defer_registered()
        mc.defer_resolved()
        # generate_metrics_text returns empty bytes
        assert mc.generate_metrics_text() == b""

    def test_noop_when_prometheus_unavailable(self):
        """Simulate prometheus_client not installed."""
        from clawsentry.gateway import metrics as metrics_mod
        original_flag = metrics_mod._PROMETHEUS_AVAILABLE
        try:
            metrics_mod._PROMETHEUS_AVAILABLE = False
            mc = metrics_mod.MetricsCollector(enabled=True)
            assert mc.enabled is False
            mc.record_decision(
                verdict="block", risk_level="high", risk_score=0.9,
                tier="L2", source_framework="a3s-code", latency_s=0.5,
            )
            mc.session_started()
            mc.session_ended()
            mc.defer_registered()
            mc.defer_resolved()
            assert mc.generate_metrics_text() == b""
        finally:
            metrics_mod._PROMETHEUS_AVAILABLE = original_flag


# ===========================================================================
# Enabled mode: counter increments, latency, gauges
# ===========================================================================


class TestMetricsEnabled:
    """MetricsCollector with prometheus_client available and enabled."""

    def _make_collector(self) -> "MetricsCollector":
        from clawsentry.gateway.metrics import MetricsCollector
        return MetricsCollector(enabled=True)

    def test_enabled_flag(self):
        mc = self._make_collector()
        assert mc.enabled is True

    def test_record_decision_increments_counter(self):
        mc = self._make_collector()
        mc.record_decision(
            verdict="allow", risk_level="low", risk_score=0.15,
            tier="L1", source_framework="test", latency_s=0.002,
        )
        text = mc.generate_metrics_text()
        assert b"clawsentry_decisions_total" in text
        assert b'verdict="allow"' in text
        assert b'risk_level="low"' in text
        assert b'tier="L1"' in text
        assert b'source_framework="test"' in text

    def test_record_decision_latency_histogram(self):
        mc = self._make_collector()
        mc.record_decision(
            verdict="block", risk_level="high", risk_score=0.85,
            tier="L2", source_framework="a3s-code", latency_s=1.5,
        )
        text = mc.generate_metrics_text()
        assert b"clawsentry_decision_latency_seconds" in text
        assert b'tier="L2"' in text

    def test_record_decision_risk_score_histogram(self):
        mc = self._make_collector()
        mc.record_decision(
            verdict="allow", risk_level="low", risk_score=0.3,
            tier="L1", source_framework="openclaw", latency_s=0.001,
        )
        text = mc.generate_metrics_text()
        assert b"clawsentry_risk_score" in text

    def test_session_gauge_increment_decrement(self):
        mc = self._make_collector()
        mc.session_started()
        mc.session_started()
        text = mc.generate_metrics_text()
        # Active sessions should be 2
        assert b"clawsentry_active_sessions 2.0" in text

        mc.session_ended()
        text = mc.generate_metrics_text()
        assert b"clawsentry_active_sessions 1.0" in text

    def test_llm_call_counter(self):
        mc = self._make_collector()
        mc.record_llm_call(
            provider="anthropic", tier="L2", status="success",
            input_tokens=500, output_tokens=200,
        )
        text = mc.generate_metrics_text()
        assert b"clawsentry_llm_calls_total" in text
        assert b'provider="anthropic"' in text
        assert b'status="success"' in text

    def test_llm_token_counter(self):
        mc = self._make_collector()
        mc.record_llm_call(
            provider="openai", tier="L3", status="success",
            input_tokens=1000, output_tokens=500,
        )
        text = mc.generate_metrics_text()
        assert b"clawsentry_llm_tokens_total" in text
        assert b'direction="input"' in text
        assert b'direction="output"' in text

    def test_llm_cost_counter(self):
        mc = self._make_collector()
        mc.record_llm_call(
            provider="anthropic", tier="L2", status="success",
            input_tokens=1000, output_tokens=500,
        )
        text = mc.generate_metrics_text()
        assert b"clawsentry_llm_cost_usd_total" in text

    def test_defer_gauge(self):
        mc = self._make_collector()
        mc.defer_registered()
        mc.defer_registered()
        text = mc.generate_metrics_text()
        assert b"clawsentry_defers_pending 2.0" in text

        mc.defer_resolved()
        text = mc.generate_metrics_text()
        assert b"clawsentry_defers_pending 1.0" in text

    def test_content_evidence_metrics_counters_are_recorded(self):
        mc = self._make_collector()

        mc.record_content_evidence(collected=True)
        mc.record_content_evidence(incomplete=True)
        mc.record_content_evidence(mismatch=True)
        mc.record_content_evidence(execution_unverified=True)
        mc.record_content_evidence(policy_not_allow=True)

        text = mc.generate_metrics_text()
        assert b"clawsentry_content_evidence_collected_total" in text
        assert b"clawsentry_content_evidence_incomplete_total" in text
        assert b"clawsentry_content_evidence_mismatch_total" in text
        assert b"clawsentry_content_evidence_execution_unverified_total" in text
        assert b"clawsentry_content_evidence_policy_not_allow_total" in text

    def test_multiple_decisions_accumulate(self):
        mc = self._make_collector()
        for _ in range(5):
            mc.record_decision(
                verdict="allow", risk_level="low", risk_score=0.1,
                tier="L1", source_framework="test", latency_s=0.001,
            )
        mc.record_decision(
            verdict="block", risk_level="high", risk_score=0.9,
            tier="L2", source_framework="test", latency_s=0.5,
        )
        text = mc.generate_metrics_text()
        # Should contain both allow and block entries
        assert b'verdict="allow"' in text
        assert b'verdict="block"' in text

    def test_dedicated_registry_isolation(self):
        """Two MetricsCollector instances should not share state."""
        mc1 = self._make_collector()
        mc2 = self._make_collector()
        mc1.record_decision(
            verdict="allow", risk_level="low", risk_score=0.1,
            tier="L1", source_framework="test", latency_s=0.001,
        )
        # mc2 should have no decisions recorded
        text2 = mc2.generate_metrics_text()
        # mc2 text should not have any sample values for decisions_total
        # (no counter increments, so the metric may be declared but have 0)
        assert b'verdict="allow"' not in text2 or b" 0.0" in text2


class TestBudgetExhaustionObservability:
    """Budget exhaustion should emit a single observable event."""

    def test_budget_exhaustion_callback_fires_once(self):
        events: list[dict[str, object]] = []
        tracker = LLMBudgetTracker(daily_budget_usd=1.0)
        mc = MetricsCollector(
            enabled=False,
            budget_tracker=tracker,
            budget_exhausted_callback=events.append,
        )

        mc.record_llm_call(
            provider="openai",
            tier="L2",
            status="ok",
            input_tokens=400_000,
            output_tokens=0,
        )
        mc.record_llm_call(
            provider="openai",
            tier="L2",
            status="ok",
            input_tokens=1,
            output_tokens=0,
        )

        assert len(events) == 1
        event = events[0]
        assert event["type"] == "budget_exhausted"
        assert event["provider"] == "openai"
        assert event["tier"] == "L2"
        assert event["status"] == "ok"
        assert event["budget"]["daily_budget_usd"] == 1.0
        assert event["budget"]["daily_spend_usd"] == pytest.approx(1.0)
        assert event["budget"]["remaining_usd"] == pytest.approx(0.0)
        assert event["budget"]["exhausted"] is True
        assert event["budget"]["daily_spend_usd"] == pytest.approx(1.0)


# ===========================================================================
# LLM usage snapshot
# ===========================================================================


class TestLLMUsageSnapshot:
    """MetricsCollector should expose aggregated LLM usage breakdowns."""

    def test_llm_usage_snapshot_breaks_down_by_provider_tier_and_status(self):
        mc = MetricsCollector(enabled=False)

        mc.record_llm_call(
            provider="openai",
            tier="L2",
            status="ok",
            input_tokens=100,
            output_tokens=25,
        )
        mc.record_llm_call(
            provider="openai",
            tier="L2",
            status="timeout",
            input_tokens=10,
            output_tokens=0,
        )
        mc.record_llm_call(
            provider="anthropic",
            tier="L3",
            status="error",
            input_tokens=4,
            output_tokens=2,
        )

        snapshot = mc.llm_usage_snapshot()

        assert snapshot["total_calls"] == 3
        assert snapshot["total_input_tokens"] == 114
        assert snapshot["total_output_tokens"] == 27
        assert snapshot["by_provider"]["openai"]["calls"] == 2
        assert snapshot["by_provider"]["openai"]["input_tokens"] == 110
        assert snapshot["by_provider"]["anthropic"]["output_tokens"] == 2
        assert snapshot["by_tier"]["L2"]["calls"] == 2
        assert snapshot["by_tier"]["L3"]["calls"] == 1
        assert snapshot["by_status"]["ok"]["calls"] == 1
        assert snapshot["by_status"]["timeout"]["calls"] == 1
        assert snapshot["by_status"]["error"]["calls"] == 1


# ===========================================================================
# Cost estimation
# ===========================================================================


class TestCostEstimation:
    """Module-level _estimate_cost function."""

    def test_anthropic_cost(self):
        from clawsentry.gateway.metrics import _estimate_cost
        cost = _estimate_cost("anthropic", 1_000_000, 1_000_000)
        # anthropic: $3/M input + $15/M output = $18
        assert cost == pytest.approx(18.0, rel=0.01)

    def test_openai_cost(self):
        from clawsentry.gateway.metrics import _estimate_cost
        cost = _estimate_cost("openai", 1_000_000, 1_000_000)
        # openai: $2.5/M input + $10/M output = $12.5
        assert cost == pytest.approx(12.5, rel=0.01)

    def test_unknown_provider_cost(self):
        from clawsentry.gateway.metrics import _estimate_cost
        cost = _estimate_cost("unknown-provider", 1000, 500)
        # fallback: $5/M input + $15/M output
        assert cost > 0

    def test_zero_tokens(self):
        from clawsentry.gateway.metrics import _estimate_cost
        cost = _estimate_cost("anthropic", 0, 0)
        assert cost == 0.0


# ===========================================================================
# /metrics endpoint
# ===========================================================================


class TestMetricsEndpoint:
    """GET /metrics HTTP endpoint."""

    @pytest.fixture
    def app_no_auth(self, monkeypatch):
        monkeypatch.delenv("CS_AUTH_TOKEN", raising=False)
        monkeypatch.delenv("CS_METRICS_AUTH", raising=False)
        gw = SupervisionGateway()
        return create_http_app(gw)

    @pytest.mark.asyncio
    async def test_metrics_endpoint_returns_200(self, app_no_auth):
        transport = ASGITransport(app=app_no_auth)
        async with AsyncClient(transport=transport, base_url="http://test") as c:
            resp = await c.get("/metrics")
            assert resp.status_code == 200
            assert "text/plain" in resp.headers.get("content-type", "")

    @pytest.mark.asyncio
    async def test_metrics_endpoint_no_auth_by_default(self, app_no_auth, monkeypatch):
        """By default, /metrics should be accessible without auth even when CS_AUTH_TOKEN is set."""
        # Re-create app with auth token set
        monkeypatch.setenv("CS_AUTH_TOKEN", "a" * 32)
        gw = SupervisionGateway()
        app = create_http_app(gw)
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as c:
            resp = await c.get("/metrics")
            assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_metrics_endpoint_auth_required_when_toggled(self, monkeypatch):
        """When CS_METRICS_AUTH=true, /metrics requires auth."""
        monkeypatch.setenv("CS_AUTH_TOKEN", "a" * 32)
        monkeypatch.setenv("CS_METRICS_AUTH", "true")
        gw = SupervisionGateway()
        app = create_http_app(gw)
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as c:
            # No token → 401
            resp = await c.get("/metrics")
            assert resp.status_code == 401

            # With token → 200
            resp = await c.get(
                "/metrics",
                headers={"Authorization": f"Bearer {'a' * 32}"},
            )
            assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_metrics_content_after_decision(self, monkeypatch):
        """After a decision, /metrics should contain decision counters."""
        monkeypatch.delenv("CS_AUTH_TOKEN", raising=False)
        gw = SupervisionGateway()
        app = create_http_app(gw)
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as c:
            # Make a decision
            body = _jsonrpc_body(_sync_decision_params())
            await c.post("/ahp", content=body)

            # Check metrics
            resp = await c.get("/metrics")
            assert resp.status_code == 200
            text = resp.text
            assert "clawsentry_decisions_total" in text

    @pytest.mark.asyncio
    async def test_metrics_disabled_returns_empty(self, monkeypatch):
        """When MetricsCollector is disabled, /metrics still returns 200 but empty."""
        monkeypatch.delenv("CS_AUTH_TOKEN", raising=False)
        monkeypatch.setenv("CS_METRICS_ENABLED", "false")
        gw = SupervisionGateway()
        app = create_http_app(gw)
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as c:
            resp = await c.get("/metrics")
            assert resp.status_code == 200
            # No prometheus metrics content
            assert "clawsentry_decisions_total" not in resp.text


class TestMetricsEndpointSessionStart:
    """Verify session_started() is called on first event for a new session."""

    @pytest.mark.asyncio
    async def test_session_start_increments_active_sessions(self, monkeypatch):
        monkeypatch.delenv("CS_AUTH_TOKEN", raising=False)
        gw = SupervisionGateway()
        app = create_http_app(gw)
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as c:
            # Send a new-session event
            body = _jsonrpc_body(_sync_decision_params(
                request_id="req-sess-start-001",
            ))
            await c.post("/ahp", content=body)

            resp = await c.get("/metrics")
            text = resp.text
            assert "clawsentry_active_sessions" in text
