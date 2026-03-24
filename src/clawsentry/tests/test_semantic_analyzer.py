"""Tests for L2 pluggable semantic analysis — SemanticAnalyzer Protocol."""

import asyncio
import pytest
from clawsentry.gateway.models import (
    CanonicalEvent,
    DecisionContext,
    EventType,
    RiskLevel,
    RiskSnapshot,
    RiskDimensions,
    ClassifiedBy,
    AgentTrustLevel,
)
from unittest.mock import AsyncMock, MagicMock
from clawsentry.gateway.semantic_analyzer import L2Result, SemanticAnalyzer, RuleBasedAnalyzer, LLMAnalyzer, LLMAnalyzerConfig, CompositeAnalyzer
from clawsentry.gateway.policy_engine import L1PolicyEngine


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _evt(tool_name=None, payload=None, event_type="pre_action",
         session_id="sess-1", **kw) -> CanonicalEvent:
    return CanonicalEvent(
        event_id="evt-test",
        trace_id="trace-test",
        event_type=event_type,
        session_id=session_id,
        agent_id="agent-test",
        source_framework="test",
        occurred_at="2026-03-19T12:00:00+00:00",
        payload=payload or {},
        tool_name=tool_name,
        **kw,
    )

def _snap(risk_level=RiskLevel.MEDIUM, score=2) -> RiskSnapshot:
    return RiskSnapshot(
        risk_level=risk_level,
        composite_score=score,
        dimensions=RiskDimensions(d1=1, d2=0, d3=0, d4=0, d5=1),
        classified_by=ClassifiedBy.L1,
        classified_at="2026-03-19T12:00:00+00:00",
    )

def _ctx(trust=None) -> DecisionContext:
    return DecisionContext(agent_trust_level=trust)


# ===========================================================================
# L2Result Tests
# ===========================================================================

class TestL2Result:
    def test_construction(self):
        r = L2Result(
            target_level=RiskLevel.HIGH,
            reasons=["test reason"],
            confidence=0.9,
            analyzer_id="test",
            latency_ms=1.5,
        )
        assert r.target_level == RiskLevel.HIGH
        assert r.confidence == 0.9
        assert r.analyzer_id == "test"

    def test_frozen(self):
        r = L2Result(
            target_level=RiskLevel.LOW,
            reasons=[],
            confidence=1.0,
            analyzer_id="test",
            latency_ms=0.0,
        )
        with pytest.raises(AttributeError):
            r.target_level = RiskLevel.HIGH


# ===========================================================================
# RuleBasedAnalyzer Tests — equivalence with policy_engine._run_l2_analysis
# ===========================================================================

class TestRuleBasedAnalyzer:
    def test_analyzer_id(self):
        a = RuleBasedAnalyzer()
        assert a.analyzer_id == "rule-based"

    def test_satisfies_protocol(self):
        a = RuleBasedAnalyzer()
        assert isinstance(a, SemanticAnalyzer)

    def test_no_hints_returns_same_level(self):
        a = RuleBasedAnalyzer()
        snap = _snap(RiskLevel.MEDIUM)
        result = asyncio.run(
            a.analyze(_evt(tool_name="write_file"), _ctx(), snap, 5000)
        )
        assert result.target_level == RiskLevel.MEDIUM
        assert result.confidence == 1.0

    def test_high_risk_hint_upgrades_to_high(self):
        a = RuleBasedAnalyzer()
        snap = _snap(RiskLevel.MEDIUM)
        evt = _evt(tool_name="write_file", risk_hints=["credential_exfiltration"])
        result = asyncio.run(
            a.analyze(evt, _ctx(), snap, 5000)
        )
        assert result.target_level == RiskLevel.HIGH
        assert "risk_hints indicate semantic threat" in result.reasons

    def test_critical_hint_upgrades_to_critical(self):
        a = RuleBasedAnalyzer()
        snap = _snap(RiskLevel.MEDIUM)
        evt = _evt(tool_name="write_file", risk_hints=["privilege_escalation_confirmed"])
        result = asyncio.run(
            a.analyze(evt, _ctx(), snap, 5000)
        )
        assert result.target_level == RiskLevel.CRITICAL

    def test_key_domain_plus_critical_intent(self):
        a = RuleBasedAnalyzer()
        snap = _snap(RiskLevel.LOW, score=1)
        evt = _evt(
            tool_name="bash",
            payload={"command": "bypass credential checks in production"},
        )
        result = asyncio.run(
            a.analyze(evt, _ctx(), snap, 5000)
        )
        assert result.target_level == RiskLevel.CRITICAL
        assert "critical intent on key domain asset" in result.reasons

    def test_key_domain_plus_dangerous_tool(self):
        a = RuleBasedAnalyzer()
        snap = _snap(RiskLevel.LOW, score=1)
        evt = _evt(
            tool_name="bash",
            payload={"command": "cat credentials.json"},
        )
        result = asyncio.run(
            a.analyze(evt, _ctx(), snap, 5000)
        )
        assert result.target_level == RiskLevel.HIGH

    def test_manual_escalation_flag(self):
        a = RuleBasedAnalyzer()
        snap = _snap(RiskLevel.LOW, score=1)
        ctx = DecisionContext(
            session_risk_summary={"l2_escalate": True},
        )
        result = asyncio.run(
            a.analyze(_evt(tool_name="read_file"), ctx, snap, 5000)
        )
        assert result.target_level == RiskLevel.HIGH

    def test_never_downgrades(self):
        """RuleBasedAnalyzer should return at least the L1 level."""
        a = RuleBasedAnalyzer()
        snap = _snap(RiskLevel.HIGH, score=4)
        evt = _evt(tool_name="read_file")
        result = asyncio.run(
            a.analyze(evt, _ctx(), snap, 5000)
        )
        assert result.target_level in (RiskLevel.HIGH, RiskLevel.CRITICAL)

    def test_latency_is_recorded(self):
        a = RuleBasedAnalyzer()
        snap = _snap(RiskLevel.MEDIUM)
        result = asyncio.run(
            a.analyze(_evt(tool_name="write_file"), _ctx(), snap, 5000)
        )
        assert result.latency_ms >= 0


# ===========================================================================
# L1PolicyEngine + SemanticAnalyzer Integration Tests
# ===========================================================================

class TestPolicyEngineIntegration:
    def test_default_uses_rule_based(self):
        """Default construction uses RuleBasedAnalyzer -- backward compatible."""
        engine = L1PolicyEngine()
        assert engine.analyzer.analyzer_id == "rule-based"

    def test_custom_analyzer_injection(self):
        """Can inject a custom analyzer."""
        class StubAnalyzer:
            @property
            def analyzer_id(self):
                return "stub"
            async def analyze(self, event, context, l1_snapshot, budget_ms):
                return L2Result(
                    target_level=RiskLevel.CRITICAL,
                    reasons=["stub always critical"],
                    confidence=0.99,
                    analyzer_id="stub",
                    latency_ms=0.1,
                )

        engine = L1PolicyEngine(analyzer=StubAnalyzer())
        evt = _evt(
            tool_name="http_request",
            payload={"url": "https://example.com"},
            risk_hints=["credential_exfiltration"],
        )
        # This event is MEDIUM L1, triggers auto-escalation to L2
        decision, snapshot, tier = engine.evaluate(evt, _ctx(AgentTrustLevel.STANDARD))
        assert tier.value == "L2"
        assert snapshot.risk_level == RiskLevel.CRITICAL
        assert decision.decision.value == "block"

    def test_backward_compat_no_args(self):
        """L1PolicyEngine() with no args behaves identically to before."""
        engine = L1PolicyEngine()
        evt = _evt(
            tool_name="http_request",
            payload={"url": "https://example.com"},
            risk_hints=["credential_exfiltration"],
        )
        decision, snapshot, tier = engine.evaluate(evt, _ctx(AgentTrustLevel.STANDARD))
        assert tier.value == "L2"
        assert snapshot.risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL)
        assert snapshot.override is not None


# ===========================================================================
# LLMAnalyzer Tests
# ===========================================================================

class TestLLMAnalyzer:
    def _make_mock_provider(self, response_text: str):
        provider = MagicMock()
        provider.provider_id = "mock-llm"
        provider.complete = AsyncMock(return_value=response_text)
        return provider

    def test_analyzer_id(self):
        provider = self._make_mock_provider("{}")
        a = LLMAnalyzer(provider=provider)
        assert a.analyzer_id == "llm-mock-llm"

    def test_successful_analysis_high(self):
        response = '{"risk_assessment": "high", "reasons": ["suspicious pattern"], "confidence": 0.85}'
        provider = self._make_mock_provider(response)
        a = LLMAnalyzer(provider=provider)
        snap = _snap(RiskLevel.MEDIUM)
        result = asyncio.run(
            a.analyze(_evt(tool_name="bash", payload={"command": "curl secrets"}), _ctx(), snap, 3000)
        )
        assert result.target_level == RiskLevel.HIGH
        assert result.confidence == 0.85
        assert "suspicious pattern" in result.reasons

    def test_successful_analysis_low(self):
        response = '{"risk_assessment": "low", "reasons": ["safe operation"], "confidence": 0.95}'
        provider = self._make_mock_provider(response)
        a = LLMAnalyzer(provider=provider)
        snap = _snap(RiskLevel.MEDIUM)
        result = asyncio.run(
            a.analyze(_evt(tool_name="read_file"), _ctx(), snap, 3000)
        )
        # LLMAnalyzer can suggest lower — upgrade-only is enforced by L1PolicyEngine
        assert result.target_level == RiskLevel.LOW
        assert result.confidence == 0.95

    def test_parse_failure_degrades_to_l1(self):
        provider = self._make_mock_provider("I cannot parse this as JSON")
        a = LLMAnalyzer(provider=provider)
        snap = _snap(RiskLevel.MEDIUM)
        result = asyncio.run(
            a.analyze(_evt(tool_name="write_file"), _ctx(), snap, 3000)
        )
        assert result.target_level == RiskLevel.MEDIUM  # Falls back to L1 level
        assert result.confidence == 0.0

    def test_timeout_degrades_to_l1(self):
        provider = MagicMock()
        provider.provider_id = "mock-slow"

        async def slow(*args, **kwargs):
            await asyncio.sleep(10)

        provider.complete = slow
        a = LLMAnalyzer(provider=provider, config=LLMAnalyzerConfig(provider_timeout_ms=50))
        snap = _snap(RiskLevel.MEDIUM)
        result = asyncio.run(
            a.analyze(_evt(tool_name="write_file"), _ctx(), snap, 100)
        )
        assert result.target_level == RiskLevel.MEDIUM
        assert result.confidence == 0.0

    def test_exception_degrades_to_l1(self):
        provider = MagicMock()
        provider.provider_id = "mock-err"
        provider.complete = AsyncMock(side_effect=RuntimeError("API error"))
        a = LLMAnalyzer(provider=provider)
        snap = _snap(RiskLevel.MEDIUM)
        result = asyncio.run(
            a.analyze(_evt(tool_name="write_file"), _ctx(), snap, 3000)
        )
        assert result.target_level == RiskLevel.MEDIUM
        assert result.confidence == 0.0

    def test_prompt_includes_event_context(self):
        """Verify the prompt sent to LLM contains event info."""
        provider = MagicMock()
        provider.provider_id = "mock"
        provider.complete = AsyncMock(return_value='{"risk_assessment":"low","reasons":[],"confidence":0.5}')
        a = LLMAnalyzer(provider=provider)
        snap = _snap(RiskLevel.MEDIUM)
        asyncio.run(
            a.analyze(
                _evt(tool_name="bash", payload={"command": "ls"}),
                _ctx(),
                snap,
                3000,
            )
        )
        call_args = provider.complete.call_args
        # The user_message is the second positional arg
        user_msg = call_args[0][1] if len(call_args[0]) > 1 else call_args[1].get("user_message", "")
        assert "bash" in user_msg
        assert "ls" in user_msg

    def test_invalid_risk_level_in_response(self):
        """Unknown risk_assessment value degrades to L1."""
        response = '{"risk_assessment": "unknown_level", "reasons": [], "confidence": 0.5}'
        provider = self._make_mock_provider(response)
        a = LLMAnalyzer(provider=provider)
        snap = _snap(RiskLevel.MEDIUM)
        result = asyncio.run(
            a.analyze(_evt(tool_name="write_file"), _ctx(), snap, 3000)
        )
        assert result.target_level == RiskLevel.MEDIUM
        assert result.confidence == 0.0


# ===========================================================================
# CompositeAnalyzer Tests
# ===========================================================================

class TestCompositeAnalyzer:
    def test_analyzer_id(self):
        a = CompositeAnalyzer(analyzers=[RuleBasedAnalyzer()])
        assert a.analyzer_id == "composite(rule-based)"

    def test_single_analyzer_passthrough(self):
        a = CompositeAnalyzer(analyzers=[RuleBasedAnalyzer()])
        snap = _snap(RiskLevel.MEDIUM)
        evt = _evt(tool_name="write_file", risk_hints=["credential_exfiltration"])
        result = asyncio.run(
            a.analyze(evt, _ctx(), snap, 5000)
        )
        assert result.target_level == RiskLevel.HIGH

    def test_takes_highest_risk_level(self):
        """When multiple analyzers return, take the highest risk level."""
        class HighAnalyzer:
            @property
            def analyzer_id(self):
                return "always-high"
            async def analyze(self, event, context, l1_snapshot, budget_ms):
                return L2Result(RiskLevel.HIGH, ["high"], 0.8, "always-high", 1.0)

        class LowAnalyzer:
            @property
            def analyzer_id(self):
                return "always-low"
            async def analyze(self, event, context, l1_snapshot, budget_ms):
                return L2Result(RiskLevel.LOW, ["low"], 0.9, "always-low", 1.0)

        a = CompositeAnalyzer(analyzers=[HighAnalyzer(), LowAnalyzer()])
        snap = _snap(RiskLevel.MEDIUM)
        result = asyncio.run(
            a.analyze(_evt(tool_name="write_file"), _ctx(), snap, 5000)
        )
        assert result.target_level == RiskLevel.HIGH

    def test_filters_degraded_results(self):
        """Results with confidence=0.0 are treated as degraded and filtered."""
        class DegradedAnalyzer:
            @property
            def analyzer_id(self):
                return "degraded"
            async def analyze(self, event, context, l1_snapshot, budget_ms):
                return L2Result(RiskLevel.CRITICAL, ["degraded"], 0.0, "degraded", 1.0)

        class GoodAnalyzer:
            @property
            def analyzer_id(self):
                return "good"
            async def analyze(self, event, context, l1_snapshot, budget_ms):
                return L2Result(RiskLevel.HIGH, ["good"], 0.8, "good", 1.0)

        a = CompositeAnalyzer(analyzers=[DegradedAnalyzer(), GoodAnalyzer()])
        snap = _snap(RiskLevel.MEDIUM)
        result = asyncio.run(
            a.analyze(_evt(tool_name="write_file"), _ctx(), snap, 5000)
        )
        assert result.target_level == RiskLevel.HIGH
        assert result.analyzer_id == "good"

    def test_all_degraded_returns_l1_level(self):
        class FailAnalyzer:
            @property
            def analyzer_id(self):
                return "fail"
            async def analyze(self, event, context, l1_snapshot, budget_ms):
                raise RuntimeError("boom")

        a = CompositeAnalyzer(analyzers=[FailAnalyzer()])
        snap = _snap(RiskLevel.MEDIUM)
        result = asyncio.run(
            a.analyze(_evt(tool_name="write_file"), _ctx(), snap, 5000)
        )
        assert result.target_level == RiskLevel.MEDIUM
        assert result.confidence == 0.0

    def test_agent_analyzer_degraded_result_is_ignored(self):
        class RuleAnalyzer:
            @property
            def analyzer_id(self):
                return "rule-based"
            async def analyze(self, event, context, l1_snapshot, budget_ms):
                return L2Result(RiskLevel.HIGH, ["rule"], 1.0, "rule-based", 0.5)

        class AgentAnalyzerStub:
            @property
            def analyzer_id(self):
                return "agent-reviewer"
            async def analyze(self, event, context, l1_snapshot, budget_ms):
                return L2Result(RiskLevel.CRITICAL, ["degraded"], 0.0, "agent-reviewer", 1.0)

        a = CompositeAnalyzer(analyzers=[RuleAnalyzer(), AgentAnalyzerStub()])
        snap = _snap(RiskLevel.MEDIUM)
        result = asyncio.run(
            a.analyze(_evt(tool_name="write_file"), _ctx(), snap, 5000)
        )
        assert result.target_level == RiskLevel.HIGH
        assert result.analyzer_id == "rule-based"


# ===========================================================================
# L2Result trace field tests
# ===========================================================================

def test_l2_result_trace_field_default_none():
    result = L2Result(target_level=RiskLevel.LOW, reasons=[], confidence=1.0, analyzer_id="test")
    assert result.trace is None


def test_l2_result_trace_field_with_data():
    trace = {"trigger_reason": "test", "turns": []}
    result = L2Result(target_level=RiskLevel.LOW, reasons=[], confidence=1.0, analyzer_id="test", trace=trace)
    assert result.trace == trace
    assert result.trace["trigger_reason"] == "test"


# ===========================================================================
# LLM Prompt Sanitization Tests (H3)
# ===========================================================================

class TestLLMPromptSanitization:
    """H3: LLM prompt should not contain raw secrets."""

    def test_payload_truncated_in_prompt(self):
        from clawsentry.gateway.semantic_analyzer import LLMAnalyzer
        from unittest.mock import AsyncMock
        provider = AsyncMock()
        provider.provider_id = "mock"
        analyzer = LLMAnalyzer(provider)
        event = _evt(
            tool_name="read_file",
            payload={"content": "A" * 50000, "command": "cat big.txt"},
        )
        from clawsentry.gateway.risk_snapshot import compute_risk_snapshot, SessionRiskTracker
        tracker = SessionRiskTracker()
        snap = compute_risk_snapshot(event, None, tracker)
        prompt = analyzer._build_prompt(event, None, snap)
        assert len(prompt) <= 8192, f"Prompt too long: {len(prompt)}"

    def test_secret_values_redacted_in_prompt(self):
        from clawsentry.gateway.semantic_analyzer import LLMAnalyzer
        from unittest.mock import AsyncMock
        provider = AsyncMock()
        provider.provider_id = "mock"
        analyzer = LLMAnalyzer(provider)
        event = _evt(
            tool_name="bash",
            payload={"command": "export AWS_SECRET_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE"},
        )
        from clawsentry.gateway.risk_snapshot import compute_risk_snapshot, SessionRiskTracker
        snap = compute_risk_snapshot(event, None, SessionRiskTracker())
        prompt = analyzer._build_prompt(event, None, snap)
        assert "AKIAIOSFODNN7EXAMPLE" not in prompt


# ===========================================================================
# _parse_response Type Safety Tests (H4)
# ===========================================================================

class TestParseResponseTypeSafety:
    """H4: _parse_response must handle non-string reasons."""

    def test_mixed_type_reasons_coerced_to_strings(self):
        from clawsentry.gateway.semantic_analyzer import LLMAnalyzer
        from unittest.mock import AsyncMock
        import json
        import time
        provider = AsyncMock()
        provider.provider_id = "mock"
        analyzer = LLMAnalyzer(provider)
        from clawsentry.gateway.risk_snapshot import compute_risk_snapshot, SessionRiskTracker
        event = _evt(tool_name="bash", payload={"command": "ls"})
        snap = compute_risk_snapshot(event, None, SessionRiskTracker())
        raw = json.dumps({
            "risk_assessment": "low",
            "reasons": [{"nested": "object"}, 42, None, "valid string"],
            "confidence": 0.8,
        })
        result = analyzer._parse_response(raw, snap, time.monotonic())
        assert all(isinstance(r, str) for r in result.reasons)
        joined = "; ".join(result.reasons)  # must not raise TypeError
        assert isinstance(joined, str)


# ===========================================================================
# event_text Size Cap Tests (M5)
# ===========================================================================

class TestEventTextSizeCap:
    """M5: event_text should cap output size."""

    def test_large_payload_capped(self):
        from clawsentry.gateway.semantic_analyzer import event_text
        event = _evt(
            tool_name="read_file",
            payload={"content": "X" * 500_000},
        )
        text = event_text(event)
        assert len(text) <= 65_536, f"event_text too long: {len(text)}"

    def test_small_payload_unchanged(self):
        from clawsentry.gateway.semantic_analyzer import event_text
        event = _evt(
            tool_name="bash",
            payload={"command": "echo hello"},
        )
        text = event_text(event)
        assert "echo hello" in text
