"""Tests for ``clawsentry test-llm`` command."""

from __future__ import annotations

import asyncio
import json
import os
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from clawsentry.cli.test_llm_command import (
    _build_provider,
    _format_l3_detail,
    _test_l2,
    _test_l3,
    _test_reachability,
    run_test_llm,
)
from clawsentry.gateway.models import RiskLevel
from clawsentry.gateway.semantic_analyzer import L2Result


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_LLM_ENV_KEYS = [
    "CS_LLM_PROVIDER",
    "CS_LLM_API_KEY",
    "CS_LLM_MODEL",
    "CS_LLM_BASE_URL",
    "ANTHROPIC_API_KEY",
    "OPENAI_API_KEY",
    "CS_L3_ENABLED",
    "CS_L3_MULTI_TURN",
    "CS_LLM_MAX_TOKENS",
]


@pytest.fixture(autouse=True)
def _clean_llm_env(monkeypatch):
    for k in _LLM_ENV_KEYS:
        monkeypatch.delenv(k, raising=False)


# ---------------------------------------------------------------------------
# _build_provider
# ---------------------------------------------------------------------------


class TestBuildProvider:
    def test_no_provider_no_key(self):
        provider, info = _build_provider()
        assert provider is None
        assert "No LLM provider" in info

    def test_auto_detect_anthropic(self, monkeypatch):
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test-key-1234567890abcdef")
        provider, info = _build_provider()
        assert provider is not None
        assert info["provider"] == "anthropic"

    def test_auto_detect_openai(self, monkeypatch):
        monkeypatch.setenv("OPENAI_API_KEY", "sk-test-key-1234567890abcdef")
        provider, info = _build_provider()
        assert provider is not None
        assert info["provider"] == "openai"

    def test_explicit_anthropic(self, monkeypatch):
        monkeypatch.setenv("CS_LLM_PROVIDER", "anthropic")
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test-key-1234567890abcdef")
        provider, info = _build_provider()
        assert provider is not None
        assert info["provider"] == "anthropic"
        assert "sk-ant" in info["key_preview"]

    def test_explicit_openai(self, monkeypatch):
        monkeypatch.setenv("CS_LLM_PROVIDER", "openai")
        monkeypatch.setenv("OPENAI_API_KEY", "sk-test-key-1234567890abcdef")
        provider, info = _build_provider()
        assert provider is not None
        assert info["provider"] == "openai"

    def test_missing_api_key_anthropic(self, monkeypatch):
        monkeypatch.setenv("CS_LLM_PROVIDER", "anthropic")
        provider, info = _build_provider()
        assert provider is None
        assert "no API key" in info

    def test_missing_api_key_openai(self, monkeypatch):
        monkeypatch.setenv("CS_LLM_PROVIDER", "openai")
        provider, info = _build_provider()
        assert provider is None
        assert "no API key" in info

    def test_unknown_provider(self, monkeypatch):
        monkeypatch.setenv("CS_LLM_PROVIDER", "llamacpp")
        provider, info = _build_provider()
        assert provider is None
        assert "Unknown" in info

    def test_custom_model(self, monkeypatch):
        monkeypatch.setenv("CS_LLM_PROVIDER", "openai")
        monkeypatch.setenv("OPENAI_API_KEY", "sk-test-key-1234567890abcdef")
        monkeypatch.setenv("CS_LLM_MODEL", "gpt-4o")
        provider, info = _build_provider()
        assert info["model"] == "gpt-4o"

    def test_cs_llm_api_key_fallback(self, monkeypatch):
        monkeypatch.setenv("CS_LLM_PROVIDER", "anthropic")
        monkeypatch.setenv("CS_LLM_API_KEY", "sk-ant-test-key-1234567890abcdef")
        provider, info = _build_provider()
        assert provider is not None

    def test_anthropic_custom_base_url(self, monkeypatch):
        monkeypatch.setenv("CS_LLM_PROVIDER", "anthropic")
        monkeypatch.setenv("CS_LLM_API_KEY", "sk-ant-test-key-1234567890abcdef")
        monkeypatch.setenv("CS_LLM_BASE_URL", "http://llm-gateway.example/v1/")
        provider, info = _build_provider()
        assert provider is not None
        assert provider._config.base_url == "http://llm-gateway.example/v1/"
        assert info["base_url"] == "http://llm-gateway.example/v1/"

    def test_key_preview_masking(self, monkeypatch):
        monkeypatch.setenv("CS_LLM_PROVIDER", "anthropic")
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-api-1234567890abcdef-long-key")
        provider, info = _build_provider()
        assert "..." in info["key_preview"]
        # Should not expose full key
        assert "1234567890" not in info["key_preview"]


# ---------------------------------------------------------------------------
# _test_reachability
# ---------------------------------------------------------------------------


class TestReachability:
    def test_success(self):
        provider = MagicMock()
        provider.complete = AsyncMock(return_value="PONG")
        ok, latency, detail = asyncio.run(_test_reachability(provider))
        assert ok is True
        assert latency > 0
        assert "PONG" in detail

    def test_passes_configured_max_tokens(self):
        provider = MagicMock()
        provider.complete = AsyncMock(return_value="PONG")
        ok, _, _ = asyncio.run(_test_reachability(provider, max_tokens=1024))
        assert ok is True
        assert provider.complete.await_args.kwargs["max_tokens"] == 1024

    def test_timeout(self):
        async def slow_complete(*args, **kwargs):
            raise asyncio.TimeoutError()

        provider = MagicMock()
        provider.complete = slow_complete
        ok, latency, detail = asyncio.run(_test_reachability(provider, timeout_ms=100))
        assert ok is False
        assert "Timeout" in detail

    def test_api_error(self):
        async def error_complete(*args, **kwargs):
            raise ConnectionError("Connection refused")

        provider = MagicMock()
        provider.complete = error_complete
        ok, latency, detail = asyncio.run(_test_reachability(provider))
        assert ok is False
        assert "Connection refused" in detail


class TestL2Probe:
    def test_passes_timeout_to_analyzer_config(self, monkeypatch):
        captured: dict[str, object] = {}

        class FakeAnalyzer:
            def __init__(self, provider, config):
                captured["provider_timeout_ms"] = config.provider_timeout_ms
                captured["max_tokens"] = config.max_tokens

            async def analyze(self, event, context, l1_snapshot, budget_ms):
                return L2Result(
                    target_level=RiskLevel.HIGH,
                    reasons=["credential access detected"],
                    confidence=0.95,
                )

        monkeypatch.setattr("clawsentry.gateway.semantic_analyzer.LLMAnalyzer", FakeAnalyzer)

        provider = MagicMock()
        ok, _, _ = asyncio.run(_test_l2(provider, timeout_ms=30000, max_tokens=1024))

        assert ok is True
        assert captured == {"provider_timeout_ms": 30000, "max_tokens": 1024}

    def test_defaults_to_large_l2_max_tokens(self, monkeypatch):
        captured: dict[str, object] = {}

        class FakeAnalyzer:
            def __init__(self, provider, config):
                captured["max_tokens"] = config.max_tokens

            async def analyze(self, event, context, l1_snapshot, budget_ms):
                return L2Result(
                    target_level=RiskLevel.HIGH,
                    reasons=["credential access detected"],
                    confidence=0.95,
                )

        monkeypatch.setattr("clawsentry.gateway.semantic_analyzer.LLMAnalyzer", FakeAnalyzer)

        provider = MagicMock()
        ok, _, _ = asyncio.run(_test_l2(provider))

        assert ok is True
        assert captured["max_tokens"] == 10000

    def test_success_formats_current_l2_result_shape(self, monkeypatch):
        async def fake_analyze(self, event, context, l1_snapshot, budget_ms):
            return L2Result(
                target_level=RiskLevel.HIGH,
                reasons=["credential access detected"],
                confidence=0.95,
            )

        monkeypatch.setattr(
            "clawsentry.gateway.semantic_analyzer.LLMAnalyzer.analyze",
            fake_analyze,
        )

        provider = MagicMock()
        ok, latency, detail = asyncio.run(_test_l2(provider))

        assert ok is True
        assert latency > 0
        assert "risk=high" in detail
        assert "confidence=0.95" in detail
        assert "credential access detected" in detail


class TestL3Probe:
    def test_format_l3_detail_includes_trigger_detail(self):
        result = L2Result(
            target_level=RiskLevel.HIGH,
            reasons=["operator review confirmed"],
            confidence=0.91,
        )

        detail = _format_l3_detail(
            result,
            {
                "mode": "multi_turn",
                "trigger_reason": "suspicious_pattern",
                "trigger_detail": "secret_plus_network",
                "turns": [],
            },
        )

        assert "mode=multi_turn" in detail
        assert "trigger=suspicious_pattern" in detail
        assert "detail=secret_plus_network" in detail

    def test_uses_runtime_multi_turn_default_when_enabled(self, monkeypatch):
        captured: dict[str, object] = {}

        class FakeAgent:
            def __init__(self, provider, toolkit, skill_registry, config, **kwargs):
                captured["enable_multi_turn"] = config.enable_multi_turn
                captured["l3_budget_ms"] = config.l3_budget_ms

            async def analyze(self, event, context, l1_snapshot, budget_ms):
                captured["budget_ms"] = budget_ms
                return L2Result(
                    target_level=RiskLevel.HIGH,
                    reasons=["operator review confirmed"],
                    confidence=0.91,
                    trace={
                        "mode": "multi_turn",
                        "trigger_reason": "manual_l3_escalate",
                        "turns": [],
                    },
                )

        monkeypatch.setenv("CS_L3_ENABLED", "true")
        monkeypatch.setattr("clawsentry.gateway.agent_analyzer.AgentAnalyzer", FakeAgent)

        provider = MagicMock()
        ok, _, detail = asyncio.run(_test_l3(provider))

        assert ok is True
        assert captured["enable_multi_turn"] is True
        assert captured["l3_budget_ms"] == 300000
        assert captured["budget_ms"] == 300000
        assert "mode=multi_turn" in detail

    def test_success_detail_includes_runtime_mode_and_trigger_reason(self, monkeypatch):
        async def fake_analyze(self, event, context, l1_snapshot, budget_ms):
            return L2Result(
                target_level=RiskLevel.HIGH,
                reasons=["operator review confirmed"],
                confidence=0.91,
                trace={
                    "mode": "multi_turn",
                    "trigger_reason": "manual_l3_escalate",
                    "turns": [],
                },
            )

        monkeypatch.setattr(
            "clawsentry.gateway.agent_analyzer.AgentAnalyzer.analyze",
            fake_analyze,
        )

        provider = MagicMock()
        ok, latency, detail = asyncio.run(_test_l3(provider))

        assert ok is True
        assert latency > 0
        assert "mode=multi_turn" in detail
        assert "trigger=manual_l3_escalate" in detail

    def test_fails_when_l3_trigger_not_matched(self, monkeypatch):
        async def fake_analyze(self, event, context, l1_snapshot, budget_ms):
            return L2Result(
                target_level=RiskLevel.HIGH,
                reasons=["L3 trigger not matched"],
                confidence=0.0,
                trace={
                    "degraded": True,
                    "trigger_reason": "trigger_not_matched",
                    "degradation_reason": "L3 trigger not matched",
                },
            )

        monkeypatch.setattr(
            "clawsentry.gateway.agent_analyzer.AgentAnalyzer.analyze",
            fake_analyze,
        )

        provider = MagicMock()
        ok, latency, detail = asyncio.run(_test_l3(provider))

        assert ok is False
        assert latency > 0
        assert "trigger not matched" in detail.lower()
        assert "reason_code=trigger_not_matched" in detail

    def test_degraded_detail_preserves_trigger_reason_and_mode(self, monkeypatch):
        async def fake_analyze(self, event, context, l1_snapshot, budget_ms):
            return L2Result(
                target_level=RiskLevel.HIGH,
                reasons=["L3 hard cap exceeded"],
                confidence=0.0,
                trace={
                    "degraded": True,
                    "mode": "multi_turn",
                    "trigger_reason": "cumulative_risk",
                    "degradation_reason": "L3 hard cap exceeded",
                },
            )

        monkeypatch.setattr(
            "clawsentry.gateway.agent_analyzer.AgentAnalyzer.analyze",
            fake_analyze,
        )

        provider = MagicMock()
        ok, latency, detail = asyncio.run(_test_l3(provider))

        assert ok is False
        assert latency > 0
        assert "mode=multi_turn" in detail
        assert "trigger=cumulative_risk" in detail
        assert "reason_code=hard_cap_exceeded" in detail

    def test_degraded_detail_prefers_structured_reason_code(self, monkeypatch):
        async def fake_analyze(self, event, context, l1_snapshot, budget_ms):
            return L2Result(
                target_level=RiskLevel.HIGH,
                reasons=["response parsing failed"],
                confidence=0.0,
                trace={
                    "degraded": True,
                    "mode": "multi_turn",
                    "trigger_reason": "cumulative_risk",
                    "degradation_reason": "L3 hard cap exceeded",
                    "l3_reason_code": "llm_response_parse_failed",
                },
            )

        monkeypatch.setattr(
            "clawsentry.gateway.agent_analyzer.AgentAnalyzer.analyze",
            fake_analyze,
        )

        provider = MagicMock()
        ok, latency, detail = asyncio.run(_test_l3(provider))

        assert ok is False
        assert latency > 0
        assert "reason_code=llm_response_parse_failed" in detail
        assert "reason_code=hard_cap_exceeded" not in detail


# ---------------------------------------------------------------------------
# run_test_llm (integration-level, no real API calls)
# ---------------------------------------------------------------------------


class TestRunTestLlm:
    def test_no_provider_configured(self):
        code = run_test_llm(color=False)
        assert code == 1

    def test_no_provider_configured_json(self, capsys):
        code = run_test_llm(color=False, json_mode=True)
        assert code == 1
        output = capsys.readouterr().out
        data = json.loads(output)
        assert "error" in data

    @patch("clawsentry.cli.test_llm_command._build_provider")
    @patch("clawsentry.cli.test_llm_command._test_reachability")
    @patch("clawsentry.cli.test_llm_command._test_l2")
    def test_all_pass_skip_l3(self, mock_l2, mock_reach, mock_build):
        mock_provider = MagicMock()
        mock_build.return_value = (mock_provider, {
            "provider": "anthropic",
            "model": "claude-haiku-4-5-20251001",
            "base_url": "(default)",
            "key_preview": "sk-ant...cdef",
        })
        mock_reach.return_value = (True, 150.0, "PONG")
        mock_l2.return_value = (True, 800.0, "risk=high, confidence=0.95, reason=test")

        code = run_test_llm(color=False, skip_l3=True)
        assert code == 0
        assert mock_reach.await_args_list[1].kwargs["timeout_ms"] == 60000
        assert mock_l2.await_args.kwargs["timeout_ms"] == 60000
        assert mock_l2.await_args.kwargs["max_tokens"] == 10000

    @patch("clawsentry.cli.test_llm_command._build_provider")
    @patch("clawsentry.cli.test_llm_command._test_reachability")
    def test_api_unreachable_skips_rest(self, mock_reach, mock_build):
        mock_build.return_value = (MagicMock(), {
            "provider": "anthropic",
            "model": "test",
            "base_url": "(default)",
            "key_preview": "sk-...test",
        })
        mock_reach.return_value = (False, 5000.0, "Timeout after 5000ms")

        code = run_test_llm(color=False, skip_l3=True)
        assert code == 1

    @patch("clawsentry.cli.test_llm_command._build_provider")
    @patch("clawsentry.cli.test_llm_command._test_reachability")
    @patch("clawsentry.cli.test_llm_command._test_l2")
    def test_json_output(self, mock_l2, mock_reach, mock_build, capsys):
        mock_build.return_value = (MagicMock(), {
            "provider": "openai",
            "model": "gpt-4o-mini",
            "base_url": "(default)",
            "key_preview": "sk-...test",
        })
        mock_reach.return_value = (True, 200.0, "PONG")
        mock_l2.return_value = (True, 600.0, "risk=medium")

        code = run_test_llm(color=False, skip_l3=True, json_mode=True)
        assert code == 0
        output = capsys.readouterr().out
        data = json.loads(output)
        assert data["all_pass"] is True
        assert len(data["results"]) >= 3

    @patch("clawsentry.cli.test_llm_command._test_reachability")
    @patch("clawsentry.cli.test_llm_command._test_l2")
    @patch("clawsentry.cli.test_llm_command._test_l3")
    def test_env_file_l3_enabled_runs_l3_without_mutating_process_env(
        self, mock_l3, mock_l2, mock_reach, tmp_path, capsys
    ):
        env_file = tmp_path / "clawsentry.env"
        env_file.write_text(
            "\n".join(
                [
                    "CS_LLM_PROVIDER=openai",
                    "OPENAI_API_KEY=sk-test-key-1234567890abcdef",
                    "CS_L3_ENABLED=true",
                ]
            ),
            encoding="utf-8",
        )
        mock_reach.return_value = (True, 200.0, "PONG")
        mock_l2.return_value = (True, 600.0, "risk=medium")
        mock_l3.return_value = (True, 900.0, "mode=multi_turn, trigger=manual_l3_escalate")

        code = run_test_llm(color=False, json_mode=True, env_file=env_file)

        assert code == 0
        assert mock_l3.await_count == 1
        assert mock_l3.await_args.kwargs["runtime_env"]["CS_L3_ENABLED"] == "true"
        data = json.loads(capsys.readouterr().out)
        l3_result = next(item for item in data["results"] if item["test"] == "l3_review")
        assert l3_result["latency_ms"] == 900.0
        assert "CS_L3_ENABLED" not in os.environ

    @patch("clawsentry.cli.test_llm_command._build_provider")
    @patch("clawsentry.cli.test_llm_command._test_reachability")
    @patch("clawsentry.cli.test_llm_command._test_l2")
    @patch("clawsentry.cli.test_llm_command._test_l3")
    def test_json_output_surfaces_l3_mode_and_trigger_detail(
        self, mock_l3, mock_l2, mock_reach, mock_build, capsys, monkeypatch
    ):
        monkeypatch.setenv("CS_L3_ENABLED", "true")
        mock_build.return_value = (MagicMock(), {
            "provider": "openai",
            "model": "gpt-4o-mini",
            "base_url": "(default)",
            "key_preview": "sk-...test",
        })
        mock_reach.side_effect = [
            (True, 200.0, "PONG"),
            (True, 220.0, "PONG"),
        ]
        mock_l2.return_value = (True, 600.0, "risk=medium")
        mock_l3.return_value = (
            True,
            900.0,
            "mode=multi_turn, trigger=manual_l3_escalate, risk=high, confidence=0.91, reason=test",
        )

        code = run_test_llm(color=False, json_mode=True)

        assert code == 0
        data = json.loads(capsys.readouterr().out)
        l3_result = next(item for item in data["results"] if item["test"] == "l3_review")
        assert "mode=multi_turn" in l3_result["detail"]
        assert "trigger=manual_l3_escalate" in l3_result["detail"]

    @patch("clawsentry.cli.test_llm_command._build_provider")
    @patch("clawsentry.cli.test_llm_command._test_reachability")
    @patch("clawsentry.cli.test_llm_command._test_l2")
    @patch("clawsentry.cli.test_llm_command._test_l3")
    def test_json_output_includes_l3_mode_detail(self, mock_l3, mock_l2, mock_reach, mock_build, capsys, monkeypatch):
        monkeypatch.setenv("CS_L3_ENABLED", "true")
        mock_build.return_value = (MagicMock(), {
            "provider": "openai",
            "model": "gpt-4o-mini",
            "base_url": "(default)",
            "key_preview": "sk-...test",
        })
        mock_reach.return_value = (True, 200.0, "PONG")
        mock_l2.return_value = (True, 600.0, "risk=medium")
        mock_l3.return_value = (
            True,
            900.0,
            "mode=multi_turn, trigger=manual_l3_escalate, risk=high, confidence=0.91, reason=test",
        )

        code = run_test_llm(color=False, json_mode=True)

        assert code == 0
        output = capsys.readouterr().out
        data = json.loads(output)
        l3_result = next(item for item in data["results"] if item["test"] == "l3_review")
        assert "mode=multi_turn" in l3_result["detail"]
