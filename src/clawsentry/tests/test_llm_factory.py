"""Tests for llm_factory — build_analyzer_from_env()."""

from __future__ import annotations

import os
from unittest import mock

from clawsentry.gateway.llm_factory import build_analyzer_from_env
from clawsentry.gateway.llm_provider import OpenAIProvider, AnthropicProvider
from clawsentry.gateway.semantic_analyzer import (
    CompositeAnalyzer,
    LLMAnalyzer,
    RuleBasedAnalyzer,
)


def _clean_env():
    """Return a mock env dict with all AHP_LLM_* and API keys cleared."""
    keys_to_clear = [
        "CS_LLM_PROVIDER",
        "CS_LLM_API_KEY",
        "CS_LLM_MODEL",
        "CS_LLM_BASE_URL",
        "CS_LLM_TEMPERATURE",
        "CS_LLM_PROVIDER_TIMEOUT_MS",
        "CS_LLM_MAX_TOKENS",
        "CS_L3_MAX_TOKENS",
        "CS_L3_ENABLED",
        "CS_L3_MULTI_TURN",
        "CS_LLM_L3_ENABLED",
        "CS_ENTERPRISE_ENABLED",
        "CS_LLM_ENTERPRISE_ENABLED",
        "ANTHROPIC_API_KEY",
        "OPENAI_API_KEY",
    ]
    return {k: "" for k in keys_to_clear}


class TestBuildAnalyzerFromEnv:
    def test_default_returns_none(self):
        """No env vars → None (gateway uses default RuleBasedAnalyzer)."""
        with mock.patch.dict(os.environ, _clean_env(), clear=False):
            result = build_analyzer_from_env()
        assert result is None

    def test_empty_provider_returns_none(self):
        """CS_LLM_PROVIDER='' → None."""
        env = {**_clean_env(), "CS_LLM_PROVIDER": ""}
        with mock.patch.dict(os.environ, env, clear=False):
            result = build_analyzer_from_env()
        assert result is None

    def test_unknown_provider_returns_none(self):
        """CS_LLM_PROVIDER=unknown → None with warning."""
        env = {**_clean_env(), "CS_LLM_PROVIDER": "unknown"}
        with mock.patch.dict(os.environ, env, clear=False):
            result = build_analyzer_from_env()
        assert result is None

    def test_openai_provider_missing_key_returns_none(self):
        """CS_LLM_PROVIDER=openai but no OPENAI_API_KEY → None."""
        env = {**_clean_env(), "CS_LLM_PROVIDER": "openai"}
        with mock.patch.dict(os.environ, env, clear=False):
            result = build_analyzer_from_env()
        assert result is None

    def test_anthropic_provider_missing_key_returns_none(self):
        """CS_LLM_PROVIDER=anthropic but no ANTHROPIC_API_KEY → None."""
        env = {**_clean_env(), "CS_LLM_PROVIDER": "anthropic"}
        with mock.patch.dict(os.environ, env, clear=False):
            result = build_analyzer_from_env()
        assert result is None

    def test_openai_provider_from_env(self):
        """CS_LLM_PROVIDER=openai + OPENAI_API_KEY → CompositeAnalyzer with OpenAIProvider."""
        env = {
            **_clean_env(),
            "CS_LLM_PROVIDER": "openai",
            "OPENAI_API_KEY": "sk-test-key-123",
        }
        with mock.patch.dict(os.environ, env, clear=False):
            result = build_analyzer_from_env()
        assert isinstance(result, CompositeAnalyzer)
        # Should contain RuleBasedAnalyzer + LLMAnalyzer
        assert len(result._analyzers) == 2
        assert isinstance(result._analyzers[0], RuleBasedAnalyzer)
        assert isinstance(result._analyzers[1], LLMAnalyzer)
        assert isinstance(result._analyzers[1]._provider, OpenAIProvider)

    def test_openai_provider_from_shared_api_key(self):
        """CS_LLM_API_KEY is the shared key for LLM-backed features."""
        env = {
            **_clean_env(),
            "CS_LLM_PROVIDER": "openai",
            "CS_LLM_API_KEY": "sk-shared-key-123",
        }
        with mock.patch.dict(os.environ, env, clear=False):
            result = build_analyzer_from_env()
        assert isinstance(result, CompositeAnalyzer)
        assert isinstance(result._analyzers[1], LLMAnalyzer)
        assert isinstance(result._analyzers[1]._provider, OpenAIProvider)
        assert result._analyzers[1]._config.provider_timeout_ms == 60000.0

    def test_openai_provider_uses_temperature_and_provider_timeout_env(self):
        env = {
            **_clean_env(),
            "CS_LLM_PROVIDER": "openai",
            "CS_LLM_API_KEY": "sk-shared-key-123",
            "CS_LLM_TEMPERATURE": "1",
            "CS_LLM_PROVIDER_TIMEOUT_MS": "20000",
        }
        with mock.patch.dict(os.environ, env, clear=False):
            result = build_analyzer_from_env()

        assert isinstance(result, CompositeAnalyzer)
        l2 = result._analyzers[1]
        assert isinstance(l2, LLMAnalyzer)
        assert l2._provider._config.temperature == 1.0
        assert l2._config.provider_timeout_ms == 20000.0
        assert l2._config.max_tokens == 10000

    def test_openai_provider_uses_l2_max_tokens_env(self):
        env = {
            **_clean_env(),
            "CS_LLM_PROVIDER": "openai",
            "CS_LLM_API_KEY": "sk-shared-key-123",
            "CS_LLM_MAX_TOKENS": "1024",
        }
        with mock.patch.dict(os.environ, env, clear=False):
            result = build_analyzer_from_env()

        assert isinstance(result, CompositeAnalyzer)
        l2 = result._analyzers[1]
        assert isinstance(l2, LLMAnalyzer)
        assert l2._config.max_tokens == 1024

    def test_anthropic_provider_from_env(self):
        """CS_LLM_PROVIDER=anthropic + ANTHROPIC_API_KEY → CompositeAnalyzer with AnthropicProvider."""
        env = {
            **_clean_env(),
            "CS_LLM_PROVIDER": "anthropic",
            "ANTHROPIC_API_KEY": "sk-ant-test-key-123",
        }
        with mock.patch.dict(os.environ, env, clear=False):
            result = build_analyzer_from_env()
        assert isinstance(result, CompositeAnalyzer)
        assert len(result._analyzers) == 2
        assert isinstance(result._analyzers[0], RuleBasedAnalyzer)
        assert isinstance(result._analyzers[1], LLMAnalyzer)
        assert isinstance(result._analyzers[1]._provider, AnthropicProvider)

    def test_anthropic_provider_from_shared_api_key(self):
        """CS_LLM_API_KEY should also work for anthropic-provider-backed flows."""
        env = {
            **_clean_env(),
            "CS_LLM_PROVIDER": "anthropic",
            "CS_LLM_API_KEY": "sk-shared-key-123",
        }
        with mock.patch.dict(os.environ, env, clear=False):
            result = build_analyzer_from_env()
        assert isinstance(result, CompositeAnalyzer)
        assert isinstance(result._analyzers[1], LLMAnalyzer)
        assert isinstance(result._analyzers[1]._provider, AnthropicProvider)

    def test_custom_base_url(self):
        """CS_LLM_BASE_URL sets OpenAIProvider.base_url for compatible endpoints."""
        env = {
            **_clean_env(),
            "CS_LLM_PROVIDER": "openai",
            "OPENAI_API_KEY": "sk-test-key-123",
            "CS_LLM_BASE_URL": "http://llm-gateway.example/v1/",
        }
        with mock.patch.dict(os.environ, env, clear=False):
            result = build_analyzer_from_env()
        assert isinstance(result, CompositeAnalyzer)
        provider = result._analyzers[1]._provider
        assert isinstance(provider, OpenAIProvider)
        assert provider._config.base_url == "http://llm-gateway.example/v1/"

    def test_anthropic_custom_base_url(self):
        """CS_LLM_BASE_URL also sets AnthropicProvider.base_url for native Claude endpoints."""
        env = {
            **_clean_env(),
            "CS_LLM_PROVIDER": "anthropic",
            "ANTHROPIC_API_KEY": "sk-ant-test-key-123",
            "CS_LLM_BASE_URL": "http://llm-gateway.example/v1/",
        }
        with mock.patch.dict(os.environ, env, clear=False):
            result = build_analyzer_from_env()
        assert isinstance(result, CompositeAnalyzer)
        provider = result._analyzers[1]._provider
        assert isinstance(provider, AnthropicProvider)
        assert provider._config.base_url == "http://llm-gateway.example/v1/"

    def test_custom_model(self):
        """CS_LLM_MODEL overrides default model name."""
        env = {
            **_clean_env(),
            "CS_LLM_PROVIDER": "openai",
            "OPENAI_API_KEY": "sk-test-key-123",
            "CS_LLM_MODEL": "custom-test-model",
        }
        with mock.patch.dict(os.environ, env, clear=False):
            result = build_analyzer_from_env()
        assert isinstance(result, CompositeAnalyzer)
        provider = result._analyzers[1]._provider
        assert isinstance(provider, OpenAIProvider)
        assert provider._model == "custom-test-model"

    def test_l3_enabled(self):
        """CS_L3_ENABLED=true nests L2 aggregate under an outer L2->L3 composite."""
        from pathlib import Path
        from clawsentry.gateway.server import TrajectoryStore
        from clawsentry.gateway.agent_analyzer import AgentAnalyzer

        env = {
            **_clean_env(),
            "CS_LLM_PROVIDER": "openai",
            "OPENAI_API_KEY": "sk-test-key-123",
            "CS_L3_ENABLED": "true",
        }
        store = TrajectoryStore(db_path=":memory:")
        with mock.patch.dict(os.environ, env, clear=False):
            result = build_analyzer_from_env(
                trajectory_store=store,
                workspace_root=Path("/tmp"),
            )
        assert isinstance(result, CompositeAnalyzer)
        assert len(result._analyzers) == 2
        inner_l2 = result._analyzers[0]
        assert isinstance(inner_l2, CompositeAnalyzer)
        assert len(inner_l2._analyzers) == 2
        assert isinstance(inner_l2._analyzers[0], RuleBasedAnalyzer)
        assert isinstance(inner_l2._analyzers[1], LLMAnalyzer)
        assert isinstance(result._analyzers[1], AgentAnalyzer)
        assert result._analyzers[1]._config.enable_multi_turn is True

    def test_l3_multi_turn_can_be_disabled_explicitly(self):
        """CS_L3_MULTI_TURN=false keeps factory-built L3 in MVP mode."""
        from pathlib import Path
        from clawsentry.gateway.server import TrajectoryStore
        from clawsentry.gateway.agent_analyzer import AgentAnalyzer

        env = {
            **_clean_env(),
            "CS_LLM_PROVIDER": "openai",
            "OPENAI_API_KEY": "sk-test-key-123",
            "CS_L3_ENABLED": "true",
            "CS_L3_MULTI_TURN": "false",
        }
        store = TrajectoryStore(db_path=":memory:")
        with mock.patch.dict(os.environ, env, clear=False):
            result = build_analyzer_from_env(
                trajectory_store=store,
                workspace_root=Path("/tmp"),
            )

        assert isinstance(result, CompositeAnalyzer)
        assert len(result._analyzers) == 2
        assert isinstance(result._analyzers[0], CompositeAnalyzer)
        assert isinstance(result._analyzers[1], AgentAnalyzer)
        assert result._analyzers[1]._config.enable_multi_turn is False

    def test_l3_max_tokens_env_configures_agent_analyzer(self):
        """CS_L3_MAX_TOKENS configures every L3 provider call budget."""
        from pathlib import Path
        from clawsentry.gateway.server import TrajectoryStore
        from clawsentry.gateway.agent_analyzer import AgentAnalyzer

        env = {
            **_clean_env(),
            "CS_LLM_PROVIDER": "openai",
            "OPENAI_API_KEY": "sk-test-key-123",
            "CS_L3_ENABLED": "true",
            "CS_L3_MAX_TOKENS": "2048",
        }
        store = TrajectoryStore(db_path=":memory:")
        with mock.patch.dict(os.environ, env, clear=False):
            result = build_analyzer_from_env(
                trajectory_store=store,
                workspace_root=Path("/tmp"),
            )

        assert isinstance(result, CompositeAnalyzer)
        assert isinstance(result._analyzers[1], AgentAnalyzer)
        assert result._analyzers[1]._config.max_tokens == 2048

    def test_l3_multi_turn_invalid_value_keeps_default_multi_turn(self):
        """Unexpected CS_L3_MULTI_TURN values should not silently force single-turn."""
        from pathlib import Path
        from clawsentry.gateway.server import TrajectoryStore
        from clawsentry.gateway.agent_analyzer import AgentAnalyzer

        env = {
            **_clean_env(),
            "CS_LLM_PROVIDER": "openai",
            "OPENAI_API_KEY": "sk-test-key-123",
            "CS_L3_ENABLED": "true",
            "CS_L3_MULTI_TURN": "maybe",
        }
        store = TrajectoryStore(db_path=":memory:")
        with mock.patch.dict(os.environ, env, clear=False):
            result = build_analyzer_from_env(
                trajectory_store=store,
                workspace_root=Path("/tmp"),
            )

        assert isinstance(result, CompositeAnalyzer)
        assert isinstance(result._analyzers[1], AgentAnalyzer)
        assert result._analyzers[1]._config.enable_multi_turn is True

    def test_l3_toolkit_receives_session_registry(self):
        """Factory-built L3 should pass SessionRegistry into ReadOnlyToolkit."""
        from pathlib import Path
        from clawsentry.gateway.server import TrajectoryStore
        from clawsentry.gateway.agent_analyzer import AgentAnalyzer

        env = {
            **_clean_env(),
            "CS_LLM_PROVIDER": "openai",
            "OPENAI_API_KEY": "sk-test-key-123",
            "CS_L3_ENABLED": "true",
        }
        store = TrajectoryStore(db_path=":memory:")
        session_registry = object()
        with mock.patch.dict(os.environ, env, clear=False):
            result = build_analyzer_from_env(
                trajectory_store=store,
                session_registry=session_registry,
                workspace_root=Path("/tmp"),
            )

        assert isinstance(result, CompositeAnalyzer)
        assert isinstance(result._analyzers[1], AgentAnalyzer)
        assert result._analyzers[1]._toolkit._session_registry is session_registry

    def test_l3_disabled_by_default(self):
        """Without CS_L3_ENABLED, no AgentAnalyzer."""
        env = {
            **_clean_env(),
            "CS_LLM_PROVIDER": "openai",
            "OPENAI_API_KEY": "sk-test-key-123",
        }
        with mock.patch.dict(os.environ, env, clear=False):
            result = build_analyzer_from_env()
        assert isinstance(result, CompositeAnalyzer)
        assert len(result._analyzers) == 2

    def test_provider_case_insensitive(self):
        """CS_LLM_PROVIDER is case-insensitive."""
        env = {
            **_clean_env(),
            "CS_LLM_PROVIDER": "OpenAI",
            "OPENAI_API_KEY": "sk-test-key-123",
        }
        with mock.patch.dict(os.environ, env, clear=False):
            result = build_analyzer_from_env()
        assert isinstance(result, CompositeAnalyzer)

    def test_l3_enabled_alias_works(self):
        """CS_LLM_L3_ENABLED should behave like CS_L3_ENABLED for the unified settings layer."""
        from pathlib import Path
        from clawsentry.gateway.server import TrajectoryStore
        from clawsentry.gateway.agent_analyzer import AgentAnalyzer

        env = {
            **_clean_env(),
            "CS_LLM_PROVIDER": "openai",
            "CS_LLM_API_KEY": "sk-test-key-123",
            "CS_LLM_L3_ENABLED": "true",
        }
        store = TrajectoryStore(db_path=":memory:")
        with mock.patch.dict(os.environ, env, clear=False):
            result = build_analyzer_from_env(
                trajectory_store=store,
                workspace_root=Path("/tmp"),
            )
        assert isinstance(result, CompositeAnalyzer)
        assert isinstance(result._analyzers[1], AgentAnalyzer)
