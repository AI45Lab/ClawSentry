"""Tests for LLM Provider — AnthropicProvider and OpenAIProvider."""

import asyncio
import sys
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from clawsentry.gateway.llm_provider import (
    LLMProvider,
    LLMProviderConfig,
    AnthropicProvider,
    OpenAIProvider,
)


# ===========================================================================
# LLMProviderConfig Tests
# ===========================================================================

class TestLLMProviderConfig:
    def test_defaults(self):
        cfg = LLMProviderConfig(api_key="test-key")
        assert cfg.max_tokens == 256
        assert cfg.temperature == 0.0
        assert cfg.model == ""
        assert cfg.base_url is None

    def test_custom_values(self):
        cfg = LLMProviderConfig(
            api_key="k",
            model="claude-sonnet-4-6",
            max_tokens=512,
            temperature=0.1,
        )
        assert cfg.model == "claude-sonnet-4-6"
        assert cfg.max_tokens == 512


# ===========================================================================
# AnthropicProvider Tests (mocked HTTP — lazy client never touches network)
# ===========================================================================

class TestAnthropicProvider:
    def _make_provider(self) -> AnthropicProvider:
        """Create provider with lazy client (no network)."""
        return AnthropicProvider(LLMProviderConfig(api_key="test"))

    def test_provider_id(self):
        p = self._make_provider()
        assert p.provider_id == "anthropic"

    def test_default_model(self):
        p = self._make_provider()
        assert p._model == AnthropicProvider.DEFAULT_MODEL

    def test_custom_model(self):
        p = AnthropicProvider(LLMProviderConfig(api_key="test", model="claude-sonnet-4-6"))
        assert p._model == "claude-sonnet-4-6"

    def test_custom_base_url_is_passed_to_lazy_client(self):
        cfg = LLMProviderConfig(api_key="test", base_url="http://example.test")
        p = AnthropicProvider(cfg)
        fake_anthropic = MagicMock()

        with patch.dict(sys.modules, {"anthropic": fake_anthropic}):
            p._get_client()

        fake_anthropic.AsyncAnthropic.assert_called_once_with(
            api_key="test",
            base_url="http://example.test",
        )

    def test_custom_base_url_strips_v1_for_anthropic_sdk(self):
        cfg = LLMProviderConfig(api_key="test", base_url="http://example.test/v1/")
        p = AnthropicProvider(cfg)
        fake_anthropic = MagicMock()

        with patch.dict(sys.modules, {"anthropic": fake_anthropic}):
            p._get_client()

        fake_anthropic.AsyncAnthropic.assert_called_once_with(
            api_key="test",
            base_url="http://example.test",
        )

    def test_satisfies_protocol(self):
        p = self._make_provider()
        assert isinstance(p, LLMProvider)

    def test_complete_success(self):
        p = self._make_provider()
        mock_response = MagicMock()
        mock_response.content = [MagicMock(text='{"risk_assessment":"high","reasons":["test"],"confidence":0.9}')]

        # Inject mock client before _get_client() is ever called
        mock_client = MagicMock()
        mock_client.messages.create = AsyncMock(return_value=mock_response)
        p._client = mock_client

        result = asyncio.run(
            p.complete("system", "user msg", timeout_ms=3000)
        )
        assert "risk_assessment" in result
        mock_client.messages.create.assert_awaited_once()

    def test_complete_uses_first_text_block_after_thinking_block(self):
        p = self._make_provider()
        mock_response = MagicMock()
        thinking_block = MagicMock()
        del thinking_block.text
        thinking_block.type = "thinking"
        text_block = MagicMock()
        text_block.type = "text"
        text_block.text = '{"risk_assessment":"high","reasons":["test"],"confidence":0.9}'
        mock_response.content = [thinking_block, text_block]

        mock_client = MagicMock()
        mock_client.messages.create = AsyncMock(return_value=mock_response)
        p._client = mock_client

        result = asyncio.run(
            p.complete("system", "user msg", timeout_ms=3000)
        )

        assert "risk_assessment" in result
        mock_client.messages.create.assert_awaited_once()

    def test_complete_timeout(self):
        p = self._make_provider()

        async def slow_call(*args, **kwargs):
            await asyncio.sleep(10)

        mock_client = MagicMock()
        mock_client.messages.create = slow_call
        p._client = mock_client

        with pytest.raises(asyncio.TimeoutError):
            asyncio.run(
                p.complete("system", "user msg", timeout_ms=50)
            )

    def test_effective_max_tokens_fallback(self):
        """When max_tokens=0 is passed, falls back to config.max_tokens."""
        cfg = LLMProviderConfig(api_key="test", max_tokens=512)
        p = AnthropicProvider(cfg)

        mock_response = MagicMock()
        mock_response.content = [MagicMock(text="ok")]
        mock_client = MagicMock()
        mock_client.messages.create = AsyncMock(return_value=mock_response)
        p._client = mock_client

        asyncio.run(p.complete("sys", "msg", timeout_ms=3000, max_tokens=0))
        call_kwargs = mock_client.messages.create.call_args[1]
        assert call_kwargs["max_tokens"] == 512


# ===========================================================================
# OpenAIProvider Tests (mocked HTTP — lazy client never touches network)
# ===========================================================================

class TestOpenAIProvider:
    def _make_provider(self, **kwargs) -> OpenAIProvider:
        """Create provider with lazy client (no network)."""
        return OpenAIProvider(LLMProviderConfig(api_key="test", **kwargs))

    def test_provider_id(self):
        p = self._make_provider()
        assert p.provider_id == "openai"

    def test_default_model(self):
        p = self._make_provider()
        assert p._model == OpenAIProvider.DEFAULT_MODEL

    def test_custom_model(self):
        p = self._make_provider(model="gpt-4o")
        assert p._model == "gpt-4o"

    def test_satisfies_protocol(self):
        p = self._make_provider()
        assert isinstance(p, LLMProvider)

    def test_complete_success(self):
        p = self._make_provider(model="gpt-4o-mini")
        mock_response = MagicMock()
        mock_choice = MagicMock()
        mock_choice.message.content = '{"risk_assessment":"medium","reasons":[],"confidence":0.7}'
        mock_response.choices = [mock_choice]

        mock_client = MagicMock()
        mock_client.chat.completions.create = AsyncMock(return_value=mock_response)
        p._client = mock_client

        result = asyncio.run(
            p.complete("system", "user msg", timeout_ms=3000)
        )
        assert "risk_assessment" in result
        mock_client.chat.completions.create.assert_awaited_once()

    def test_custom_base_url(self):
        """OpenAIProvider stores custom base_url for Ollama/local models."""
        cfg = LLMProviderConfig(api_key="test", base_url="http://localhost:11434/v1")
        p = OpenAIProvider(cfg)
        assert p.provider_id == "openai"
        assert p._config.base_url == "http://localhost:11434/v1"

    def test_complete_timeout(self):
        p = self._make_provider()

        async def slow_call(*args, **kwargs):
            await asyncio.sleep(10)

        mock_client = MagicMock()
        mock_client.chat.completions.create = slow_call
        p._client = mock_client

        with pytest.raises(asyncio.TimeoutError):
            asyncio.run(
                p.complete("system", "user msg", timeout_ms=50)
            )

    def test_effective_max_tokens_fallback(self):
        """When max_tokens=0 is passed, falls back to config.max_tokens."""
        cfg = LLMProviderConfig(api_key="test", max_tokens=512)
        p = OpenAIProvider(cfg)

        mock_response = MagicMock()
        mock_choice = MagicMock()
        mock_choice.message.content = "ok"
        mock_response.choices = [mock_choice]

        mock_client = MagicMock()
        mock_client.chat.completions.create = AsyncMock(return_value=mock_response)
        p._client = mock_client

        asyncio.run(p.complete("sys", "msg", timeout_ms=3000, max_tokens=0))
        call_kwargs = mock_client.chat.completions.create.call_args[1]
        assert call_kwargs["max_tokens"] == 512
