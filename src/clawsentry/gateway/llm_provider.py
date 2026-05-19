"""
LLM Provider abstraction — multi-provider support for L2 semantic analysis.

Design basis: 09-l2-pluggable-semantic-analysis.md section 4.4
"""

from __future__ import annotations

import asyncio
import inspect
from dataclasses import dataclass
from typing import Optional, Protocol, runtime_checkable


@dataclass
class LLMProviderConfig:
    """Configuration for an LLM provider."""
    api_key: str
    model: str = ""
    max_tokens: int = 256
    temperature: float = 0.0
    base_url: Optional[str] = None


@dataclass(frozen=True)
class LLMUsage:
    """Immutable record of token usage from a single LLM call."""
    input_tokens: int = 0
    output_tokens: int = 0
    provider: str = ""
    model: str = ""


@runtime_checkable
class LLMProvider(Protocol):
    """Protocol for LLM provider implementations."""

    @property
    def provider_id(self) -> str: ...

    async def complete(
        self,
        system_prompt: str,
        user_message: str,
        timeout_ms: float,
        max_tokens: int = 256,
    ) -> str: ...


class AnthropicProvider:
    """Anthropic Claude API provider."""

    DEFAULT_MODEL = "claude-haiku-4-5-20251001"

    def __init__(self, config: LLMProviderConfig) -> None:
        self._config = config
        self._model = config.model or self.DEFAULT_MODEL
        self._client: Optional[object] = None
        self._last_usage: LLMUsage = LLMUsage()

    @staticmethod
    def _client_base_url(base_url: str) -> str:
        normalized = base_url.rstrip("/")
        if normalized.endswith("/v1"):
            return normalized[:-3]
        return normalized

    def _get_client(self) -> object:
        """Lazy-init the Anthropic async client (deferred to avoid proxy issues at import)."""
        if self._client is None:
            import anthropic
            kwargs: dict = {"api_key": self._config.api_key}
            if self._config.base_url:
                kwargs["base_url"] = self._client_base_url(self._config.base_url)
            self._client = anthropic.AsyncAnthropic(**kwargs)
        return self._client

    @property
    def provider_id(self) -> str:
        return "anthropic"

    @staticmethod
    def _extract_text_content(response: object) -> str:
        content = getattr(response, "content", None) or []
        for block in content:
            text = getattr(block, "text", None)
            if isinstance(text, str) and text.strip():
                return text
        raise ValueError("Anthropic response did not contain a text content block")

    async def aclose(self) -> None:
        """Close any lazy async client before its owning event loop exits."""

        client = self._client
        self._client = None
        if client is None:
            return
        close = getattr(client, "close", None) or getattr(client, "aclose", None)
        if callable(close):
            result = close()
            if inspect.isawaitable(result):
                await result

    async def complete(
        self,
        system_prompt: str,
        user_message: str,
        timeout_ms: float,
        max_tokens: int = 256,
    ) -> str:
        effective_max_tokens = max_tokens or self._config.max_tokens
        client = self._get_client()
        response = await asyncio.wait_for(
            client.messages.create(  # type: ignore[union-attr]
                model=self._model,
                max_tokens=effective_max_tokens,
                temperature=self._config.temperature,
                system=system_prompt,
                messages=[{"role": "user", "content": user_message}],
            ),
            timeout=timeout_ms / 1000,
        )
        usage = getattr(response, "usage", None)
        self._last_usage = LLMUsage(
            input_tokens=getattr(usage, "input_tokens", 0) if usage else 0,
            output_tokens=getattr(usage, "output_tokens", 0) if usage else 0,
            provider="anthropic",
            model=self._model,
        )
        return self._extract_text_content(response)


class OpenAIProvider:
    """OpenAI-compatible API provider (supports custom base_url for Ollama etc.)."""

    DEFAULT_MODEL = "gpt-4o-mini"

    def __init__(self, config: LLMProviderConfig) -> None:
        self._config = config
        self._model = config.model or self.DEFAULT_MODEL
        self._client: Optional[object] = None
        self._last_usage: LLMUsage = LLMUsage()

    def _get_client(self) -> object:
        """Lazy-init the OpenAI async client (deferred to avoid proxy issues at import)."""
        if self._client is None:
            import openai
            kwargs: dict = {"api_key": self._config.api_key}
            if self._config.base_url:
                kwargs["base_url"] = self._config.base_url
            self._client = openai.AsyncOpenAI(**kwargs)
        return self._client

    @property
    def provider_id(self) -> str:
        return "openai"

    async def aclose(self) -> None:
        """Close any lazy async client before its owning event loop exits."""

        client = self._client
        self._client = None
        if client is None:
            return
        close = getattr(client, "close", None) or getattr(client, "aclose", None)
        if callable(close):
            result = close()
            if inspect.isawaitable(result):
                await result

    async def complete(
        self,
        system_prompt: str,
        user_message: str,
        timeout_ms: float,
        max_tokens: int = 256,
    ) -> str:
        effective_max_tokens = max_tokens or self._config.max_tokens
        client = self._get_client()
        response = await asyncio.wait_for(
            client.chat.completions.create(  # type: ignore[union-attr]
                model=self._model,
                max_tokens=effective_max_tokens,
                temperature=self._config.temperature,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_message},
                ],
            ),
            timeout=timeout_ms / 1000,
        )
        usage = getattr(response, "usage", None)
        self._last_usage = LLMUsage(
            input_tokens=getattr(usage, "prompt_tokens", 0) if usage else 0,
            output_tokens=getattr(usage, "completion_tokens", 0) if usage else 0,
            provider="openai",
            model=self._model,
        )
        content = response.choices[0].message.content  # type: ignore[union-attr]
        if not isinstance(content, str) or not content.strip():
            raise ValueError("OpenAI response did not contain message content")
        return content


class InstrumentedProvider:
    """Wrapper that delegates to an inner LLM provider and records metrics.

    After each ``complete()`` call, reads ``inner._last_usage`` (with a
    ``getattr`` fallback to ``LLMUsage()``) and reports token counts, status,
    and tier to the provided ``MetricsCollector`` via ``record_llm_call()``.

    Satisfies the ``LLMProvider`` Protocol (``provider_id`` property +
    ``async complete() -> str``).
    """

    def __init__(self, inner: LLMProvider, metrics: object, *, tier: str) -> None:
        self._inner = inner
        self._metrics = metrics
        self._tier = tier

    @property
    def provider_id(self) -> str:
        return self._inner.provider_id

    @property
    def _last_usage(self) -> LLMUsage:
        return getattr(self._inner, "_last_usage", LLMUsage())

    async def complete(
        self,
        system_prompt: str,
        user_message: str,
        timeout_ms: float,
        max_tokens: int = 256,
    ) -> str:
        status = "ok"
        try:
            result = await self._inner.complete(
                system_prompt, user_message, timeout_ms, max_tokens,
            )
            return result
        except asyncio.TimeoutError:
            status = "timeout"
            raise
        except Exception:
            status = "error"
            raise
        finally:
            usage = getattr(self._inner, "_last_usage", LLMUsage())
            provider_name = usage.provider if usage.provider else self._inner.provider_id
            self._metrics.record_llm_call(  # type: ignore[union-attr]
                provider=provider_name,
                tier=self._tier,
                status=status,
                input_tokens=usage.input_tokens,
                output_tokens=usage.output_tokens,
            )
