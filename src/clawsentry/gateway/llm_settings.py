"""
Shared LLM settings resolver.

This module centralizes provider, API key, model, base URL, and feature-flag
resolution while preserving legacy env compatibility.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Mapping, Optional

_TRUTHY_VALUES = {"true", "1", "yes", "on"}
_SUPPORTED_PROVIDERS = {"anthropic", "openai"}


@dataclass(frozen=True)
class LLMSettings:
    """Resolved LLM configuration shared by L2/L3/enterprise flows."""

    provider: str
    api_key: str
    model: str = ""
    base_url: Optional[str] = None
    temperature: float = 0.0
    provider_timeout_ms: float = 3000.0
    l3_enabled: bool = False
    enterprise_enabled: bool = False

    @property
    def normalized_provider(self) -> str:
        return self.provider.strip().lower()


def _env(
    name: str,
    *,
    environ: Optional[Mapping[str, str]] = None,
    default: str = "",
) -> str:
    source = environ if environ is not None else os.environ
    return str(source.get(name, default))


def _env_bool(
    name: str,
    *,
    environ: Optional[Mapping[str, str]] = None,
    default: bool = False,
) -> bool:
    raw = _env(name, environ=environ).strip()
    if not raw:
        return default
    return raw.lower() in _TRUTHY_VALUES


def _env_float(
    name: str,
    *,
    environ: Optional[Mapping[str, str]] = None,
    default: float,
) -> float:
    raw = _env(name, environ=environ).strip()
    if not raw:
        return default
    try:
        return float(raw)
    except ValueError:
        return default


def _resolve_api_key(provider: str, *, environ: Optional[Mapping[str, str]] = None) -> str:
    shared = _env("CS_LLM_API_KEY", environ=environ).strip()
    if shared:
        return shared
    custom_env_name = _env("CS_LLM_API_KEY_ENV", environ=environ).strip()
    if custom_env_name:
        custom_value = _env(custom_env_name, environ=environ).strip()
        if custom_value:
            return custom_value
    if provider == "anthropic":
        return _env("ANTHROPIC_API_KEY", environ=environ).strip()
    if provider == "openai":
        return _env("OPENAI_API_KEY", environ=environ).strip()
    return ""


def resolve_llm_settings(
    *,
    environ: Optional[Mapping[str, str]] = None,
) -> Optional[LLMSettings]:
    """Resolve shared LLM settings from env-like mappings.

    Legacy compatibility:
    - `OPENAI_API_KEY` / `ANTHROPIC_API_KEY` still work.
    - `CS_L3_ENABLED` still works.
    - `CS_LLM_L3_ENABLED`, `CS_ENTERPRISE_OS_ENABLED`, and
      `CS_LLM_ENTERPRISE_ENABLED` are accepted aliases.
    """
    provider = _env("CS_LLM_PROVIDER", environ=environ).strip().lower()
    if not provider or provider not in _SUPPORTED_PROVIDERS:
        return None

    api_key = _resolve_api_key(provider, environ=environ)
    if not api_key.strip():
        return None

    model = _env("CS_LLM_MODEL", environ=environ).strip()
    base_url = _env("CS_LLM_BASE_URL", environ=environ).strip() or None
    temperature = _env_float("CS_LLM_TEMPERATURE", environ=environ, default=0.0)
    provider_timeout_ms = _env_float("CS_LLM_PROVIDER_TIMEOUT_MS", environ=environ, default=3000.0)
    l3_enabled = _env_bool("CS_L3_ENABLED", environ=environ) or _env_bool("CS_LLM_L3_ENABLED", environ=environ)
    enterprise_enabled = (
        _env_bool("CS_ENTERPRISE_ENABLED", environ=environ)
        or _env_bool("CS_ENTERPRISE_OS_ENABLED", environ=environ)
        or _env_bool("CS_LLM_ENTERPRISE_ENABLED", environ=environ)
    )

    return LLMSettings(
        provider=provider,
        api_key=api_key,
        model=model,
        base_url=base_url,
        temperature=temperature,
        provider_timeout_ms=provider_timeout_ms,
        l3_enabled=l3_enabled,
        enterprise_enabled=enterprise_enabled,
    )
