"""Tests for shared LLM settings resolution."""

from __future__ import annotations

import os
from unittest import mock

from clawsentry.gateway.llm_settings import LLMSettings, resolve_llm_settings


def _clean_env() -> dict[str, str]:
    return {
        "CS_LLM_PROVIDER": "",
        "CS_LLM_API_KEY": "",
        "CS_LLM_MODEL": "",
        "CS_LLM_BASE_URL": "",
        "CS_LLM_TEMPERATURE": "",
        "CS_LLM_PROVIDER_TIMEOUT_MS": "",
        "CS_LLM_API_KEY_ENV": "",
        "CS_L3_ENABLED": "",
        "CS_LLM_L3_ENABLED": "",
        "CS_ENTERPRISE_ENABLED": "",
        "CS_ENTERPRISE_OS_ENABLED": "",
        "CS_LLM_ENTERPRISE_ENABLED": "",
        "OPENAI_API_KEY": "",
        "ANTHROPIC_API_KEY": "",
    }


class TestResolveLlmSettings:
    def test_returns_none_without_provider(self):
        with mock.patch.dict(os.environ, _clean_env(), clear=False):
            assert resolve_llm_settings() is None

    def test_resolves_shared_api_key_for_openai(self):
        env = {
            **_clean_env(),
            "CS_LLM_PROVIDER": "openai",
            "CS_LLM_API_KEY": "sk-shared-key",
            "CS_LLM_MODEL": "gpt-4o-mini",
            "CS_LLM_BASE_URL": "http://localhost:11434/v1",
            "CS_LLM_TEMPERATURE": "1",
            "CS_LLM_PROVIDER_TIMEOUT_MS": "20000",
            "CS_LLM_L3_ENABLED": "true",
            "CS_LLM_ENTERPRISE_ENABLED": "1",
        }
        with mock.patch.dict(os.environ, env, clear=False):
            settings = resolve_llm_settings()

        assert settings == LLMSettings(
            provider="openai",
            api_key="sk-shared-key",
            model="gpt-4o-mini",
            base_url="http://localhost:11434/v1",
            temperature=1.0,
            provider_timeout_ms=20000.0,
            l3_enabled=True,
            enterprise_enabled=True,
        )

    def test_invalid_optional_numeric_values_fall_back_to_defaults(self):
        env = {
            **_clean_env(),
            "CS_LLM_PROVIDER": "openai",
            "CS_LLM_API_KEY": "sk-shared-key",
            "CS_LLM_TEMPERATURE": "not-a-number",
            "CS_LLM_PROVIDER_TIMEOUT_MS": "also-bad",
        }
        with mock.patch.dict(os.environ, env, clear=False):
            settings = resolve_llm_settings()

        assert settings is not None
        assert settings.temperature == 0.0
        assert settings.provider_timeout_ms == 3000.0

    def test_legacy_openai_key_is_still_supported(self):
        env = {
            **_clean_env(),
            "CS_LLM_PROVIDER": "openai",
            "OPENAI_API_KEY": "sk-legacy-key",
        }
        with mock.patch.dict(os.environ, env, clear=False):
            settings = resolve_llm_settings()

        assert settings is not None
        assert settings.api_key == "sk-legacy-key"
        assert settings.provider == "openai"

    def test_custom_api_key_env_is_honored(self):
        env = {
            **_clean_env(),
            "CS_LLM_PROVIDER": "openai",
            "CS_LLM_API_KEY_ENV": "CUSTOM_LLM_KEY",
            "CUSTOM_LLM_KEY": "sk-custom-key",
        }
        with mock.patch.dict(os.environ, env, clear=False):
            settings = resolve_llm_settings()

        assert settings is not None
        assert settings.api_key == "sk-custom-key"

    def test_legacy_anthropic_key_is_still_supported(self):
        env = {
            **_clean_env(),
            "CS_LLM_PROVIDER": "anthropic",
            "ANTHROPIC_API_KEY": "sk-ant-legacy-key",
        }
        with mock.patch.dict(os.environ, env, clear=False):
            settings = resolve_llm_settings()

        assert settings is not None
        assert settings.api_key == "sk-ant-legacy-key"
        assert settings.provider == "anthropic"

    def test_unknown_provider_returns_none(self):
        env = {
            **_clean_env(),
            "CS_LLM_PROVIDER": "unknown",
            "CS_LLM_API_KEY": "sk-test",
        }
        with mock.patch.dict(os.environ, env, clear=False):
            assert resolve_llm_settings() is None

    def test_blank_api_key_returns_none(self):
        env = {
            **_clean_env(),
            "CS_LLM_PROVIDER": "openai",
            "CS_LLM_API_KEY": "   ",
        }
        with mock.patch.dict(os.environ, env, clear=False):
            assert resolve_llm_settings() is None

    def test_enterprise_os_alias_enables_enterprise_flag(self):
        env = {
            **_clean_env(),
            "CS_LLM_PROVIDER": "openai",
            "CS_LLM_API_KEY": "sk-shared-key",
            "CS_ENTERPRISE_OS_ENABLED": "true",
        }
        with mock.patch.dict(os.environ, env, clear=False):
            settings = resolve_llm_settings()

        assert settings is not None
        assert settings.enterprise_enabled is True
