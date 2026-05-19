"""
LLM Analyzer factory — builds SemanticAnalyzer from environment variables.

Environment variables:
  CS_LLM_PROVIDER     = "anthropic" | "openai" | "" (default: rule-based only)
  CS_LLM_API_KEY      = shared API key for all LLM-backed features
  ANTHROPIC_API_KEY   = legacy API key for Anthropic provider
  OPENAI_API_KEY      = legacy API key for OpenAI-compatible provider
  CS_LLM_MODEL        = override default model name
  CS_LLM_BASE_URL     = OpenAI-compatible base URL
  CS_LLM_TEMPERATURE  = optional model temperature override
  CS_LLM_PROVIDER_TIMEOUT_MS = optional per-call provider timeout override
  CS_L3_ENABLED       = "true" to enable AgentAnalyzer (L3 review agent)
  CS_LLM_L3_ENABLED   = alias for CS_L3_ENABLED
  CS_L3_MULTI_TURN    = "false" to force legacy single-turn mode when L3 is enabled
  CS_ENTERPRISE_ENABLED = enterprise compatibility feature flag
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any, Optional

from .llm_provider import AnthropicProvider, InstrumentedProvider, LLMProviderConfig, OpenAIProvider
from .llm_settings import LLMSettings, resolve_llm_settings
from .semantic_analyzer import CompositeAnalyzer, LLMAnalyzer, LLMAnalyzerConfig, RuleBasedAnalyzer

logger = logging.getLogger("ahp.llm-factory")


def _env_bool(name: str, default: bool = False) -> bool:
    """Backward-compatible helper retained for CLI/runtime imports."""
    raw = str(os.getenv(name, "")).strip()
    if not raw:
        return default
    return raw.lower() in ("true", "1", "yes", "on")


def _build_provider(settings: LLMSettings) -> AnthropicProvider | OpenAIProvider:
    config_kwargs = {
        "api_key": settings.api_key,
        "model": settings.model,
        "temperature": settings.temperature,
    }
    if settings.provider == "anthropic":
        return AnthropicProvider(LLMProviderConfig(base_url=settings.base_url, **config_kwargs))
    if settings.provider == "openai":
        return OpenAIProvider(LLMProviderConfig(base_url=settings.base_url, **config_kwargs))
    raise ValueError(f"Unsupported LLM provider: {settings.provider!r}")


def build_provider_from_env() -> AnthropicProvider | OpenAIProvider | None:
    """Build a raw LLM provider from shared env settings, or None if unset."""
    settings = resolve_llm_settings()
    if settings is None:
        return None
    return _build_provider(settings)


def build_analyzer_from_env(
    *,
    trajectory_store: Any = None,
    session_registry: Any = None,
    workspace_root: Optional[Path] = None,
    patterns_path: Optional[str] = None,
    evolved_patterns_path: Optional[str] = None,
    l3_budget_ms: Optional[float] = None,
    metrics: Optional[Any] = None,
) -> Optional[CompositeAnalyzer | LLMAnalyzer | RuleBasedAnalyzer]:
    """Build a SemanticAnalyzer from environment variables.

    Returns None when no LLM provider is configured (gateway will use its
    default RuleBasedAnalyzer).  When a provider is configured, returns a
    CompositeAnalyzer wrapping RuleBasedAnalyzer + LLMAnalyzer (and
    optionally AgentAnalyzer for L3).

    Args:
        trajectory_store: TrajectoryStore instance for L3 ReadOnlyToolkit.
        workspace_root: Workspace root path for L3 ReadOnlyToolkit.
    """
    settings = resolve_llm_settings()
    if settings is None:
        return None

    provider = _build_provider(settings)

    logger.info(
        "LLM provider configured: %s (model=%s, base_url=%s)",
        settings.provider,
        settings.model or "(default)",
        settings.base_url or "(default)",
    )
    if settings.enterprise_enabled:
        logger.info("Enterprise LLM compatibility flag enabled")

    # Wrap L2 provider with instrumentation when metrics collector is provided.
    l2_provider = InstrumentedProvider(provider, metrics, tier="L2") if metrics is not None else provider

    l2_analyzers: list = [
        RuleBasedAnalyzer(patterns_path=patterns_path, evolved_patterns_path=evolved_patterns_path),
        LLMAnalyzer(
            l2_provider,
            LLMAnalyzerConfig(
                provider_timeout_ms=settings.provider_timeout_ms,
                max_tokens=settings.max_tokens,
            ),
        ),
    ]
    l2_composite = CompositeAnalyzer(l2_analyzers)

    if settings.l3_enabled:
        try:
            from .agent_analyzer import AgentAnalyzer
            from .review_toolkit import ReadOnlyToolkit
            from .review_skills import SkillRegistry

            ws_root = workspace_root or Path.cwd()
            toolkit = ReadOnlyToolkit(ws_root, trajectory_store, session_registry=session_registry)
            skills_dir = Path(__file__).parent / "skills"
            skill_registry = SkillRegistry(skills_dir)
            custom_skills_dir = os.getenv("AHP_SKILLS_DIR", "").strip()
            if custom_skills_dir:
                custom_path = Path(custom_skills_dir)
                if custom_path.exists() and custom_path.is_dir():
                    loaded = skill_registry.load_additional(custom_path)
                    logger.info("Custom skills loaded from %s (%d skills)", custom_path, loaded)
            from .agent_analyzer import AgentAnalyzerConfig
            l3_multi_turn_raw = str(os.getenv("CS_L3_MULTI_TURN", "")).strip().lower()
            enable_multi_turn = l3_multi_turn_raw not in {"false", "0", "no", "off"}
            agent_config = AgentAnalyzerConfig(
                l3_budget_ms=l3_budget_ms,
                max_tokens=settings.l3_max_tokens,
                enable_multi_turn=enable_multi_turn,
            )
            # Wrap L3 provider separately so L2 and L3 calls are tracked independently.
            l3_provider = InstrumentedProvider(provider, metrics, tier="L3") if metrics is not None else provider
            agent = AgentAnalyzer(
                provider=l3_provider,
                toolkit=toolkit,
                skill_registry=skill_registry,
                config=agent_config,
                trajectory_store=trajectory_store,
                session_registry=session_registry,
            )
            logger.info("L3 AgentAnalyzer enabled")
            return CompositeAnalyzer([l2_composite, agent])
        except Exception:
            logger.warning("Failed to initialize L3 AgentAnalyzer; continuing with L1+L2 only", exc_info=True)

    return l2_composite
