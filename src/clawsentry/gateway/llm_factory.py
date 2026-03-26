"""
LLM Analyzer factory — builds SemanticAnalyzer from environment variables.

Environment variables:
  CS_LLM_PROVIDER     = "anthropic" | "openai" | "" (default: rule-based only)
  ANTHROPIC_API_KEY    = API key for Anthropic provider
  OPENAI_API_KEY       = API key for OpenAI-compatible provider
  CS_LLM_MODEL        = override default model name
  CS_LLM_BASE_URL     = OpenAI-compatible base URL (e.g. kimi-k2.5 endpoint)
  CS_L3_ENABLED       = "true" to enable AgentAnalyzer (L3 review agent)
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any, Optional

from .llm_provider import AnthropicProvider, LLMProviderConfig, OpenAIProvider
from .semantic_analyzer import CompositeAnalyzer, LLMAnalyzer, RuleBasedAnalyzer

logger = logging.getLogger("ahp.llm-factory")


def build_analyzer_from_env(
    *,
    trajectory_store: Any = None,
    workspace_root: Optional[Path] = None,
    patterns_path: Optional[str] = None,
    evolved_patterns_path: Optional[str] = None,
    l3_budget_ms: Optional[float] = None,
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
    provider_name = os.getenv("CS_LLM_PROVIDER", "").strip().lower()
    if not provider_name:
        return None

    model = os.getenv("CS_LLM_MODEL", "").strip() or ""
    base_url = os.getenv("CS_LLM_BASE_URL", "").strip() or None

    if provider_name == "anthropic":
        api_key = os.getenv("ANTHROPIC_API_KEY", "").strip()
        if not api_key:
            logger.warning("CS_LLM_PROVIDER=anthropic but ANTHROPIC_API_KEY is empty; falling back to rule-based")
            return None
        config = LLMProviderConfig(api_key=api_key, model=model)
        provider = AnthropicProvider(config)

    elif provider_name == "openai":
        api_key = os.getenv("OPENAI_API_KEY", "").strip()
        if not api_key:
            logger.warning("CS_LLM_PROVIDER=openai but OPENAI_API_KEY is empty; falling back to rule-based")
            return None
        config = LLMProviderConfig(api_key=api_key, model=model, base_url=base_url)
        provider = OpenAIProvider(config)

    else:
        logger.warning("Unknown CS_LLM_PROVIDER=%r; falling back to rule-based", provider_name)
        return None

    logger.info(
        "LLM provider configured: %s (model=%s, base_url=%s)",
        provider_name,
        model or "(default)",
        base_url or "(default)",
    )

    analyzers: list = [RuleBasedAnalyzer(patterns_path=patterns_path, evolved_patterns_path=evolved_patterns_path), LLMAnalyzer(provider)]

    l3_enabled = os.getenv("CS_L3_ENABLED", "").strip().lower() in ("true", "1", "yes")
    if l3_enabled:
        try:
            from .agent_analyzer import AgentAnalyzer
            from .review_toolkit import ReadOnlyToolkit
            from .review_skills import SkillRegistry

            ws_root = workspace_root or Path.cwd()
            toolkit = ReadOnlyToolkit(ws_root, trajectory_store)
            skills_dir = Path(__file__).parent / "skills"
            skill_registry = SkillRegistry(skills_dir)
            custom_skills_dir = os.getenv("AHP_SKILLS_DIR", "").strip()
            if custom_skills_dir:
                custom_path = Path(custom_skills_dir)
                if custom_path.exists() and custom_path.is_dir():
                    loaded = skill_registry.load_additional(custom_path)
                    logger.info("Custom skills loaded from %s (%d skills)", custom_path, loaded)
            from .agent_analyzer import AgentAnalyzerConfig
            agent_config = AgentAnalyzerConfig()
            if l3_budget_ms is not None:
                agent_config = AgentAnalyzerConfig(l3_budget_ms=l3_budget_ms)
            agent = AgentAnalyzer(
                provider=provider,
                toolkit=toolkit,
                skill_registry=skill_registry,
                config=agent_config,
            )
            analyzers.append(agent)
            logger.info("L3 AgentAnalyzer enabled")
        except Exception:
            logger.warning("Failed to initialize L3 AgentAnalyzer; continuing with L1+L2 only", exc_info=True)

    return CompositeAnalyzer(analyzers)
