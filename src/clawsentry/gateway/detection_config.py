"""
Unified detection configuration — single source of truth for tunable parameters.

The runtime keeps old field names such as ``l2_budget_ms`` for compatibility,
but the canonical operator-facing vocabulary is now timeout/token based.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from typing import Optional

from .llm_settings import resolve_llm_settings

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class DetectionConfig:
    """Immutable configuration for ClawSentry detection pipeline.

    Every field has a default that matches the original hardcoded constant,
    ensuring zero behavioural change when no overrides are provided.
    """

    # --- Composite scoring weights (risk_snapshot._composite_score_v2) ---
    composite_weight_max_d123: float = 0.4
    composite_weight_d4: float = 0.25
    composite_weight_d5: float = 0.15
    d6_injection_multiplier: float = 0.5  # formula: 1.0 + X * (d6/3.0)

    # --- Risk level thresholds ---
    threshold_critical: float = 2.2
    threshold_high: float = 1.5
    threshold_medium: float = 0.8

    # --- D4 session accumulation thresholds ---
    d4_high_threshold: int = 5   # count >= X → d4=2
    d4_mid_threshold: int = 2    # count >= X → d4=1

    # --- Operating mode ---
    mode: str = "normal"  # "normal", "strict", "permissive", or "benchmark"

    # --- L2/L3 semantic analysis ---
    l2_budget_ms: float = 60_000.0
    l3_budget_ms: Optional[float] = 300_000.0
    hard_timeout_ms: float = 600_000.0
    l3_routing_mode: str = "normal"  # "normal" or "replace_l2"
    l3_trigger_profile: str = "default"  # "default" or "eager"
    l3_budget_tuning_enabled: bool = False
    l3_advisory_async_enabled: bool = False
    l3_heartbeat_review_enabled: bool = False
    attack_patterns_path: Optional[str] = None  # None = built-in default

    # --- Post-action tier thresholds ---
    post_action_emergency: float = 0.9
    post_action_escalate: float = 0.6
    post_action_monitor: float = 0.3
    post_action_whitelist: Optional[tuple[str, ...]] = field(default=None)

    # --- Trajectory analyzer ---
    trajectory_max_events: int = 50
    trajectory_max_sessions: int = 10_000
    trajectory_alert_action: str = "broadcast"  # "broadcast", "defer", or "block"
    post_action_finding_action: str = "broadcast"  # "broadcast", "defer", or "block"

    # --- E-8: External content safety ---
    external_content_d6_boost: float = 0.3
    external_content_post_action_multiplier: float = 1.3

    # --- E-8: D4 frequency anomaly detection ---
    d4_freq_enabled: bool = True
    d4_freq_burst_count: int = 10
    d4_freq_burst_window_s: float = 5.0
    d4_freq_repetitive_count: int = 20
    d4_freq_repetitive_window_s: float = 60.0
    d4_freq_rate_limit_per_min: int = 60

    # --- E-9: DEFER timeout ---
    defer_timeout_action: str = "block"   # "block" or "allow"
    defer_timeout_s: float = 86_400.0     # 24 hours; benchmark mode never waits
    defer_bridge_enabled: bool = True     # Enable DEFER→operator bridge
    defer_max_pending: int = 0            # Max concurrent pending DEFERs (0 = unlimited)

    # --- LLM token budgets ---
    llm_token_budget_enabled: bool = False
    llm_daily_token_budget: int = 0
    llm_token_budget_scope: str = "total"  # "total", "input", or "output"
    llm_daily_budget_usd: float = 0.0      # deprecated; informational only

    # --- Benchmark/autonomous mode ---
    benchmark_auto_resolve_defer: bool = True
    benchmark_defer_action: str = "block"
    benchmark_persist_scope: str = "project"

    # --- Anti-bypass follow-up guard (default-off) ---
    anti_bypass_guard_enabled: bool = False
    anti_bypass_memory_ttl_s: float = 86_400.0
    anti_bypass_memory_max_records_per_session: int = 256
    anti_bypass_min_prior_risk: str = "high"
    anti_bypass_prior_verdicts: tuple[str, ...] = ("block", "defer")
    anti_bypass_exact_repeat_action: str = "block"
    anti_bypass_normalized_destructive_repeat_action: str = "defer"
    anti_bypass_cross_tool_similarity_action: str = "force_l3"
    anti_bypass_similarity_threshold: float = 0.92
    anti_bypass_same_tool_similarity_threshold: float = 0.88
    anti_bypass_record_allow_decisions: bool = False
    anti_bypass_llm_recognition_enabled: bool = False
    anti_bypass_llm_candidate_threshold: float = 0.55
    anti_bypass_llm_confidence_threshold: float = 0.75
    anti_bypass_llm_timeout_ms: float = 800.0
    anti_bypass_llm_max_priors: int = 3
    anti_bypass_llm_action: str = "force_l3"

    # --- E-5: Self-evolving pattern repository ---
    evolving_enabled: bool = False
    evolved_patterns_path: Optional[str] = None

    def __post_init__(self) -> None:
        # Convert list to tuple if passed (convenience for callers)
        if isinstance(self.post_action_whitelist, list):
            object.__setattr__(self, "post_action_whitelist", tuple(self.post_action_whitelist))
        if isinstance(self.anti_bypass_prior_verdicts, list):
            object.__setattr__(
                self,
                "anti_bypass_prior_verdicts",
                tuple(self.anti_bypass_prior_verdicts),
            )
        # Validate threshold ordering
        if not (self.threshold_medium <= self.threshold_high <= self.threshold_critical):
            raise ValueError(
                f"threshold ordering violated: medium={self.threshold_medium} "
                f"<= high={self.threshold_high} <= critical={self.threshold_critical}"
            )
        if self.d4_mid_threshold > self.d4_high_threshold:
            raise ValueError(
                f"d4 threshold ordering violated: mid={self.d4_mid_threshold} "
                f"> high={self.d4_high_threshold}"
            )
        for wname in ("composite_weight_max_d123", "composite_weight_d4", "composite_weight_d5", "d6_injection_multiplier"):
            if getattr(self, wname) < 0:
                raise ValueError(f"weight {wname} must be >= 0, got {getattr(self, wname)}")
        if self.mode not in ("normal", "strict", "permissive", "benchmark"):
            logger.warning("Invalid mode=%r, falling back to 'normal'", self.mode)
            object.__setattr__(self, "mode", "normal")
        if self.l2_budget_ms <= 0:
            raise ValueError(f"l2_budget_ms must be > 0, got {self.l2_budget_ms}")
        if self.l3_budget_ms is not None and self.l3_budget_ms <= 0:
            raise ValueError(f"l3_budget_ms must be > 0, got {self.l3_budget_ms}")
        if self.hard_timeout_ms <= 0:
            raise ValueError(f"hard_timeout_ms must be > 0, got {self.hard_timeout_ms}")
        if self.hard_timeout_ms < self.l2_budget_ms:
            raise ValueError("hard_timeout_ms must be >= l2_budget_ms")
        if self.l3_budget_ms is not None and self.hard_timeout_ms < self.l3_budget_ms:
            raise ValueError("hard_timeout_ms must be >= l3_budget_ms")
        if self.l3_routing_mode not in ("normal", "replace_l2"):
            logger.warning(
                "Invalid l3_routing_mode=%r, falling back to 'normal'",
                self.l3_routing_mode,
            )
            object.__setattr__(self, "l3_routing_mode", "normal")
        if self.l3_trigger_profile not in ("default", "eager"):
            logger.warning(
                "Invalid l3_trigger_profile=%r, falling back to 'default'",
                self.l3_trigger_profile,
            )
            object.__setattr__(self, "l3_trigger_profile", "default")
        for field_name in (
            "post_action_monitor",
            "post_action_escalate",
            "post_action_emergency",
        ):
            value = getattr(self, field_name)
            if value < 0:
                raise ValueError(f"{field_name} must be >= 0, got {value}")
            if value > 3.0:
                logger.warning(
                    "%s=%s is unreachable for post-action score range 0.0..3.0",
                    field_name,
                    value,
                )
        if not (self.post_action_monitor <= self.post_action_escalate <= self.post_action_emergency):
            raise ValueError(
                f"post_action tier ordering violated: monitor={self.post_action_monitor} "
                f"<= escalate={self.post_action_escalate} <= emergency={self.post_action_emergency}"
            )
        if self.defer_timeout_action not in ("block", "allow"):
            logger.warning(
                "Invalid defer_timeout_action=%r, falling back to 'block'",
                self.defer_timeout_action,
            )
            object.__setattr__(self, "defer_timeout_action", "block")
        for field_name in ("trajectory_alert_action", "post_action_finding_action"):
            if getattr(self, field_name) not in ("broadcast", "defer", "block"):
                logger.warning(
                    "Invalid %s=%r, falling back to 'broadcast'",
                    field_name,
                    getattr(self, field_name),
                )
                object.__setattr__(self, field_name, "broadcast")
        if self.defer_timeout_s <= 0:
            raise ValueError(f"defer_timeout_s must be > 0, got {self.defer_timeout_s}")
        if self.llm_daily_budget_usd < 0:
            raise ValueError(f"llm_daily_budget_usd must be >= 0, got {self.llm_daily_budget_usd}")
        if self.llm_token_budget_scope not in ("total", "input", "output"):
            logger.warning(
                "Invalid llm_token_budget_scope=%r, falling back to 'total'",
                self.llm_token_budget_scope,
            )
            object.__setattr__(self, "llm_token_budget_scope", "total")
        if self.llm_daily_token_budget < 0:
            raise ValueError(
                f"llm_daily_token_budget must be >= 0, got {self.llm_daily_token_budget}"
            )
        if self.llm_token_budget_enabled and self.llm_daily_token_budget <= 0:
            logger.error(
                "LLM token budget enabled with non-positive limit; disabling token budget enforcement"
            )
            object.__setattr__(self, "llm_token_budget_enabled", False)
        if self.benchmark_defer_action not in ("block", "allow", "allow_low_block_high"):
            logger.warning(
                "Invalid benchmark_defer_action=%r, falling back to 'block'",
                self.benchmark_defer_action,
            )
            object.__setattr__(self, "benchmark_defer_action", "block")
        if self.benchmark_persist_scope not in ("project", "temp"):
            logger.warning(
                "Invalid benchmark_persist_scope=%r, falling back to 'project'",
                self.benchmark_persist_scope,
            )
            object.__setattr__(self, "benchmark_persist_scope", "project")
        if self.anti_bypass_memory_ttl_s <= 0:
            raise ValueError(
                f"anti_bypass_memory_ttl_s must be > 0, got {self.anti_bypass_memory_ttl_s}"
            )
        if self.anti_bypass_memory_max_records_per_session < 1:
            raise ValueError(
                "anti_bypass_memory_max_records_per_session must be >= 1, "
                f"got {self.anti_bypass_memory_max_records_per_session}"
            )
        if self.anti_bypass_min_prior_risk not in ("low", "medium", "high", "critical"):
            logger.warning(
                "Invalid anti_bypass_min_prior_risk=%r, falling back to 'high'",
                self.anti_bypass_min_prior_risk,
            )
            object.__setattr__(self, "anti_bypass_min_prior_risk", "high")
        valid_verdicts = {"allow", "defer", "block"}
        prior_verdicts = tuple(str(v).strip().lower() for v in self.anti_bypass_prior_verdicts)
        if not prior_verdicts or any(v not in valid_verdicts for v in prior_verdicts):
            logger.warning(
                "Invalid anti_bypass_prior_verdicts=%r, falling back to ('block', 'defer')",
                self.anti_bypass_prior_verdicts,
            )
            object.__setattr__(self, "anti_bypass_prior_verdicts", ("block", "defer"))
        else:
            object.__setattr__(self, "anti_bypass_prior_verdicts", prior_verdicts)
        repeat_actions = {"observe", "force_l2", "force_l3", "defer", "block"}
        for field_name, fallback in (
            ("anti_bypass_exact_repeat_action", "block"),
            ("anti_bypass_normalized_destructive_repeat_action", "defer"),
        ):
            if getattr(self, field_name) not in repeat_actions:
                logger.warning(
                    "Invalid %s=%r, falling back to %r",
                    field_name,
                    getattr(self, field_name),
                    fallback,
                )
                object.__setattr__(self, field_name, fallback)
        cross_tool_actions = {"observe", "force_l2", "force_l3", "defer"}
        if self.anti_bypass_cross_tool_similarity_action not in cross_tool_actions:
            logger.warning(
                "Invalid anti_bypass_cross_tool_similarity_action=%r, falling back to 'force_l3'",
                self.anti_bypass_cross_tool_similarity_action,
            )
            object.__setattr__(self, "anti_bypass_cross_tool_similarity_action", "force_l3")
        if not (0.0 <= self.anti_bypass_similarity_threshold <= 1.0):
            raise ValueError(
                "anti_bypass_similarity_threshold must be between 0.0 and 1.0, "
                f"got {self.anti_bypass_similarity_threshold}"
            )
        if not (0.0 <= self.anti_bypass_same_tool_similarity_threshold <= 1.0):
            raise ValueError(
                "anti_bypass_same_tool_similarity_threshold must be between 0.0 and 1.0, "
                f"got {self.anti_bypass_same_tool_similarity_threshold}"
            )
        if not (0.0 <= self.anti_bypass_llm_candidate_threshold <= 1.0):
            raise ValueError(
                "anti_bypass_llm_candidate_threshold must be between 0.0 and 1.0, "
                f"got {self.anti_bypass_llm_candidate_threshold}"
            )
        if not (0.0 <= self.anti_bypass_llm_confidence_threshold <= 1.0):
            raise ValueError(
                "anti_bypass_llm_confidence_threshold must be between 0.0 and 1.0, "
                f"got {self.anti_bypass_llm_confidence_threshold}"
            )
        if self.anti_bypass_llm_timeout_ms <= 0:
            raise ValueError(
                f"anti_bypass_llm_timeout_ms must be > 0, got {self.anti_bypass_llm_timeout_ms}"
            )
        if self.anti_bypass_llm_max_priors < 1:
            raise ValueError(
                f"anti_bypass_llm_max_priors must be >= 1, got {self.anti_bypass_llm_max_priors}"
            )
        llm_actions = {"observe", "force_l2", "force_l3", "defer"}
        if self.anti_bypass_llm_action not in llm_actions:
            logger.warning(
                "Invalid anti_bypass_llm_action=%r, falling back to 'force_l3'",
                self.anti_bypass_llm_action,
            )
            object.__setattr__(self, "anti_bypass_llm_action", "force_l3")
        if self.threshold_critical > 3.0:
            logger.warning(
                "threshold_critical=%.2f exceeds max achievable score (3.0) with default weights; "
                "CRITICAL level may be unreachable",
                self.threshold_critical,
            )

    @property
    def l2_timeout_ms(self) -> float:
        """Canonical alias retained for compatibility with the new config contract."""
        return self.l2_budget_ms

    @property
    def l3_timeout_ms(self) -> float | None:
        """Canonical alias retained for compatibility with the new config contract."""
        return self.l3_budget_ms


# ---------------------------------------------------------------------------
# Environment-variable mapping: CS_<FIELD_NAME> → field
# ---------------------------------------------------------------------------

_ENV_MAP: list[tuple[str, str, type]] = [
    ("CS_MODE", "mode", str),
    ("CS_COMPOSITE_WEIGHT_MAX_D123", "composite_weight_max_d123", float),
    ("CS_COMPOSITE_WEIGHT_D4", "composite_weight_d4", float),
    ("CS_COMPOSITE_WEIGHT_D5", "composite_weight_d5", float),
    ("CS_D6_INJECTION_MULTIPLIER", "d6_injection_multiplier", float),
    ("CS_THRESHOLD_CRITICAL", "threshold_critical", float),
    ("CS_THRESHOLD_HIGH", "threshold_high", float),
    ("CS_THRESHOLD_MEDIUM", "threshold_medium", float),
    ("CS_D4_HIGH_THRESHOLD", "d4_high_threshold", int),
    ("CS_D4_MID_THRESHOLD", "d4_mid_threshold", int),
    ("CS_L2_TIMEOUT_MS", "l2_budget_ms", float),
    ("CS_L3_TIMEOUT_MS", "l3_budget_ms", float),
    ("CS_HARD_TIMEOUT_MS", "hard_timeout_ms", float),
    ("CS_L3_ROUTING_MODE", "l3_routing_mode", str),
    ("CS_L3_TRIGGER_PROFILE", "l3_trigger_profile", str),
    ("CS_ATTACK_PATTERNS_PATH", "attack_patterns_path", str),
    ("CS_POST_ACTION_EMERGENCY", "post_action_emergency", float),
    ("CS_POST_ACTION_ESCALATE", "post_action_escalate", float),
    ("CS_POST_ACTION_MONITOR", "post_action_monitor", float),
    ("CS_TRAJECTORY_MAX_EVENTS", "trajectory_max_events", int),
    ("CS_TRAJECTORY_MAX_SESSIONS", "trajectory_max_sessions", int),
    ("CS_TRAJECTORY_ALERT_ACTION", "trajectory_alert_action", str),
    ("CS_POST_ACTION_FINDING_ACTION", "post_action_finding_action", str),
    ("CS_EVOLVED_PATTERNS_PATH", "evolved_patterns_path", str),
    ("CS_EXTERNAL_CONTENT_D6_BOOST", "external_content_d6_boost", float),
    ("CS_EXTERNAL_CONTENT_POST_ACTION_MULTIPLIER", "external_content_post_action_multiplier", float),
    ("CS_D4_FREQ_BURST_COUNT", "d4_freq_burst_count", int),
    ("CS_D4_FREQ_BURST_WINDOW_S", "d4_freq_burst_window_s", float),
    ("CS_D4_FREQ_REPETITIVE_COUNT", "d4_freq_repetitive_count", int),
    ("CS_D4_FREQ_REPETITIVE_WINDOW_S", "d4_freq_repetitive_window_s", float),
    ("CS_D4_FREQ_RATE_LIMIT_PER_MIN", "d4_freq_rate_limit_per_min", int),
    ("CS_DEFER_TIMEOUT_ACTION", "defer_timeout_action", str),
    ("CS_DEFER_TIMEOUT_S", "defer_timeout_s", float),
    ("CS_DEFER_MAX_PENDING", "defer_max_pending", int),
    ("CS_LLM_DAILY_TOKEN_BUDGET", "llm_daily_token_budget", int),
    ("CS_LLM_TOKEN_BUDGET_SCOPE", "llm_token_budget_scope", str),
    ("CS_LLM_DAILY_BUDGET_USD", "llm_daily_budget_usd", float),
    ("CS_BENCHMARK_DEFER_ACTION", "benchmark_defer_action", str),
    ("CS_BENCHMARK_PERSIST_SCOPE", "benchmark_persist_scope", str),
    ("CS_ANTI_BYPASS_MEMORY_TTL_S", "anti_bypass_memory_ttl_s", float),
    ("CS_ANTI_BYPASS_MEMORY_MAX_RECORDS_PER_SESSION", "anti_bypass_memory_max_records_per_session", int),
    ("CS_ANTI_BYPASS_MIN_PRIOR_RISK", "anti_bypass_min_prior_risk", str),
    ("CS_ANTI_BYPASS_EXACT_REPEAT_ACTION", "anti_bypass_exact_repeat_action", str),
    ("CS_ANTI_BYPASS_NORMALIZED_DESTRUCTIVE_REPEAT_ACTION", "anti_bypass_normalized_destructive_repeat_action", str),
    ("CS_ANTI_BYPASS_CROSS_TOOL_SIMILARITY_ACTION", "anti_bypass_cross_tool_similarity_action", str),
    ("CS_ANTI_BYPASS_SIMILARITY_THRESHOLD", "anti_bypass_similarity_threshold", float),
    ("CS_ANTI_BYPASS_SAME_TOOL_SIMILARITY_THRESHOLD", "anti_bypass_same_tool_similarity_threshold", float),
    ("CS_ANTI_BYPASS_LLM_CANDIDATE_THRESHOLD", "anti_bypass_llm_candidate_threshold", float),
    ("CS_ANTI_BYPASS_LLM_CONFIDENCE_THRESHOLD", "anti_bypass_llm_confidence_threshold", float),
    ("CS_ANTI_BYPASS_LLM_TIMEOUT_MS", "anti_bypass_llm_timeout_ms", float),
    ("CS_ANTI_BYPASS_LLM_MAX_PRIORS", "anti_bypass_llm_max_priors", int),
    ("CS_ANTI_BYPASS_LLM_ACTION", "anti_bypass_llm_action", str),
]

_ENV_ALIAS_MAP: list[tuple[str, str, type, str]] = [
    ("CS_L2_BUDGET_MS", "l2_budget_ms", float, "CS_L2_TIMEOUT_MS"),
    ("CS_L3_BUDGET_MS", "l3_budget_ms", float, "CS_L3_TIMEOUT_MS"),
]

# Comma-separated list vars handled separately
_ENV_LIST_MAP: list[tuple[str, str]] = [
    ("CS_POST_ACTION_WHITELIST", "post_action_whitelist"),
    ("CS_ANTI_BYPASS_PRIOR_VERDICTS", "anti_bypass_prior_verdicts"),
]


def _anti_bypass_llm_auto_enable_allowed(params: dict[str, object]) -> bool:
    if str(params.get("mode") or "normal").strip().lower() == "benchmark":
        return False
    for env_key in ("CS_DRY_RUN", "CS_NO_NETWORK", "CS_LLM_NO_NETWORK"):
        raw = os.getenv(env_key, "").strip().lower()
        if raw in ("1", "true", "yes", "on"):
            return False
    return True


def build_detection_config_from_env() -> DetectionConfig:
    """Build a :class:`DetectionConfig` from ``CS_`` environment variables.

    Missing or unparseable variables silently fall back to defaults.
    If the combination of overrides violates validation constraints,
    the entire config falls back to defaults with an error log.
    """
    preset_name = os.getenv("CS_PRESET", "medium").strip() or "medium"
    try:
        overrides: dict = dict(PRESETS[preset_name])
    except KeyError:
        logger.warning("Invalid CS_PRESET=%r, using medium defaults", preset_name)
        overrides = {}

    for env_key, field_name, typ in _ENV_MAP:
        raw = os.getenv(env_key)
        if raw is None:
            continue
        try:
            overrides[field_name] = typ(raw)
        except (ValueError, TypeError):
            logger.warning("Invalid value for %s=%r, using default", env_key, raw)

    for env_key, field_name, typ, canonical_key in _ENV_ALIAS_MAP:
        raw = os.getenv(env_key)
        if raw is None:
            continue
        if os.getenv(canonical_key) is not None or field_name in overrides:
            logger.warning(
                "Ignoring deprecated %s because canonical %s is set",
                env_key,
                canonical_key,
            )
            continue
        try:
            overrides[field_name] = typ(raw)
            logger.warning("Deprecated %s is accepted as alias for %s", env_key, canonical_key)
        except (ValueError, TypeError):
            logger.warning("Invalid value for %s=%r, using default", env_key, raw)

    for env_key, field_name in _ENV_LIST_MAP:
        raw = os.getenv(env_key)
        if raw is None:
            continue
        items = [s.strip() for s in raw.split(",") if s.strip()]
        if items:
            overrides[field_name] = tuple(items)

    # Bool env vars (special handling: "1"/"true"/"yes" → True)
    def _parse_bool_env(env_key: str, field_name: str) -> bool:
        raw = os.getenv(env_key, "").strip().lower()
        if raw in ("1", "true", "yes"):
            overrides[field_name] = True
            return True
        if raw in ("0", "false", "no"):
            overrides[field_name] = False
            return True
        if raw:
            logger.warning("Invalid value for %s=%r, using default", env_key, raw)
            return True
        return False

    _parse_bool_env("CS_EVOLVING_ENABLED", "evolving_enabled")
    _parse_bool_env("CS_D4_FREQ_ENABLED", "d4_freq_enabled")
    _parse_bool_env("CS_DEFER_BRIDGE_ENABLED", "defer_bridge_enabled")
    _parse_bool_env("CS_L3_BUDGET_TUNING_ENABLED", "l3_budget_tuning_enabled")
    _parse_bool_env("CS_L3_ADVISORY_ASYNC_ENABLED", "l3_advisory_async_enabled")
    _parse_bool_env("CS_L3_HEARTBEAT_REVIEW_ENABLED", "l3_heartbeat_review_enabled")
    _parse_bool_env("CS_LLM_TOKEN_BUDGET_ENABLED", "llm_token_budget_enabled")
    _parse_bool_env("CS_BENCHMARK_AUTO_RESOLVE_DEFER", "benchmark_auto_resolve_defer")
    _parse_bool_env("CS_ANTI_BYPASS_GUARD_ENABLED", "anti_bypass_guard_enabled")
    _parse_bool_env("CS_ANTI_BYPASS_RECORD_ALLOW_DECISIONS", "anti_bypass_record_allow_decisions")
    explicit_anti_bypass_llm = _parse_bool_env(
        "CS_ANTI_BYPASS_LLM_RECOGNITION_ENABLED",
        "anti_bypass_llm_recognition_enabled",
    )
    if (
        not explicit_anti_bypass_llm
        and bool(overrides.get("anti_bypass_guard_enabled", False))
        and _anti_bypass_llm_auto_enable_allowed(overrides)
        and resolve_llm_settings() is not None
    ):
        overrides["anti_bypass_llm_recognition_enabled"] = True

    # Deprecated USD budgets are migration telemetry only on the env/runtime
    # path.  Enforcement uses provider-reported token usage, so the legacy
    # estimate must not exhaust budget by itself.
    if "llm_daily_budget_usd" in overrides:
        logger.warning(
            "CS_LLM_DAILY_BUDGET_USD is deprecated and informational; "
            "use CS_LLM_TOKEN_BUDGET_ENABLED/CS_LLM_DAILY_TOKEN_BUDGET"
        )
        overrides["llm_daily_budget_usd"] = 0.0

    try:
        return DetectionConfig(**overrides)
    except (ValueError, TypeError) as exc:
        logger.error(
            "CS_ env vars produce invalid DetectionConfig (%s); falling back to defaults",
            exc,
        )
        return DetectionConfig()


# --- Preset security levels ---

PRESETS: dict[str, dict[str, object]] = {
    "low": {
        "threshold_critical": 2.8,
        "threshold_high": 2.0,
        "threshold_medium": 1.2,
        "d6_injection_multiplier": 0.3,
        "post_action_emergency": 0.95,
        "post_action_escalate": 0.7,
        "post_action_monitor": 0.4,
        "defer_timeout_action": "allow",
        "defer_bridge_enabled": False,
    },
    "medium": {},  # all defaults
    "high": {
        "threshold_critical": 1.8,
        "threshold_high": 1.2,
        "threshold_medium": 0.5,
        "d6_injection_multiplier": 0.7,
        "post_action_emergency": 0.8,
        "post_action_escalate": 0.5,
        "post_action_monitor": 0.2,
        "trajectory_alert_action": "defer",
        "post_action_finding_action": "defer",
    },
    "strict": {
        "threshold_critical": 1.3,
        "threshold_high": 0.9,
        "threshold_medium": 0.3,
        "d6_injection_multiplier": 1.0,
        "post_action_emergency": 0.7,
        "post_action_escalate": 0.4,
        "post_action_monitor": 0.15,
        "trajectory_alert_action": "block",
        "post_action_finding_action": "block",
    },
}


def from_preset(name: str, **overrides: object) -> DetectionConfig:
    """Create a DetectionConfig from a named preset with optional overrides.

    Raises KeyError if preset name is unknown.
    """
    if name not in PRESETS:
        raise KeyError(f"Unknown preset: {name!r}. Available: {sorted(PRESETS.keys())}")
    params = dict(PRESETS[name])
    params.update(overrides)
    return DetectionConfig(**params)


def build_detection_config_with_preset(
    preset_name: str,
    project_overrides: dict[str, object],
) -> DetectionConfig:
    """Build a :class:`DetectionConfig` from a preset, project overrides, and env vars.

    Priority chain (highest wins):
      1. ``CS_`` environment variables
      2. explicit preset/override parameters
      3. Preset values
      4. :class:`DetectionConfig` defaults

    If the preset name is unknown, logs a warning and falls back to defaults.
    If the final combination violates validation, falls back to defaults.
    """
    # 1. Start from preset
    try:
        preset_params = dict(PRESETS[preset_name])
    except KeyError:
        logger.warning(
            "Unknown preset %r in project config; using defaults", preset_name
        )
        preset_params = {}

    # 2. Apply project overrides on top
    params: dict[str, object] = {**preset_params, **project_overrides}

    # 3. Apply env var overrides on top (highest priority)
    for env_key, field_name, typ in _ENV_MAP:
        raw = os.getenv(env_key)
        if raw is None:
            continue
        try:
            params[field_name] = typ(raw)
        except (ValueError, TypeError):
            logger.warning("Invalid value for %s=%r, using default", env_key, raw)

    for env_key, field_name, typ, canonical_key in _ENV_ALIAS_MAP:
        raw = os.getenv(env_key)
        if raw is None:
            continue
        if os.getenv(canonical_key) is not None or field_name in params:
            logger.warning(
                "Ignoring deprecated %s because canonical %s is set",
                env_key,
                canonical_key,
            )
            continue
        try:
            params[field_name] = typ(raw)
            logger.warning("Deprecated %s is accepted as alias for %s", env_key, canonical_key)
        except (ValueError, TypeError):
            logger.warning("Invalid value for %s=%r, using default", env_key, raw)

    for env_key, field_name in _ENV_LIST_MAP:
        raw = os.getenv(env_key)
        if raw is None:
            continue
        items = [s.strip() for s in raw.split(",") if s.strip()]
        if items:
            params[field_name] = tuple(items)

    def _parse_bool_env(env_key: str, field_name: str) -> bool:
        raw = os.getenv(env_key, "").strip().lower()
        if raw in ("1", "true", "yes"):
            params[field_name] = True
            return True
        if raw in ("0", "false", "no"):
            params[field_name] = False
            return True
        if raw:
            logger.warning("Invalid value for %s=%r, using default", env_key, raw)
            return True
        return False

    _parse_bool_env("CS_EVOLVING_ENABLED", "evolving_enabled")
    _parse_bool_env("CS_D4_FREQ_ENABLED", "d4_freq_enabled")
    _parse_bool_env("CS_DEFER_BRIDGE_ENABLED", "defer_bridge_enabled")
    _parse_bool_env("CS_L3_BUDGET_TUNING_ENABLED", "l3_budget_tuning_enabled")
    _parse_bool_env("CS_L3_ADVISORY_ASYNC_ENABLED", "l3_advisory_async_enabled")
    _parse_bool_env("CS_L3_HEARTBEAT_REVIEW_ENABLED", "l3_heartbeat_review_enabled")
    _parse_bool_env("CS_LLM_TOKEN_BUDGET_ENABLED", "llm_token_budget_enabled")
    _parse_bool_env("CS_BENCHMARK_AUTO_RESOLVE_DEFER", "benchmark_auto_resolve_defer")
    _parse_bool_env("CS_ANTI_BYPASS_GUARD_ENABLED", "anti_bypass_guard_enabled")
    _parse_bool_env("CS_ANTI_BYPASS_RECORD_ALLOW_DECISIONS", "anti_bypass_record_allow_decisions")
    explicit_anti_bypass_llm = _parse_bool_env(
        "CS_ANTI_BYPASS_LLM_RECOGNITION_ENABLED",
        "anti_bypass_llm_recognition_enabled",
    )
    if (
        not explicit_anti_bypass_llm
        and bool(params.get("anti_bypass_guard_enabled", False))
        and _anti_bypass_llm_auto_enable_allowed(params)
        and resolve_llm_settings() is not None
    ):
        params["anti_bypass_llm_recognition_enabled"] = True

    # Keep legacy USD budgets informational on the env/runtime path.
    if "llm_daily_budget_usd" in params:
        logger.warning(
            "CS_LLM_DAILY_BUDGET_USD is deprecated and informational; "
            "use CS_LLM_TOKEN_BUDGET_ENABLED/CS_LLM_DAILY_TOKEN_BUDGET"
        )
        params["llm_daily_budget_usd"] = 0.0

    try:
        return DetectionConfig(**params)
    except (ValueError, TypeError) as exc:
        logger.error(
            "Preset %r + overrides produce invalid DetectionConfig (%s); "
            "falling back to defaults",
            preset_name,
            exc,
        )
        return DetectionConfig()
