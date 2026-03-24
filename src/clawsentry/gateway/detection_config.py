"""
Unified detection configuration — single source of truth for all tunable parameters.

All defaults match the pre-existing hardcoded values for 100% backward compatibility.
Parameters can be overridden via constructor or ``CS_`` environment variables.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from typing import Optional

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

    # --- L2 semantic analysis ---
    l2_budget_ms: float = 5000.0
    attack_patterns_path: Optional[str] = None  # None = built-in default

    # --- Post-action tier thresholds ---
    post_action_emergency: float = 0.9
    post_action_escalate: float = 0.6
    post_action_monitor: float = 0.3
    post_action_whitelist: Optional[tuple[str, ...]] = field(default=None)

    # --- Trajectory analyzer ---
    trajectory_max_events: int = 50
    trajectory_max_sessions: int = 10_000

    def __post_init__(self) -> None:
        # Convert list to tuple if passed (convenience for callers)
        if isinstance(self.post_action_whitelist, list):
            object.__setattr__(self, "post_action_whitelist", tuple(self.post_action_whitelist))
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
        for wname in ("composite_weight_max_d123", "composite_weight_d4", "composite_weight_d5"):
            if getattr(self, wname) < 0:
                raise ValueError(f"weight {wname} must be >= 0, got {getattr(self, wname)}")
        if self.l2_budget_ms <= 0:
            raise ValueError(f"l2_budget_ms must be > 0, got {self.l2_budget_ms}")
        if not (self.post_action_monitor <= self.post_action_escalate <= self.post_action_emergency):
            raise ValueError(
                f"post_action tier ordering violated: monitor={self.post_action_monitor} "
                f"<= escalate={self.post_action_escalate} <= emergency={self.post_action_emergency}"
            )


# ---------------------------------------------------------------------------
# Environment-variable mapping: CS_<FIELD_NAME> → field
# ---------------------------------------------------------------------------

_ENV_MAP: list[tuple[str, str, type]] = [
    ("CS_COMPOSITE_WEIGHT_MAX_D123", "composite_weight_max_d123", float),
    ("CS_COMPOSITE_WEIGHT_D4", "composite_weight_d4", float),
    ("CS_COMPOSITE_WEIGHT_D5", "composite_weight_d5", float),
    ("CS_D6_INJECTION_MULTIPLIER", "d6_injection_multiplier", float),
    ("CS_THRESHOLD_CRITICAL", "threshold_critical", float),
    ("CS_THRESHOLD_HIGH", "threshold_high", float),
    ("CS_THRESHOLD_MEDIUM", "threshold_medium", float),
    ("CS_D4_HIGH_THRESHOLD", "d4_high_threshold", int),
    ("CS_D4_MID_THRESHOLD", "d4_mid_threshold", int),
    ("CS_L2_BUDGET_MS", "l2_budget_ms", float),
    ("CS_ATTACK_PATTERNS_PATH", "attack_patterns_path", str),
    ("CS_POST_ACTION_EMERGENCY", "post_action_emergency", float),
    ("CS_POST_ACTION_ESCALATE", "post_action_escalate", float),
    ("CS_POST_ACTION_MONITOR", "post_action_monitor", float),
    ("CS_TRAJECTORY_MAX_EVENTS", "trajectory_max_events", int),
    ("CS_TRAJECTORY_MAX_SESSIONS", "trajectory_max_sessions", int),
]

# Comma-separated list vars handled separately
_ENV_LIST_MAP: list[tuple[str, str]] = [
    ("CS_POST_ACTION_WHITELIST", "post_action_whitelist"),
]


def build_detection_config_from_env() -> DetectionConfig:
    """Build a :class:`DetectionConfig` from ``CS_`` environment variables.

    Missing or unparseable variables silently fall back to defaults.
    """
    overrides: dict = {}

    for env_key, field_name, typ in _ENV_MAP:
        raw = os.getenv(env_key)
        if raw is None:
            continue
        try:
            overrides[field_name] = typ(raw)
        except (ValueError, TypeError):
            logger.warning("Invalid value for %s=%r, using default", env_key, raw)

    for env_key, field_name in _ENV_LIST_MAP:
        raw = os.getenv(env_key)
        if raw is None:
            continue
        items = [s.strip() for s in raw.split(",") if s.strip()]
        if items:
            overrides[field_name] = tuple(items)

    return DetectionConfig(**overrides)
