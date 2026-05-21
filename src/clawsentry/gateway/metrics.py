"""
Prometheus metrics collector for ClawSentry Gateway.

Provides a ``MetricsCollector`` class that records decision counters, latency
histograms, LLM token/cost tracking, and session/defer gauges.  When
``prometheus_client`` is not installed the collector degrades gracefully to a
no-op implementation so the gateway runs without the optional dependency.

Usage::

    from clawsentry.gateway.metrics import MetricsCollector

    mc = MetricsCollector(enabled=True)
    mc.record_decision(verdict="allow", risk_level="low", risk_score=0.12,
                       tier="L1", source_framework="test", latency_s=0.002)
    print(mc.generate_metrics_text())
"""

from __future__ import annotations

import logging
import threading
from datetime import datetime, timezone
from typing import Any, Callable, Optional

logger = logging.getLogger("clawsentry.metrics")

# ---------------------------------------------------------------------------
# Optional prometheus_client import
# ---------------------------------------------------------------------------

try:
    from prometheus_client import (
        CollectorRegistry,
        Counter,
        Gauge,
        Histogram,
        generate_latest,
    )
    _PROMETHEUS_AVAILABLE = True
except ImportError:  # pragma: no cover
    _PROMETHEUS_AVAILABLE = False

# ---------------------------------------------------------------------------
# Cost estimation helper
# ---------------------------------------------------------------------------

# Hardcoded per-token pricing (USD per 1M tokens).
# These are rough estimates — Task 2 will add per-provider config.
_PRICING: dict[str, tuple[float, float]] = {
    # provider: (input_price_per_M, output_price_per_M)
    "anthropic": (3.0, 15.0),
    "openai": (2.5, 10.0),
}
_DEFAULT_PRICING = (5.0, 15.0)  # fallback for unknown providers


def _estimate_cost(
    provider: str,
    input_tokens: int,
    output_tokens: int,
) -> float:
    """Estimate USD cost for an LLM call based on hardcoded pricing.

    Returns 0.0 when both token counts are zero.
    """
    if input_tokens == 0 and output_tokens == 0:
        return 0.0
    input_price, output_price = _PRICING.get(
        provider.lower(), _DEFAULT_PRICING,
    )
    return (input_tokens * input_price + output_tokens * output_price) / 1_000_000


def _empty_llm_usage_bucket() -> dict[str, float | int]:
    return {
        "calls": 0,
        "input_tokens": 0,
        "output_tokens": 0,
        "cost_usd": 0.0,
    }


# ---------------------------------------------------------------------------
# MetricsCollector
# ---------------------------------------------------------------------------


class MetricsCollector:
    """Prometheus metrics collector with graceful no-op degradation.

    Each instance creates a **dedicated** ``CollectorRegistry`` so that
    multiple test instances do not pollute each other's state (the global
    default registry is never used).

    Parameters
    ----------
    enabled:
        If ``False`` — or if ``prometheus_client`` is not installed — all
        recording methods become silent no-ops and
        :meth:`generate_metrics_text` returns ``b""``.
    budget_tracker:
        Optional shared :class:`LLMBudgetTracker` to update from LLM spend
        accounting.  Spend recording happens even when Prometheus metrics are
        disabled so budget gating stays active.
    """

    def __init__(
        self,
        enabled: bool = True,
        *,
        budget_tracker: Optional["LLMBudgetTracker"] = None,
        budget_exhausted_callback: Optional[Callable[[dict[str, Any]], None]] = None,
    ) -> None:
        if not _PROMETHEUS_AVAILABLE:
            self.enabled = False
        else:
            self.enabled = enabled
        self._budget_tracker = budget_tracker
        self._budget_exhausted_callback = budget_exhausted_callback
        self._llm_usage_lock = threading.Lock()
        self._llm_usage_breakdown: dict[str, Any] = {
            "total_calls": 0,
            "total_input_tokens": 0,
            "total_output_tokens": 0,
            "total_cost_usd": 0.0,
            "by_provider": {},
            "by_tier": {},
            "by_status": {},
        }

        if not self.enabled:
            return

        # Private registry — never touches the global default.
        self._registry = CollectorRegistry()

        # --- Counters ---
        self._decisions_total = Counter(
            "clawsentry_decisions_total",
            "Total supervision decisions",
            ["verdict", "risk_level", "tier", "source_framework"],
            registry=self._registry,
        )

        self._llm_calls_total = Counter(
            "clawsentry_llm_calls_total",
            "Total LLM API calls",
            ["provider", "tier", "status"],
            registry=self._registry,
        )

        self._llm_tokens_total = Counter(
            "clawsentry_llm_tokens_total",
            "Total LLM tokens consumed",
            ["provider", "direction"],
            registry=self._registry,
        )

        self._llm_cost_total = Counter(
            "clawsentry_llm_cost_usd_total",
            "Estimated cumulative LLM cost in USD",
            ["provider"],
            registry=self._registry,
        )

        self._content_evidence_collected_total = Counter(
            "clawsentry_content_evidence_collected_total",
            "Total content evidence collection attempts that produced an envelope",
            registry=self._registry,
        )

        self._content_evidence_incomplete_total = Counter(
            "clawsentry_content_evidence_incomplete_total",
            "Total content evidence envelopes with incomplete content",
            registry=self._registry,
        )

        self._content_evidence_mismatch_total = Counter(
            "clawsentry_content_evidence_mismatch_total",
            "Total content evidence collection mismatches",
            registry=self._registry,
        )

        self._content_evidence_execution_unverified_total = Counter(
            "clawsentry_content_evidence_execution_unverified_total",
            "Total content evidence execution verification failures",
            registry=self._registry,
        )

        self._content_evidence_policy_not_allow_total = Counter(
            "clawsentry_content_evidence_policy_not_allow_total",
            "Total decisions where content evidence contributed to a non-allow policy outcome",
            registry=self._registry,
        )

        # --- Histograms ---
        self._decision_latency = Histogram(
            "clawsentry_decision_latency_seconds",
            "Decision latency in seconds",
            ["tier", "source_framework"],
            registry=self._registry,
        )

        self._risk_score = Histogram(
            "clawsentry_risk_score",
            "Observed risk scores",
            ["source_framework"],
            registry=self._registry,
        )

        # --- Gauges ---
        self._active_sessions = Gauge(
            "clawsentry_active_sessions",
            "Number of currently active sessions",
            registry=self._registry,
        )

        self._defers_pending = Gauge(
            "clawsentry_defers_pending",
            "Number of DEFER decisions awaiting operator resolution",
            registry=self._registry,
        )

    # ------------------------------------------------------------------
    # Recording methods
    # ------------------------------------------------------------------

    def _update_llm_usage_bucket(
        self,
        bucket_map: dict[str, dict[str, float | int]],
        key: str,
        *,
        input_tokens: int,
        output_tokens: int,
        cost: float,
    ) -> None:
        bucket = bucket_map.get(key)
        if bucket is None:
            bucket = _empty_llm_usage_bucket()
            bucket_map[key] = bucket
        bucket["calls"] = int(bucket["calls"]) + 1
        bucket["input_tokens"] = int(bucket["input_tokens"]) + input_tokens
        bucket["output_tokens"] = int(bucket["output_tokens"]) + output_tokens
        bucket["cost_usd"] = float(bucket["cost_usd"]) + cost

    def _record_llm_usage_breakdown(
        self,
        *,
        provider: str,
        tier: str,
        status: str,
        input_tokens: int,
        output_tokens: int,
        cost: float,
    ) -> None:
        provider_key = str(provider or "unknown")
        tier_key = str(tier or "unknown")
        status_key = str(status or "unknown")
        with self._llm_usage_lock:
            self._llm_usage_breakdown["total_calls"] = int(
                self._llm_usage_breakdown["total_calls"]
            ) + 1
            self._llm_usage_breakdown["total_input_tokens"] = int(
                self._llm_usage_breakdown["total_input_tokens"]
            ) + input_tokens
            self._llm_usage_breakdown["total_output_tokens"] = int(
                self._llm_usage_breakdown["total_output_tokens"]
            ) + output_tokens
            self._llm_usage_breakdown["total_cost_usd"] = float(
                self._llm_usage_breakdown["total_cost_usd"]
            ) + cost
            self._update_llm_usage_bucket(
                self._llm_usage_breakdown["by_provider"],
                provider_key,
                input_tokens=input_tokens,
                output_tokens=output_tokens,
                cost=cost,
            )
            self._update_llm_usage_bucket(
                self._llm_usage_breakdown["by_tier"],
                tier_key,
                input_tokens=input_tokens,
                output_tokens=output_tokens,
                cost=cost,
            )
            self._update_llm_usage_bucket(
                self._llm_usage_breakdown["by_status"],
                status_key,
                input_tokens=input_tokens,
                output_tokens=output_tokens,
                cost=cost,
            )

    def record_decision(
        self,
        *,
        verdict: str,
        risk_level: str,
        risk_score: float,
        tier: str,
        source_framework: str,
        latency_s: float,
    ) -> None:
        """Record a supervision decision."""
        if not self.enabled:
            return
        self._decisions_total.labels(
            verdict=verdict,
            risk_level=risk_level,
            tier=tier,
            source_framework=source_framework,
        ).inc()
        self._decision_latency.labels(
            tier=tier,
            source_framework=source_framework,
        ).observe(latency_s)
        self._risk_score.labels(
            source_framework=source_framework,
        ).observe(risk_score)

    def record_llm_call(
        self,
        *,
        provider: str,
        tier: str,
        status: str,
        input_tokens: int = 0,
        output_tokens: int = 0,
    ) -> None:
        """Record an LLM API call with token counts."""
        cost = _estimate_cost(provider, input_tokens, output_tokens)
        no_token_usage = input_tokens == 0 and output_tokens == 0
        self._record_llm_usage_breakdown(
            provider=provider,
            tier=tier,
            status=status,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            cost=cost,
        )
        if self._budget_tracker is not None:
            if self._budget_tracker.enabled:
                if no_token_usage:
                    exhausted = self._budget_tracker.record_unknown_usage()
                else:
                    exhausted = self._budget_tracker.record_usage(
                        input_tokens=input_tokens,
                        output_tokens=output_tokens,
                    )
            else:
                exhausted = self._budget_tracker.record_spend(cost)
            if exhausted:
                budget_snapshot = self._budget_tracker.snapshot()
                exhausted_event = {
                    "type": "budget_exhausted",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "provider": provider,
                    "tier": tier,
                    "status": status,
                    "estimated_cost_usd": cost,
                    "input_tokens": input_tokens,
                    "output_tokens": output_tokens,
                    "budget": budget_snapshot,
                }
                if self._budget_exhausted_callback is not None:
                    try:
                        self._budget_exhausted_callback(exhausted_event)
                    except Exception:
                        logger.exception("budget exhaustion callback failed")
                logger.warning(
                    "LLM token budget exhausted after input=%s output=%s provider=%s tier=%s",
                    input_tokens,
                    output_tokens,
                    provider,
                    tier,
                )
        if not self.enabled:
            return
        self._llm_calls_total.labels(
            provider=provider,
            tier=tier,
            status=status,
        ).inc()
        if input_tokens:
            self._llm_tokens_total.labels(
                provider=provider,
                direction="input",
            ).inc(input_tokens)
        if output_tokens:
            self._llm_tokens_total.labels(
                provider=provider,
                direction="output",
            ).inc(output_tokens)
        if cost > 0:
            self._llm_cost_total.labels(provider=provider).inc(cost)

    def session_started(self) -> None:
        """Increment the active-sessions gauge."""
        if not self.enabled:
            return
        self._active_sessions.inc()

    def session_ended(self) -> None:
        """Decrement the active-sessions gauge."""
        if not self.enabled:
            return
        self._active_sessions.dec()

    def defer_registered(self) -> None:
        """Increment the pending-defers gauge."""
        if not self.enabled:
            return
        self._defers_pending.inc()

    def defer_resolved(self) -> None:
        """Decrement the pending-defers gauge."""
        if not self.enabled:
            return
        self._defers_pending.dec()

    def record_content_evidence(
        self,
        *,
        collected: bool = False,
        incomplete: bool = False,
        mismatch: bool = False,
        execution_unverified: bool = False,
        policy_not_allow: bool = False,
    ) -> None:
        """Record content evidence rollout counters."""
        if not self.enabled:
            return
        if collected:
            self._content_evidence_collected_total.inc()
        if incomplete:
            self._content_evidence_incomplete_total.inc()
        if mismatch:
            self._content_evidence_mismatch_total.inc()
        if execution_unverified:
            self._content_evidence_execution_unverified_total.inc()
        if policy_not_allow:
            self._content_evidence_policy_not_allow_total.inc()

    # ------------------------------------------------------------------
    # Output
    # ------------------------------------------------------------------

    def generate_metrics_text(self) -> bytes:
        """Render all metrics in Prometheus exposition format.

        Returns ``b""`` when the collector is disabled.
        """
        if not self.enabled:
            return b""
        return generate_latest(self._registry)

    def llm_usage_snapshot(self) -> dict[str, Any]:
        """Return a read-only snapshot of aggregated LLM usage."""
        with self._llm_usage_lock:
            return {
                "total_calls": int(self._llm_usage_breakdown["total_calls"]),
                "total_input_tokens": int(self._llm_usage_breakdown["total_input_tokens"]),
                "total_output_tokens": int(self._llm_usage_breakdown["total_output_tokens"]),
                "total_cost_usd": float(self._llm_usage_breakdown["total_cost_usd"]),
                "by_provider": {
                    provider: {
                        "calls": int(bucket["calls"]),
                        "input_tokens": int(bucket["input_tokens"]),
                        "output_tokens": int(bucket["output_tokens"]),
                        "cost_usd": float(bucket["cost_usd"]),
                    }
                    for provider, bucket in self._llm_usage_breakdown["by_provider"].items()
                },
                "by_tier": {
                    tier: {
                        "calls": int(bucket["calls"]),
                        "input_tokens": int(bucket["input_tokens"]),
                        "output_tokens": int(bucket["output_tokens"]),
                        "cost_usd": float(bucket["cost_usd"]),
                    }
                    for tier, bucket in self._llm_usage_breakdown["by_tier"].items()
                },
                "by_status": {
                    status: {
                        "calls": int(bucket["calls"]),
                        "input_tokens": int(bucket["input_tokens"]),
                        "output_tokens": int(bucket["output_tokens"]),
                        "cost_usd": float(bucket["cost_usd"]),
                    }
                    for status, bucket in self._llm_usage_breakdown["by_status"].items()
                },
            }


# ---------------------------------------------------------------------------
# LLMBudgetTracker
# ---------------------------------------------------------------------------


class LLMBudgetTracker:
    """Thread-safe daily token budget tracker (UTC).

    Enforcement is based on provider-reported token usage only. Estimated USD
    cost remains informational telemetry and never exhausts this tracker.
    """

    def __init__(
        self,
        daily_budget_usd: float = 0.0,
        *,
        enabled: bool = False,
        limit_tokens: int = 0,
        scope: str = "total",
        source: str = "default",
    ) -> None:
        self._budget = daily_budget_usd  # deprecated compatibility surface
        self.enabled = bool(enabled and limit_tokens > 0)
        self.limit_tokens = max(int(limit_tokens), 0)
        self.scope = scope if scope in ("total", "input", "output") else "total"
        self.source = source
        self._lock = threading.Lock()
        self._used_input_tokens = 0
        self._used_output_tokens = 0
        self._unknown_usage_calls = 0
        self._daily_spend = 0.0  # deprecated compatibility metric only
        self._day_start = datetime.now(timezone.utc).date()
        self._exhausted_notified = False

    def _maybe_reset(self) -> None:
        """Reset if UTC day has changed.  Must be called under lock."""
        today = datetime.now(timezone.utc).date()
        if today != self._day_start:
            self._daily_spend = 0.0
            self._used_input_tokens = 0
            self._used_output_tokens = 0
            self._unknown_usage_calls = 0
            self._day_start = today
            self._exhausted_notified = False

    def can_spend(self) -> bool:
        """Return ``True`` if token budget allows another LLM call."""
        if not self.enabled and self._budget <= 0:
            return True  # unlimited
        with self._lock:
            self._maybe_reset()
            if self.enabled:
                return self._used_for_scope() < self.limit_tokens
            return self._daily_spend < self._budget

    def record_spend(self, cost_usd: float) -> bool:
        """Record estimated spend for explicit legacy USD-budget compatibility."""
        if cost_usd < 0:
            raise ValueError(f"cost_usd must be >= 0, got {cost_usd}")
        if self.enabled or self._budget <= 0:
            with self._lock:
                self._maybe_reset()
                self._daily_spend += cost_usd
            return False
        with self._lock:
            self._maybe_reset()
            was_ok = self._daily_spend < self._budget
            self._daily_spend += cost_usd
            is_exhausted = self._daily_spend >= self._budget
            if was_ok and is_exhausted and not self._exhausted_notified:
                self._exhausted_notified = True
                return True
            return False

    def _used_for_scope(self) -> int:
        if self.scope == "input":
            return self._used_input_tokens
        if self.scope == "output":
            return self._used_output_tokens
        return self._used_input_tokens + self._used_output_tokens

    def record_usage(self, *, input_tokens: int = 0, output_tokens: int = 0) -> bool:
        """Record actual tokens; return True on first exhaustion transition."""
        if input_tokens < 0 or output_tokens < 0:
            raise ValueError("token counts must be >= 0")
        with self._lock:
            self._maybe_reset()
            was_ok = (not self.enabled) or self._used_for_scope() < self.limit_tokens
            self._used_input_tokens += input_tokens
            self._used_output_tokens += output_tokens
            is_exhausted = self.enabled and self._used_for_scope() >= self.limit_tokens
            if was_ok and is_exhausted and not self._exhausted_notified:
                self._exhausted_notified = True
                return True
            return False

    def record_unknown_usage(self) -> bool:
        """Track a provider-reported usage miss; never consumes budget."""
        with self._lock:
            self._maybe_reset()
            self._unknown_usage_calls += 1
            return False

    def snapshot(self) -> dict[str, float | int | str | bool | None]:
        """Return a point-in-time view of the current UTC-day token budget state."""
        with self._lock:
            self._maybe_reset()
            used_total = self._used_input_tokens + self._used_output_tokens
            used_scope = self._used_for_scope()
            remaining_tokens = None if not self.enabled else max(self.limit_tokens - used_scope, 0)
            token_exhausted = bool(self.enabled and used_scope >= self.limit_tokens)
            legacy_exhausted = bool((not self.enabled) and self._budget > 0 and self._daily_spend >= self._budget)
            remaining_usd = max(self._budget - self._daily_spend, 0.0) if self._budget > 0 else None
            exhausted = token_exhausted or legacy_exhausted
            snapshot = {
                "enabled": self.enabled,
                "scope": self.scope,
                "limit_tokens": self.limit_tokens,
                "used_input_tokens": self._used_input_tokens,
                "used_output_tokens": self._used_output_tokens,
                "used_total_tokens": used_total,
                "remaining_tokens": remaining_tokens,
                "exhausted": exhausted,
                "unknown_usage_calls": self._unknown_usage_calls,
                "last_reset_utc": self._day_start.isoformat(),
                "source": self.source,
            }
            if not (self.enabled and self.limit_tokens > 0):
                # Deprecated compatibility fields: informational only when not in token mode.
                snapshot["daily_budget_usd"] = self._budget
                snapshot["daily_spend_usd"] = self._daily_spend
                snapshot["remaining_usd"] = remaining_usd
            return snapshot
