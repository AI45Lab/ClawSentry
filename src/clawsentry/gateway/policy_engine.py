"""
L1 Policy Engine — rule-based fast-path decision.

Design basis:
  - 04-policy-decision-and-fallback.md section 2.1 (L1 fast path)
  - 04-policy-decision-and-fallback.md section 12 (risk scoring)
  - 04-policy-decision-and-fallback.md section 11.3 (fallback matrix)
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import logging
import time
from typing import Optional

from .models import (
    RISK_LEVEL_ORDER,
    ClassifiedBy,
    CanonicalDecision,
    CanonicalEvent,
    DecisionContext,
    DecisionSource,
    DecisionTier,
    DecisionVerdict,
    EventType,
    FailureClass,
    RiskLevel,
    RiskOverride,
    RiskSnapshot,
    SessionScopeVerdict,
    utc_now_iso,
)
from .detection_config import DetectionConfig
from .risk_snapshot import DANGEROUS_TOOLS, SessionRiskTracker, compute_risk_snapshot
from .session_scope import evaluate_session_scope
from .semantic_analyzer import (
    KEY_DOMAIN_PATTERN,
    L2Result,
    RuleBasedAnalyzer,
    event_text,
    has_manual_l2_escalation_flag,
)

# Overhead margin (ms) subtracted from deadline budget to leave room for
# recording, response building, and thread-pool teardown after L2 analysis.
_L2_OVERHEAD_MARGIN_MS: float = 200.0

# Inner margin (ms) subtracted from the analyzer budget so analyzers can
# degrade gracefully (producing traces/results) before the outer timeout fires.
_INNER_BUDGET_MARGIN_MS: float = 300.0


def _analyzer_supports_l3(analyzer) -> bool:
    analyzer_id = str(getattr(analyzer, "analyzer_id", "") or "")
    if analyzer_id == "agent-reviewer":
        return True
    for child in getattr(analyzer, "_analyzers", []) or []:
        if _analyzer_supports_l3(child):
            return True
    return False


def _effective_requested_tier_for_l3_config(
    requested_tier: DecisionTier,
    config: DetectionConfig,
    analyzer,
) -> DecisionTier:
    if (
        requested_tier == DecisionTier.L2
        and config.l3_routing_mode == "replace_l2"
        and _analyzer_supports_l3(analyzer)
    ):
        return DecisionTier.L3
    return requested_tier


def _context_with_l3_config(
    context: Optional[DecisionContext],
    config: DetectionConfig,
    requested_tier: DecisionTier,
) -> Optional[DecisionContext]:
    if requested_tier != DecisionTier.L3:
        return context
    updates: dict[str, str] = {}
    if config.l3_trigger_profile == "eager":
        updates["l3_trigger_profile"] = "eager"
    if config.l3_routing_mode == "replace_l2":
        updates["l3_routing_mode"] = "replace_l2"
    if not updates:
        return context

    session_summary = {}
    if context is not None and isinstance(context.session_risk_summary, dict):
        session_summary.update(context.session_risk_summary)
    session_summary.update(updates)
    if context is not None:
        return context.model_copy(update={"session_risk_summary": session_summary})
    return DecisionContext(session_risk_summary=session_summary)


def _build_min_score_map(config: DetectionConfig) -> dict[RiskLevel, float]:
    return {
        RiskLevel.LOW: 0.0,
        RiskLevel.MEDIUM: config.threshold_medium,
        RiskLevel.HIGH: config.threshold_high,
        RiskLevel.CRITICAL: config.threshold_critical,
    }


class L1PolicyEngine:
    """
    L1 rule-based policy engine.

    Responsibilities:
    - Compute risk snapshot for each event.
    - Produce CanonicalDecision based on risk level.
    - Track per-session risk accumulation (D4).
    """

    POLICY_ID = "L1-rule-engine"
    POLICY_VERSION = "1.0"

    def __init__(self, analyzer=None, config: Optional[DetectionConfig] = None) -> None:
        self._config = config if config is not None else DetectionConfig()
        self._session_tracker = SessionRiskTracker(
            d4_high_threshold=self._config.d4_high_threshold,
            d4_mid_threshold=self._config.d4_mid_threshold,
            freq_enabled=self._config.d4_freq_enabled,
            freq_burst_count=self._config.d4_freq_burst_count,
            freq_burst_window_s=self._config.d4_freq_burst_window_s,
            freq_repetitive_count=self._config.d4_freq_repetitive_count,
            freq_repetitive_window_s=self._config.d4_freq_repetitive_window_s,
            freq_rate_limit_per_min=self._config.d4_freq_rate_limit_per_min,
        )
        self._min_score_for_level = _build_min_score_map(self._config)
        _evolved = self._config.evolved_patterns_path if self._config.evolving_enabled else None
        self._analyzer = (
            analyzer if analyzer is not None
            else RuleBasedAnalyzer(
                patterns_path=self._config.attack_patterns_path,
                evolved_patterns_path=_evolved,
            )
        )
        self._l2_pool = concurrent.futures.ThreadPoolExecutor(max_workers=2)

    def shutdown(self) -> None:
        """Shutdown the shared L2 thread pool."""
        self._l2_pool.shutdown(wait=False, cancel_futures=True)

    @property
    def analyzer(self):
        return self._analyzer

    @property
    def session_tracker(self) -> SessionRiskTracker:
        return self._session_tracker

    def evaluate(
        self,
        event: CanonicalEvent,
        context: Optional[DecisionContext] = None,
        requested_tier: DecisionTier = DecisionTier.L1,
        deadline_budget_ms: float | None = None,
        config: Optional[DetectionConfig] = None,
    ) -> tuple[CanonicalDecision, RiskSnapshot, DecisionTier]:
        """
        Evaluate an event and produce a decision.

        Args:
            deadline_budget_ms: If set, caps L2 budget to remaining deadline.
            config: Per-request config override (e.g. from project preset).
                    Uses the engine's default config when ``None``.

        Returns:
            (decision, risk_snapshot, actual_tier)
        """
        effective_config = config if config is not None else self._config
        requested_tier = _effective_requested_tier_for_l3_config(
            requested_tier,
            effective_config,
            self._analyzer,
        )
        context = _context_with_l3_config(context, effective_config, requested_tier)
        start = time.monotonic()

        l1_snapshot = compute_risk_snapshot(event, context, self._session_tracker, effective_config)
        snapshot = l1_snapshot
        decision = self._decide(event, snapshot, context)
        actual_tier = DecisionTier.L1

        if self._should_run_l2(event, context, l1_snapshot, requested_tier):
            try:
                snapshot, actual_tier = self._run_l2_analysis(
                    event, context, l1_snapshot, deadline_budget_ms,
                    requested_tier=requested_tier,
                    config_override=effective_config,
                )
                decision = self._decide(event, snapshot, context)
            except Exception:
                logging.getLogger(__name__).warning(
                    "L2 analysis failed; falling back to L1", exc_info=True,
                )
                # snapshot and decision remain at L1 values
            if (
                l1_snapshot.risk_level not in (RiskLevel.HIGH, RiskLevel.CRITICAL)
                and snapshot.risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL)
            ):
                # L2 upgraded a non-high event into high/critical.
                self._session_tracker.record_high_risk_event(event.session_id)

        elapsed_ms = (time.monotonic() - start) * 1000
        decision.decision_latency_ms = round(elapsed_ms, 2)

        return decision, snapshot, actual_tier

    def _decide(
        self,
        event: CanonicalEvent,
        snapshot: RiskSnapshot,
        context: Optional[DecisionContext] = None,
    ) -> CanonicalDecision:
        """Map risk level to decision for the given event type."""
        risk = snapshot.risk_level
        etype = event.event_type

        # Non-blocking event types: always allow (observation only)
        if etype in (
            EventType.POST_ACTION,
            EventType.POST_RESPONSE,
            EventType.ERROR,
            EventType.SESSION,
        ):
            return CanonicalDecision(
                decision=DecisionVerdict.ALLOW,
                reason=f"Non-blocking event type '{etype.value}': observation only",
                policy_id=self.POLICY_ID,
                risk_level=risk,
                decision_source=DecisionSource.POLICY,
                policy_version=self.POLICY_VERSION,
                failure_class=FailureClass.NONE,
                final=True,
            )

        # pre_prompt: generally allow (fail-open)
        if etype == EventType.PRE_PROMPT:
            return CanonicalDecision(
                decision=DecisionVerdict.ALLOW,
                reason="Pre-prompt events are fail-open to avoid blocking user input",
                policy_id=self.POLICY_ID,
                risk_level=risk,
                decision_source=DecisionSource.POLICY,
                policy_version=self.POLICY_VERSION,
                failure_class=FailureClass.NONE,
                final=True,
            )

        # pre_action: decide based on risk level
        if risk == RiskLevel.CRITICAL:
            return self._with_scope_evaluation(
                CanonicalDecision(
                    decision=DecisionVerdict.BLOCK,
                    reason=self._build_reason(event, snapshot, "Critical risk: action blocked"),
                    policy_id=self.POLICY_ID,
                    risk_level=risk,
                    decision_source=DecisionSource.POLICY,
                    policy_version=self.POLICY_VERSION,
                    failure_class=FailureClass.NONE,
                    final=True,
                ),
                event,
                context,
            )

        if risk == RiskLevel.HIGH:
            return self._with_scope_evaluation(
                CanonicalDecision(
                    decision=DecisionVerdict.BLOCK,
                    reason=self._build_reason(event, snapshot, "High risk: action blocked"),
                    policy_id=self.POLICY_ID,
                    risk_level=risk,
                    decision_source=DecisionSource.POLICY,
                    policy_version=self.POLICY_VERSION,
                    failure_class=FailureClass.NONE,
                    final=True,
                ),
                event,
                context,
            )

        if risk == RiskLevel.MEDIUM:
            return self._with_scope_evaluation(
                CanonicalDecision(
                    decision=DecisionVerdict.ALLOW,
                    reason=self._build_reason(event, snapshot, "Medium risk: allowed with audit"),
                    policy_id=self.POLICY_ID,
                    risk_level=risk,
                    decision_source=DecisionSource.POLICY,
                    policy_version=self.POLICY_VERSION,
                    failure_class=FailureClass.NONE,
                    final=True,
                ),
                event,
                context,
            )

        # LOW risk
        return self._with_scope_evaluation(
            CanonicalDecision(
                decision=DecisionVerdict.ALLOW,
                reason=self._build_reason(event, snapshot, "Low risk: safe operation"),
                policy_id=self.POLICY_ID,
                risk_level=risk,
                decision_source=DecisionSource.POLICY,
                policy_version=self.POLICY_VERSION,
                failure_class=FailureClass.NONE,
                final=True,
            ),
            event,
            context,
        )

    def _with_scope_evaluation(
        self,
        decision: CanonicalDecision,
        event: CanonicalEvent,
        context: Optional[DecisionContext],
    ) -> CanonicalDecision:
        """Apply confirmed scope restrictions without ever lowering risk blocks."""

        if event.event_type != EventType.PRE_ACTION:
            return decision
        scope_eval = evaluate_session_scope(event, context)
        if scope_eval is None:
            return decision

        summary = scope_eval.summary()
        reason_suffix = (
            f" | scope={summary.verdict.value}"
            f" enforced={str(summary.enforced).lower()}"
            f" source={summary.source.value}"
            f" confirmed={str(summary.confirmed).lower()}"
            f" dry_run={str(summary.dry_run).lower()}"
            f" reasons={','.join(summary.reason_codes)}"
        )

        if not summary.enforced:
            return decision.model_copy(update={
                "reason": decision.reason + reason_suffix,
                "scope_evaluation": summary,
            })

        if summary.verdict == SessionScopeVerdict.DENY:
            return CanonicalDecision(
                decision=DecisionVerdict.BLOCK,
                reason="Session scope denied action" + reason_suffix + f" | prior={decision.reason}",
                policy_id="session-scope",
                risk_level=decision.risk_level,
                decision_source=DecisionSource.POLICY,
                policy_version=self.POLICY_VERSION,
                failure_class=FailureClass.NONE,
                final=True,
                scope_evaluation=summary,
            )

        if (
            summary.verdict == SessionScopeVerdict.DEFER
            and decision.decision not in (DecisionVerdict.BLOCK, DecisionVerdict.DEFER)
        ):
            return CanonicalDecision(
                decision=DecisionVerdict.DEFER,
                reason="Session scope requires operator review" + reason_suffix + f" | prior={decision.reason}",
                policy_id="session-scope",
                risk_level=decision.risk_level,
                decision_source=DecisionSource.POLICY,
                policy_version=self.POLICY_VERSION,
                failure_class=FailureClass.NONE,
                final=False,
                scope_evaluation=summary,
            )

        return decision.model_copy(update={
            "reason": decision.reason + reason_suffix,
            "scope_evaluation": summary,
        })

    def apply_scope_evaluation(
        self,
        decision: CanonicalDecision,
        event: CanonicalEvent,
        context: Optional[DecisionContext],
    ) -> CanonicalDecision:
        """Apply session-scope tightening to externally composed decisions."""

        return self._with_scope_evaluation(decision, event, context)

    def _build_reason(
        self,
        event: CanonicalEvent,
        snapshot: RiskSnapshot,
        base: str,
    ) -> str:
        """Build a human-readable reason with context."""
        parts = [base]
        dims = snapshot.dimensions
        parts.append(
            f"D1={dims.d1} D2={dims.d2} D3={dims.d3} D4={dims.d4} D5={dims.d5} D6={dims.d6:.2f}"
        )
        parts.append(f"score={snapshot.composite_score:.4f}")
        if snapshot.short_circuit_rule:
            parts.append(f"short_circuit={snapshot.short_circuit_rule}")
        if event.tool_name:
            parts.append(f"tool={event.tool_name}")
        return " | ".join(parts)

    def _should_run_l2(
        self,
        event: CanonicalEvent,
        context: Optional[DecisionContext],
        l1_snapshot: RiskSnapshot,
        requested_tier: DecisionTier,
    ) -> bool:
        if requested_tier in (DecisionTier.L2, DecisionTier.L3):
            return True
        if event.event_type == EventType.PRE_ACTION and l1_snapshot.risk_level == RiskLevel.MEDIUM:
            return True
        if self._is_key_domain_event(event):
            return True
        return has_manual_l2_escalation_flag(context)

    @staticmethod
    def _is_key_domain_event(event: CanonicalEvent) -> bool:
        text = event_text(event)
        return bool(KEY_DOMAIN_PATTERN.search(text))

    def _run_l2_analysis(
        self,
        event: CanonicalEvent,
        context: Optional[DecisionContext],
        l1_snapshot: RiskSnapshot,
        deadline_budget_ms: float | None = None,
        requested_tier: DecisionTier = DecisionTier.L2,
        config_override: Optional[DetectionConfig] = None,
    ) -> tuple[RiskSnapshot, DecisionTier]:
        # Run async analyzer synchronously
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None

        cfg = config_override if config_override is not None else self._config
        budget = cfg.l2_budget_ms
        if requested_tier == DecisionTier.L3 and cfg.l3_budget_ms is not None:
            budget = max(budget, cfg.l3_budget_ms)
        if deadline_budget_ms is not None:
            budget = min(budget, max(0, deadline_budget_ms - _L2_OVERHEAD_MARGIN_MS))
        timeout_sec = budget / 1000.0
        # Give analyzers slightly less budget than the outer timeout so they
        # can degrade gracefully (producing traces) before being cancelled.
        inner_budget = max(budget - _INNER_BUDGET_MARGIN_MS, 0.0)

        if loop and loop.is_running():
            result = self._l2_pool.submit(
                asyncio.run,
                asyncio.wait_for(
                    self._analyzer.analyze(event, context, l1_snapshot, inner_budget),
                    timeout=timeout_sec,
                ),
            ).result(timeout=timeout_sec + 0.5)  # outer timeout as safety net
        else:
            async def _run_with_timeout() -> L2Result:
                return await asyncio.wait_for(
                    self._analyzer.analyze(event, context, l1_snapshot, inner_budget),
                    timeout=timeout_sec,
                )
            result = asyncio.run(_run_with_timeout())

        # Build RiskSnapshot from L2Result (upgrade-only enforced here)
        target_level = result.target_level
        target_level = self._max_risk_level(target_level, l1_snapshot.risk_level)
        actual_tier = result.decision_tier

        if actual_tier == DecisionTier.L1:
            return l1_snapshot.model_copy(update={"l3_trace": result.trace}), DecisionTier.L1

        upgraded = target_level != l1_snapshot.risk_level
        override = (
            RiskOverride(
                original_level=l1_snapshot.risk_level,
                reason="; ".join(result.reasons) if result.reasons else "L2 semantic escalation",
            )
            if upgraded
            else None
        )
        score = max(
            l1_snapshot.composite_score,
            self._min_score_for_level[target_level],
        )
        classified_by = ClassifiedBy.L3 if actual_tier == DecisionTier.L3 else ClassifiedBy.L2
        return RiskSnapshot(
            risk_level=target_level,
            composite_score=score,
            dimensions=l1_snapshot.dimensions,
            short_circuit_rule=l1_snapshot.short_circuit_rule,
            missing_dimensions=list(l1_snapshot.missing_dimensions),
            classified_by=classified_by,
            classified_at=utc_now_iso(),
            override=override,
            l1_snapshot=l1_snapshot if upgraded else None,
            l3_trace=result.trace,
        ), actual_tier

    @staticmethod
    def _max_risk_level(a: RiskLevel, b: RiskLevel) -> RiskLevel:
        return a if RISK_LEVEL_ORDER[a] >= RISK_LEVEL_ORDER[b] else b


# ---------------------------------------------------------------------------
# Fallback decision factory (04 section 11.3)
# ---------------------------------------------------------------------------

def make_fallback_decision(
    event: CanonicalEvent,
    risk_hints_contain_high_danger: bool = False,
) -> CanonicalDecision:
    """
    Produce a local fallback decision when the Gateway is unreachable.

    Per 04-policy-decision-and-fallback.md section 11.3.
    """
    etype = event.event_type

    if etype == EventType.PRE_ACTION:
        if risk_hints_contain_high_danger or _tool_matches_danger(event):
            return CanonicalDecision(
                decision=DecisionVerdict.BLOCK,
                reason="Fallback: fail-closed for high-risk pre_action (gateway unreachable)",
                policy_id="fallback-fail-closed",
                risk_level=RiskLevel.HIGH,
                decision_source=DecisionSource.SYSTEM,
                failure_class=FailureClass.UPSTREAM_UNAVAILABLE,
                final=True,
            )
        return CanonicalDecision(
            decision=DecisionVerdict.DEFER,
            reason="Fallback: defer for pre_action without high-risk markers (gateway unreachable)",
            policy_id="fallback-defer",
            risk_level=RiskLevel.MEDIUM,
            decision_source=DecisionSource.SYSTEM,
            failure_class=FailureClass.UPSTREAM_UNAVAILABLE,
            retry_after_ms=1000,
        )

    if etype == EventType.PRE_PROMPT:
        return CanonicalDecision(
            decision=DecisionVerdict.ALLOW,
            reason="Fallback: fail-open for pre_prompt (gateway unreachable)",
            policy_id="fallback-fail-open",
            risk_level=RiskLevel.LOW,
            decision_source=DecisionSource.SYSTEM,
            failure_class=FailureClass.UPSTREAM_UNAVAILABLE,
            final=True,
        )

    # post_action / post_response / error / session
    return CanonicalDecision(
        decision=DecisionVerdict.ALLOW,
        reason=f"Fallback: fail-open for {etype.value} (observation, gateway unreachable)",
        policy_id="fallback-fail-open",
        risk_level=RiskLevel.LOW,
        decision_source=DecisionSource.SYSTEM,
        failure_class=FailureClass.UPSTREAM_UNAVAILABLE,
        final=True,
    )


def _tool_matches_danger(event: CanonicalEvent) -> bool:
    """Check if tool name matches known dangerous patterns."""
    tool = (event.tool_name or "").lower()
    return tool in DANGEROUS_TOOLS
