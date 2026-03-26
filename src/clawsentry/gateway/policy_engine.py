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
    utc_now_iso,
)
from .detection_config import DetectionConfig
from .risk_snapshot import DANGEROUS_TOOLS, SessionRiskTracker, compute_risk_snapshot
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
    ) -> tuple[CanonicalDecision, RiskSnapshot, DecisionTier]:
        """
        Evaluate an event and produce a decision.

        Args:
            deadline_budget_ms: If set, caps L2 budget to remaining deadline.

        Returns:
            (decision, risk_snapshot, actual_tier)
        """
        start = time.monotonic()

        l1_snapshot = compute_risk_snapshot(event, context, self._session_tracker, self._config)
        snapshot = l1_snapshot
        decision = self._decide(event, snapshot)
        actual_tier = DecisionTier.L1

        if self._should_run_l2(event, context, l1_snapshot, requested_tier):
            try:
                snapshot = self._run_l2_analysis(event, context, l1_snapshot, deadline_budget_ms)
                decision = self._decide(event, snapshot)
                actual_tier = DecisionTier.L2
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
            return CanonicalDecision(
                decision=DecisionVerdict.BLOCK,
                reason=self._build_reason(event, snapshot, "Critical risk: action blocked"),
                policy_id=self.POLICY_ID,
                risk_level=risk,
                decision_source=DecisionSource.POLICY,
                policy_version=self.POLICY_VERSION,
                failure_class=FailureClass.NONE,
                final=True,
            )

        if risk == RiskLevel.HIGH:
            return CanonicalDecision(
                decision=DecisionVerdict.BLOCK,
                reason=self._build_reason(event, snapshot, "High risk: action blocked"),
                policy_id=self.POLICY_ID,
                risk_level=risk,
                decision_source=DecisionSource.POLICY,
                policy_version=self.POLICY_VERSION,
                failure_class=FailureClass.NONE,
                final=True,
            )

        if risk == RiskLevel.MEDIUM:
            return CanonicalDecision(
                decision=DecisionVerdict.ALLOW,
                reason=self._build_reason(event, snapshot, "Medium risk: allowed with audit"),
                policy_id=self.POLICY_ID,
                risk_level=risk,
                decision_source=DecisionSource.POLICY,
                policy_version=self.POLICY_VERSION,
                failure_class=FailureClass.NONE,
                final=True,
            )

        # LOW risk
        return CanonicalDecision(
            decision=DecisionVerdict.ALLOW,
            reason=self._build_reason(event, snapshot, "Low risk: safe operation"),
            policy_id=self.POLICY_ID,
            risk_level=risk,
            decision_source=DecisionSource.POLICY,
            policy_version=self.POLICY_VERSION,
            failure_class=FailureClass.NONE,
            final=True,
        )

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
        if requested_tier == DecisionTier.L2:
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
    ) -> RiskSnapshot:
        # Run async analyzer synchronously
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None

        budget = self._config.l2_budget_ms
        if self._config.l3_budget_ms is not None:
            budget = max(budget, self._config.l3_budget_ms)
        if deadline_budget_ms is not None:
            budget = min(budget, max(0, deadline_budget_ms - _L2_OVERHEAD_MARGIN_MS))
        timeout_sec = budget / 1000.0

        if loop and loop.is_running():
            pool = concurrent.futures.ThreadPoolExecutor(max_workers=1)
            try:
                result = pool.submit(
                    asyncio.run,
                    asyncio.wait_for(
                        self._analyzer.analyze(event, context, l1_snapshot, budget),
                        timeout=timeout_sec,
                    ),
                ).result(timeout=timeout_sec + 0.5)  # outer timeout as safety net
            finally:
                # cancel_futures=True (Python 3.9+) avoids blocking on timed-out threads
                pool.shutdown(wait=False, cancel_futures=True)
        else:
            async def _run_with_timeout() -> L2Result:
                return await asyncio.wait_for(
                    self._analyzer.analyze(event, context, l1_snapshot, budget),
                    timeout=timeout_sec,
                )
            result = asyncio.run(_run_with_timeout())

        # Build RiskSnapshot from L2Result (upgrade-only enforced here)
        target_level = result.target_level
        target_level = self._max_risk_level(target_level, l1_snapshot.risk_level)
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
        return RiskSnapshot(
            risk_level=target_level,
            composite_score=score,
            dimensions=l1_snapshot.dimensions,
            short_circuit_rule=l1_snapshot.short_circuit_rule,
            missing_dimensions=list(l1_snapshot.missing_dimensions),
            classified_by=ClassifiedBy.L2,
            classified_at=utc_now_iso(),
            override=override,
            l1_snapshot=l1_snapshot if upgraded else None,
            l3_trace=result.trace,
        )

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
