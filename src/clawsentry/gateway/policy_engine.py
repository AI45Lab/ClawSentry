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
import re
import time
from typing import Any, Optional

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

_BENCHMARK_SHELL_TOOLS = {
    "bash",
    "exec_command",
    "run_shell_command",
    "shell",
    "sh",
}

_BENCHMARK_FORBIDDEN_COMMAND_RE = re.compile(
    r"(?ix)"
    r"(\b(rm|sudo|su|chmod|chown|mkfs|dd|mount|umount|ssh|scp|curl|wget|nc|ncat|"
    r"telnet|docker|kubectl|apt|apt-get|pip|npm)\b"
    r"|/etc(?:/|\b)|/root(?:/|\b)|/proc(?:/|\b)|/sys(?:/|\b)|/dev(?:/|\b)"
    r"|docker\.sock|auth\.json|\.env\b|api[_-]?key|secret|token|credential)"
)

_BENCHMARK_SAFE_ANCHOR_RE = re.compile(
    r"(?x)"
    r"(/app(?:/|\b)|/logs/agent(?:/|\b)|/tmp/clawsentry-benchmark(?:/|\b)|"
    r"/skills(?:/|\b)|/root/output(?:/|\b)|/root/data(?:/|\b)|"
    r"\$CODEX_HOME(?:/|\b)|\$HOME/\.agents(?:/|\b)|~/\.agents(?:/|\b))"
)

_BENCHMARK_SIMPLE_READONLY_RE = re.compile(
    r"(?sx)"
    r"\A\s*"
    r"(?:"
    r"pwd|true|whoami|id|"
    r"echo(?:\s+(?:\$HOME|['\"][^'\"]*['\"]|[A-Za-z0-9_./:-]+))*|"
    r"ls(?:\s+-[A-Za-z0-9]+)*(?:\s+(?:[A-Za-z0-9_./:-]+|\$CODEX_HOME(?:/[^\s;&|]*)?|\$HOME/\.agents(?:/[^\s;&|]*)?))*|"
    r"test\s+-s\s+/app/output/[A-Za-z0-9_.-]+"
    r")"
    r"(?:\s+2>/dev/null)?"
    r"(?:\s*\|\|\s*echo\s+['\"]?[^;&|`$()]*['\"]?)?"
    r"\s*\Z"
)

_BENCHMARK_SAFE_FIND_RE = re.compile(
    r"(?sx)\A\s*find\s+"
    r"(?:/app|\$CODEX_HOME|\$HOME/\.agents|~/\.agents|/logs/agent)"
    r"(?:\s+[^;&|`$()]*)?\s*\Z"
)

_BENCHMARK_SAFE_MKDIR_RE = re.compile(
    r"(?sx)\A\s*mkdir\s+-p\s+"
    r"(?:/app/output|/root/output(?:/[A-Za-z0-9_.-]+)?|"
    r"/logs/agent(?:/[A-Za-z0-9_.-]+)?|"
    r"\$CODEX_HOME(?:/skills)?|\$HOME/\.agents(?:/skills)?)"
    r"(?:\s+(?:/app/output|/root/output(?:/[A-Za-z0-9_.-]+)?|"
    r"/logs/agent(?:/[A-Za-z0-9_.-]+)?|"
    r"\$CODEX_HOME(?:/skills)?|\$HOME/\.agents(?:/skills)?))*"
    r"\s*\Z"
)

_BENCHMARK_SAFE_OUTPUT_PATH_RE = re.compile(
    r"(?x)(?:^|[\s>])"
    r"(?:/app/output|/root/output)/[A-Za-z0-9_./@+:-]+"
)

def _analyzer_supports_l3(analyzer) -> bool:
    analyzer_id = str(getattr(analyzer, "analyzer_id", "") or "")
    if analyzer_id == "agent-reviewer":
        return True
    for child in getattr(analyzer, "_analyzers", []) or []:
        if _analyzer_supports_l3(child):
            return True
    return False


def _select_l3_analyzer(analyzer):
    analyzer_id = str(getattr(analyzer, "analyzer_id", "") or "")
    if analyzer_id == "agent-reviewer":
        return analyzer
    for child in getattr(analyzer, "_analyzers", []) or []:
        selected = _select_l3_analyzer(child)
        if selected is not None:
            return selected
    return None


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


def _benchmark_shell_command(event: CanonicalEvent) -> str | None:
    tool_name = (event.tool_name or "").strip().lower()
    if tool_name not in _BENCHMARK_SHELL_TOOLS:
        return None
    payload = event.payload or {}
    for key in ("command", "cmd"):
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    tool_input = payload.get("tool_input")
    if isinstance(tool_input, dict):
        for key in ("command", "cmd"):
            value = tool_input.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
    return None


def _is_benchmark_safe_shell_command(event: CanonicalEvent, config: DetectionConfig) -> bool:
    if config.mode != "benchmark" or not config.benchmark_safe_shell_allow:
        return False

    command = _benchmark_shell_command(event)
    if not command:
        return False
    normalized = " ".join(command.split())
    safety_scan = re.sub(r"(?:^|\s)[12]?>/dev/null\b", " ", normalized)
    safety_scan = safety_scan.replace("/root/output", "/SAFE_ROOT_OUTPUT")
    safety_scan = safety_scan.replace("/root/data", "/SAFE_ROOT_DATA")
    if _BENCHMARK_FORBIDDEN_COMMAND_RE.search(safety_scan):
        return False

    if _BENCHMARK_SIMPLE_READONLY_RE.fullmatch(normalized):
        return True
    if _BENCHMARK_SAFE_FIND_RE.fullmatch(normalized):
        return True
    if _BENCHMARK_SAFE_MKDIR_RE.fullmatch(normalized):
        return True
    first = normalized.split(None, 1)[0] if normalized.split(None, 1) else ""
    if first in {"cat", "ls", "find", "head", "sed", "test", "cp", "mkdir", "tee"} and _BENCHMARK_SAFE_ANCHOR_RE.search(normalized):
        return True

    if normalized.startswith(("cd /app && ", "cd /app; ")):
        tail = normalized.split("&& ", 1)[-1] if "&& " in normalized else normalized.split("; ", 1)[-1]
        if _BENCHMARK_SIMPLE_READONLY_RE.fullmatch(tail):
            return True

    if normalized.startswith(("python ", "python3 ")) and (
        _BENCHMARK_SAFE_ANCHOR_RE.search(normalized)
        or normalized == 'python3 -c "import sys; print(sys.path)"'
        or normalized == "python3 -c 'import sys; print(sys.path)'"
    ):
        return True

    if _BENCHMARK_SAFE_OUTPUT_PATH_RE.search(normalized) and (
        normalized.startswith(("cat > ", "tee ", "python ", "python3 ", "printf "))
        or " > /app/output/" in normalized
        or " > /root/output/" in normalized
        or normalized.startswith("mkdir -p /app/output && cat > /app/output/")
        or normalized.startswith("mkdir -p /root/output && cat > /root/output/")
    ):
        return True

    return False


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
        if event.event_type == EventType.PRE_ACTION and l1_snapshot.short_circuit_rule == "SC-4":
            decision, snapshot, actual_tier = self._decide_persistence_write(
                event,
                l1_snapshot,
                context,
                effective_config,
                deadline_budget_ms,
            )
            decision.decision_latency_ms = round((time.monotonic() - start) * 1000, 2)
            return decision, snapshot, actual_tier

        decision = self._decide(event, snapshot, context, effective_config)
        actual_tier = DecisionTier.L1

        if self._should_run_l2(event, context, l1_snapshot, requested_tier):
            try:
                snapshot, actual_tier = self._run_l2_analysis(
                    event, context, l1_snapshot, deadline_budget_ms,
                    requested_tier=requested_tier,
                    config_override=effective_config,
                )
                decision = self._decide(event, snapshot, context, effective_config)
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
        config: Optional[DetectionConfig] = None,
    ) -> CanonicalDecision:
        """Map risk level to decision for the given event type."""
        effective_config = config if config is not None else self._config
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
        if risk in (RiskLevel.CRITICAL, RiskLevel.HIGH) and snapshot.short_circuit_rule == "SC-4":
            action = effective_config.resolved_persistence_write_action()
            return self._persistence_write_action_decision(
                event,
                snapshot,
                context,
                action,
                "L1 persistence-write policy",
            )

        if (
            risk in (RiskLevel.CRITICAL, RiskLevel.HIGH)
            and _is_benchmark_safe_shell_command(event, effective_config)
        ):
            return self._with_scope_evaluation(
                CanonicalDecision(
                    decision=DecisionVerdict.ALLOW,
                    reason=self._build_reason(
                        event,
                        snapshot,
                        "Benchmark safe shell command allowed with audit",
                    ),
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

    def _decide_persistence_write(
        self,
        event: CanonicalEvent,
        l1_snapshot: RiskSnapshot,
        context: Optional[DecisionContext],
        config: DetectionConfig,
        deadline_budget_ms: float | None,
    ) -> tuple[CanonicalDecision, RiskSnapshot, DecisionTier]:
        action = config.resolved_persistence_write_action()
        if action != "force_l3":
            return (
                self._persistence_write_action_decision(
                    event,
                    l1_snapshot,
                    context,
                    action,
                    "L1 persistence-write policy",
                ),
                l1_snapshot.model_copy(update={
                    "l3_trace": {
                        "sc4_action_resolved": action,
                        "l3_verdict_source": "policy",
                    }
                }),
                DecisionTier.L1,
            )

        l3_analyzer = _select_l3_analyzer(self._analyzer)
        if l3_analyzer is None:
            return self._persistence_write_fallback(
                event,
                l1_snapshot,
                context,
                config,
                "l3_analyzer_unavailable",
                trace={"l3_verdict_source": "fallback"},
            )

        try:
            result = self._run_sc4_l3_verdict(
                l3_analyzer,
                event,
                context,
                l1_snapshot,
                deadline_budget_ms,
                config,
            )
        except Exception as exc:
            logging.getLogger(__name__).warning(
                "SC-4 L3 review failed; applying persistence-write fallback",
                exc_info=True,
            )
            return self._persistence_write_fallback(
                event,
                l1_snapshot,
                context,
                config,
                "l3_exception",
                trace={
                    "l3_verdict_source": "exception",
                    "exception_type": type(exc).__name__,
                },
            )

        trace = dict(result.trace or {})
        trace.update({
            "sc4_action_resolved": action,
            "l3_verdict_source": result.analyzer_id or "agent-reviewer",
        })
        fallback_reason = self._sc4_l3_fallback_reason(result, trace, config)
        if fallback_reason is not None:
            return self._persistence_write_fallback(
                event,
                l1_snapshot.model_copy(update={"l3_trace": trace}),
                context,
                config,
                fallback_reason,
                trace=trace,
            )

        reviewed_snapshot = l1_snapshot.model_copy(update={
            "risk_level": result.target_level,
            "composite_score": max(
                l1_snapshot.composite_score,
                self._min_score_for_level.get(result.target_level, 0.0),
            ),
            "classified_by": ClassifiedBy.L3,
            "classified_at": utc_now_iso(),
            "l3_trace": trace,
        })
        if result.target_level in (RiskLevel.HIGH, RiskLevel.CRITICAL):
            decision = self._persistence_write_action_decision(
                event,
                reviewed_snapshot,
                context,
                "block",
                "L3 persistence-write review blocked",
            )
            return decision, reviewed_snapshot, DecisionTier.L3

        decision = self._persistence_write_action_decision(
            event,
            reviewed_snapshot,
            context,
            "audit",
            "L3 persistence-write review allowed with audit",
        )
        return decision, reviewed_snapshot, DecisionTier.L3

    def _run_sc4_l3_verdict(
        self,
        analyzer,
        event: CanonicalEvent,
        context: Optional[DecisionContext],
        l1_snapshot: RiskSnapshot,
        deadline_budget_ms: float | None,
        config: DetectionConfig,
    ) -> L2Result:
        review_context = _context_with_l3_config(context, config, DecisionTier.L3)
        review_event = self._redacted_persistence_write_review_event(event, l1_snapshot)
        budget = config.l3_budget_ms if config.l3_budget_ms is not None else config.l2_budget_ms
        if deadline_budget_ms is not None:
            budget = min(budget, max(0.0, deadline_budget_ms - _L2_OVERHEAD_MARGIN_MS))
        timeout_sec = max(budget, 1.0) / 1000.0
        inner_budget = max(budget - _INNER_BUDGET_MARGIN_MS, 0.0)

        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None

        if loop and loop.is_running():
            return self._l2_pool.submit(
                asyncio.run,
                asyncio.wait_for(
                    analyzer.analyze(review_event, review_context, l1_snapshot, inner_budget),
                    timeout=timeout_sec,
                ),
            ).result(timeout=timeout_sec + 0.5)

        async def _run_with_timeout() -> L2Result:
            return await asyncio.wait_for(
                analyzer.analyze(review_event, review_context, l1_snapshot, inner_budget),
                timeout=timeout_sec,
            )

        return asyncio.run(_run_with_timeout())

    def _redacted_persistence_write_review_event(
        self,
        event: CanonicalEvent,
        l1_snapshot: RiskSnapshot,
    ) -> CanonicalEvent:
        evidence = dict(l1_snapshot.risk_evidence or {})
        return event.model_copy(update={
            "payload": {
                "persistence_write_evidence": evidence,
                "payload_redacted": True,
            },
            "risk_hints": sorted(set([*(event.risk_hints or []), "persistence_write", "SC-4"])),
        })

    def _sc4_l3_fallback_reason(
        self,
        result: L2Result,
        trace: dict[str, Any],
        config: DetectionConfig,
    ) -> str | None:
        if result.decision_tier != DecisionTier.L3:
            return "l3_not_completed"
        if bool(trace.get("degraded")):
            return str(trace.get("l3_reason_code") or trace.get("degradation_reason") or "l3_degraded")
        if str(trace.get("trigger_reason") or "") == "trigger_not_matched":
            return "trigger_not_matched"
        if result.confidence <= 0.0:
            return "l3_zero_confidence"
        if (
            result.target_level in (RiskLevel.LOW, RiskLevel.MEDIUM)
            and result.confidence < config.persistence_write_l3_allow_confidence
        ):
            return "l3_allow_confidence_below_threshold"
        return None

    def _persistence_write_fallback(
        self,
        event: CanonicalEvent,
        snapshot: RiskSnapshot,
        context: Optional[DecisionContext],
        config: DetectionConfig,
        fallback_reason: str,
        trace: Optional[dict[str, Any]] = None,
    ) -> tuple[CanonicalDecision, RiskSnapshot, DecisionTier]:
        action = config.persistence_write_fallback_action
        l3_trace = dict(trace or snapshot.l3_trace or {})
        l3_trace.update({
            "sc4_action_resolved": config.resolved_persistence_write_action(),
            "fallback_reason": fallback_reason,
        })
        fallback_snapshot = snapshot.model_copy(update={"l3_trace": l3_trace})
        decision = self._persistence_write_action_decision(
            event,
            fallback_snapshot,
            context,
            action,
            f"persistent execution entrypoint write L3 fallback: {fallback_reason}",
        )
        return decision, fallback_snapshot, DecisionTier.L1

    def _persistence_write_action_decision(
        self,
        event: CanonicalEvent,
        snapshot: RiskSnapshot,
        context: Optional[DecisionContext],
        action: str,
        base_reason: str,
    ) -> CanonicalDecision:
        if action == "audit":
            verdict = DecisionVerdict.ALLOW
            final = True
            reason = f"{base_reason}: allowed with audit"
        elif action == "defer":
            verdict = DecisionVerdict.DEFER
            final = False
            reason = f"{base_reason}: operator review required"
        else:
            verdict = DecisionVerdict.BLOCK
            final = True
            reason = f"{base_reason}: blocked"

        return self._with_scope_evaluation(
            CanonicalDecision(
                decision=verdict,
                reason=self._build_reason(event, snapshot, reason),
                policy_id=self.POLICY_ID,
                risk_level=snapshot.risk_level,
                decision_source=DecisionSource.POLICY,
                policy_version=self.POLICY_VERSION,
                failure_class=FailureClass.NONE,
                final=final,
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
            risk_evidence=dict(l1_snapshot.risk_evidence or {}),
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
