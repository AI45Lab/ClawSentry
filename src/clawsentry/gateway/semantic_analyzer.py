"""
L2 Pluggable Semantic Analysis — SemanticAnalyzer Protocol and implementations.

Design basis: 09-l2-pluggable-semantic-analysis.md
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import time
from dataclasses import dataclass, field
from typing import Optional, Protocol, runtime_checkable

logger = logging.getLogger(__name__)

from .models import (
    RISK_LEVEL_ORDER,
    CanonicalEvent,
    DecisionContext,
    RiskLevel,
    RiskSnapshot,
)
from .llm_provider import LLMProvider
from .pattern_matcher import PatternMatcher
from .risk_snapshot import DANGEROUS_TOOLS


@dataclass(frozen=True)
class L2Result:
    """Immutable result from a semantic analyzer."""
    target_level: RiskLevel
    reasons: list[str] = field(default_factory=list)
    confidence: float = 0.0
    analyzer_id: str = ""
    latency_ms: float = 0.0
    trace: Optional[dict] = None


@runtime_checkable
class SemanticAnalyzer(Protocol):
    """Protocol for pluggable L2 semantic analyzers."""

    @property
    def analyzer_id(self) -> str: ...

    async def analyze(
        self,
        event: CanonicalEvent,
        context: Optional[DecisionContext],
        l1_snapshot: RiskSnapshot,
        budget_ms: float,
    ) -> L2Result: ...


# ---------------------------------------------------------------------------
# Constants for RuleBasedAnalyzer
# ---------------------------------------------------------------------------

_L2_HIGH_RISK_HINTS = frozenset({
    "credential_exfiltration",
    "privilege_escalation",
    "prompt_injection",
    "supply_chain_attack",
    "destructive_intent",
})

_L2_CRITICAL_HINTS = frozenset({
    "privilege_escalation_confirmed",
    "credential_exfiltration_confirmed",
})

KEY_DOMAIN_PATTERN = re.compile(
    r"\b(prod|production|credential|credentials|secret|token|password|api_key|private_key|ssh_key)\b",
    re.IGNORECASE,
)
_CRITICAL_INTENT_PATTERN = re.compile(
    r"\b(exfiltrat|bypass|disable\s+security|privilege\s+escalat|steal)\b",
    re.IGNORECASE,
)
_SECRET_RE = re.compile(
    r"(AKIA[0-9A-Z]{16}|ghp_[a-zA-Z0-9]{36}|sk-[a-zA-Z0-9]{32,}|"
    r"-----BEGIN[A-Z ]*PRIVATE KEY-----|"
    r"[a-zA-Z_]*(?:SECRET|TOKEN|PASSWORD|API_KEY)[a-zA-Z_]*\s*[=:]\s*\S+)",
    re.IGNORECASE,
)
_MAX_PROMPT_PAYLOAD_LEN = 4096
_MAX_EVENT_TEXT_LEN = 65_536  # 64KB cap for regex scanning

# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

def _max_risk_level(a: RiskLevel, b: RiskLevel) -> RiskLevel:
    return a if RISK_LEVEL_ORDER[a] >= RISK_LEVEL_ORDER[b] else b


def event_text(event: CanonicalEvent) -> str:
    payload_text = json.dumps(event.payload or {}, ensure_ascii=False, sort_keys=True)
    risk_hints = " ".join(event.risk_hints or [])
    tool_name = event.tool_name or ""
    text = f"{tool_name} {risk_hints} {payload_text}".lower()
    if len(text) > _MAX_EVENT_TEXT_LEN:
        text = text[:_MAX_EVENT_TEXT_LEN]
    return text


def has_manual_l2_escalation_flag(context: Optional[DecisionContext]) -> bool:
    if context is None or not isinstance(context.session_risk_summary, dict):
        return False
    flags = ("l2_escalate", "force_l2", "manual_l2_escalation")
    return any(bool(context.session_risk_summary.get(flag)) for flag in flags)


# ---------------------------------------------------------------------------
# RuleBasedAnalyzer
# ---------------------------------------------------------------------------

class RuleBasedAnalyzer:
    """L2 rule-based semantic analyzer — extracted from L1PolicyEngine._run_l2_analysis."""

    def __init__(self, patterns_path: Optional[str] = None) -> None:
        self._pattern_matcher = PatternMatcher(patterns_path=patterns_path)

    @property
    def analyzer_id(self) -> str:
        return "rule-based"

    async def analyze(
        self,
        event: CanonicalEvent,
        context: Optional[DecisionContext],
        l1_snapshot: RiskSnapshot,
        budget_ms: float,
    ) -> L2Result:
        start = time.monotonic()
        text = event_text(event)
        hints = {str(h).lower() for h in (event.risk_hints or [])}
        target_level = l1_snapshot.risk_level
        reasons: list[str] = []

        if hints.intersection(_L2_CRITICAL_HINTS):
            target_level = RiskLevel.CRITICAL
            reasons.append("confirmed high-severity semantic signal")
        elif hints.intersection(_L2_HIGH_RISK_HINTS):
            target_level = _max_risk_level(target_level, RiskLevel.HIGH)
            reasons.append("risk_hints indicate semantic threat")

        key_domain = bool(KEY_DOMAIN_PATTERN.search(text))
        critical_intent = bool(_CRITICAL_INTENT_PATTERN.search(text))
        if key_domain and critical_intent:
            target_level = RiskLevel.CRITICAL
            reasons.append("critical intent on key domain asset")
        elif key_domain and (event.tool_name or "").lower() in DANGEROUS_TOOLS:
            target_level = _max_risk_level(target_level, RiskLevel.HIGH)
            reasons.append("dangerous tool on key domain asset")

        # Attack pattern matching (E-4)
        matched = self._pattern_matcher.match(
            tool_name=event.tool_name or "",
            payload=event.payload or {},
            content=text,
        )
        if matched:
            max_pattern_risk = max(
                matched, key=lambda p: RISK_LEVEL_ORDER.get(p.risk_level, 0)
            ).risk_level
            target_level = _max_risk_level(target_level, max_pattern_risk)
            reasons.append(f"attack_pattern: {', '.join(p.id for p in matched)}")

        if has_manual_l2_escalation_flag(context):
            target_level = _max_risk_level(target_level, RiskLevel.HIGH)
            reasons.append("manual L2 escalation flag present")

        # Never downgrade from L1 level
        target_level = _max_risk_level(target_level, l1_snapshot.risk_level)

        elapsed_ms = (time.monotonic() - start) * 1000
        return L2Result(
            target_level=target_level,
            reasons=reasons,
            confidence=1.0,
            analyzer_id=self.analyzer_id,
            latency_ms=round(elapsed_ms, 3),
        )


# ---------------------------------------------------------------------------
# LLMAnalyzer — L2 semantic analyzer backed by an LLM provider
# ---------------------------------------------------------------------------

@dataclass
class LLMAnalyzerConfig:
    """Configuration for LLMAnalyzer."""
    provider_timeout_ms: float = 3000.0
    max_tokens: int = 256
    temperature: float = 0.0


_LLM_SYSTEM_PROMPT = """\
You are a security risk analyzer for an Agent Harness Policy (AHP) supervision system.
Analyze the given agent action event and assess its security risk level.

Respond ONLY with a JSON object in this exact format:
{"risk_assessment": "<low|medium|high|critical>", "reasons": ["reason1", "reason2"], "confidence": 0.0-1.0}

Rules:
- "low": read-only, no side effects, safe operations
- "medium": write operations in user workspace, standard tool usage
- "high": system-level access, credential handling, network exfiltration potential
- "critical": confirmed privilege escalation, credential theft, destructive system operations
"""

_VALID_RISK_LEVELS = {"low", "medium", "high", "critical"}


class LLMAnalyzer:
    """L2 semantic analyzer backed by an LLM provider."""

    def __init__(
        self,
        provider: LLMProvider,
        config: Optional[LLMAnalyzerConfig] = None,
    ) -> None:
        self._provider = provider
        self._config = config or LLMAnalyzerConfig()

    @property
    def analyzer_id(self) -> str:
        return f"llm-{self._provider.provider_id}"

    async def analyze(
        self,
        event: CanonicalEvent,
        context: Optional[DecisionContext],
        l1_snapshot: RiskSnapshot,
        budget_ms: float,
    ) -> L2Result:
        start = time.monotonic()
        timeout = min(budget_ms, self._config.provider_timeout_ms)
        user_msg = self._build_prompt(event, context, l1_snapshot)

        try:
            raw = await asyncio.wait_for(
                self._provider.complete(
                    _LLM_SYSTEM_PROMPT,
                    user_msg,
                    timeout_ms=timeout,
                    max_tokens=self._config.max_tokens,
                ),
                timeout=timeout / 1000,
            )
            return self._parse_response(raw, l1_snapshot, start)
        except Exception:
            logger.warning("LLM analysis failed; falling back to L1", exc_info=True)
            elapsed_ms = (time.monotonic() - start) * 1000
            return L2Result(
                target_level=l1_snapshot.risk_level,
                reasons=["LLM analysis failed; falling back to L1"],
                confidence=0.0,
                analyzer_id=self.analyzer_id,
                latency_ms=round(elapsed_ms, 3),
            )

    def _build_prompt(
        self,
        event: CanonicalEvent,
        context: Optional[DecisionContext],
        l1_snapshot: RiskSnapshot,
    ) -> str:
        dims = l1_snapshot.dimensions
        payload_str = json.dumps(event.payload or {}, ensure_ascii=False)
        if len(payload_str) > _MAX_PROMPT_PAYLOAD_LEN:
            payload_str = payload_str[:_MAX_PROMPT_PAYLOAD_LEN] + "...[truncated]"
        payload_str = _SECRET_RE.sub("[REDACTED]", payload_str)
        parts = [
            f"Tool: {event.tool_name or 'unknown'}",
            f"Event type: {event.event_type.value}",
            f"Payload: {payload_str}",
            f"Risk hints: {event.risk_hints or []}",
            f"L1 risk level: {l1_snapshot.risk_level.value}",
            f"L1 dimensions: D1={dims.d1} D2={dims.d2} D3={dims.d3} D4={dims.d4} D5={dims.d5} D6={dims.d6:.2f}",
            f"L1 composite score: {l1_snapshot.composite_score}",
        ]
        if l1_snapshot.short_circuit_rule:
            parts.append(f"Short-circuit: {l1_snapshot.short_circuit_rule}")
        return "\n".join(parts)

    def _parse_response(
        self,
        raw: str,
        l1_snapshot: RiskSnapshot,
        start: float,
    ) -> L2Result:
        elapsed_ms = (time.monotonic() - start) * 1000
        try:
            data = json.loads(raw)
            level_str = data.get("risk_assessment", "").lower()
            if level_str not in _VALID_RISK_LEVELS:
                raise ValueError(f"Invalid risk_assessment: {level_str}")
            reasons = data.get("reasons", [])
            if not isinstance(reasons, list):
                reasons = [str(reasons)]
            else:
                reasons = [str(r) for r in reasons if r is not None]
            confidence = float(data.get("confidence", 0.0))
            confidence = max(0.0, min(1.0, confidence))
            return L2Result(
                target_level=RiskLevel(level_str),
                reasons=reasons,
                confidence=confidence,
                analyzer_id=self.analyzer_id,
                latency_ms=round(elapsed_ms, 3),
            )
        except (json.JSONDecodeError, ValueError, KeyError, TypeError):
            return L2Result(
                target_level=l1_snapshot.risk_level,
                reasons=["LLM response parse failed; falling back to L1"],
                confidence=0.0,
                analyzer_id=self.analyzer_id,
                latency_ms=round(elapsed_ms, 3),
            )


# ---------------------------------------------------------------------------
# CompositeAnalyzer — chains multiple analyzers and merges results
# ---------------------------------------------------------------------------

class CompositeAnalyzer:
    """Chains multiple analyzers and merges results (highest risk wins)."""

    def __init__(self, analyzers: list) -> None:
        self._analyzers = analyzers

    @property
    def analyzer_id(self) -> str:
        ids = ",".join(a.analyzer_id for a in self._analyzers)
        return f"composite({ids})"

    async def analyze(
        self,
        event: CanonicalEvent,
        context: Optional[DecisionContext],
        l1_snapshot: RiskSnapshot,
        budget_ms: float,
    ) -> L2Result:
        start = time.monotonic()
        tasks = [
            a.analyze(event, context, l1_snapshot, budget_ms)
            for a in self._analyzers
        ]
        raw_results = await asyncio.gather(*tasks, return_exceptions=True)

        valid: list[L2Result] = []
        for r in raw_results:
            if isinstance(r, L2Result) and r.confidence > 0.0:
                valid.append(r)

        elapsed_ms = (time.monotonic() - start) * 1000

        if not valid:
            return L2Result(
                target_level=l1_snapshot.risk_level,
                reasons=["All analyzers degraded; falling back to L1"],
                confidence=0.0,
                analyzer_id=self.analyzer_id,
                latency_ms=round(elapsed_ms, 3),
            )

        # Pick highest risk level; tie-break by confidence
        best = max(
            valid,
            key=lambda r: (RISK_LEVEL_ORDER.get(r.target_level, 0), r.confidence),
        )
        return L2Result(
            target_level=best.target_level,
            reasons=best.reasons,
            confidence=best.confidence,
            analyzer_id=best.analyzer_id,
            latency_ms=round(elapsed_ms, 3),
        )
