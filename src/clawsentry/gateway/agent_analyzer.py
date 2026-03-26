"""L3 AgentAnalyzer — MVP (single-turn) and standard (multi-turn) modes.

Design basis: 11-long-term-evolution-vision.md section 3 (Phase 5.2)

MVP mode (enable_multi_turn=False):
  trigger -> select skill -> collect min context -> single LLM call -> L2Result

Standard mode (enable_multi_turn=True):
  same entry; LLM drives tool selection each turn via structured JSON protocol.
  Each turn: LLM returns {thought, tool_call, done} or final {risk_level, findings, confidence}.
  Hard constraints: MAX_TOOL_CALLS budget, max_reasoning_turns, hard_cap_ms.

Fail-safe: any error / timeout / budget exhaustion -> degrade to l1_snapshot level, confidence=0.
"""

from __future__ import annotations

import asyncio
import json
import time
from dataclasses import dataclass
from typing import Any, Optional

from .l3_trigger import L3TriggerPolicy
from .llm_provider import LLMProvider
from .models import CanonicalEvent, DecisionContext, RiskLevel, RiskSnapshot
from .review_skills import ReviewSkill, SkillRegistry
from .review_toolkit import ReadOnlyToolkit, ToolCallBudgetExhausted
from .semantic_analyzer import L2Result, _max_risk_level


# Whitelist of toolkit methods callable by LLM in multi-turn mode
_ALLOWED_TOOL_CALLS: dict[str, str] = {
    "read_trajectory": "read_trajectory",
    "read_file": "read_file",
    "search_codebase": "search_codebase",
    "query_git_diff": "query_git_diff",
    "list_directory": "list_directory",
}


@dataclass
class AgentAnalyzerConfig:
    provider_timeout_ms: float = 20_000.0
    hard_cap_ms: float = 30_000.0
    l3_budget_ms: Optional[float] = None  # User-configurable L3 budget; None = use passed budget
    max_reasoning_turns: int = 8
    initial_trajectory_limit: int = 20
    max_findings: int = 10
    enable_multi_turn: bool = False


class AgentAnalyzer:
    """L3 review analyzer implementing the SemanticAnalyzer-compatible interface."""

    def __init__(
        self,
        provider: LLMProvider,
        toolkit: ReadOnlyToolkit,
        skill_registry: SkillRegistry,
        trigger_policy: Optional[L3TriggerPolicy] = None,
        config: Optional[AgentAnalyzerConfig] = None,
    ) -> None:
        self._provider = provider
        self._toolkit = toolkit
        self._skill_registry = skill_registry
        self._trigger_policy = trigger_policy or L3TriggerPolicy()
        self._config = config or AgentAnalyzerConfig()

    @property
    def analyzer_id(self) -> str:
        return "agent-reviewer"

    def _build_trace(
        self,
        *,
        trigger_reason: str,
        skill_selected: Optional[str],
        mode: Optional[str],
        turns: list[dict],
        final_verdict: Optional[dict],
        start: float,
        degraded: bool,
        degradation_reason: Optional[str] = None,
    ) -> dict:
        """Build a structured trace dict capturing the L3 reasoning process."""
        tool_calls_used = sum(1 for t in turns if t.get("type") == "tool_call")
        return {
            "trigger_reason": trigger_reason,
            "skill_selected": skill_selected,
            "mode": mode,
            "turns": turns,
            "final_verdict": final_verdict,
            "total_latency_ms": round((time.monotonic() - start) * 1000, 3),
            "tool_calls_used": tool_calls_used,
            "degraded": degraded,
            "degradation_reason": degradation_reason,
        }

    async def analyze(
        self,
        event: CanonicalEvent,
        context: Optional[DecisionContext],
        l1_snapshot: RiskSnapshot,
        budget_ms: float,
    ) -> L2Result:
        start = time.monotonic()
        self._toolkit.reset_budget()

        if not self._trigger_policy.should_trigger(event, context, l1_snapshot, []):
            result = self._degraded(l1_snapshot, start, "L3 trigger not matched")
            trace = self._build_trace(
                trigger_reason="trigger_not_matched",
                skill_selected=None, mode=None, turns=[],
                final_verdict=None, start=start,
                degraded=True, degradation_reason="L3 trigger not matched",
            )
            return L2Result(
                target_level=result.target_level, reasons=result.reasons,
                confidence=result.confidence, analyzer_id=result.analyzer_id,
                latency_ms=result.latency_ms, trace=trace,
            )

        try:
            skill = self._skill_registry.select_skill(event, event.risk_hints or [])
            trajectory = await self._toolkit.read_trajectory(
                event.session_id,
                limit=self._config.initial_trajectory_limit,
            )
            base_budget = self._config.l3_budget_ms if self._config.l3_budget_ms is not None else budget_ms
            effective_budget = min(
                base_budget, self._config.provider_timeout_ms, self._config.hard_cap_ms
            )

            if self._config.enable_multi_turn:
                return await self._run_multi_turn(
                    event, context, l1_snapshot, skill, trajectory, effective_budget, start
                )
            else:
                return await self._run_single_turn(
                    event, l1_snapshot, skill, trajectory, effective_budget, start
                )
        except Exception:
            result = self._degraded(
                l1_snapshot, start,
                "L3 analysis degraded; falling back to prior risk assessment",
            )
            trace = self._build_trace(
                trigger_reason="triggered",
                skill_selected=None, mode=None, turns=[],
                final_verdict=None, start=start,
                degraded=True,
                degradation_reason="L3 analysis degraded; falling back to prior risk assessment",
            )
            return L2Result(
                target_level=result.target_level, reasons=result.reasons,
                confidence=result.confidence, analyzer_id=result.analyzer_id,
                latency_ms=result.latency_ms, trace=trace,
            )

    # ------------------------------------------------------------------
    # Single-turn (MVP)
    # ------------------------------------------------------------------

    async def _run_single_turn(
        self,
        event: CanonicalEvent,
        l1_snapshot: RiskSnapshot,
        skill: ReviewSkill,
        trajectory: list[dict],
        effective_budget: float,
        start: float,
    ) -> L2Result:
        prompt = self._build_initial_prompt(event, l1_snapshot, skill, trajectory)

        llm_start = time.monotonic()
        raw = await asyncio.wait_for(
            self._provider.complete(
                skill.system_prompt,
                prompt,
                timeout_ms=effective_budget,
                max_tokens=256,
            ),
            timeout=effective_budget / 1000,
        )
        llm_latency = (time.monotonic() - llm_start) * 1000

        result = self._parse_final_response(raw, l1_snapshot, start)

        turns = [{
            "turn": 1,
            "type": "llm_call",
            "prompt_length": len(prompt),
            "response_raw": raw,
            "latency_ms": round(llm_latency, 3),
        }]

        final_verdict: Optional[dict] = None
        if result.confidence > 0.0:
            final_verdict = {
                "risk_level": result.target_level.value,
                "findings": list(result.reasons),
                "confidence": result.confidence,
            }

        trace = self._build_trace(
            trigger_reason="triggered",
            skill_selected=skill.name,
            mode="single_turn",
            turns=turns,
            final_verdict=final_verdict,
            start=start,
            degraded=result.confidence == 0.0,
            degradation_reason=(
                result.reasons[0] if result.confidence == 0.0 and result.reasons else None
            ),
        )

        return L2Result(
            target_level=result.target_level, reasons=result.reasons,
            confidence=result.confidence, analyzer_id=result.analyzer_id,
            latency_ms=result.latency_ms, trace=trace,
        )

    # ------------------------------------------------------------------
    # Multi-turn (standard)
    # ------------------------------------------------------------------

    async def _run_multi_turn(
        self,
        event: CanonicalEvent,
        context: Optional[DecisionContext],
        l1_snapshot: RiskSnapshot,
        skill: ReviewSkill,
        trajectory: list[dict],
        effective_budget: float,
        start: float,
    ) -> L2Result:
        system_prompt = self._build_multi_turn_system_prompt(skill)
        messages: list[dict[str, str]] = [
            {
                "role": "user",
                "content": self._build_initial_prompt(event, l1_snapshot, skill, trajectory),
            }
        ]

        turns: list[dict] = []
        turn_counter = 0

        def _attach_trace(
            result: L2Result,
            final_verdict: Optional[dict] = None,
            degraded: bool = False,
            degradation_reason: Optional[str] = None,
        ) -> L2Result:
            trace = self._build_trace(
                trigger_reason="triggered",
                skill_selected=skill.name,
                mode="multi_turn",
                turns=turns,
                final_verdict=final_verdict,
                start=start,
                degraded=degraded,
                degradation_reason=degradation_reason,
            )
            return L2Result(
                target_level=result.target_level, reasons=result.reasons,
                confidence=result.confidence, analyzer_id=result.analyzer_id,
                latency_ms=result.latency_ms, trace=trace,
            )

        for _turn in range(self._config.max_reasoning_turns):
            elapsed = (time.monotonic() - start) * 1000
            remaining = effective_budget - elapsed
            if remaining <= 0:
                result = self._degraded(l1_snapshot, start, "L3 hard cap exceeded")
                return _attach_trace(
                    result, degraded=True,
                    degradation_reason="L3 hard cap exceeded",
                )

            msg_json = json.dumps(messages, ensure_ascii=False)
            llm_start = time.monotonic()
            try:
                raw = await asyncio.wait_for(
                    self._provider.complete(
                        system_prompt,
                        msg_json,
                        timeout_ms=min(remaining, self._config.provider_timeout_ms),
                        max_tokens=512,
                    ),
                    timeout=min(remaining, self._config.provider_timeout_ms) / 1000,
                )
            except (asyncio.TimeoutError, Exception):
                result = self._degraded(l1_snapshot, start, "L3 LLM call failed")
                return _attach_trace(
                    result, degraded=True,
                    degradation_reason="L3 LLM call failed",
                )

            llm_latency = (time.monotonic() - llm_start) * 1000
            turn_counter += 1
            turns.append({
                "turn": turn_counter,
                "type": "llm_call",
                "prompt_length": len(msg_json),
                "response_raw": raw,
                "latency_ms": round(llm_latency, 3),
            })

            # Try to parse as tool_call or final response
            parsed = self._parse_tool_call_response(raw)
            if parsed is None:
                # Not a valid tool_call response -- try as final
                result = self._parse_final_response(raw, l1_snapshot, start)
                final_verdict = (
                    {"risk_level": result.target_level.value,
                     "findings": list(result.reasons),
                     "confidence": result.confidence}
                    if result.confidence > 0.0 else None
                )
                return _attach_trace(
                    result, final_verdict=final_verdict,
                    degraded=result.confidence == 0.0,
                    degradation_reason=(
                        result.reasons[0]
                        if result.confidence == 0.0 and result.reasons else None
                    ),
                )

            tool_name, tool_args, done = parsed
            if done:
                # done=True in tool_call response means final without tool
                result = self._parse_final_response(raw, l1_snapshot, start)
                final_verdict = (
                    {"risk_level": result.target_level.value,
                     "findings": list(result.reasons),
                     "confidence": result.confidence}
                    if result.confidence > 0.0 else None
                )
                return _attach_trace(
                    result, final_verdict=final_verdict,
                    degraded=result.confidence == 0.0,
                )

            # Validate tool name against whitelist
            if tool_name not in _ALLOWED_TOOL_CALLS:
                reason = f"L3 requested non-whitelisted tool: {tool_name}"
                result = self._degraded(l1_snapshot, start, reason)
                return _attach_trace(
                    result, degraded=True, degradation_reason=reason,
                )

            # Execute the toolkit call
            tool_start = time.monotonic()
            tool_result = await self._execute_tool(tool_name, tool_args)
            tool_latency = (time.monotonic() - tool_start) * 1000
            turn_counter += 1
            tool_result_str = (
                json.dumps(tool_result)
                if not isinstance(tool_result, str) else tool_result
            )
            turns.append({
                "turn": turn_counter,
                "type": "tool_call",
                "tool_name": tool_name,
                "tool_args": tool_args,
                "tool_result_length": len(tool_result_str),
                "latency_ms": round(tool_latency, 3),
            })

            messages.append({"role": "assistant", "content": raw})
            messages.append({"role": "user", "content": json.dumps({"tool_result": tool_result})})

        result = self._degraded(l1_snapshot, start, "L3 max reasoning turns exceeded")
        return _attach_trace(
            result, degraded=True,
            degradation_reason="L3 max reasoning turns exceeded",
        )

    async def _execute_tool(self, tool_name: str, tool_args: dict[str, Any]) -> Any:
        try:
            method = getattr(self._toolkit, tool_name)
            return await method(**tool_args)
        except ToolCallBudgetExhausted:
            raise
        except Exception as exc:
            return {"error": str(exc)}

    # ------------------------------------------------------------------
    # Prompt builders
    # ------------------------------------------------------------------

    def _build_initial_prompt(
        self,
        event: CanonicalEvent,
        l1_snapshot: RiskSnapshot,
        skill: ReviewSkill,
        trajectory: list[dict],
    ) -> str:
        trajectory_summary = [
            {
                "recorded_at": item.get("recorded_at"),
                "tool_name": item.get("event", {}).get("tool_name"),
                "event_type": item.get("event", {}).get("event_type"),
                "risk_hints": item.get("event", {}).get("risk_hints", []),
                "risk_level": item.get("risk_level"),
            }
            for item in trajectory
        ]
        payload = {
            "skill": {
                "name": skill.name,
                "description": skill.description,
                "evaluation_criteria": skill.evaluation_criteria,
            },
            "event": event.model_dump(mode="json"),
            "l1_snapshot": l1_snapshot.model_dump(mode="json"),
            "trajectory_summary": trajectory_summary,
            "constraints": {
                "must_not_downgrade_below_l1": True,
                "final_response_format": {
                    "risk_level": "low|medium|high|critical",
                    "findings": ["short finding"],
                    "confidence": 0.0,
                },
            },
        }
        return json.dumps(payload, ensure_ascii=False, sort_keys=True)

    def _build_multi_turn_system_prompt(self, skill: ReviewSkill) -> str:
        return (
            skill.system_prompt
            + "\n\n"
            + "You may call read-only tools to gather more evidence. "
            + "Each intermediate response must be JSON: "
            + '{"thought": "...", "tool_call": {"name": "<tool>", "arguments": {...}}, "done": false}. '
            + "Available tools: read_trajectory, read_file, search_codebase, query_git_diff, list_directory. "
            + "When you have enough information, respond with the final JSON ONLY: "
            + '{"risk_level": "low|medium|high|critical", "findings": ["..."], "confidence": 0.0}.'
        )

    # ------------------------------------------------------------------
    # Response parsers
    # ------------------------------------------------------------------

    def _parse_tool_call_response(
        self, raw: str
    ) -> Optional[tuple[str, dict[str, Any], bool]]:
        """Return (tool_name, tool_args, done) if raw is a tool-call response, else None."""
        try:
            data = json.loads(raw)
            if not isinstance(data, dict):
                return None
            done = bool(data.get("done", False))
            tool_call = data.get("tool_call")
            if tool_call is None:
                return None
            if not isinstance(tool_call, dict):
                return None
            tool_name = str(tool_call.get("name") or "")
            tool_args = tool_call.get("arguments") or {}
            if not isinstance(tool_args, dict):
                tool_args = {}
            if not tool_name:
                return None
            return tool_name, tool_args, done
        except (json.JSONDecodeError, TypeError):
            return None

    def _parse_final_response(
        self,
        raw: str,
        l1_snapshot: RiskSnapshot,
        start: float,
    ) -> L2Result:
        elapsed_ms = (time.monotonic() - start) * 1000
        try:
            data = json.loads(raw)
            risk_level = RiskLevel(str(data.get("risk_level", "")).lower())
            findings = data.get("findings", [])
            if not isinstance(findings, list):
                findings = [str(findings)]
            confidence = float(data.get("confidence", 0.0))
            confidence = max(0.0, min(1.0, confidence))
            target_level = _max_risk_level(risk_level, l1_snapshot.risk_level)
            return L2Result(
                target_level=target_level,
                reasons=[str(item) for item in findings[: self._config.max_findings]],
                confidence=confidence,
                analyzer_id=self.analyzer_id,
                latency_ms=round(elapsed_ms, 3),
            )
        except Exception:
            return self._degraded(
                l1_snapshot, start,
                "L3 analysis degraded; falling back to prior risk assessment",
            )

    def _degraded(self, l1_snapshot: RiskSnapshot, start: float, reason: str) -> L2Result:
        elapsed_ms = (time.monotonic() - start) * 1000
        return L2Result(
            target_level=l1_snapshot.risk_level,
            reasons=[reason],
            confidence=0.0,
            analyzer_id=self.analyzer_id,
            latency_ms=round(elapsed_ms, 3),
        )
