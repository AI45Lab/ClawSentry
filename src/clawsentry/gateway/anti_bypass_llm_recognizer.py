"""Sanitized LLM recognizer for ambiguous anti-bypass follow-up candidates."""

from __future__ import annotations

import asyncio
import json
import logging
from dataclasses import dataclass
from typing import Any, Protocol

from .anti_bypass_guard import AntiBypassLLMCandidate, AntiBypassMatch
from .detection_config import DetectionConfig

logger = logging.getLogger(__name__)

SCHEMA_VERSION = "cs.anti_bypass.recognition.v1"
_SYSTEM_PROMPT = """\
You are a follow-up recognizer for an anti-bypass guard.
You receive sanitized semantic capsules only. Decide whether the current action
is a follow-up attempt related to a prior risky final decision.

Return only JSON with this schema:
{"schema":"cs.anti_bypass.recognition.v1","matched":true|false,"confidence":0.0-1.0,"action":"observe|force_l2|force_l3|defer","prior_record_id":0,"reason_codes":[],"evidence_categories":[]}

Rules:
- Do not score security risk.
- Do not choose enforcement semantics. The gateway will apply its configured
  action when you report a match.
- Use only the provided categories, labels, overlap counts, similarity values,
  and record ids.
"""


class AntiBypassLLMProvider(Protocol):
    @property
    def provider_id(self) -> str: ...

    async def complete(
        self,
        system_prompt: str,
        user_message: str,
        timeout_ms: float,
        max_tokens: int = 256,
    ) -> str: ...


@dataclass(frozen=True)
class AntiBypassLLMRecognition:
    match: AntiBypassMatch | None
    state: str
    confidence: float = 0.0
    reason: str = ""


async def recognize_anti_bypass_candidate(
    *,
    provider: AntiBypassLLMProvider | None,
    candidates: list[AntiBypassLLMCandidate],
    config: DetectionConfig,
) -> AntiBypassLLMRecognition:
    if provider is None:
        return AntiBypassLLMRecognition(match=None, state="disabled", reason="provider_unavailable")
    if not config.anti_bypass_llm_recognition_enabled:
        return AntiBypassLLMRecognition(match=None, state="disabled", reason="disabled")
    if not candidates:
        return AntiBypassLLMRecognition(match=None, state="not_matched", reason="no_candidate")

    prompt = _build_user_message(candidates)
    timeout_ms = float(config.anti_bypass_llm_timeout_ms)
    try:
        raw = await asyncio.wait_for(
            provider.complete(
                _SYSTEM_PROMPT,
                prompt,
                timeout_ms=timeout_ms,
                max_tokens=256,
            ),
            timeout=timeout_ms / 1000,
        )
    except (asyncio.TimeoutError, TimeoutError):
        logger.warning("anti-bypass LLM recognition timed out")
        return AntiBypassLLMRecognition(match=None, state="degraded", reason="timeout")
    except Exception:
        logger.warning("anti-bypass LLM recognition failed", exc_info=True)
        return AntiBypassLLMRecognition(match=None, state="degraded", reason="provider_error")

    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return AntiBypassLLMRecognition(match=None, state="degraded", reason="invalid_json")

    candidate_by_id = {c.prior_record.record_id: c for c in candidates}
    if str(data.get("schema") or "") != SCHEMA_VERSION:
        return AntiBypassLLMRecognition(match=None, state="degraded", reason="invalid_schema")
    try:
        confidence = max(0.0, min(1.0, float(data.get("confidence", 0.0))))
    except (TypeError, ValueError):
        confidence = 0.0
    if not bool(data.get("matched")):
        return AntiBypassLLMRecognition(match=None, state="not_matched", confidence=confidence)
    if confidence < config.anti_bypass_llm_confidence_threshold:
        return AntiBypassLLMRecognition(match=None, state="not_matched", confidence=confidence, reason="low_confidence")
    try:
        prior_record_id = int(data.get("prior_record_id"))
    except (TypeError, ValueError):
        return AntiBypassLLMRecognition(match=None, state="degraded", confidence=confidence, reason="invalid_prior_id")
    candidate = candidate_by_id.get(prior_record_id)
    if candidate is None:
        return AntiBypassLLMRecognition(match=None, state="degraded", confidence=confidence, reason="prior_id_mismatch")

    action = config.anti_bypass_llm_action

    reason_codes = _trusted_subset(
        _string_tuple(data.get("reason_codes")),
        candidate.reason_codes,
    ) or candidate.reason_codes
    evidence_categories = _trusted_subset(
        _string_tuple(data.get("evidence_categories")),
        candidate.evidence_categories,
    ) or candidate.evidence_categories
    match = AntiBypassMatch(
        match_type="cross_tool_script_similarity",
        action=action,
        prior_event_id=candidate.prior_record.event_id,
        prior_record_id=candidate.prior_record.record_id,
        prior_policy_id=candidate.prior_record.policy_id,
        prior_risk_level=candidate.prior_record.risk_level,
        raw_payload_hash=candidate.current_raw_payload_hash,
        normalized_action_fingerprint=candidate.current_normalized_action_fingerprint,
        destructive_intent_fingerprint=candidate.current_destructive_intent_fingerprint,
        destructive_intent_label=candidate.current_destructive_intent_label,
        destructive_operation_category=candidate.current_destructive_operation_category,
        similarity=candidate.similarity,
        recognition_source="llm_assisted",
        match_reason=reason_codes[0] if reason_codes else "llm_followup_match",
        similarity_mode="llm_capsule",
        llm_confidence=confidence,
        llm_state="matched",
        reason_codes=reason_codes,
        evidence_categories=evidence_categories,
    )
    return AntiBypassLLMRecognition(match=match, state="matched", confidence=confidence)


def _build_user_message(candidates: list[AntiBypassLLMCandidate]) -> str:
    body: dict[str, Any] = {
        "schema": SCHEMA_VERSION,
        "task": "follow_up_relationship_only",
        "candidates": [candidate.capsule for candidate in candidates],
    }
    return json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _string_tuple(value: Any) -> tuple[str, ...]:
    if not isinstance(value, list):
        return ()
    return tuple(str(item) for item in value if item is not None)


def _trusted_subset(values: tuple[str, ...], allowed: tuple[str, ...]) -> tuple[str, ...]:
    allowed_set = set(allowed)
    return tuple(value for value in values if value in allowed_set)
