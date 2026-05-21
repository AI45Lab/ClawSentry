"""Compact PRE_ACTION anti-bypass follow-up guard.

The guard keeps a bounded, per-session memory of final risky decisions using
only hashes, fingerprints, ids, and labels.  It never stores raw commands,
payloads, prompts, environment variables, or L3 traces.
"""

from __future__ import annotations

import hashlib
import json
import time
from collections import defaultdict, deque
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any, Deque

from .command_normalization import normalize_shell_command_head
from .detection_config import DetectionConfig
from .effect_normalizer import artifact_families, effect_hash, normalize_action_effect, target_hashes
from .models import CanonicalDecision, CanonicalEvent, EventType, RiskSnapshot


_RISK_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}
_DESTRUCTIVE_HEADS = {
    "rm",
    "rmdir",
    "unlink",
    "shred",
    "dd",
    "mkfs",
    "chmod",
    "chown",
    "curl",
    "wget",
    "scp",
    "rsync",
    "ssh",
    "git",
}


@dataclass(frozen=True)
class AntiBypassRecord:
    event_id: str
    record_id: int
    session_id_hash: str
    tool_name: str
    raw_payload_hash: str
    normalized_action_fingerprint: str
    destructive_intent_label: str
    destructive_intent_fingerprint: str
    destructive_operation_category: str
    target_scope_categories: tuple[str, ...]
    normalized_feature_hashes: tuple[str, ...]
    policy_id: str
    decision: str
    risk_level: str
    occurred_at: str
    recorded_at: str
    expires_at: str
    source_framework: str


@dataclass(frozen=True)
class DeniedEffectMemoryRecord:
    event_id: str
    record_id: int
    session_id_hash: str
    capability: str
    effect_hash: str
    target_hashes: tuple[str, ...]
    artifact_families: tuple[str, ...]
    policy_id: str
    policy_version: str
    decision: str
    risk_level: str
    occurred_at: str
    recorded_at: str
    expires_at: str


@dataclass(frozen=True)
class PendingEffectHoldRecord:
    event_id: str
    record_id: int
    session_id_hash: str
    capability: str
    effect_hash: str
    target_hashes: tuple[str, ...]
    artifact_families: tuple[str, ...]
    policy_id: str
    decision: str
    risk_level: str
    occurred_at: str
    recorded_at: str
    expires_at: str
    hold_reason: str = "operator_review"
    contextual_effect_hash: str | None = None


@dataclass(frozen=True)
class AntiBypassMatch:
    match_type: str
    action: str
    prior_event_id: str
    prior_record_id: int
    prior_policy_id: str
    prior_risk_level: str
    raw_payload_hash: str
    normalized_action_fingerprint: str
    destructive_intent_fingerprint: str
    destructive_intent_label: str = ""
    destructive_operation_category: str = ""
    similarity: float | None = None
    recognition_source: str = "deterministic"
    match_reason: str = ""
    similarity_mode: str = ""
    llm_confidence: float | None = None
    llm_state: str | None = None
    reason_codes: tuple[str, ...] = ()
    evidence_categories: tuple[str, ...] = ()

    def to_metadata(self) -> dict[str, Any]:
        meta = {
            "matched": True,
            "match_type": self.match_type,
            "action": self.action,
            "recognition_source": self.recognition_source,
            "prior_event_id": self.prior_event_id,
            "prior_record_id": self.prior_record_id,
            "prior_policy_id": self.prior_policy_id,
            "prior_risk_level": self.prior_risk_level,
            "raw_payload_hash": self.raw_payload_hash,
            "normalized_action_fingerprint": self.normalized_action_fingerprint,
            "destructive_intent_fingerprint": self.destructive_intent_fingerprint,
        }
        if self.match_reason:
            meta["match_reason"] = self.match_reason
        if self.similarity_mode:
            meta["similarity_mode"] = self.similarity_mode
        if self.destructive_intent_label:
            meta["destructive_intent_label"] = self.destructive_intent_label
        if self.destructive_operation_category:
            meta["destructive_operation_category"] = self.destructive_operation_category
        if self.similarity is not None:
            meta["similarity"] = round(self.similarity, 4)
        if self.llm_confidence is not None:
            meta["llm_confidence"] = round(self.llm_confidence, 4)
        if self.llm_state:
            meta["llm_state"] = self.llm_state
        if self.reason_codes:
            meta["reason_codes"] = list(self.reason_codes)
        if self.evidence_categories:
            meta["evidence_categories"] = list(self.evidence_categories)
        if self.action in ("force_l2", "force_l3"):
            meta["forced_tier"] = "L2" if self.action == "force_l2" else "L3"
        return meta


@dataclass(frozen=True)
class AntiBypassLLMCandidate:
    prior_record: AntiBypassRecord
    similarity: float
    reason_codes: tuple[str, ...]
    evidence_categories: tuple[str, ...]
    current_raw_payload_hash: str
    current_normalized_action_fingerprint: str
    current_destructive_intent_fingerprint: str
    current_destructive_intent_label: str
    current_destructive_operation_category: str
    capsule: dict[str, Any]


@dataclass(frozen=True)
class _EventFingerprints:
    raw_payload_hash: str
    normalized_action_fingerprint: str
    destructive_intent_fingerprint: str
    destructive_intent_label: str
    destructive_operation_category: str
    normalized_feature_hashes: frozenset[str]
    normalized_text: str
    command_head_category: str
    target_scope_categories: frozenset[str]


class AntiBypassGuard:
    """Bounded per-session anti-bypass memory and matcher."""

    def __init__(self) -> None:
        self._records: dict[str, Deque[AntiBypassRecord]] = defaultdict(deque)
        self._denied_effects: dict[str, Deque[DeniedEffectMemoryRecord]] = defaultdict(deque)
        self._pending_effect_holds: dict[str, Deque[PendingEffectHoldRecord]] = defaultdict(deque)
        self.memory_evictions: int = 0

    def match_pre_action(
        self,
        event: CanonicalEvent,
        context: Any,
        config: DetectionConfig,
    ) -> AntiBypassMatch | None:
        del context  # reserved for future compact context-derived features
        if not config.anti_bypass_guard_enabled:
            return None
        if event.event_type != EventType.PRE_ACTION:
            return None

        session_id = str(event.session_id or "")
        self._evict(session_id, config)
        current = _fingerprints_for_event(event)
        effect_match = self._match_denied_effect(event, session_id, config)
        if effect_match is not None:
            return effect_match
        pending_match = self._match_pending_effect_hold(event, session_id)
        if pending_match is not None:
            return pending_match
        tool_name = str(event.tool_name or "")
        ranked_matches: list[tuple[int, int, AntiBypassMatch]] = []
        for index, prior in enumerate(self._records.get(session_id, ())):
            if not _eligible_prior(prior, config):
                continue
            if prior.tool_name == tool_name and prior.raw_payload_hash == current.raw_payload_hash:
                ranked_matches.append(
                    (
                        0,
                        -index,
                        AntiBypassMatch(
                            match_type="exact_raw_repeat",
                            action=config.anti_bypass_exact_repeat_action,
                            prior_event_id=prior.event_id,
                            prior_record_id=prior.record_id,
                            prior_policy_id=prior.policy_id,
                            prior_risk_level=prior.risk_level,
                            raw_payload_hash=current.raw_payload_hash,
                            normalized_action_fingerprint=current.normalized_action_fingerprint,
                            destructive_intent_fingerprint=current.destructive_intent_fingerprint,
                            destructive_intent_label=current.destructive_intent_label,
                            destructive_operation_category=current.destructive_operation_category,
                            match_reason="raw_payload_hash",
                            similarity_mode="raw_hash",
                        ),
                    )
                )
            if (
                prior.normalized_action_fingerprint
                and prior.normalized_action_fingerprint == current.normalized_action_fingerprint
                and prior.destructive_intent_label != "non-destructive"
                and current.destructive_intent_label != "non-destructive"
            ):
                if prior.tool_name == tool_name:
                    ranked_matches.append(
                        (
                            1,
                            -index,
                            AntiBypassMatch(
                                match_type="normalized_destructive_repeat",
                                action=config.anti_bypass_normalized_destructive_repeat_action,
                                prior_event_id=prior.event_id,
                                prior_record_id=prior.record_id,
                                prior_policy_id=prior.policy_id,
                                prior_risk_level=prior.risk_level,
                                raw_payload_hash=current.raw_payload_hash,
                                normalized_action_fingerprint=current.normalized_action_fingerprint,
                                destructive_intent_fingerprint=current.destructive_intent_fingerprint,
                                destructive_intent_label=current.destructive_intent_label,
                                destructive_operation_category=current.destructive_operation_category,
                                match_reason="exact_normalized_fingerprint",
                                similarity_mode="normalized_hash",
                            ),
                        )
                    )
                else:
                    ranked_matches.append(
                        (
                            3,
                            -index,
                            AntiBypassMatch(
                                match_type="cross_tool_script_similarity",
                                action=config.anti_bypass_cross_tool_similarity_action,
                                prior_event_id=prior.event_id,
                                prior_record_id=prior.record_id,
                                prior_policy_id=prior.policy_id,
                                prior_risk_level=prior.risk_level,
                                raw_payload_hash=current.raw_payload_hash,
                                normalized_action_fingerprint=current.normalized_action_fingerprint,
                                destructive_intent_fingerprint=current.destructive_intent_fingerprint,
                                destructive_intent_label=current.destructive_intent_label,
                                destructive_operation_category=current.destructive_operation_category,
                                match_reason="exact_normalized_fingerprint",
                                similarity_mode="normalized_hash",
                            ),
                        )
                )
            if (
                prior.tool_name != tool_name
                and prior.destructive_intent_label != "non-destructive"
                and current.destructive_intent_label != "non-destructive"
                and prior.destructive_intent_fingerprint == current.destructive_intent_fingerprint
                and _has_cross_tool_label_support(prior, current, similarity=None, config=config)
            ):
                ranked_matches.append(
                    (
                        5,
                        -index,
                        AntiBypassMatch(
                            match_type="cross_tool_script_similarity",
                            action=config.anti_bypass_cross_tool_similarity_action,
                            prior_event_id=prior.event_id,
                            prior_record_id=prior.record_id,
                            prior_policy_id=prior.policy_id,
                            prior_risk_level=prior.risk_level,
                            raw_payload_hash=current.raw_payload_hash,
                            normalized_action_fingerprint=current.normalized_action_fingerprint,
                            destructive_intent_fingerprint=current.destructive_intent_fingerprint,
                            destructive_intent_label=current.destructive_intent_label,
                            destructive_operation_category=current.destructive_operation_category,
                            match_reason="destructive_intent_label",
                            similarity_mode="intent_label",
                        ),
                    )
                )
            if (
                prior.tool_name != tool_name
                and _same_destructive_operation_family(
                    prior.destructive_operation_category,
                    current.destructive_operation_category,
                )
                and set(_record_scope_categories(prior)) & set(current.target_scope_categories)
            ):
                ranked_matches.append(
                    (
                        4,
                        -index,
                        AntiBypassMatch(
                            match_type="cross_tool_script_similarity",
                            action=config.anti_bypass_cross_tool_similarity_action,
                            prior_event_id=prior.event_id,
                            prior_record_id=prior.record_id,
                            prior_policy_id=prior.policy_id,
                            prior_risk_level=prior.risk_level,
                            raw_payload_hash=current.raw_payload_hash,
                            normalized_action_fingerprint=current.normalized_action_fingerprint,
                            destructive_intent_fingerprint=current.destructive_intent_fingerprint,
                            destructive_intent_label=current.destructive_intent_label,
                            destructive_operation_category=current.destructive_operation_category,
                            match_reason="destructive_operation_scope",
                            similarity_mode="operation_scope",
                        ),
                    )
                )

            similarity = _jaccard(
                frozenset(prior.normalized_feature_hashes),
                current.normalized_feature_hashes,
            )
            if (
                prior.tool_name == tool_name
                and prior.destructive_intent_label != "non-destructive"
                and current.destructive_intent_label != "non-destructive"
                and similarity >= config.anti_bypass_same_tool_similarity_threshold
            ):
                ranked_matches.append(
                    (
                        2,
                        -index,
                        AntiBypassMatch(
                            match_type="normalized_destructive_repeat",
                            action=config.anti_bypass_normalized_destructive_repeat_action,
                            prior_event_id=prior.event_id,
                            prior_record_id=prior.record_id,
                            prior_policy_id=prior.policy_id,
                            prior_risk_level=prior.risk_level,
                            raw_payload_hash=current.raw_payload_hash,
                            normalized_action_fingerprint=current.normalized_action_fingerprint,
                            destructive_intent_fingerprint=current.destructive_intent_fingerprint,
                            destructive_intent_label=current.destructive_intent_label,
                            destructive_operation_category=current.destructive_operation_category,
                            similarity=similarity,
                            match_reason="same_tool_feature_similarity",
                            similarity_mode="same_tool_jaccard",
                        ),
                    )
                )
            if (
                prior.tool_name != tool_name
                and prior.destructive_intent_label != "non-destructive"
                and current.destructive_intent_label != "non-destructive"
                and similarity >= config.anti_bypass_similarity_threshold
                and _has_cross_tool_label_support(prior, current, similarity=similarity, config=config)
            ):
                ranked_matches.append(
                    (
                        6,
                        -index,
                        AntiBypassMatch(
                            match_type="cross_tool_script_similarity",
                            action=config.anti_bypass_cross_tool_similarity_action,
                            prior_event_id=prior.event_id,
                            prior_record_id=prior.record_id,
                            prior_policy_id=prior.policy_id,
                            prior_risk_level=prior.risk_level,
                            raw_payload_hash=current.raw_payload_hash,
                            normalized_action_fingerprint=current.normalized_action_fingerprint,
                            destructive_intent_fingerprint=current.destructive_intent_fingerprint,
                            destructive_intent_label=current.destructive_intent_label,
                            destructive_operation_category=current.destructive_operation_category,
                            similarity=similarity,
                            match_reason="cross_tool_feature_similarity",
                            similarity_mode="cross_tool_jaccard",
                        ),
                    )
                )
        if not ranked_matches:
            return None
        return min(ranked_matches, key=lambda item: (item[0], item[1]))[2]

    def llm_candidates(
        self,
        event: CanonicalEvent,
        context: Any,
        config: DetectionConfig,
    ) -> list[AntiBypassLLMCandidate]:
        del context
        if not config.anti_bypass_guard_enabled:
            return []
        if event.event_type != EventType.PRE_ACTION:
            return []
        session_id = str(event.session_id or "")
        self._evict(session_id, config)
        current = _fingerprints_for_event(event)
        if current.destructive_intent_label == "non-destructive":
            return []
        tool_name = str(event.tool_name or "")
        candidates: list[AntiBypassLLMCandidate] = []
        for prior in reversed(self._records.get(session_id, ())):
            if len(candidates) >= config.anti_bypass_llm_max_priors:
                break
            if not _eligible_prior(prior, config):
                continue
            if prior.tool_name == tool_name:
                continue
            similarity = _jaccard(
                frozenset(prior.normalized_feature_hashes),
                current.normalized_feature_hashes,
            )
            reason_codes, evidence_categories = _weak_similarity_signals(
                prior,
                current,
                similarity,
                config,
            )
            if not _llm_candidate_admissible(reason_codes):
                continue
            candidates.append(
                AntiBypassLLMCandidate(
                    prior_record=prior,
                    similarity=similarity,
                    reason_codes=tuple(reason_codes),
                    evidence_categories=tuple(evidence_categories),
                    current_raw_payload_hash=current.raw_payload_hash,
                    current_normalized_action_fingerprint=current.normalized_action_fingerprint,
                    current_destructive_intent_fingerprint=current.destructive_intent_fingerprint,
                    current_destructive_intent_label=current.destructive_intent_label,
                    current_destructive_operation_category=current.destructive_operation_category,
                    capsule=_semantic_capsule(
                        prior=prior,
                        current=current,
                        current_tool_name=tool_name,
                        similarity=similarity,
                        reason_codes=reason_codes,
                        evidence_categories=evidence_categories,
                    ),
                )
            )
        return candidates

    def record_final_decision(
        self,
        event: CanonicalEvent,
        decision: CanonicalDecision,
        snapshot: RiskSnapshot | None,
        meta: dict[str, Any],
        record_id: int,
        config: DetectionConfig,
    ) -> None:
        del meta  # memory is intentionally compact and recomputed
        if not config.anti_bypass_guard_enabled:
            return
        if event.event_type != EventType.PRE_ACTION:
            return
        decision_value = str(getattr(decision.decision, "value", decision.decision))
        summary = snapshot.l2_l3_summary if snapshot is not None else {}
        contextual_status = str((summary or {}).get("status") or "")
        if getattr(decision, "final", None) is not True:
            if decision_value == "defer":
                session_id = str(event.session_id or "")
                self._evict(session_id, config)
                now = time.time()
                self._record_pending_effect_hold(
                    event=event,
                    decision=decision,
                    record_id=record_id,
                    risk_level=str(getattr(decision.risk_level, "value", decision.risk_level)),
                    recorded_at=_iso_from_ts(now),
                    expires_at=_iso_from_ts(now + float(config.anti_bypass_memory_ttl_s)),
                    config=config,
                    hold_reason=(
                        "contextual_review"
                        if contextual_status == "contextual_review_deferred"
                        else "operator_review"
                    ),
                )
            return

        if decision_value == "allow" and not config.anti_bypass_record_allow_decisions:
            return
        if decision_value not in set(config.anti_bypass_prior_verdicts) and not (
            decision_value == "allow" and config.anti_bypass_record_allow_decisions
        ):
            return

        risk_level = str(getattr(decision.risk_level, "value", decision.risk_level))
        if _risk_rank(risk_level) < _risk_rank(config.anti_bypass_min_prior_risk):
            return

        session_id = str(event.session_id or "")
        self._evict(session_id, config)
        fp = _fingerprints_for_event(event)
        now = time.time()
        record = AntiBypassRecord(
            event_id=str(event.event_id or ""),
            record_id=int(record_id or 0),
            session_id_hash=_sha256(session_id),
            tool_name=str(event.tool_name or ""),
            raw_payload_hash=fp.raw_payload_hash,
            normalized_action_fingerprint=fp.normalized_action_fingerprint,
            destructive_intent_fingerprint=fp.destructive_intent_fingerprint,
            destructive_intent_label=fp.destructive_intent_label,
            destructive_operation_category=fp.destructive_operation_category,
            target_scope_categories=tuple(sorted(fp.target_scope_categories)),
            normalized_feature_hashes=tuple(sorted(fp.normalized_feature_hashes)),
            policy_id=str(decision.policy_id or ""),
            decision=decision_value,
            risk_level=risk_level,
            occurred_at=str(event.occurred_at or ""),
            recorded_at=_iso_from_ts(now),
            expires_at=_iso_from_ts(now + float(config.anti_bypass_memory_ttl_s)),
            source_framework=str(event.source_framework or ""),
        )
        records = self._records[session_id]
        records.append(record)
        while len(records) > config.anti_bypass_memory_max_records_per_session:
            records.popleft()
            self.memory_evictions += 1
        if decision_value == "block":
            if contextual_status == "contextual_review_failed_closed":
                return
            self._record_denied_effect(
                event=event,
                decision=decision,
                record_id=record_id,
                risk_level=risk_level,
                recorded_at=_iso_from_ts(now),
                expires_at=_iso_from_ts(now + float(config.anti_bypass_memory_ttl_s)),
                config=config,
            )

    def records_for_session(self, session_id: str) -> list[dict[str, Any]]:
        """Return serialized compact records for tests and reporting hooks."""
        return [asdict(record) for record in self._records.get(str(session_id or ""), ())]

    def denied_effect_records_for_session(self, session_id: str) -> list[dict[str, Any]]:
        """Return serialized denied-effect records for tests/reporting hooks."""
        return [asdict(record) for record in self._denied_effects.get(str(session_id or ""), ())]

    def pending_effect_holds_for_session(self, session_id: str) -> list[dict[str, Any]]:
        """Return serialized pending-effect holds for tests/reporting hooks."""
        return [asdict(record) for record in self._pending_effect_holds.get(str(session_id or ""), ())]

    def resolve_pending_effect_hold(
        self,
        *,
        event: CanonicalEvent,
        decision: CanonicalDecision,
        record_id: int,
        config: DetectionConfig,
    ) -> None:
        """Clear a pending hold and promote terminal blocks into denied memory."""
        if not config.anti_bypass_guard_enabled:
            return
        session_id = str(event.session_id or "")
        pending = self._pending_effect_holds.get(session_id)
        if pending:
            retained = deque(
                record for record in pending
                if record.event_id != str(event.event_id or "")
            )
            self._pending_effect_holds[session_id] = retained
        decision_value = str(getattr(decision.decision, "value", decision.decision))
        if getattr(decision, "final", None) is True and decision_value == "block":
            now = time.time()
            self._evict(session_id, config)
            self._record_denied_effect(
                event=event,
                decision=decision,
                record_id=record_id,
                risk_level=str(getattr(decision.risk_level, "value", decision.risk_level)),
                recorded_at=_iso_from_ts(now),
                expires_at=_iso_from_ts(now + float(config.anti_bypass_memory_ttl_s)),
                config=config,
            )

    def _record_denied_effect(
        self,
        *,
        event: CanonicalEvent,
        decision: CanonicalDecision,
        record_id: int,
        risk_level: str,
        recorded_at: str,
        expires_at: str,
        config: DetectionConfig,
    ) -> None:
        envelope = normalize_action_effect(event)
        effect_targets = tuple(target_hashes(envelope))
        effect_families = tuple(artifact_families(envelope))
        if not envelope.effects or (not effect_targets and not effect_families):
            return
        session_id = str(event.session_id or "")
        records = self._denied_effects[session_id]
        compact_capabilities = [
            effect for effect in envelope.effects
            if effect in {
                "filesystem.write",
                "network.fetch",
                "command.exec",
                "package.install",
                "delegated_effect_request",
            }
        ]
        for capability in compact_capabilities:
            records.append(
                DeniedEffectMemoryRecord(
                    event_id=str(event.event_id or ""),
                    record_id=int(record_id or 0),
                    session_id_hash=_sha256(session_id),
                    capability=capability,
                    effect_hash=effect_hash(envelope),
                    target_hashes=effect_targets,
                    artifact_families=effect_families,
                    policy_id=str(decision.policy_id or ""),
                    policy_version=str(decision.policy_version or ""),
                    decision="block",
                    risk_level=risk_level,
                    occurred_at=str(event.occurred_at or ""),
                    recorded_at=recorded_at,
                    expires_at=expires_at,
                )
            )
        while len(records) > config.anti_bypass_memory_max_records_per_session:
            records.popleft()
            self.memory_evictions += 1

    def _record_pending_effect_hold(
        self,
        *,
        event: CanonicalEvent,
        decision: CanonicalDecision,
        record_id: int,
        risk_level: str,
        recorded_at: str,
        expires_at: str,
        config: DetectionConfig,
        hold_reason: str = "operator_review",
    ) -> None:
        envelope = normalize_action_effect(event)
        effect_targets = tuple(target_hashes(envelope))
        effect_families = tuple(artifact_families(envelope))
        if not envelope.effects or (not effect_targets and not effect_families):
            return
        session_id = str(event.session_id or "")
        records = self._pending_effect_holds[session_id]
        compact_capabilities = [
            effect for effect in envelope.effects
            if effect in {
                "filesystem.write",
                "network.fetch",
                "command.exec",
                "package.install",
                "delegated_effect_request",
            }
        ]
        for capability in compact_capabilities:
            records.append(
                PendingEffectHoldRecord(
                    event_id=str(event.event_id or ""),
                    record_id=int(record_id or 0),
                    session_id_hash=_sha256(session_id),
                    capability=capability,
                    effect_hash=effect_hash(envelope),
                    target_hashes=effect_targets,
                    artifact_families=effect_families,
                    policy_id=str(decision.policy_id or ""),
                    decision="defer",
                    risk_level=risk_level,
                    occurred_at=str(event.occurred_at or ""),
                    recorded_at=recorded_at,
                    expires_at=expires_at,
                    hold_reason=hold_reason,
                    contextual_effect_hash=(
                        _contextual_pending_hash(envelope)
                        if hold_reason == "contextual_review"
                        else None
                    ),
                )
            )
        while len(records) > config.anti_bypass_memory_max_records_per_session:
            records.popleft()
            self.memory_evictions += 1

    def _evict(self, session_id: str, config: DetectionConfig) -> None:
        records = self._records.get(session_id)
        now = time.time()
        if records:
            while records and _parse_iso(records[0].expires_at) <= now:
                records.popleft()
                self.memory_evictions += 1
        denied_effects = self._denied_effects.get(session_id)
        if denied_effects:
            while denied_effects and _parse_iso(denied_effects[0].expires_at) <= now:
                denied_effects.popleft()
                self.memory_evictions += 1
        pending_effect_holds = self._pending_effect_holds.get(session_id)
        if pending_effect_holds:
            while pending_effect_holds and _parse_iso(pending_effect_holds[0].expires_at) <= now:
                pending_effect_holds.popleft()
                self.memory_evictions += 1

    def _match_denied_effect(
        self,
        event: CanonicalEvent,
        session_id: str,
        config: DetectionConfig,
    ) -> AntiBypassMatch | None:
        current_effect = normalize_action_effect(event)
        current_targets = set(target_hashes(current_effect))
        current_families = set(artifact_families(current_effect))
        current_capabilities = set(current_effect.effects)
        if not current_capabilities:
            return None

        for prior in reversed(self._denied_effects.get(session_id, ())):
            if prior.capability not in current_capabilities:
                continue
            target_match = bool(current_targets.intersection(prior.target_hashes))
            family_match = bool(current_families.intersection(prior.artifact_families))
            if not target_match and not family_match:
                continue
            reason_codes = ["denied_effect_repeat"]
            if family_match and not target_match:
                reason_codes.append("artifact_family_match")
            action = "block"
            if family_match and not target_match and config.mode in {"normal", "permissive"}:
                action = "defer"
            return AntiBypassMatch(
                match_type="denied_effect_repeat",
                action=action,
                prior_event_id=prior.event_id,
                prior_record_id=prior.record_id,
                prior_policy_id=prior.policy_id,
                prior_risk_level=prior.risk_level,
                raw_payload_hash=current_effect.raw_payload_hash or "",
                normalized_action_fingerprint=current_effect.canonical_argv_hash or "",
                destructive_intent_fingerprint=effect_hash(current_effect),
                destructive_intent_label=prior.capability,
                destructive_operation_category=prior.capability,
                match_reason="effect_target" if target_match else "artifact_family",
                similarity_mode="effect_hash",
                reason_codes=tuple(reason_codes),
                evidence_categories=(prior.capability,),
            )
        return None

    def _match_pending_effect_hold(
        self,
        event: CanonicalEvent,
        session_id: str,
    ) -> AntiBypassMatch | None:
        current_effect = normalize_action_effect(event)
        current_targets = set(target_hashes(current_effect))
        current_families = set(artifact_families(current_effect))
        current_capabilities = set(current_effect.effects)
        if not current_capabilities:
            return None

        for prior in reversed(self._pending_effect_holds.get(session_id, ())):
            if prior.capability not in current_capabilities:
                continue
            if prior.hold_reason == "contextual_review":
                current_hash = _contextual_pending_hash(current_effect)
                if prior.contextual_effect_hash != current_hash:
                    continue
                return AntiBypassMatch(
                    match_type="contextual_pending_effect_repeat",
                    action="defer",
                    prior_event_id=prior.event_id,
                    prior_record_id=prior.record_id,
                    prior_policy_id=prior.policy_id,
                    prior_risk_level=prior.risk_level,
                    raw_payload_hash=current_effect.raw_payload_hash or "",
                    normalized_action_fingerprint=current_effect.canonical_argv_hash or "",
                    destructive_intent_fingerprint=current_hash,
                    destructive_intent_label=prior.capability,
                    destructive_operation_category=prior.capability,
                    match_reason="contextual_effect_hash",
                    similarity_mode="contextual_pending_exact_effect",
                    reason_codes=("contextual_pending_effect_repeat",),
                    evidence_categories=(prior.capability,),
                )
            target_match = bool(current_targets.intersection(prior.target_hashes))
            family_match = bool(current_families.intersection(prior.artifact_families))
            if not target_match and not family_match:
                continue
            reason_codes = ["pending_effect_equivalent"]
            if family_match and not target_match:
                reason_codes.append("artifact_family_match")
            return AntiBypassMatch(
                match_type="pending_effect_equivalent",
                action="defer",
                prior_event_id=prior.event_id,
                prior_record_id=prior.record_id,
                prior_policy_id=prior.policy_id,
                prior_risk_level=prior.risk_level,
                raw_payload_hash=current_effect.raw_payload_hash or "",
                normalized_action_fingerprint=current_effect.canonical_argv_hash or "",
                destructive_intent_fingerprint=effect_hash(current_effect),
                destructive_intent_label=prior.capability,
                destructive_operation_category=prior.capability,
                match_reason="effect_target" if target_match else "artifact_family",
                similarity_mode="pending_effect_hold",
                reason_codes=tuple(reason_codes),
                evidence_categories=(prior.capability,),
            )
        return None


def _eligible_prior(record: AntiBypassRecord, config: DetectionConfig) -> bool:
    return (
        record.decision in set(config.anti_bypass_prior_verdicts)
        and _risk_rank(record.risk_level) >= _risk_rank(config.anti_bypass_min_prior_risk)
    )


def _fingerprints_for_event(event: CanonicalEvent) -> _EventFingerprints:
    raw_projection = {
        "event_type": event.event_type.value,
        "tool_name": str(event.tool_name or ""),
        "payload": _canonical_payload_projection(event.payload or {}),
    }
    normalized_text = _normalized_action_text(event)
    normalized_feature_hashes = frozenset(_sha256(token) for token in _tokenize(normalized_text))
    destructive_intent = _destructive_intent_label(normalized_text)
    destructive_operation = _destructive_operation_category(normalized_text, destructive_intent)
    return _EventFingerprints(
        raw_payload_hash=_sha256_json(raw_projection),
        normalized_action_fingerprint=_sha256(normalized_text),
        destructive_intent_label=destructive_intent,
        destructive_intent_fingerprint=_sha256(destructive_intent),
        destructive_operation_category=destructive_operation,
        normalized_feature_hashes=normalized_feature_hashes,
        normalized_text=normalized_text,
        command_head_category=_command_head_category(normalized_text),
        target_scope_categories=frozenset(_scope_categories(normalized_text)),
    )


def _contextual_pending_hash(envelope) -> str:
    return _sha256_json({
        "effect_hash": effect_hash(envelope),
        "canonical_argv_hash": envelope.canonical_argv_hash,
        "raw_payload_hash": envelope.raw_payload_hash,
        "effects": list(envelope.effects),
        "targets": [
            {
                "path_hash": target.path_hash,
                "path_role": target.path_role,
            }
            for target in envelope.targets
        ],
    })


def _canonical_payload_projection(payload: dict[str, Any]) -> Any:
    def project(value: Any) -> Any:
        if isinstance(value, dict):
            return {str(k): project(v) for k, v in sorted(value.items(), key=lambda item: str(item[0]))}
        if isinstance(value, (list, tuple)):
            return [project(v) for v in value]
        if isinstance(value, (str, int, float, bool)) or value is None:
            return value
        return str(type(value).__name__)

    return project(payload)


def _normalized_action_text(event: CanonicalEvent) -> str:
    payload = event.payload or {}
    command = _first_text(payload, ("command", "cmd", "shell_command", "script", "code", "input"))
    if command:
        return normalize_shell_command_head(command).strip().lower()
    projected = {
        "tool_name": str(event.tool_name or ""),
        "payload_keys": sorted(str(key) for key in payload.keys()),
        "action": _first_text(payload, ("action", "operation", "name", "path", "target_path", "file_path")),
    }
    return json.dumps(projected, sort_keys=True, separators=(",", ":")).lower()


def _first_text(payload: dict[str, Any], keys: tuple[str, ...]) -> str:
    for key in keys:
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            return value
    return ""


def _destructive_intent_label(normalized_text: str) -> str:
    tokens = _tokenize(normalized_text)
    head = tokens[0] if tokens else ""
    if head in _DESTRUCTIVE_HEADS:
        return head
    if _contains_python_delete_api(tokens):
        return "destructive-generic"
    if any(token in {"delete", "remove", "destroy", "exfiltrate", "download", "upload", "unlink", "truncate"} for token in tokens):
        return "destructive-generic"
    return "non-destructive"


def _contains_python_delete_api(tokens: list[str]) -> bool:
    token_set = set(tokens)
    return (
        {"shutil", "rmtree"} <= token_set
        or "unlink" in token_set
        or "rmdir" in token_set
        or {"os", "remove"} <= token_set
        or {"os", "unlink"} <= token_set
        or {"os", "rmdir"} <= token_set
        or "truncate" in token_set
        or "ftruncate" in token_set
    )


def _destructive_operation_category(normalized_text: str, destructive_intent: str) -> str:
    tokens = _tokenize(normalized_text)
    token_set = set(tokens)
    if destructive_intent == "non-destructive":
        return "none"
    if destructive_intent in {"curl", "wget", "scp", "rsync", "ssh"}:
        return "network_transfer"
    if destructive_intent == "git":
        return "vcs_operation"
    if destructive_intent in {"chmod", "chown"}:
        return "permission_change"
    if destructive_intent in {"dd", "mkfs", "shred"}:
        return "destructive_storage"
    if destructive_intent in {"rm", "rmdir", "unlink"}:
        if destructive_intent == "rm" and ("rf" in token_set or "r" in token_set):
            return "delete_tree"
        if destructive_intent == "rmdir":
            return "delete_tree"
        return "delete_path"
    if {"shutil", "rmtree"} <= token_set:
        return "delete_tree"
    if "rmdir" in token_set:
        return "delete_tree"
    if "unlink" in token_set or {"os", "remove"} <= token_set:
        return "delete_path"
    if "truncate" in token_set or "ftruncate" in token_set:
        return "truncate_path"
    return "destructive_generic"


def _weak_similarity_signals(
    prior: AntiBypassRecord,
    current: _EventFingerprints,
    similarity: float,
    config: DetectionConfig,
) -> tuple[list[str], list[str]]:
    reason_codes: list[str] = []
    evidence_categories: list[str] = []
    if similarity >= config.anti_bypass_llm_candidate_threshold:
        reason_codes.append("candidate_feature_similarity")
        evidence_categories.append("feature_overlap")
    if (
        prior.destructive_intent_label != "non-destructive"
        and current.destructive_intent_label != "non-destructive"
    ):
        reason_codes.append("destructive_label_overlap")
        evidence_categories.append("operation_overlap")
    if prior.destructive_intent_label == current.destructive_intent_label:
        reason_codes.append("intent_label_match")
        evidence_categories.append("intent_label")
    if (
        prior.destructive_operation_category != "none"
        and _same_destructive_operation_family(
            prior.destructive_operation_category,
            current.destructive_operation_category,
        )
    ):
        reason_codes.append("operation_category_match")
        evidence_categories.append("operation_overlap")
    prior_scope = set(_record_scope_categories(prior))
    current_scope = set(current.target_scope_categories)
    if prior_scope and current_scope and prior_scope & current_scope:
        reason_codes.append("target_scope_overlap")
        evidence_categories.append("scope_overlap")
    return reason_codes, list(dict.fromkeys(evidence_categories))


def _llm_candidate_admissible(reason_codes: list[str]) -> bool:
    unique_reasons = set(reason_codes)
    if len(unique_reasons) < 2:
        return False
    if unique_reasons == {"target_scope_overlap"}:
        return False
    return True


def _semantic_capsule(
    *,
    prior: AntiBypassRecord,
    current: _EventFingerprints,
    current_tool_name: str,
    similarity: float,
    reason_codes: list[str],
    evidence_categories: list[str],
) -> dict[str, Any]:
    prior_scope = set(_record_scope_categories(prior))
    current_scope = set(current.target_scope_categories)
    prior_features = set(prior.normalized_feature_hashes)
    current_features = set(current.normalized_feature_hashes)
    return {
        "prior": {
            "record_id": prior.record_id,
            "risk_level": prior.risk_level,
            "decision": prior.decision,
            "destructive_intent_label": prior.destructive_intent_label,
            "destructive_operation_category": prior.destructive_operation_category,
            "target_scope_categories": sorted(prior_scope),
        },
        "current": {
            "tool_category": _tool_category(current_tool_name),
            "destructive_intent_label": current.destructive_intent_label,
            "destructive_operation_category": current.destructive_operation_category,
            "command_head_category": current.command_head_category,
            "target_scope_categories": sorted(current.target_scope_categories),
        },
        "overlap": {
            "feature_count": len(prior_features & current_features),
            "scope_categories": sorted(prior_scope & current_scope),
            "same_operation_category": _same_destructive_operation_family(
                prior.destructive_operation_category,
                current.destructive_operation_category,
            ),
            "same_intent_label": prior.destructive_intent_label == current.destructive_intent_label,
        },
        "similarity_score": round(similarity, 4),
        "reason_codes": list(reason_codes),
        "evidence_categories": list(evidence_categories),
    }


def _record_scope_categories(record: AntiBypassRecord) -> frozenset[str]:
    return frozenset(record.target_scope_categories)


def _scope_categories(text: str) -> list[str]:
    lowered = text.lower()
    categories: list[str] = []
    if "/tmp" in lowered or " tmp " in f" {lowered} ":
        categories.append("tmp_path")
    if "project" in lowered or "workspace" in lowered:
        categories.append("project_workspace")
    if "cache" in lowered:
        categories.append("cache_path")
    if "secret" in lowered or "token" in lowered or "authorization" in lowered:
        categories.append("credential_related")
    if any(token in _tokenize(lowered) for token in ("target", "path", "file")):
        categories.append("file_target")
    return list(dict.fromkeys(categories))


def _has_cross_tool_label_support(
    prior: AntiBypassRecord,
    current: _EventFingerprints,
    *,
    similarity: float | None,
    config: DetectionConfig,
) -> bool:
    if (
        prior.destructive_operation_category != "none"
        and _same_destructive_operation_family(
            prior.destructive_operation_category,
            current.destructive_operation_category,
        )
        and set(_record_scope_categories(prior)) & set(current.target_scope_categories)
    ):
        return True
    if set(_record_scope_categories(prior)) & set(current.target_scope_categories):
        return True
    if similarity is not None and similarity >= config.anti_bypass_similarity_threshold:
        return True
    return False


def _same_destructive_operation_family(left: str, right: str) -> bool:
    if left == "none" or right == "none":
        return False
    if left == right:
        return True
    delete_family = {"delete_tree", "delete_path"}
    return left in delete_family and right in delete_family


def _tool_category(tool_name: str) -> str:
    value = str(tool_name or "").strip().lower()
    if value in {"bash", "sh", "zsh"}:
        return "shell"
    if value.startswith("python"):
        return "python"
    if value:
        return "tool"
    return "unknown"


def _command_head_category(text: str) -> str:
    tokens = _tokenize(text)
    if not tokens:
        return "unknown"
    head = tokens[0]
    if head in _DESTRUCTIVE_HEADS:
        return f"destructive:{head}"
    if head.startswith("python"):
        return "script:python"
    if head in {"bash", "sh", "zsh"}:
        return "script:shell"
    return f"tool:{head}"


def _tokenize(text: str) -> list[str]:
    return [token for token in "".join(ch if ch.isalnum() else " " for ch in text.lower()).split() if token]


def _jaccard(left: frozenset[str], right: frozenset[str]) -> float:
    if not left or not right:
        return 0.0
    return len(left & right) / len(left | right)


def _risk_rank(value: str) -> int:
    return _RISK_ORDER.get(str(value).lower(), 0)


def _sha256(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()


def _sha256_json(value: Any) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return _sha256(payload)


def _iso_from_ts(ts: float) -> str:
    return datetime.fromtimestamp(ts, timezone.utc).isoformat()


def _parse_iso(value: str) -> float:
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
    except (TypeError, ValueError):
        return 0.0
