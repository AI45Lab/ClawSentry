"""In-memory live session view for current-process metrics endpoints."""

from __future__ import annotations

import copy
import time
from collections import defaultdict, deque
from typing import Any, Optional

from .models import adapter_effect_result_summary, decision_effect_summary, utc_now_iso
from .trajectory_store import _parse_iso_timestamp

_RISK_LEVEL_RANK: dict[str, int] = {"low": 0, "medium": 1, "high": 2, "critical": 3}
SESSION_RISK_EWMA_ALPHA = 0.3
POST_ACTION_SCORE_EWMA_ALPHA = 0.3
RISK_VELOCITY_DELTA_THRESHOLD = 0.25
DISPLAY_SCORE_RANGE = [0.0, 3.0]
DISPLAY_SCORE_SEMANTICS = {
    "range": DISPLAY_SCORE_RANGE,
    "zero_with_no_events": "no_data_not_confirmed_low_risk",
    "decision_affecting": False,
}
POST_ACTION_SCORE_SEMANTICS = {
    "range": DISPLAY_SCORE_RANGE,
    "zero_with_no_events": "no_post_action_data_not_confirmed_low_risk",
    "decision_affecting": False,
    "aggregation": "latest, sum, avg, and EWMA are separate from session_risk_ewma; do not add raw channels",
}


def _risk_rank(risk_level: Optional[str]) -> int:
    return _RISK_LEVEL_RANK.get(str(risk_level or "low").lower(), 0)


def _safe_float(value: Any) -> float:
    if isinstance(value, bool):
        return 0.0
    try:
        return float(value or 0.0)
    except (TypeError, ValueError):
        return 0.0


def _risk_velocity_from_scores(scores: list[float]) -> str:
    if len(scores) < 2:
        return "unknown"
    delta = scores[-1] - scores[0]
    if delta > RISK_VELOCITY_DELTA_THRESHOLD:
        return "up"
    if delta < -RISK_VELOCITY_DELTA_THRESHOLD:
        return "down"
    return "flat"


def _new_io_metric_bucket() -> dict[str, float | int]:
    return {
        "calls": 0,
        "total_seconds": 0.0,
        "last_seconds": 0.0,
        "max_seconds": 0.0,
    }


def _observe_io_metric(bucket: dict[str, float | int], elapsed_seconds: float) -> None:
    elapsed = max(0.0, float(elapsed_seconds))
    bucket["calls"] = int(bucket["calls"]) + 1
    bucket["total_seconds"] = float(bucket["total_seconds"]) + elapsed
    bucket["last_seconds"] = elapsed
    bucket["max_seconds"] = max(float(bucket["max_seconds"]), elapsed)


def _snapshot_io_metric(bucket: dict[str, float | int]) -> dict[str, float | int]:
    return {
        "calls": int(bucket["calls"]),
        "total_seconds": round(float(bucket["total_seconds"]), 6),
        "last_seconds": round(float(bucket["last_seconds"]), 6),
        "max_seconds": round(float(bucket["max_seconds"]), 6),
    }


def _clean_text(value: Any) -> Optional[str]:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _clean_int(value: Any) -> Optional[int]:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        text = value.strip()
        if text.isdigit():
            return int(text)
    return None


def _normalize_compat_event_type(value: Any) -> Optional[str]:
    raw = _clean_text(value)
    if raw is None:
        return None
    lowered = raw.lower()
    if lowered.startswith("compat:"):
        lowered = lowered.split(":", 1)[1]
    aliases = {
        "contextperception": "context_perception",
        "context_perception": "context_perception",
        "memoryrecall": "memory_recall",
        "memory_recall": "memory_recall",
        "planning": "planning",
        "reasoning": "reasoning",
        "intentdetection": "intent_detection",
        "intent_detection": "intent_detection",
    }
    return aliases.get(lowered)


def _lookup_nested(mapping: Any, *path: str) -> Any:
    current = mapping
    for segment in path:
        if not isinstance(current, dict):
            return None
        current = current.get(segment)
    return current


def _first_text(*values: Any) -> Optional[str]:
    for value in values:
        cleaned = _clean_text(value)
        if cleaned is not None:
            return cleaned
    return None


def _first_int(*values: Any) -> Optional[int]:
    for value in values:
        cleaned = _clean_int(value)
        if cleaned is not None:
            return cleaned
    return None


def _compact_operator_value(value: Any) -> Any:
    if value is None:
        return None
    if isinstance(value, str):
        cleaned = value.strip()
        return cleaned or None
    if isinstance(value, dict):
        compact_dict = {
            str(key): compact_value
            for key, raw_value in value.items()
            if (compact_value := _compact_operator_value(raw_value)) is not None
        }
        return compact_dict or None
    if isinstance(value, (list, tuple)):
        compact_list = [
            compact_value
            for raw_value in value
            if (compact_value := _compact_operator_value(raw_value)) is not None
        ]
        return compact_list or None
    return copy.deepcopy(value)


def _first_operator_value(*values: Any) -> Any:
    for value in values:
        compact_value = _compact_operator_value(value)
        if compact_value is not None:
            return compact_value
    return None


def _selected_summary(fields: dict[str, Any]) -> Optional[dict[str, Any]]:
    compact = {
        key: value
        for key, value in fields.items()
        if value is not None
    }
    return compact or None


def build_compatibility_evidence_summary(event: Any) -> Optional[dict[str, Any]]:
    if not isinstance(event, dict):
        return None

    payload = event.get("payload")
    if not isinstance(payload, dict):
        return None

    payload_args = payload.get("arguments")
    if not isinstance(payload_args, dict):
        payload_args = {}

    meta = payload.get("_clawsentry_meta")
    if not isinstance(meta, dict):
        meta = {}
    compat = meta.get("ahp_compat")
    if not isinstance(compat, dict):
        compat = {}

    compat_event_type = _normalize_compat_event_type(
        compat.get("raw_event_type") or event.get("event_subtype")
    )
    if compat_event_type is None:
        return None

    compat_context = compat.get("context")
    if not isinstance(compat_context, dict):
        compat_context = {}
    compat_metadata = compat.get("metadata")
    if not isinstance(compat_metadata, dict):
        compat_metadata = {}

    if compat_event_type == "context_perception":
        compat_summary = {
            "intent": _first_text(
                payload.get("intent"),
                payload_args.get("intent"),
                compat_context.get("intent"),
                _lookup_nested(compat_context, "session", "intent"),
            ),
            "target": _first_text(
                payload.get("target"),
                payload_args.get("target"),
                compat.get("target"),
            ),
            "workspace": _first_text(
                payload.get("cwd"),
                payload.get("working_directory"),
                payload.get("workspace_root"),
                payload_args.get("cwd"),
                payload_args.get("working_directory"),
                payload_args.get("workspace_root"),
                _lookup_nested(compat_context, "session", "workspace"),
                _lookup_nested(compat_context, "session", "working_directory"),
                compat_context.get("workspace"),
                compat_context.get("working_directory"),
            ),
            "query": _first_text(
                payload.get("query"),
                payload_args.get("query"),
                compat.get("query"),
            ),
        }
    elif compat_event_type == "memory_recall":
        compat_summary = {
            "query": _first_text(
                payload.get("query"),
                payload_args.get("query"),
                compat.get("query"),
            ),
            "memory_type": _first_text(
                payload.get("memory_type"),
                payload_args.get("memory_type"),
                compat_metadata.get("memory_type"),
            ),
            "max_results": _first_int(
                payload.get("max_results"),
                payload_args.get("max_results"),
                compat_metadata.get("max_results"),
            ),
            "working_directory": _first_text(
                payload.get("working_directory"),
                payload.get("cwd"),
                payload.get("workspace_root"),
                payload_args.get("working_directory"),
                payload_args.get("cwd"),
                payload_args.get("workspace_root"),
                _lookup_nested(compat_context, "session", "working_directory"),
                _lookup_nested(compat_context, "session", "workspace"),
                compat_context.get("working_directory"),
                compat_context.get("workspace"),
            ),
        }
    elif compat_event_type == "planning":
        planning_summary = _selected_summary({
            "task": _first_text(
                payload.get("task"),
                payload_args.get("task"),
                compat.get("task"),
            ),
            "strategy": _first_operator_value(
                payload.get("strategy"),
                payload_args.get("strategy"),
                compat.get("strategy"),
            ),
            "constraints": _first_operator_value(
                payload.get("constraints"),
                payload_args.get("constraints"),
                compat.get("constraints"),
            ),
        })
        if planning_summary is None:
            return None
        return {
            "compat_event_type": compat_event_type,
            "planning_summary": planning_summary,
        }
    elif compat_event_type == "reasoning":
        reasoning_summary = _selected_summary({
            "reasoning_type": _first_text(
                payload.get("reasoning_type"),
                payload_args.get("reasoning_type"),
                compat.get("reasoning_type"),
            ),
            "problem_statement": _first_text(
                payload.get("problem_statement"),
                payload_args.get("problem_statement"),
                compat.get("problem_statement"),
            ),
            "hints": _first_operator_value(
                payload.get("hints"),
                payload_args.get("hints"),
                compat.get("hints"),
            ),
        })
        if reasoning_summary is None:
            return None
        return {
            "compat_event_type": compat_event_type,
            "reasoning_summary": reasoning_summary,
        }
    elif compat_event_type == "intent_detection":
        intent_summary = _selected_summary({
            "detected_intent": _first_text(
                payload.get("detected_intent"),
                payload_args.get("detected_intent"),
                compat.get("detected_intent"),
            ),
            "target_hints": _first_operator_value(
                payload.get("target_hints"),
                payload_args.get("target_hints"),
                compat.get("target_hints"),
            ),
            "language_hint": _first_text(
                payload.get("language_hint"),
                payload_args.get("language_hint"),
                compat.get("language_hint"),
            ),
        })
        if intent_summary is None:
            return None
        return {
            "compat_event_type": compat_event_type,
            "intent_summary": intent_summary,
        }
    else:
        return None

    compact_summary = {
        key: value
        for key, value in compat_summary.items()
        if value is not None
    }
    if not compact_summary:
        return None

    return {
        "compat_event_type": compat_event_type,
        "compat_summary": compact_summary,
    }


def compact_evidence_summary(summary: Any) -> Optional[dict[str, Any]]:
    if not isinstance(summary, dict):
        return None

    compact: dict[str, Any] = {}

    retained_sources = summary.get("retained_sources")
    if isinstance(retained_sources, list):
        compact_sources = [
            str(source).strip()
            for source in retained_sources
            if str(source).strip()
        ]
        if compact_sources:
            compact["retained_sources"] = compact_sources

    tool_calls = summary.get("tool_calls")
    if isinstance(tool_calls, list):
        compact["tool_calls_count"] = len(tool_calls)
    else:
        tool_calls_count = summary.get("tool_calls_count")
        if isinstance(tool_calls_count, int):
            compact["tool_calls_count"] = tool_calls_count

    toolkit_budget_mode = str(summary.get("toolkit_budget_mode") or "").strip()
    if toolkit_budget_mode:
        compact["toolkit_budget_mode"] = toolkit_budget_mode

    toolkit_budget_cap = summary.get("toolkit_budget_cap")
    if isinstance(toolkit_budget_cap, int):
        compact["toolkit_budget_cap"] = toolkit_budget_cap

    toolkit_calls_remaining = summary.get("toolkit_calls_remaining")
    if isinstance(toolkit_calls_remaining, int):
        compact["toolkit_calls_remaining"] = toolkit_calls_remaining
    toolkit_budget_exhausted = summary.get("toolkit_budget_exhausted")
    if isinstance(toolkit_budget_exhausted, bool):
        compact["toolkit_budget_exhausted"] = toolkit_budget_exhausted
    elif isinstance(toolkit_budget_cap, int) and toolkit_budget_cap > 0 and isinstance(toolkit_calls_remaining, int):
        compact["toolkit_budget_exhausted"] = toolkit_calls_remaining <= 0

    compat_event_type = _normalize_compat_event_type(summary.get("compat_event_type"))
    compat_summary = summary.get("compat_summary")
    if compat_event_type is not None and isinstance(compat_summary, dict):
        compact_compat_summary = {
            key: value
            for key, value in compat_summary.items()
            if value is not None and value != ""
        }
        if compact_compat_summary:
            compact["compat_event_type"] = compat_event_type
            compact["compat_summary"] = compact_compat_summary

    cognition_summary_keys = {
        "planning": "planning_summary",
        "reasoning": "reasoning_summary",
        "intent_detection": "intent_summary",
    }
    summary_key = cognition_summary_keys.get(str(compat_event_type or ""))
    if summary_key is not None and isinstance(summary.get(summary_key), dict):
        compact_cognition_summary = _compact_operator_value(summary.get(summary_key))
        if isinstance(compact_cognition_summary, dict) and compact_cognition_summary:
            compact["compat_event_type"] = compat_event_type
            compact[summary_key] = compact_cognition_summary

    return compact or None


class SessionRegistry:
    """In-memory live session view for current-process metrics endpoints."""

    DEFAULT_MAX_SESSIONS = 10_000
    DEFAULT_MAX_TIMELINE_PER_SESSION = 1000

    def __init__(
        self,
        max_sessions: int = DEFAULT_MAX_SESSIONS,
        max_timeline_per_session: int = DEFAULT_MAX_TIMELINE_PER_SESSION,
        ) -> None:
        self.max_sessions = max(max_sessions, 1)
        self.max_timeline_per_session = max(max_timeline_per_session, 1)
        self._sessions: dict[str, dict[str, Any]] = {}
        self._io_metrics = {
            "list_sessions": _new_io_metric_bucket(),
            "get_session_risk": _new_io_metric_bucket(),
        }

    def io_metrics_snapshot(self) -> dict[str, dict[str, float | int]]:
        return {
            name: _snapshot_io_metric(bucket)
            for name, bucket in self._io_metrics.items()
        }

    def _evict_if_needed(self) -> None:
        while len(self._sessions) > self.max_sessions:
            oldest_session_id = next(iter(self._sessions))
            del self._sessions[oldest_session_id]

    def get_current_risk(self, session_id: str) -> Optional[str]:
        """Return current risk level for session_id, or None if not tracked yet."""
        session = self._sessions.get(session_id)
        return str(session["current_risk_level"]) if session is not None else None

    def get_session_stats(self, session_id: str) -> dict[str, Any]:
        """Return a copy of session stats for alert generation."""
        return dict(self._sessions.get(session_id, {}))

    @staticmethod
    def _decrement_counter(counter: defaultdict[int] | defaultdict[str, int], key: str) -> None:
        if key not in counter:
            return
        counter[key] -= 1
        if counter[key] <= 0:
            del counter[key]

    @staticmethod
    def _compact_evidence_summary(summary: Any) -> Optional[dict[str, Any]]:
        return compact_evidence_summary(summary)

    @staticmethod
    def _timeline_display_metrics(
        timeline: list[dict[str, Any]],
        *,
        alpha: float = SESSION_RISK_EWMA_ALPHA,
    ) -> dict[str, Any]:
        scores = [_safe_float(item.get("composite_score")) for item in timeline]
        points = [_risk_rank(str(item.get("risk_level") or "low")) for item in timeline]

        if not scores:
            latest_score = 0.0
            risk_sum = 0.0
            ewma = 0.0
            velocity = "unknown"
        else:
            latest_score = scores[-1]
            risk_sum = sum(scores)
            ewma = scores[0]
            for score in scores[1:]:
                ewma = (alpha * score) + ((1.0 - alpha) * ewma)
            velocity = _risk_velocity_from_scores(scores)

        return {
            "latest_composite_score": latest_score,
            "session_risk_sum": risk_sum,
            "session_risk_ewma": ewma,
            "risk_points_sum": sum(points),
            "risk_velocity": velocity,
        }

    @classmethod
    def _window_risk_summary(
        cls,
        timeline: list[dict[str, Any]],
        *,
        window_seconds: Optional[int],
    ) -> dict[str, Any]:
        metrics = cls._timeline_display_metrics(timeline)
        high_or_critical_count = sum(
            1 for item in timeline
            if _risk_rank(str(item.get("risk_level") or "low")) >= _risk_rank("high")
        )
        return {
            "window_seconds": window_seconds,
            "generated_at": utc_now_iso(),
            "event_count": len(timeline),
            "high_or_critical_count": high_or_critical_count,
            "latest_composite_score": metrics["latest_composite_score"],
            "session_risk_sum": metrics["session_risk_sum"],
            "session_risk_ewma": metrics["session_risk_ewma"],
            "risk_points_sum": metrics["risk_points_sum"],
            "risk_velocity": metrics["risk_velocity"],
            "score_range": list(DISPLAY_SCORE_RANGE),
            "score_semantics": dict(DISPLAY_SCORE_SEMANTICS),
            "decision_affecting": False,
        }

    @classmethod
    def _session_display_metrics(
        cls,
        session: dict[str, Any],
        *,
        window_timeline: Optional[list[dict[str, Any]]] = None,
        window_seconds: Optional[int] = None,
    ) -> dict[str, Any]:
        timeline = [
            item for item in list(session.get("risk_timeline") or [])
            if isinstance(item, dict)
        ]
        metrics = cls._timeline_display_metrics(timeline)
        metrics["window_risk_summary"] = cls._window_risk_summary(
            window_timeline if window_timeline is not None else timeline,
            window_seconds=window_seconds,
        )
        return metrics

    @staticmethod
    def _post_action_score_metrics(
        timeline: list[dict[str, Any]],
        *,
        alpha: float = POST_ACTION_SCORE_EWMA_ALPHA,
    ) -> dict[str, Any]:
        scores = [_safe_float(item.get("score")) for item in timeline]
        if not scores:
            return {
                "latest_post_action_score": 0.0,
                "post_action_score_sum": 0.0,
                "post_action_score_avg": 0.0,
                "post_action_score_ewma": 0.0,
                "post_action_event_count": 0,
            }

        ewma = scores[0]
        for score in scores[1:]:
            ewma = (alpha * score) + ((1.0 - alpha) * ewma)
        score_sum = sum(scores)
        return {
            "latest_post_action_score": scores[-1],
            "post_action_score_sum": score_sum,
            "post_action_score_avg": score_sum / len(scores),
            "post_action_score_ewma": ewma,
            "post_action_event_count": len(scores),
        }

    @classmethod
    def _post_action_score_summary(
        cls,
        timeline: list[dict[str, Any]],
        *,
        window_seconds: Optional[int],
    ) -> dict[str, Any]:
        metrics = cls._post_action_score_metrics(timeline)
        return {
            "window_seconds": window_seconds,
            "generated_at": utc_now_iso(),
            "event_count": metrics["post_action_event_count"],
            "latest_post_action_score": round(metrics["latest_post_action_score"], 4),
            "post_action_score_sum": round(metrics["post_action_score_sum"], 4),
            "post_action_score_avg": round(metrics["post_action_score_avg"], 4),
            "post_action_score_ewma": round(metrics["post_action_score_ewma"], 4),
            "score_range": list(DISPLAY_SCORE_RANGE),
            "score_semantics": dict(POST_ACTION_SCORE_SEMANTICS),
            "decision_affecting": False,
        }

    @staticmethod
    def _latest_session_annotations(session: dict[str, Any]) -> dict[str, Any]:
        annotations: dict[str, Any] = {}

        evidence_summary = session.get("latest_evidence_summary")
        if evidence_summary is None:
            timeline = session.get("risk_timeline")
            if timeline:
                latest_item = timeline[-1]
                if isinstance(latest_item, dict):
                    evidence_summary = latest_item.get("evidence_summary")
        if evidence_summary is not None:
            annotations["evidence_summary"] = dict(evidence_summary)

        l3_fields = (
            ("l3_state", session.get("latest_l3_state")),
            ("l3_reason", session.get("latest_l3_reason")),
            ("l3_reason_code", session.get("latest_l3_reason_code")),
        )
        if not any(value is not None for _, value in l3_fields):
            timeline = session.get("risk_timeline")
            if timeline:
                latest_item = timeline[-1]
                if isinstance(latest_item, dict):
                    l3_fields = (
                        ("l3_state", latest_item.get("l3_state")),
                        ("l3_reason", latest_item.get("l3_reason")),
                        ("l3_reason_code", latest_item.get("l3_reason_code")),
                    )

        for key, value in l3_fields:
            if value is not None:
                annotations[key] = str(value)

        approval_fields = (
            ("approval_id", session.get("latest_approval_id")),
            ("approval_kind", session.get("latest_approval_kind")),
            ("approval_state", session.get("latest_approval_state")),
            ("approval_reason", session.get("latest_approval_reason")),
            ("approval_reason_code", session.get("latest_approval_reason_code")),
            ("approval_timeout_s", session.get("latest_approval_timeout_s")),
        )
        if not any(value is not None and value != "" for _, value in approval_fields):
            timeline = session.get("risk_timeline")
            if timeline:
                latest_item = timeline[-1]
                if isinstance(latest_item, dict):
                    approval_fields = (
                        ("approval_id", latest_item.get("approval_id")),
                        ("approval_kind", latest_item.get("approval_kind")),
                        ("approval_state", latest_item.get("approval_state")),
                        ("approval_reason", latest_item.get("approval_reason")),
                        ("approval_reason_code", latest_item.get("approval_reason_code")),
                        ("approval_timeout_s", latest_item.get("approval_timeout_s")),
                    )

        for key, value in approval_fields:
            if value is None or value == "":
                continue
            if key == "approval_timeout_s":
                annotations[key] = float(value)
            else:
                annotations[key] = str(value)

        return annotations

    def record(
        self,
        *,
        event: dict[str, Any],
        decision: dict[str, Any],
        snapshot: dict[str, Any],
        meta: dict[str, Any],
    ) -> None:
        session_id = str(event.get("session_id") or "")
        if not session_id:
            return

        occurred_at = str(event.get("occurred_at") or utc_now_iso())
        occurred_at_ts = _parse_iso_timestamp(occurred_at)
        risk_level = str(snapshot.get("risk_level") or decision.get("risk_level") or "low")
        dimensions = snapshot.get("dimensions") or {}
        tool_name = event.get("tool_name")
        decision_verdict = str(decision.get("decision") or "unknown")
        actual_tier = str(meta.get("actual_tier") or "unknown")
        classified_by = str(snapshot.get("classified_by") or actual_tier or "unknown")
        l3_state = meta.get("l3_state")
        l3_reason = meta.get("l3_reason")
        l3_reason_code = meta.get("l3_reason_code")
        l3_trace_summary = (
            dict(meta.get("l3_trace_summary"))
            if isinstance(meta.get("l3_trace_summary"), dict)
            else None
        )
        approval_id = meta.get("approval_id") or event.get("approval_id")
        approval_kind = meta.get("approval_kind")
        approval_state = meta.get("approval_state")
        approval_reason = meta.get("approval_reason")
        approval_reason_code = meta.get("approval_reason_code")
        approval_timeout_s = meta.get("approval_timeout_s")
        evidence_summary = None
        for source in (meta, event, decision, snapshot):
            evidence_summary = self._compact_evidence_summary(
                source.get("evidence_summary")
            )
            if evidence_summary is not None:
                break
        if evidence_summary is None:
            evidence_summary = build_compatibility_evidence_summary(event)
        record_type = str(meta.get("record_type") or "decision")
        payload = event.get("payload") if isinstance(event.get("payload"), dict) else {}
        workspace_root = str(
            payload.get("cwd")
            or payload.get("working_directory")
            or payload.get("workspace_root")
            or ""
        )
        transcript_path = str(payload.get("transcript_path") or "")

        session = self._sessions.pop(session_id, None)
        if session is None:
            session = {
                "session_id": session_id,
                "agent_id": str(event.get("agent_id") or "unknown"),
                "source_framework": str(event.get("source_framework") or "unknown"),
                "caller_adapter": str(meta.get("caller_adapter") or "unknown"),
                "current_risk_level": "low",
                "cumulative_score": 0,
                "event_count": 0,
                "high_risk_event_count": 0,
                "decision_distribution": defaultdict(int),
                "actual_tier_distribution": defaultdict(int),
                "first_event_at": occurred_at,
                "last_event_at": occurred_at,
                "last_event_ts": occurred_at_ts,
                "d4_accumulation": 0,
                "dimensions_latest": {"d1": 0, "d2": 0, "d3": 0, "d4": 0, "d5": 0},
                "risk_hints_seen": set(),
                "tools_used": set(),
                "latest_evidence_summary": None,
                "latest_l3_state": None,
                "latest_l3_reason": None,
                "latest_l3_reason_code": None,
                "latest_approval_id": None,
                "latest_approval_kind": None,
                "latest_approval_state": None,
                "latest_approval_reason": None,
                "latest_approval_reason_code": None,
                "latest_approval_timeout_s": None,
                "latest_decision_effect_summary": None,
                "latest_adapter_effect_result_summary": None,
                "quarantine": None,
                "risk_timeline": deque(maxlen=self.max_timeline_per_session),
                "post_action_score_timeline": deque(maxlen=self.max_timeline_per_session),
                "workspace_root": "",
                "transcript_path": "",
            }

        session["agent_id"] = str(event.get("agent_id") or session["agent_id"])
        session["source_framework"] = str(event.get("source_framework") or session["source_framework"])
        session["caller_adapter"] = str(meta.get("caller_adapter") or session["caller_adapter"])
        if workspace_root:
            session["workspace_root"] = workspace_root
        if transcript_path:
            session["transcript_path"] = transcript_path
        timeline = session["risk_timeline"]
        timeline_entry = {
            "event_id": str(event.get("event_id") or "unknown"),
            "occurred_at": occurred_at,
            "occurred_at_ts": occurred_at_ts,
            "risk_level": risk_level,
            "composite_score": _safe_float(snapshot.get("composite_score")),
            "tool_name": tool_name,
            "decision": decision_verdict,
            "actual_tier": actual_tier,
            "classified_by": classified_by,
            "l3_state": str(l3_state) if l3_state is not None else None,
            "l3_reason": str(l3_reason) if l3_reason is not None else None,
            "l3_reason_code": str(l3_reason_code) if l3_reason_code is not None else None,
        }
        if approval_id not in (None, ""):
            timeline_entry["approval_id"] = str(approval_id)
        if approval_kind not in (None, ""):
            timeline_entry["approval_kind"] = str(approval_kind)
        if approval_state not in (None, ""):
            timeline_entry["approval_state"] = str(approval_state)
        if approval_reason not in (None, ""):
            timeline_entry["approval_reason"] = str(approval_reason)
        if approval_reason_code not in (None, ""):
            timeline_entry["approval_reason_code"] = str(approval_reason_code)
        if approval_timeout_s is not None:
            timeline_entry["approval_timeout_s"] = float(approval_timeout_s)
        if evidence_summary is not None:
            timeline_entry["evidence_summary"] = evidence_summary
        if l3_trace_summary is not None:
            timeline_entry["l3_trace_summary"] = l3_trace_summary

        effect_summary = decision_effect_summary(decision.get("decision_effects"))
        if effect_summary is not None:
            timeline_entry["decision_effect_summary"] = effect_summary

        if record_type == "decision_resolution":
            matched = None
            for item in reversed(timeline):
                if item.get("event_id") == timeline_entry["event_id"]:
                    matched = item
                    break
            if matched is not None:
                previous_decision = str(matched.get("decision") or "unknown")
                previous_tier = str(matched.get("actual_tier") or "unknown")
                previous_high = _risk_rank(str(matched.get("risk_level") or "low")) >= _risk_rank("high")
                self._decrement_counter(session["decision_distribution"], previous_decision)
                self._decrement_counter(session["actual_tier_distribution"], previous_tier)
                if previous_high and session["high_risk_event_count"] > 0:
                    session["high_risk_event_count"] -= 1
            timeline.append(timeline_entry)
            session["decision_distribution"][decision_verdict] += 1
            session["actual_tier_distribution"][actual_tier] += 1
            if _risk_rank(risk_level) >= _risk_rank("high"):
                session["high_risk_event_count"] += 1
        else:
            session["event_count"] += 1
            session["decision_distribution"][decision_verdict] += 1
            session["actual_tier_distribution"][actual_tier] += 1
            session["d4_accumulation"] = session["d4_accumulation"] + int(dimensions.get("d4") or 0)
            if _risk_rank(risk_level) >= _risk_rank("high"):
                session["high_risk_event_count"] += 1
            if tool_name:
                session["tools_used"].add(str(tool_name))
            for hint in event.get("risk_hints", []) or []:
                session["risk_hints_seen"].add(str(hint))
            timeline.append(timeline_entry)

        if evidence_summary is not None:
            session["latest_evidence_summary"] = evidence_summary
        if l3_state is not None:
            session["latest_l3_state"] = str(l3_state)
        if l3_reason is not None:
            session["latest_l3_reason"] = str(l3_reason)
        if l3_reason_code is not None:
            session["latest_l3_reason_code"] = str(l3_reason_code)
        if approval_id not in (None, ""):
            session["latest_approval_id"] = str(approval_id)
        if approval_kind not in (None, ""):
            session["latest_approval_kind"] = str(approval_kind)
        if approval_state not in (None, ""):
            session["latest_approval_state"] = str(approval_state)
        if approval_reason not in (None, ""):
            session["latest_approval_reason"] = str(approval_reason)
        if approval_reason_code not in (None, ""):
            session["latest_approval_reason_code"] = str(approval_reason_code)
        if approval_timeout_s is not None:
            session["latest_approval_timeout_s"] = float(approval_timeout_s)
        if effect_summary is not None:
            session["latest_decision_effect_summary"] = effect_summary
            if (
                decision_verdict == "block"
                and effect_summary.get("action_scope") == "session"
                and isinstance(effect_summary.get("session_effect"), dict)
            ):
                session["quarantine"] = {
                    "state": "quarantined",
                    "effect_id": effect_summary.get("effect_id"),
                    "mode": effect_summary["session_effect"].get("mode") or "mark_blocked",
                    "reason_code": effect_summary["session_effect"].get("reason_code"),
                    "durability": "volatile",
                    "released_at": None,
                    "released_by": None,
                    "released_reason": None,
                    "updated_at": occurred_at,
                }
        session["current_risk_level"] = risk_level
        if dimensions:
            session["cumulative_score"] = int(snapshot.get("composite_score") or 0)
            dimensions_latest = {
                "d1": int(dimensions.get("d1") or 0),
                "d2": int(dimensions.get("d2") or 0),
                "d3": int(dimensions.get("d3") or 0),
                "d4": int(dimensions.get("d4") or 0),
                "d5": int(dimensions.get("d5") or 0),
            }
            if "d6" in dimensions:
                dimensions_latest["d6"] = int(dimensions.get("d6") or 0)
            session["dimensions_latest"] = dimensions_latest
        if occurred_at_ts and occurred_at_ts < _parse_iso_timestamp(session["first_event_at"]):
            session["first_event_at"] = occurred_at
        if occurred_at_ts >= float(session.get("last_event_ts", 0.0)):
            session["last_event_at"] = occurred_at
            session["last_event_ts"] = occurred_at_ts
        self._sessions[session_id] = session
        self._evict_if_needed()

    def record_adapter_effect_result(self, result: dict[str, Any]) -> None:
        """Update live session summary from a separate adapter effect result."""

        summary = adapter_effect_result_summary(result)
        if summary is None:
            return
        session_id = str(result.get("session_id") or "")
        if not session_id:
            return
        session = self._sessions.get(session_id)
        if session is None:
            session = {
                "session_id": session_id,
                "agent_id": "unknown",
                "source_framework": str(result.get("framework") or "unknown"),
                "caller_adapter": str(result.get("adapter") or "unknown"),
                "current_risk_level": "low",
                "cumulative_score": 0,
                "event_count": 0,
                "high_risk_event_count": 0,
                "decision_distribution": defaultdict(int),
                "actual_tier_distribution": defaultdict(int),
                "first_event_at": utc_now_iso(),
                "last_event_at": utc_now_iso(),
                "last_event_ts": time.time(),
                "d4_accumulation": 0,
                "dimensions_latest": {"d1": 0, "d2": 0, "d3": 0, "d4": 0, "d5": 0},
                "risk_hints_seen": set(),
                "tools_used": set(),
                "latest_evidence_summary": None,
                "latest_l3_state": None,
                "latest_l3_reason": None,
                "latest_l3_reason_code": None,
                "latest_approval_id": None,
                "latest_approval_kind": None,
                "latest_approval_state": None,
                "latest_approval_reason": None,
                "latest_approval_reason_code": None,
                "latest_approval_timeout_s": None,
                "latest_decision_effect_summary": None,
                "latest_adapter_effect_result_summary": None,
                "quarantine": None,
                "risk_timeline": deque(maxlen=self.max_timeline_per_session),
                "post_action_score_timeline": deque(maxlen=self.max_timeline_per_session),
                "workspace_root": "",
                "transcript_path": "",
            }
        session["latest_adapter_effect_result_summary"] = summary
        session["last_event_at"] = utc_now_iso()
        session["last_event_ts"] = time.time()
        self._sessions[session_id] = session
        self._evict_if_needed()

    def record_post_action_score(
        self,
        *,
        session_id: str,
        event_id: str,
        occurred_at: str,
        score: float,
        tier: str,
        patterns_matched: list[str],
        tool_name: Optional[str] = None,
        source_framework: Optional[str] = None,
        handling: Optional[str] = None,
    ) -> None:
        """Record a post-action guard score for session-level reporting."""

        if not session_id:
            return

        occurred_at_ts = _parse_iso_timestamp(occurred_at)
        session = self._sessions.get(session_id)
        if session is None:
            session = {
                "session_id": session_id,
                "agent_id": "unknown",
                "source_framework": str(source_framework or "unknown"),
                "caller_adapter": "unknown",
                "current_risk_level": "low",
                "cumulative_score": 0,
                "event_count": 0,
                "high_risk_event_count": 0,
                "decision_distribution": defaultdict(int),
                "actual_tier_distribution": defaultdict(int),
                "first_event_at": occurred_at,
                "last_event_at": occurred_at,
                "last_event_ts": occurred_at_ts,
                "d4_accumulation": 0,
                "dimensions_latest": {"d1": 0, "d2": 0, "d3": 0, "d4": 0, "d5": 0},
                "risk_hints_seen": set(),
                "tools_used": set(),
                "latest_evidence_summary": None,
                "latest_l3_state": None,
                "latest_l3_reason": None,
                "latest_l3_reason_code": None,
                "latest_approval_id": None,
                "latest_approval_kind": None,
                "latest_approval_state": None,
                "latest_approval_reason": None,
                "latest_approval_reason_code": None,
                "latest_approval_timeout_s": None,
                "latest_decision_effect_summary": None,
                "latest_adapter_effect_result_summary": None,
                "quarantine": None,
                "risk_timeline": deque(maxlen=self.max_timeline_per_session),
                "post_action_score_timeline": deque(maxlen=self.max_timeline_per_session),
                "workspace_root": "",
                "transcript_path": "",
            }
        if "post_action_score_timeline" not in session:
            session["post_action_score_timeline"] = deque(maxlen=self.max_timeline_per_session)

        session["post_action_score_timeline"].append({
            "event_id": str(event_id or "unknown"),
            "occurred_at": occurred_at,
            "occurred_at_ts": occurred_at_ts,
            "score": max(0.0, min(_safe_float(score), 3.0)),
            "tier": str(tier or "log_only"),
            "patterns_matched": [str(item) for item in patterns_matched],
            "tool_name": str(tool_name) if tool_name else None,
            "source_framework": str(source_framework or session.get("source_framework") or "unknown"),
            "handling": str(handling) if handling else None,
        })
        if tool_name:
            session["tools_used"].add(str(tool_name))
        if source_framework:
            session["source_framework"] = str(source_framework)
        if occurred_at_ts >= float(session.get("last_event_ts", 0.0)):
            session["last_event_at"] = occurred_at
            session["last_event_ts"] = occurred_at_ts
        if occurred_at_ts and occurred_at_ts < _parse_iso_timestamp(session["first_event_at"]):
            session["first_event_at"] = occurred_at

        self._sessions[session_id] = session
        self._evict_if_needed()

    def get_quarantine(self, session_id: str) -> Optional[dict[str, Any]]:
        session = self._sessions.get(session_id)
        if not session:
            return None
        quarantine = session.get("quarantine")
        if not isinstance(quarantine, dict):
            return None
        if quarantine.get("state") != "quarantined":
            return None
        return dict(quarantine)

    def release_quarantine(
        self,
        session_id: str,
        *,
        released_by: str = "operator",
        reason: str | None = None,
    ) -> bool:
        session = self._sessions.get(session_id)
        if not session or not isinstance(session.get("quarantine"), dict):
            return False
        quarantine = dict(session["quarantine"])
        if quarantine.get("state") != "quarantined":
            return False
        quarantine.update(
            {
                "state": "released",
                "released_at": utc_now_iso(),
                "released_by": released_by,
                "released_reason": reason,
            }
        )
        session["quarantine"] = quarantine
        return True

    def list_sessions(
        self,
        *,
        status: str = "active",
        sort: str = "risk_level",
        min_risk: Optional[str] = None,
        limit: int = 50,
        max_limit: int = 200,
        since_seconds: Optional[int] = None,
    ) -> dict[str, Any]:
        start = time.perf_counter()
        try:
            _ = status
            sessions = list(self._sessions.values())
            if since_seconds is not None and since_seconds > 0:
                cutoff = time.time() - since_seconds
                sessions = [s for s in sessions if float(s.get("last_event_ts", 0.0)) >= cutoff]
            if min_risk:
                min_rank = _risk_rank(min_risk)
                sessions = [
                    s for s in sessions
                    if _risk_rank(s.get("current_risk_level")) >= min_rank
                ]

            if sort == "last_event":
                sessions.sort(
                    key=lambda s: (float(s.get("last_event_ts", 0.0)), _risk_rank(s.get("current_risk_level"))),
                    reverse=True,
                )
            else:
                sessions.sort(
                    key=lambda s: (_risk_rank(s.get("current_risk_level")), float(s.get("last_event_ts", 0.0))),
                    reverse=True,
                )

            effective_limit = min(max(limit, 1), max(max_limit, 1))
            serialized_sessions: list[dict[str, Any]] = []
            for session in sessions[:effective_limit]:
                serialized_session = {
                    "session_id": session["session_id"],
                    "agent_id": session["agent_id"],
                    "source_framework": session["source_framework"],
                    "caller_adapter": session["caller_adapter"],
                    "workspace_root": session["workspace_root"],
                    "transcript_path": session["transcript_path"],
                    "current_risk_level": session["current_risk_level"],
                    "cumulative_score": session["cumulative_score"],
                    "event_count": session["event_count"],
                    "high_risk_event_count": session["high_risk_event_count"],
                    "decision_distribution": dict(session["decision_distribution"]),
                    "first_event_at": session["first_event_at"],
                    "last_event_at": session["last_event_at"],
                    "d4_accumulation": session["d4_accumulation"],
                    "quarantine": (
                        dict(session["quarantine"])
                        if isinstance(session.get("quarantine"), dict)
                        else None
                    ),
                    "latest_decision_effect_summary": session.get("latest_decision_effect_summary"),
                    "latest_adapter_effect_result_summary": session.get("latest_adapter_effect_result_summary"),
                }
                serialized_session.update(
                    self._session_display_metrics(
                        session,
                        window_seconds=since_seconds,
                    )
                )
                post_action_timeline = [
                    item for item in list(session.get("post_action_score_timeline") or [])
                    if isinstance(item, dict)
                ]
                if since_seconds is not None and since_seconds > 0:
                    cutoff = time.time() - since_seconds
                    post_action_timeline = [
                        item for item in post_action_timeline
                        if float(item.get("occurred_at_ts", 0.0)) >= cutoff
                    ]
                serialized_session.update(self._post_action_score_metrics(post_action_timeline))
                serialized_session["post_action_score_summary"] = self._post_action_score_summary(
                    post_action_timeline,
                    window_seconds=since_seconds,
                )
                serialized_session.update(self._latest_session_annotations(session))
                serialized_sessions.append(serialized_session)

            return {
                "sessions": serialized_sessions,
                "total_active": len(sessions),
            }
        finally:
            _observe_io_metric(self._io_metrics["list_sessions"], time.perf_counter() - start)

    def get_session_risk(
        self,
        session_id: str,
        *,
        limit: int = 100,
        since_seconds: Optional[int] = None,
    ) -> dict[str, Any]:
        start = time.perf_counter()
        try:
            session = self._sessions.get(session_id)
            if session is None:
                return {
                    "session_id": session_id,
                    "current_risk_level": "low",
                    "cumulative_score": 0,
                    "latest_composite_score": 0.0,
                    "session_risk_sum": 0.0,
                    "session_risk_ewma": 0.0,
                    "risk_points_sum": 0,
                    "risk_velocity": "unknown",
                    "window_risk_summary": self._window_risk_summary(
                        [],
                        window_seconds=since_seconds,
                    ),
                    "latest_post_action_score": 0.0,
                    "post_action_score_sum": 0.0,
                    "post_action_score_avg": 0.0,
                    "post_action_score_ewma": 0.0,
                    "post_action_event_count": 0,
                    "post_action_score_summary": self._post_action_score_summary(
                        [],
                        window_seconds=since_seconds,
                    ),
                    "dimensions_latest": {"d1": 0, "d2": 0, "d3": 0, "d4": 0, "d5": 0},
                    "risk_timeline": [],
                    "post_action_scores": [],
                    "evidence_summary": None,
                    "risk_hints_seen": [],
                    "tools_used": [],
                    "actual_tier_distribution": {},
                    "quarantine": None,
                    "latest_decision_effect_summary": None,
                    "latest_adapter_effect_result_summary": None,
                }

            timeline = list(session["risk_timeline"])
            post_action_timeline = [
                item for item in list(session.get("post_action_score_timeline") or [])
                if isinstance(item, dict)
            ]
            if since_seconds is not None and since_seconds > 0:
                cutoff = time.time() - since_seconds
                timeline = [item for item in timeline if float(item.get("occurred_at_ts", 0.0)) >= cutoff]
                post_action_timeline = [
                    item for item in post_action_timeline
                    if float(item.get("occurred_at_ts", 0.0)) >= cutoff
                ]
            effective_limit = min(max(limit, 1), 1000)
            timeline = timeline[-effective_limit:]
            post_action_timeline = post_action_timeline[-effective_limit:]

            return {
                "session_id": session_id,
                "agent_id": session["agent_id"],
                "source_framework": session["source_framework"],
                "caller_adapter": session["caller_adapter"],
                "workspace_root": session["workspace_root"],
                "transcript_path": session["transcript_path"],
                "current_risk_level": session["current_risk_level"],
                "cumulative_score": session["cumulative_score"],
                "dimensions_latest": dict(session["dimensions_latest"]),
                "event_count": session["event_count"],
                "high_risk_event_count": session["high_risk_event_count"],
                "first_event_at": session["first_event_at"],
                "last_event_at": session["last_event_at"],
                "risk_timeline": [
                    {
                        "event_id": item["event_id"],
                        "occurred_at": item["occurred_at"],
                        "risk_level": item["risk_level"],
                        "composite_score": item["composite_score"],
                        "tool_name": item["tool_name"],
                        "decision": item["decision"],
                        "actual_tier": item["actual_tier"],
                        "classified_by": item["classified_by"],
                        "l3_state": item.get("l3_state"),
                        "l3_reason": item.get("l3_reason"),
                        "l3_reason_code": item.get("l3_reason_code"),
                        **(
                            {"approval_id": item["approval_id"]}
                            if item.get("approval_id") not in (None, "")
                            else {}
                        ),
                        **(
                            {"approval_kind": item["approval_kind"]}
                            if item.get("approval_kind") not in (None, "")
                            else {}
                        ),
                        **(
                            {"approval_state": item["approval_state"]}
                            if item.get("approval_state") not in (None, "")
                            else {}
                        ),
                        **(
                            {"approval_reason": item["approval_reason"]}
                            if item.get("approval_reason") not in (None, "")
                            else {}
                        ),
                        **(
                            {"approval_reason_code": item["approval_reason_code"]}
                            if item.get("approval_reason_code") not in (None, "")
                            else {}
                        ),
                        **(
                            {"approval_timeout_s": float(item["approval_timeout_s"])}
                            if item.get("approval_timeout_s") is not None
                            else {}
                        ),
                        **(
                            {"evidence_summary": item["evidence_summary"]}
                            if item.get("evidence_summary") is not None
                            else {}
                        ),
                        **(
                            {"l3_trace_summary": item["l3_trace_summary"]}
                            if item.get("l3_trace_summary") is not None
                            else {}
                        ),
                        **(
                            {"decision_effect_summary": item["decision_effect_summary"]}
                            if item.get("decision_effect_summary") is not None
                            else {}
                        ),
                    }
                    for item in timeline
                ],
                "post_action_scores": [
                    {
                        "event_id": item["event_id"],
                        "occurred_at": item["occurred_at"],
                        "tool_name": item.get("tool_name"),
                        "source_framework": item.get("source_framework"),
                        "tier": item.get("tier"),
                        "patterns_matched": list(item.get("patterns_matched") or []),
                        "score": item["score"],
                        "handling": item.get("handling"),
                    }
                    for item in post_action_timeline
                ],
                "evidence_summary": (
                    dict(session["latest_evidence_summary"])
                    if session.get("latest_evidence_summary") is not None
                    else None
                ),
                "risk_hints_seen": sorted(session["risk_hints_seen"]),
                "tools_used": sorted(session["tools_used"]),
                "actual_tier_distribution": dict(session["actual_tier_distribution"]),
                "quarantine": (
                    dict(session["quarantine"])
                    if isinstance(session.get("quarantine"), dict)
                    else None
                ),
                "latest_decision_effect_summary": session.get("latest_decision_effect_summary"),
                "latest_adapter_effect_result_summary": session.get("latest_adapter_effect_result_summary"),
                **self._session_display_metrics(
                    session,
                    window_timeline=timeline,
                    window_seconds=since_seconds,
                ),
                **self._post_action_score_metrics(post_action_timeline),
                "post_action_score_summary": self._post_action_score_summary(
                    post_action_timeline,
                    window_seconds=since_seconds,
                ),
                **self._latest_session_annotations(session),
            }
        finally:
            _observe_io_metric(self._io_metrics["get_session_risk"], time.perf_counter() - start)
