"""``clawsentry watch`` — real-time SSE event monitor for the terminal."""

from __future__ import annotations

import asyncio
import json
import sys
import time
import urllib.request
import urllib.error
import urllib.parse
from datetime import datetime
from typing import Any, Callable

from clawsentry.cli.http_utils import urlopen_gateway

# ── ANSI colour helpers ──────────────────────────────────────────────────────

_COLORS: dict[str, str] = {
    "red": "\033[91m",
    "green": "\033[92m",
    "yellow": "\033[93m",
    "magenta": "\033[95m",
    "cyan": "\033[96m",
    "bold": "\033[1m",
    "dim": "\033[2m",
    "grey": "\033[90m",
    "white": "\033[97m",
    "reset": "\033[0m",
}

_RISK_COLORS: dict[str, str] = {
    "critical": "red",
    "high": "red",
    "medium": "yellow",
    "low": "green",
    "unknown": "grey",
}

_DECISION_COLORS: dict[str, str] = {
    "block": "red",
    "allow": "green",
    "defer": "yellow",
    "modify": "cyan",
}

_EMOJIS: dict[str, str] = {
    "block": "🚫",
    "allow": "✅",
    "defer": "⏸️",
    "modify": "✏️",
    "alert": "⚠️",
    "budget_exhausted": "⚠️",
    "session": "📍",
    "risk_change": "📊",
    "enforcement": "🔒",
    "expires": "⏱️",
    "trajectory": "🧭",
    "post_action": "🛡️",
    "pattern_candidate": "🧪",
    "pattern_evolved": "🧬",
    "l3_advisory": "🧾",
    "risk_high": "🔴",
    "risk_medium": "🟡",
    "risk_low": "🟢",
    "risk_critical": "🔴",
}

_CMD_MAX_LEN = 50
_SESSION_WIDTH = 62
_TREE_INDENT = " " * 11  # aligns with position after "[HH:MM:SS] "
_SESSION_PREFIX = "│ "

_PRIORITY_STREAM_TYPES: tuple[str, ...] = (
    "decision",
    "alert",
    "session_enforcement_change",
    "defer_pending",
    "defer_resolved",
    "adapter_effect_result",
    "budget_exhausted",
    "l3_advisory_snapshot",
    "l3_advisory_review",
    "l3_advisory_job",
    "l3_advisory_action",
)


def _c(name: str, text: str, *, color: bool = True) -> str:
    """Wrap *text* in ANSI colour codes if *color* is enabled."""
    if not color:
        return text
    return f"{_COLORS.get(name, '')}{text}{_COLORS['reset']}"


def _timestamp_hms(ts: str | None) -> str:
    """Extract ``HH:MM:SS`` from an ISO-8601 timestamp string.

    Converts to the local timezone before formatting.
    Falls back to the current local time if the string cannot be parsed.
    """
    if ts:
        try:
            dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            return dt.astimezone().strftime("%H:%M:%S")
        except (ValueError, AttributeError):
            pass
    return datetime.now().strftime("%H:%M:%S")


def _truncate(text: str, max_len: int = _CMD_MAX_LEN) -> str:
    if len(text) <= max_len:
        return text
    return text[: max_len - 3] + "..."


def _emoji(key: str, *, no_emoji: bool = False) -> str:
    """Return emoji for the given key, or empty string if *no_emoji* is True."""
    if no_emoji:
        return ""
    return _EMOJIS.get(key, "")


def _risk_display(level: str, *, color: bool = True, no_emoji: bool = False) -> str:
    """Return colored risk level string with optional risk emoji."""
    color_name = _RISK_COLORS.get(level.lower(), "grey")
    e = _emoji(f"risk_{level.lower()}", no_emoji=no_emoji)
    prefix = f"{e} " if e else ""
    return _c(color_name, f"{prefix}{level}", color=color)


def _format_evidence_summary(summary: dict[str, Any] | None) -> str | None:
    if not isinstance(summary, dict):
        return None

    parts: list[str] = []

    retained_sources = summary.get("retained_sources")
    if isinstance(retained_sources, list):
        sources = [
            str(source).strip()
            for source in retained_sources
            if str(source).strip()
        ]
        if sources:
            parts.append(", ".join(sources))

    tool_calls_count = summary.get("tool_calls_count")
    if isinstance(tool_calls_count, int):
        parts.append(f"{tool_calls_count} tool call(s)")

    toolkit_budget_cap = summary.get("toolkit_budget_cap")
    toolkit_calls_remaining = summary.get("toolkit_calls_remaining")
    if isinstance(toolkit_budget_cap, int) and isinstance(toolkit_calls_remaining, int) and toolkit_budget_cap > 0:
        toolkit_summary = f"toolkit {toolkit_calls_remaining}/{toolkit_budget_cap}"
        if summary.get("toolkit_budget_exhausted") is True:
            parts.append(f"{toolkit_summary} (exhausted)")
        else:
            parts.append(toolkit_summary)
    elif summary.get("toolkit_budget_exhausted") is True:
        parts.append("toolkit exhausted")

    return " · ".join(parts) if parts else None


def _format_counts(counts: Any) -> str:
    if not isinstance(counts, dict) or not counts:
        return "none"
    return ", ".join(f"{key}={value}" for key, value in sorted(counts.items()))


def _format_scope_evaluation(scope: Any) -> list[str]:
    if not isinstance(scope, dict):
        return []
    profile_id = str(scope.get("profile_id") or "unknown")
    verdict = str(scope.get("verdict") or "neutral")
    if scope.get("enforced"):
        mode = "enforced"
    elif scope.get("dry_run"):
        mode = "dry-run only"
    else:
        mode = "not enforced"
    reasons = ", ".join(str(item) for item in scope.get("reason_codes") or [])
    line = f"Scope: {mode} profile={profile_id} verdict={verdict}"
    if reasons:
        line += f" reasons={reasons}"
    return [line]


def _format_sanitize_summary(sanitize: Any) -> list[str]:
    if not isinstance(sanitize, dict):
        return []
    target = str(sanitize.get("target") or "tool_output")
    advisory = bool(sanitize.get("advisory_only", sanitize.get("would_sanitize", False)))
    outcome = str(sanitize.get("outcome") or "")
    state = (
        "would_sanitize"
        if advisory or outcome.endswith("would_sanitize")
        else "sanitize_requested"
    )
    lines = [f"Sanitizer: {state} {target}"]
    counts = _format_counts(sanitize.get("redaction_counts"))
    if counts != "none":
        lines.append(f"Redactions: {counts}")
    preview = (
        sanitize.get("sanitized_preview_redacted")
        or sanitize.get("redacted_preview")
        or sanitize.get("original_preview_redacted")
    )
    if preview:
        lines.append(f"Preview: {preview}")
    return lines




def _stringify_operator_hint(value: Any) -> str | None:
    """Return a concise human-readable operator hint.

    Machine-readable payloads may carry richer dictionaries/lists; watch human
    output intentionally keeps only a compact summary while ``--json`` keeps the
    original fields intact.
    """
    if value is None:
        return None
    if isinstance(value, str):
        text = value.strip()
        return text or None
    if isinstance(value, dict):
        for key in ("summary", "message", "hint", "label", "status", "direction", "state"):
            text = _stringify_operator_hint(value.get(key))
            if text:
                return text
        return None
    if isinstance(value, (list, tuple)):
        items = [_stringify_operator_hint(item) for item in value]
        compact_items = [item for item in items if item]
        if compact_items:
            return ", ".join(compact_items[:3])
    return None


def _event_hint(event: dict[str, Any], *keys: str) -> str | None:
    """Extract a compact hint from top-level or watch/operator hint maps."""
    containers: list[dict[str, Any]] = [event]
    for container_key in ("operator_hints", "watch_hints", "risk_hints_summary"):
        value = event.get(container_key)
        if isinstance(value, dict):
            containers.append(value)

    for container in containers:
        for key in keys:
            text = _stringify_operator_hint(container.get(key))
            if text:
                return text
    return None


def _posture_hint(event: dict[str, Any]) -> str | None:
    return _event_hint(
        event,
        "risk_posture_hint",
        "posture_hint",
        "operator_posture_hint",
        "risk_posture",
        "posture",
    )


def _trend_hint(event: dict[str, Any]) -> str | None:
    return _event_hint(
        event,
        "risk_trend_hint",
        "trend_hint",
        "operator_trend_hint",
        "high_risk_trend_hint",
        "risk_trend",
        "trend",
    )


def _append_posture_trend_items(
    detail_items: list[str],
    event: dict[str, Any],
    *,
    color: bool = True,
) -> None:
    """Append compact posture/trend detail rows when present.

    Keep this helper human-output only. ``format_event(..., json_mode=True)``
    returns the raw event so automation receives the full structured fields.
    """
    posture = _posture_hint(event)
    trend = _trend_hint(event)
    if posture:
        detail_items.append(f"Posture: {_c('grey', posture, color=color)}")
    if trend:
        detail_items.append(f"Trend: {_c('grey', trend, color=color)}")

def _operator_action_hint(event: dict[str, Any]) -> str | None:
    """Return a human scanning hint for action-oriented watch events.

    The hint is display-only: it must never feed back into gateway safety
    decisions or alter machine-readable output modes.
    """
    decision = str(event.get("decision") or "").lower()
    risk = str(event.get("risk_level") or "").lower()
    l3_state = str(event.get("l3_state") or "").lower()
    l3_reason_code = str(event.get("l3_reason_code") or "").lower()

    if decision == "defer":
        return "operator approval pending"
    if decision == "block":
        return "blocked; inspect session evidence"
    if l3_state and l3_state != "completed":
        return f"L3 {l3_state}; monitor advisory review"
    if l3_reason_code in {"toolkit_budget_exhausted", "hard_cap_exceeded"}:
        return "evidence budget constrained; review retained context"
    if risk in {"critical", "high"} and decision != "allow":
        return "prioritize in operator queue"
    return None


def _l3_advisory_job_transition_hint(job_state: str) -> str | None:
    """Return a display-only transition hint for advisory job lifecycle states."""
    normalized = job_state.lower()
    if normalized == "queued":
        return "waiting for explicit operator run"
    if normalized == "running":
        return "worker executing frozen evidence review"
    if normalized == "completed":
        return "review available; canonical decision unchanged"
    if normalized == "failed":
        return "worker failed; inspect advisory job evidence"
    if normalized == "degraded":
        return "review degraded; check LLM provider configuration and retained evidence boundary"
    return None


_OPERATOR_LABELS: dict[str, dict[str, str]] = {
    "job_state": {
        "queued": "Queued",
        "running": "Running",
        "completed": "Completed",
        "failed": "Failed",
        "degraded": "Degraded",
    },
    "l3_state": {
        "pending": "Pending",
        "running": "Running",
        "completed": "Completed",
        "failed": "Failed",
        "degraded": "Degraded",
        "skipped": "Skipped",
        "not_triggered": "Not triggered",
    },
    "operator_action": {
        "inspect": "Inspect",
        "escalate": "Escalate",
        "pause": "Pause",
        "none": "None",
        "configure_llm_provider": "Configure LLM provider",
    },
    "runner": {
        "deterministic_local": "Deterministic local",
        "llm_provider": "LLM provider",
    },
}


def _humanize_operator_id(value: str) -> str:
    words = value.replace("_", " ").replace("-", " ").strip()
    if not words:
        return "Unknown"
    return words[:1].upper() + words[1:].lower()


def _operator_label(kind: str, value: str) -> str:
    normalized = str(value or "").strip()
    if not normalized:
        return "Unknown"
    return _OPERATOR_LABELS.get(kind, {}).get(normalized.lower(), _humanize_operator_id(normalized))


def _operator_display(kind: str, value: str) -> str:
    normalized = str(value or "").strip()
    label = _operator_label(kind, normalized)
    if not normalized or label == normalized:
        return label
    return f"{label} ({normalized})"


# ── SSE line parser ──────────────────────────────────────────────────────────


def parse_sse_line(line: str) -> dict | None:
    """Parse a single SSE line.

    Returns the parsed JSON dict for ``data:`` lines,
    or ``None`` for comments and blank lines.
    """
    if not line or line.startswith(":"):
        return None
    if line.startswith("data: "):
        payload = line[6:]
        try:
            return json.loads(payload)
        except json.JSONDecodeError:
            return None
    return None


def _normalize_filter_types(filter_types: str | None) -> list[str]:
    if not filter_types:
        return []
    items: list[str] = []
    seen: set[str] = set()
    for item in filter_types.split(","):
        normalized = item.strip()
        if not normalized or normalized in seen:
            continue
        seen.add(normalized)
        items.append(normalized)
    return items


def _build_stream_url(
    gateway_url: str,
    *,
    filter_types: str | None = None,
    priority_only: bool = False,
) -> str:
    base = f"{gateway_url.rstrip('/')}/report/stream"

    selected_types = _normalize_filter_types(filter_types)
    if priority_only:
        for event_type in _PRIORITY_STREAM_TYPES:
            if event_type not in selected_types:
                selected_types.append(event_type)

    if not selected_types:
        return base

    query = urllib.parse.urlencode({"types": ",".join(selected_types)})
    return f"{base}?{query}"


# ── Session tracker ──────────────────────────────────────────────────────────


class SessionTracker:
    """Tracks session context and generates box-drawing session headers/footers."""

    def __init__(self) -> None:
        self.current_session_id: str | None = None
        self.session_info: dict[str, dict] = {}
        self.in_session: bool = False

    def update(
        self,
        event: dict,
        *,
        color: bool = True,
        compact: bool = False,
        no_emoji: bool = False,
    ) -> tuple[str | None, str | None]:
        """Process an event and return text to print around it.

        Returns:
            ``(before_event_text, after_event_text)`` — either may be ``None``.

            *before_event_text* is printed **before** the formatted event.
            *after_event_text* is printed **after** (only used for session_end).
        """
        session_id = self._extract_session_id(event)
        event_type = str(event.get("type") or "")

        # session_end: footer goes AFTER the event (still inside the box)
        if event_type == "session_end" and self.in_session:
            after_text = self._format_footer(color=color, compact=compact)
            self.current_session_id = None
            self.in_session = False
            return None, after_text

        if not session_id:
            return None, None

        if session_id != self.current_session_id:
            # New session: close previous box (if any), open new box
            before_parts: list[str] = []
            if self.in_session:
                before_parts.append(self._format_footer(color=color, compact=compact))
            self.current_session_id = session_id
            self.session_info[session_id] = self._extract_session_info(event)
            before_parts.append(
                self._format_header(
                    session_id, color=color, compact=compact, no_emoji=no_emoji
                )
            )
            self.in_session = True
            return "\n".join(before_parts), None

        # Same session — no transition needed
        return None, None

    def _extract_session_id(self, event: dict) -> str | None:
        sid = event.get("session_id") or event.get("sessionId")
        if sid and str(sid).strip() not in ("", "None", "unknown"):
            return str(sid)
        return None

    def _extract_session_info(self, event: dict) -> dict:
        return {
            "agent_id": str(
                event.get("agent_id") or event.get("agentId") or "unknown"
            ),
            "framework": str(
                event.get("source_framework")
                or event.get("caller_adapter")
                or "unknown"
            ),
            "started": _timestamp_hms(event.get("timestamp")),
        }

    def _format_header(
        self,
        session_id: str,
        *,
        color: bool = True,
        compact: bool = False,
        no_emoji: bool = False,
    ) -> str:
        info = self.session_info.get(session_id, {})
        agent = info.get("agent_id", "unknown")
        framework = info.get("framework", "unknown")
        started = info.get("started", "?")

        e = _emoji("session", no_emoji=no_emoji)
        label = f"{e} Session: {session_id}" if e else f"Session: {session_id}"

        if compact:
            return _c("cyan", f"=== {label} ({agent}, {framework}) ===", color=color)

        # Unicode box drawing
        title_part = f"╭─ {label} "
        # Use len() as rough estimate (emoji may render as 2 columns, but close enough)
        fill_count = max(0, _SESSION_WIDTH - len(title_part) - 1)
        top = _c("cyan", f"{title_part}{'─' * fill_count}╮", color=color)
        meta = _c(
            "grey",
            f"│  Agent: {agent} | Framework: {framework} | Started: {started}",
            color=color,
        )
        blank = _c("grey", "│", color=color)
        return f"\n{top}\n{meta}\n{blank}"

    def _format_footer(self, *, color: bool = True, compact: bool = False) -> str:
        if compact:
            return _c("cyan", "===", color=color)
        fill = "─" * _SESSION_WIDTH
        return _c("grey", f"│\n╰{fill}╯\n", color=color)


# ── Event formatters ─────────────────────────────────────────────────────────


def format_decision(
    event: dict,
    *,
    color: bool = True,
    verbose: bool = False,
    no_emoji: bool = False,
    compact: bool = False,
) -> str:
    """Format a *decision* event for terminal output.

    **ALLOW** decisions use a compact single-line format unless ``verbose=True``.
    **BLOCK**, **DEFER**, and **MODIFY** use a detailed multi-line tree format.

    Returns an empty string for observation-only events (pre-prompt / post-response)
    that carry no tool name — callers should skip these.
    """
    hms = _timestamp_hms(event.get("timestamp"))
    decision = str(event.get("decision") or "unknown").lower()
    command = _truncate(str(event.get("command") or event.get("tool_name") or ""))
    risk = str(event.get("risk_level") or "unknown")
    reason = str(event.get("reason") or "")
    expires_at_ms = event.get("expires_at")

    # Skip observation-only events that carry no tool name.
    if command.strip() in ("", "None"):
        return ""

    colour_name = _DECISION_COLORS.get(decision, "cyan")
    e = _emoji(decision, no_emoji=no_emoji)
    e_str = f"{e} " if e else ""
    decision_label = _c(colour_name, decision.upper(), color=color)
    ts_str = _c("grey", f"[{hms}]", color=color)

    first_line = f"{ts_str} {e_str}{decision_label}  {command}"

    # Compact ALLOW: single line only (unless verbose requested)
    if decision == "allow" and not verbose:
        return first_line

    # Detailed tree format for BLOCK / DEFER / MODIFY (and verbose ALLOW)
    lines = [first_line]
    detail_items: list[str] = []

    # Risk level
    if risk and risk != "unknown":
        detail_items.append(
            f"Risk: {_risk_display(risk, color=color, no_emoji=no_emoji)}"
        )
    elif verbose:
        detail_items.append(f"Risk: {_c('grey', 'unknown', color=color)}")

    # Reason
    if reason:
        detail_items.append(f"Reason: {_c('grey', reason, color=color)}")

    action_hint = _operator_action_hint(event)
    if action_hint:
        detail_items.append(f"Action: {_c('grey', action_hint, color=color)}")

    _append_posture_trend_items(detail_items, event, color=color)

    trigger_detail = str(event.get("trigger_detail") or "")
    if trigger_detail:
        detail_items.append(f"Trigger: {_c('grey', trigger_detail, color=color)}")

    l3_reason_code = str(event.get("l3_reason_code") or "")
    if l3_reason_code:
        detail_items.append(f"L3 reason code: {_c('grey', l3_reason_code, color=color)}")

    l3_state = str(event.get("l3_state") or "")
    if l3_state and l3_state != "completed":
        detail_items.append(f"L3 state: {_c('grey', l3_state, color=color)}")

    l3_reason = str(event.get("l3_reason") or "")
    if l3_reason and l3_state != "completed":
        detail_items.append(f"L3 reason: {_c('grey', l3_reason, color=color)}")

    # DEFER: optional expiry countdown
    if decision == "defer" and expires_at_ms is not None:
        remaining_s = int(expires_at_ms / 1000 - time.time())
        if remaining_s > 0:
            exp_e = _emoji("expires", no_emoji=no_emoji)
            exp_str = f"{exp_e} " if exp_e else ""
            detail_items.append(f"{exp_str}Expires in: {remaining_s}s")

    effect_summary = event.get("effect_summary") or event.get("decision_effect_summary")
    rewrite_summary = (
        effect_summary.get("rewrite_effect")
        if isinstance(effect_summary, dict)
        else None
    )

    # MODIFY: legacy modified command display. Rewrite decisions use the
    # redacted replacement preview from effect_summary below; never render
    # full replacement payloads for rewrite effects in watch output.
    if decision == "modify" and not isinstance(rewrite_summary, dict):
        modified = event.get("modified_command") or event.get("modified")
        if modified:
            detail_items.append(
                f"Modified: {_c('cyan', str(modified), color=color)}"
            )

    if isinstance(effect_summary, dict):
        if effect_summary.get("action_scope") == "session":
            detail_items.append(
                f"Effect: {_c('red', 'BLOCK SESSION / QUARANTINE', color=color)}"
            )
        rewrite_effect = rewrite_summary
        if isinstance(rewrite_effect, dict):
            target = str(rewrite_effect.get("target") or "command")
            detail_items.append(
                f"Rewrite: {_c('cyan', f'{target} requested', color=color)}"
            )
            replacement_preview = rewrite_effect.get("replacement_preview_redacted")
            if replacement_preview:
                detail_items.append(
                    f"Replacement: {_c('cyan', str(replacement_preview), color=color)}"
                )
        for sanitize_line in _format_sanitize_summary(effect_summary.get("sanitize_effect")):
            detail_items.append(_c("yellow", sanitize_line, color=color))

    for scope_line in _format_scope_evaluation(event.get("scope_evaluation")):
        detail_items.append(_c("cyan", scope_line, color=color))

    adapter_summary = event.get("adapter_effect_result_summary")
    if isinstance(adapter_summary, dict):
        enforced = adapter_summary.get("enforced") or []
        degraded = adapter_summary.get("degraded") or adapter_summary.get("unsupported") or []
        if enforced:
            detail_items.append(
                f"Adapter effect: {_c('green', 'ENFORCED', color=color)}"
            )
        elif degraded:
            reason_text = str(adapter_summary.get("degrade_reason") or "degraded")
            detail_items.append(
                f"Adapter effect: {_c('yellow', f'DEGRADED ({reason_text})', color=color)}"
            )

    # Verbose: tier info
    if verbose:
        actual_tier = str(event.get("actual_tier") or "")
        if actual_tier:
            detail_items.append(f"Tier: {_c('grey', actual_tier, color=color)}")

        raw_evidence_summary = event.get("evidence_summary")
        evidence_summary = _format_evidence_summary(
            raw_evidence_summary if isinstance(raw_evidence_summary, dict) else None
        )
        if evidence_summary:
            detail_items.append(
                f"Evidence: {_c('grey', evidence_summary, color=color)}"
            )

    for i, item in enumerate(detail_items):
        connector = "└─" if i == len(detail_items) - 1 else "├─"
        lines.append(f"{_TREE_INDENT}{connector} {item}")

    return "\n".join(lines)


def format_alert(
    event: dict,
    *,
    color: bool = True,
    no_emoji: bool = False,
) -> str:
    """Format an *alert* event for terminal output.

    Example (colour stripped)::

        [10:30:45] ⚠️ ALERT  Risk escalation detected
                   ├─ Session: sess-001
                   └─ Severity: 🔴 high
    """
    hms = _timestamp_hms(event.get("timestamp"))
    session_id = str(event.get("session_id") or "unknown")
    severity = str(event.get("severity") or "unknown")
    message = str(event.get("message") or "")

    e = _emoji("alert", no_emoji=no_emoji)
    e_str = f"{e} " if e else ""
    alert_label = _c("magenta", f"{e_str}ALERT", color=color)
    ts_str = _c("grey", f"[{hms}]", color=color)

    lines = [f"{ts_str} {alert_label}  {message}"]
    detail_items = [
        f"Session: {_c('grey', session_id, color=color)}",
        f"Severity: {_risk_display(severity, color=color, no_emoji=no_emoji)}",
    ]
    _append_posture_trend_items(detail_items, event, color=color)
    for i, item in enumerate(detail_items):
        connector = "└─" if i == len(detail_items) - 1 else "├─"
        lines.append(f"{_TREE_INDENT}{connector} {item}")

    return "\n".join(lines)


def _format_session_start(
    event: dict,
    *,
    color: bool = True,
    no_emoji: bool = False,
) -> str:
    """Format a *session_start* event.

    Returns an empty string because the ``SessionTracker`` already prints the
    session box header with all relevant information — printing a duplicate
    line here would be redundant.
    """
    return ""


def _format_risk_change(
    event: dict,
    *,
    color: bool = True,
    no_emoji: bool = False,
) -> str:
    """Format a *session_risk_change* event for terminal output.

    Example (colour stripped)::

        [10:32:20] 📊 RISK  my-session: 🟢 low → 🔴 high
    """
    hms = _timestamp_hms(event.get("timestamp"))
    session_id = str(event.get("session_id") or "unknown")
    prev = str(event.get("previous_risk") or "?")
    curr = str(event.get("current_risk") or "?")

    e = _emoji("risk_change", no_emoji=no_emoji)
    e_str = f"{e} " if e else ""
    label = _c("yellow", f"{e_str}RISK", color=color)
    ts_str = _c("grey", f"[{hms}]", color=color)

    prev_str = _risk_display(prev, color=color, no_emoji=no_emoji) if prev != "?" else prev
    curr_str = _risk_display(curr, color=color, no_emoji=no_emoji) if curr != "?" else curr
    line = f"{ts_str} {label}  {session_id}: {prev_str} → {curr_str}"
    hint_parts: list[str] = []
    posture = _posture_hint(event)
    trend = _trend_hint(event)
    if posture:
        hint_parts.append(f"Posture: {posture}")
    if trend:
        hint_parts.append(f"Trend: {trend}")
    if hint_parts:
        line = f"{line}  ·  {_c('grey', ' · '.join(hint_parts), color=color)}"
    return line


def _format_enforcement_change(
    event: dict,
    *,
    color: bool = True,
    no_emoji: bool = False,
) -> str:
    """Format a *session_enforcement_change* event for terminal output.

    Example (colour stripped)::

        [10:32:25] 🔒 ENFORCEMENT  my-session: DEFER mode activated
                   └─ Reason: Threshold exceeded (5 high-risk events)
    """
    hms = _timestamp_hms(event.get("timestamp"))
    session_id = str(event.get("session_id") or "unknown")
    action = str(
        event.get("action") or event.get("enforcement_action") or "unknown"
    )
    reason = str(event.get("reason") or "")

    e = _emoji("enforcement", no_emoji=no_emoji)
    e_str = f"{e} " if e else ""
    label = _c("red", f"{e_str}ENFORCEMENT", color=color)
    ts_str = _c("grey", f"[{hms}]", color=color)

    lines = [f"{ts_str} {label}  {session_id}: {action}"]
    if reason:
        lines.append(
            f"{_TREE_INDENT}└─ Reason: {_c('grey', reason, color=color)}"
        )
    return "\n".join(lines)


def _format_defer_pending(
    event: dict,
    *,
    color: bool = True,
    no_emoji: bool = False,
) -> str:
    """Format a *defer_pending* SSE event for terminal output.

    Example (colour stripped)::

        [10:30:45] ⏸️ DEFER PENDING  rm -rf /data(rm -rf /...)
                      Reason: D1: destructive pattern
                      Approval ID: appr-abc-123  Timeout: 300s
    """
    hms = _timestamp_hms(event.get("timestamp"))
    approval_id = str(event.get("approval_id") or "unknown")
    tool = str(event.get("tool_name") or "")
    command = str(event.get("command") or "")
    reason = str(event.get("reason") or "")
    timeout_s = event.get("timeout_s", 300)

    e = _emoji("defer", no_emoji=no_emoji)
    e_str = f"{e} " if e else ""

    # Tool/command display
    cmd_display = tool
    if command:
        cmd_short = _truncate(command)
        cmd_display = f"{tool}({cmd_short})" if tool else cmd_short

    ts_str = _c("grey", f"[{hms}]", color=color)
    label = _c("yellow", f"{_COLORS['bold']}DEFER PENDING{_COLORS['reset']}", color=color) if color else "DEFER PENDING"

    line1 = f"{ts_str} {e_str}{label}  {cmd_display}"

    lines = [line1]
    if reason:
        lines.append(f"{_TREE_INDENT}  Reason: {reason}")
    lines.append(
        f"{_TREE_INDENT}  Approval ID: {approval_id}  Timeout: {int(timeout_s)}s"
    )

    return "\n".join(lines)


def _format_defer_resolved(
    event: dict,
    *,
    color: bool = True,
    no_emoji: bool = False,
) -> str:
    """Format a *defer_resolved* SSE event for terminal output.

    Example (colour stripped)::

        [10:31:10] ✅ DEFER RESOLVED: ALLOW
                      Approval ID: appr-abc-123
                      Reason: operator approved

    Or for a block/deny:

        [10:31:10] 🚫 DEFER RESOLVED: BLOCK
                      Approval ID: appr-abc-123
                      Reason: operator denied via watch CLI
    """
    hms = _timestamp_hms(event.get("timestamp"))
    approval_id = str(event.get("approval_id") or "unknown")
    resolved_decision = str(event.get("resolved_decision") or "unknown")
    resolved_reason = str(event.get("resolved_reason") or "")

    is_allow = resolved_decision in ("allow", "allow-once")

    if is_allow:
        e = _emoji("allow", no_emoji=no_emoji)
        status_color = "green"
        decision_label = "DEFER RESOLVED: ALLOW"
    else:
        e = _emoji("block", no_emoji=no_emoji)
        status_color = "red"
        decision_label = "DEFER RESOLVED: BLOCK"

    e_str = f"{e} " if e else ""
    ts_str = _c("grey", f"[{hms}]", color=color)
    label = _c(status_color, decision_label, color=color)

    lines = [f"{ts_str} {e_str}{label}"]
    lines.append(f"{_TREE_INDENT}  Approval ID: {approval_id}")
    if resolved_reason:
        lines.append(f"{_TREE_INDENT}  Reason: {resolved_reason}")

    return "\n".join(lines)


def _format_trajectory_alert(
    event: dict,
    *,
    color: bool = True,
    no_emoji: bool = False,
    compact: bool = False,
) -> str:
    """Format a multi-step trajectory alert for terminal output."""
    hms = _timestamp_hms(event.get("timestamp"))
    session_id = str(event.get("session_id") or "unknown")
    sequence_id = str(event.get("sequence_id") or "unknown")
    risk = str(event.get("risk_level") or "unknown")
    reason = str(event.get("reason") or "")
    handling = str(event.get("handling") or "broadcast")
    matched = event.get("matched_event_ids") or []
    matched_text = ", ".join(str(item) for item in matched) if matched else "(none)"

    e = _emoji("trajectory", no_emoji=no_emoji)
    e_str = f"{e} " if e else ""
    label = _c("red", f"{e_str}TRAJECTORY", color=color)
    ts_str = _c("grey", f"[{hms}]", color=color)

    if compact:
        return (
            f"{ts_str} {label}  {sequence_id}  "
            f"Session={session_id}  Risk={risk}  Handling={handling}"
        )

    lines = [f"{ts_str} {label}  {sequence_id}"]
    detail_items = [
        f"Session: {_c('grey', session_id, color=color)}",
        f"Risk: {_risk_display(risk, color=color, no_emoji=no_emoji)}",
        f"Handling: {_c('grey', handling, color=color)}",
    ]
    if reason:
        detail_items.append(f"Reason: {_c('grey', reason, color=color)}")
    detail_items.append(f"Matched events: {_c('grey', matched_text, color=color)}")

    for i, item in enumerate(detail_items):
        connector = "└─" if i == len(detail_items) - 1 else "├─"
        lines.append(f"{_TREE_INDENT}{connector} {item}")
    return "\n".join(lines)


def _format_post_action_finding(
    event: dict,
    *,
    color: bool = True,
    no_emoji: bool = False,
    compact: bool = False,
) -> str:
    """Format a post-action guardrail finding for terminal output."""
    hms = _timestamp_hms(event.get("timestamp"))
    session_id = str(event.get("session_id") or "unknown")
    tier = str(event.get("tier") or "unknown")
    score = event.get("score")
    handling = str(event.get("handling") or "broadcast")
    patterns = event.get("patterns_matched") or []
    patterns_text = ", ".join(str(item) for item in patterns) if patterns else "(none)"

    e = _emoji("post_action", no_emoji=no_emoji)
    e_str = f"{e} " if e else ""
    label = _c("magenta", f"{e_str}POST-ACTION", color=color)
    ts_str = _c("grey", f"[{hms}]", color=color)
    if compact:
        return (
            f"{ts_str} {label}  {tier}  "
            f"Session={session_id}  Score={score}  Handling={handling}"
        )

    lines = [f"{ts_str} {label}  {tier}"]
    detail_items = [
        f"Session: {_c('grey', session_id, color=color)}",
        f"Score: {_c('grey', str(score), color=color)}",
        f"Handling: {_c('grey', handling, color=color)}",
        f"Patterns: {_c('grey', patterns_text, color=color)}",
    ]
    for sanitize_line in _format_sanitize_summary(event.get("sanitize_advisory")):
        detail_items.append(_c("yellow", sanitize_line, color=color))
    for i, item in enumerate(detail_items):
        connector = "└─" if i == len(detail_items) - 1 else "├─"
        lines.append(f"{_TREE_INDENT}{connector} {item}")
    return "\n".join(lines)


def _format_pattern_evolved(
    event: dict,
    *,
    color: bool = True,
    no_emoji: bool = False,
    compact: bool = False,
) -> str:
    """Format a self-evolving pattern lifecycle event."""
    hms = _timestamp_hms(event.get("timestamp"))
    pattern_id = str(event.get("pattern_id") or "unknown")
    result = str(event.get("result") or event.get("status") or "unknown")
    confirmed = event.get("confirmed")

    e = _emoji("pattern_evolved", no_emoji=no_emoji)
    e_str = f"{e} " if e else ""
    label = _c("cyan", f"{e_str}PATTERN EVOLVED", color=color)
    ts_str = _c("grey", f"[{hms}]", color=color)

    if compact:
        return f"{ts_str} {label}  {pattern_id}  Result={result}"

    lines = [f"{ts_str} {label}  {pattern_id}"]
    detail_items = [f"Result: {_c('grey', result, color=color)}"]
    if confirmed is not None:
        detail_items.append(f"Confirmed: {_c('grey', str(bool(confirmed)).lower(), color=color)}")

    for i, item in enumerate(detail_items):
        connector = "└─" if i == len(detail_items) - 1 else "├─"
        lines.append(f"{_TREE_INDENT}{connector} {item}")
    return "\n".join(lines)


def _format_pattern_candidate(
    event: dict,
    *,
    color: bool = True,
    no_emoji: bool = False,
    compact: bool = False,
) -> str:
    """Format a new candidate extracted by the evolution manager."""
    hms = _timestamp_hms(event.get("timestamp"))
    pattern_id = str(event.get("pattern_id") or "unknown")
    session_id = str(event.get("session_id") or "unknown")
    status = str(event.get("status") or "candidate")
    source_framework = str(event.get("source_framework") or "unknown")

    e = _emoji("pattern_candidate", no_emoji=no_emoji)
    e_str = f"{e} " if e else ""
    label = _c("yellow", f"{e_str}PATTERN CANDIDATE", color=color)
    ts_str = _c("grey", f"[{hms}]", color=color)

    if compact:
        return (
            f"{ts_str} {label}  {pattern_id}  "
            f"Session={session_id}  Status={status}  Framework={source_framework}"
        )

    lines = [f"{ts_str} {label}  {pattern_id}"]
    detail_items = [
        f"Session: {_c('grey', session_id, color=color)}",
        f"Status: {_c('grey', status, color=color)}",
        f"Framework: {_c('grey', source_framework, color=color)}",
    ]
    for i, item in enumerate(detail_items):
        connector = "└─" if i == len(detail_items) - 1 else "├─"
        lines.append(f"{_TREE_INDENT}{connector} {item}")
    return "\n".join(lines)


def _format_budget_exhausted(
    event: dict,
    *,
    color: bool = True,
    no_emoji: bool = False,
    compact: bool = False,
) -> str:
    """Format a budget exhaustion event for terminal output."""
    hms = _timestamp_hms(event.get("timestamp"))
    provider = str(event.get("provider") or "unknown")
    tier = str(event.get("tier") or "unknown")
    status = str(event.get("status") or "unknown")
    cost = event.get("cost_usd")
    budget = event.get("budget") or {}

    def _format_usd(value: Any) -> str:
        try:
            return f"${float(value):.2f}"
        except (TypeError, ValueError):
            return str(value)

    spent = budget.get("daily_spend_usd")
    limit = budget.get("daily_budget_usd")
    remaining = budget.get("remaining_usd")

    e = _emoji("budget_exhausted", no_emoji=no_emoji)
    e_str = f"{e} " if e else ""
    label = _c("red", f"{e_str}BUDGET EXHAUSTED", color=color)
    ts_str = _c("grey", f"[{hms}]", color=color)

    line = (
        f"{ts_str} {label}  "
        f"provider={provider} tier={tier} status={status} "
        f"cost={_format_usd(cost)} "
        f"budget={_format_usd(spent)}/{_format_usd(limit)} "
        f"remaining={_format_usd(remaining)}"
    )
    return line


def _format_l3_advisory_snapshot(
    event: dict,
    *,
    color: bool = True,
    no_emoji: bool = False,
    compact: bool = False,
) -> str:
    hms = _timestamp_hms(event.get("timestamp"))
    session_id = str(event.get("session_id") or "unknown")
    snapshot_id = str(event.get("snapshot_id") or "unknown")
    trigger_reason = str(event.get("trigger_reason") or "unknown")
    event_range = event.get("event_range") if isinstance(event.get("event_range"), dict) else {}
    from_id = event_range.get("from_record_id", "-")
    to_id = event_range.get("to_record_id", "-")

    e = _emoji("l3_advisory", no_emoji=no_emoji)
    e_str = f"{e} " if e else ""
    label = _c("cyan", f"{e_str}L3 ADVISORY SNAPSHOT", color=color)
    ts_str = _c("grey", f"[{hms}]", color=color)

    if compact:
        return (
            f"{ts_str} {label}  {snapshot_id}  "
            f"Session={session_id} Trigger={trigger_reason} Range={from_id}->{to_id}"
        )

    lines = [f"{ts_str} {label}  {snapshot_id}"]
    for i, item in enumerate([
        f"Session: {_c('grey', session_id, color=color)}",
        f"Trigger: {_c('grey', trigger_reason, color=color)}",
        f"Range: {_c('grey', f'{from_id}->{to_id}', color=color)}",
    ]):
        connector = "└─" if i == 2 else "├─"
        lines.append(f"{_TREE_INDENT}{connector} {item}")
    return "\n".join(lines)


def _format_l3_advisory_review(
    event: dict,
    *,
    color: bool = True,
    no_emoji: bool = False,
    compact: bool = False,
) -> str:
    hms = _timestamp_hms(event.get("timestamp"))
    session_id = str(event.get("session_id") or "unknown")
    review_id = str(event.get("review_id") or "unknown")
    snapshot_id = str(event.get("snapshot_id") or "unknown")
    risk_level = str(event.get("risk_level") or "unknown")
    action = str(event.get("recommended_operator_action") or "inspect")
    l3_state = str(event.get("l3_state") or "unknown")
    l3_reason_code = str(event.get("l3_reason_code") or "").strip()
    action_label = _operator_display("operator_action", action)
    l3_state_label = _operator_display("l3_state", l3_state)

    e = _emoji("l3_advisory", no_emoji=no_emoji)
    e_str = f"{e} " if e else ""
    label = _c("yellow", f"{e_str}L3 ADVISORY REVIEW", color=color)
    ts_str = _c("grey", f"[{hms}]", color=color)
    risk = _risk_display(risk_level, color=color, no_emoji=no_emoji)

    if compact:
        return (
            f"{ts_str} {label}  {review_id}  "
            f"Session={session_id} Risk={risk_level} State={l3_state_label} Action={action_label}"
        )

    lines = [f"{ts_str} {label}  {review_id}"]
    detail_items = [
        f"Session: {_c('grey', session_id, color=color)}",
        f"Snapshot: {_c('grey', snapshot_id, color=color)}",
        f"Risk: {risk}",
        f"State: {_c('grey', l3_state_label, color=color)}",
        f"Action: {_c('grey', action_label, color=color)}",
    ]
    if l3_reason_code:
        detail_items.append(
            f"Provider/config: {_c('grey', _operator_display('l3_reason_code', l3_reason_code), color=color)}"
        )
    if event.get("advisory_only") is True:
        if event.get("canonical_decision_mutated") is False:
            boundary = "advisory only; canonical unchanged"
        else:
            boundary = "advisory only"
        detail_items.append(f"Boundary: {_c('grey', boundary, color=color)}")

    for i, item in enumerate(detail_items):
        connector = "└─" if i == len(detail_items) - 1 else "├─"
        lines.append(f"{_TREE_INDENT}{connector} {item}")
    return "\n".join(lines)


def _format_l3_advisory_job(
    event: dict,
    *,
    color: bool = True,
    no_emoji: bool = False,
    compact: bool = False,
) -> str:
    hms = _timestamp_hms(event.get("timestamp"))
    session_id = str(event.get("session_id") or "unknown")
    job_id = str(event.get("job_id") or "unknown")
    snapshot_id = str(event.get("snapshot_id") or "unknown")
    review_id = str(event.get("review_id") or "").strip()
    job_state = str(event.get("job_state") or "unknown")
    runner = str(event.get("runner") or "unknown")
    error = str(event.get("error") or "").strip()
    job_state_label = _operator_display("job_state", job_state)
    runner_label = _operator_display("runner", runner)

    e = _emoji("l3_advisory", no_emoji=no_emoji)
    e_str = f"{e} " if e else ""
    label = _c("magenta", f"{e_str}L3 ADVISORY JOB", color=color)
    ts_str = _c("grey", f"[{hms}]", color=color)

    if compact:
        review_segment = f" Review={review_id}" if review_id else ""
        return (
            f"{ts_str} {label}  {job_id}  "
            f"Session={session_id} State={job_state_label} Runner={runner_label}{review_segment}"
        )

    lines = [f"{ts_str} {label}  {job_id}"]
    detail_items = [
        f"Session: {_c('grey', session_id, color=color)}",
        f"Snapshot: {_c('grey', snapshot_id, color=color)}",
        f"State: {_c('grey', job_state_label, color=color)}",
        f"Runner: {_c('grey', runner_label, color=color)}",
    ]
    if review_id:
        detail_items.append(f"Review: {_c('grey', review_id, color=color)}")
    if error:
        detail_items.append(f"Error: {_c('grey', error, color=color)}")
    transition_hint = _l3_advisory_job_transition_hint(job_state)
    if transition_hint:
        detail_items.append(f"Next: {_c('grey', transition_hint, color=color)}")
    detail_items.append(
        f"Boundary: {_c('grey', 'frozen snapshot; explicit run only', color=color)}"
    )

    for i, item in enumerate(detail_items):
        connector = "└─" if i == len(detail_items) - 1 else "├─"
        lines.append(f"{_TREE_INDENT}{connector} {item}")
    return "\n".join(lines)


def _format_l3_advisory_action(
    event: dict,
    *,
    color: bool = True,
    no_emoji: bool = False,
    compact: bool = False,
) -> str:
    hms = _timestamp_hms(event.get("timestamp") or event.get("created_at"))
    session_id = str(event.get("session_id") or "unknown")
    review_id = str(event.get("review_id") or "unknown")
    snapshot_id = str(event.get("snapshot_id") or "unknown")
    job_id = str(event.get("job_id") or "").strip()
    risk_level = str(event.get("risk_level") or "unknown")
    action = str(event.get("recommended_operator_action") or "inspect")
    action_label = _operator_display("operator_action", action)
    source_range = event.get("source_record_range") if isinstance(event.get("source_record_range"), dict) else {}
    from_id = source_range.get("from_record_id", "-")
    to_id = source_range.get("to_record_id", "-")

    e = _emoji("l3_advisory", no_emoji=no_emoji)
    e_str = f"{e} " if e else ""
    label = _c("yellow", f"{e_str}L3 ADVISORY ACTION", color=color)
    ts_str = _c("grey", f"[{hms}]", color=color)

    if compact:
        return (
            f"{ts_str} {label}  {review_id}  "
            f"Session={session_id} Risk={risk_level} Action={action_label} "
            "advisory only; canonical unchanged"
        )

    detail_items = [
        f"Session: {_c('grey', session_id, color=color)}",
        f"Snapshot: {_c('grey', snapshot_id, color=color)}",
        f"Review: {_c('grey', review_id, color=color)}",
        f"Risk: {_risk_display(risk_level, color=color, no_emoji=no_emoji)}",
        f"Action: {_c('grey', action_label, color=color)}",
        f"Range: {_c('grey', f'{from_id}->{to_id}', color=color)}",
        f"Boundary: {_c('grey', 'advisory only; canonical unchanged', color=color)}",
    ]
    if job_id:
        detail_items.insert(3, f"Job: {_c('grey', job_id, color=color)}")
    summary = str(event.get("summary") or "").strip()
    if summary:
        detail_items.append(f"Summary: {_c('grey', summary, color=color)}")

    lines = [f"{ts_str} {label}  {review_id}"]
    for i, item in enumerate(detail_items):
        connector = "└─" if i == len(detail_items) - 1 else "├─"
        lines.append(f"{_TREE_INDENT}{connector} {item}")
    return "\n".join(lines)


def _format_adapter_effect_result(
    event: dict,
    *,
    color: bool = True,
    no_emoji: bool = False,
    compact: bool = False,
) -> str:
    hms = _timestamp_hms(event.get("timestamp"))
    summary = event.get("adapter_effect_result_summary")
    summary = summary if isinstance(summary, dict) else {}
    effect_id = str(event.get("effect_id") or summary.get("effect_id") or "unknown")
    adapter = str(summary.get("adapter") or "unknown")
    enforced = summary.get("enforced") or []
    degraded = summary.get("degraded") or summary.get("unsupported") or []
    status = "ENFORCED" if enforced else "DEGRADED" if degraded else "OBSERVED"
    status_color = "green" if enforced else "yellow" if degraded else "grey"
    label = _c(status_color, f"ADAPTER EFFECT {status}", color=color)
    ts_str = _c("grey", f"[{hms}]", color=color)
    if compact:
        return f"{ts_str} {label}  {effect_id} adapter={adapter}"
    detail_items = [
        f"Adapter: {_c('grey', adapter, color=color)}",
        f"Requested: {_c('grey', ', '.join(summary.get('requested') or []) or 'none', color=color)}",
    ]
    if enforced:
        detail_items.append(f"Enforced: {_c('green', ', '.join(enforced), color=color)}")
    if degraded:
        detail_items.append(f"Degraded: {_c('yellow', ', '.join(degraded), color=color)}")
    if summary.get("degrade_reason"):
        detail_items.append(f"Reason: {_c('grey', str(summary.get('degrade_reason')), color=color)}")
    lines = [f"{ts_str} {label}  {effect_id}"]
    for i, item in enumerate(detail_items):
        connector = "└─" if i == len(detail_items) - 1 else "├─"
        lines.append(f"{_TREE_INDENT}{connector} {item}")
    return "\n".join(lines)


def format_event(
    event: dict,
    *,
    color: bool = True,
    json_mode: bool = False,
    verbose: bool = False,
    no_emoji: bool = False,
    compact: bool = False,
) -> str:
    """Unified dispatcher: routes to the appropriate formatter.

    If *json_mode* is ``True``, returns ``json.dumps(event)`` regardless of
    event type.
    """
    if json_mode:
        return json.dumps(event)

    event_type = str(event.get("type") or "unknown")

    if event_type == "decision":
        return format_decision(
            event, color=color, verbose=verbose, no_emoji=no_emoji, compact=compact
        )
    if event_type == "alert":
        return format_alert(event, color=color, no_emoji=no_emoji)
    if event_type == "session_start":
        return _format_session_start(event, color=color, no_emoji=no_emoji)
    if event_type == "session_risk_change":
        return _format_risk_change(event, color=color, no_emoji=no_emoji)
    if event_type == "session_enforcement_change":
        return _format_enforcement_change(event, color=color, no_emoji=no_emoji)
    if event_type == "defer_pending":
        return _format_defer_pending(event, color=color, no_emoji=no_emoji)
    if event_type == "defer_resolved":
        return _format_defer_resolved(event, color=color, no_emoji=no_emoji)
    if event_type == "trajectory_alert":
        return _format_trajectory_alert(
            event, color=color, no_emoji=no_emoji, compact=compact
        )
    if event_type == "post_action_finding":
        return _format_post_action_finding(
            event, color=color, no_emoji=no_emoji, compact=compact
        )
    if event_type == "pattern_evolved":
        return _format_pattern_evolved(
            event, color=color, no_emoji=no_emoji, compact=compact
        )
    if event_type == "pattern_candidate":
        return _format_pattern_candidate(
            event, color=color, no_emoji=no_emoji, compact=compact
        )
    if event_type == "budget_exhausted":
        return _format_budget_exhausted(
            event, color=color, no_emoji=no_emoji, compact=compact
        )
    if event_type == "l3_advisory_snapshot":
        return _format_l3_advisory_snapshot(
            event, color=color, no_emoji=no_emoji, compact=compact
        )
    if event_type == "l3_advisory_review":
        return _format_l3_advisory_review(
            event, color=color, no_emoji=no_emoji, compact=compact
        )
    if event_type == "l3_advisory_job":
        return _format_l3_advisory_job(
            event, color=color, no_emoji=no_emoji, compact=compact
        )
    if event_type == "l3_advisory_action":
        return _format_l3_advisory_action(
            event, color=color, no_emoji=no_emoji, compact=compact
        )
    if event_type == "adapter_effect_result":
        return _format_adapter_effect_result(
            event, color=color, no_emoji=no_emoji, compact=compact
        )

    # Fallback: compact JSON
    return json.dumps(event)


# ── Interactive DEFER handler ────────────────────────────────────────────────

SAFETY_MARGIN_S = 5  # seconds before OpenClaw timeout to stop accepting input


async def handle_defer_interactive(
    event: dict,
    *,
    resolve_fn: Callable[..., Any],
    _input_fn: Callable[[str], str] | None = None,
) -> str:
    """Handle a DEFER decision interactively.

    Returns one of: ``"allow"``, ``"deny"``, ``"skip"``, or ``"expired"``.

    Parameters
    ----------
    event:
        The SSE decision event dict (must contain ``approval_id`` and
        optionally ``expires_at`` in epoch-milliseconds).
    resolve_fn:
        ``async fn(approval_id, decision, *, reason=None) -> bool``
        called to resolve the approval in the upstream gateway.
    _input_fn:
        Injectable synchronous callable for testing. Receives the prompt
        string and returns the user answer.  When ``None`` (production),
        uses ``asyncio`` + blocking ``input()`` with a timeout.
    """
    approval_id = event.get("approval_id")
    if not approval_id:
        return "skip"

    # ── compute remaining time budget ────────────────────────────────────
    expires_at_ms = event.get("expires_at")
    remaining: float | None = None
    if expires_at_ms is not None:
        remaining = (expires_at_ms / 1000) - time.time() - SAFETY_MARGIN_S
        if remaining <= 0:
            return "expired"

    # ── build prompt ─────────────────────────────────────────────────────
    reason = event.get("reason") or ""
    command = event.get("command") or ""
    timeout_hint = f" (timeout in {int(remaining)}s)" if remaining else ""
    prompt = (
        f"\n  Command: {command}\n"
        f"  Reason:  {reason}\n"
        f"  [A]llow  [D]eny  [S]kip{timeout_hint} > "
    )

    # ── get user input ───────────────────────────────────────────────────
    try:
        if _input_fn is not None:
            answer = _input_fn(prompt)
        else:
            loop = asyncio.get_running_loop()
            if remaining is not None:
                answer = await asyncio.wait_for(
                    loop.run_in_executor(None, input, prompt),
                    timeout=remaining,
                )
            else:
                answer = await loop.run_in_executor(None, input, prompt)
    except (asyncio.TimeoutError, EOFError):
        return "skip"

    choice = answer.strip().lower()

    if choice == "a":
        await resolve_fn(approval_id, "allow-once")
        return "allow"
    elif choice == "d":
        await resolve_fn(
            approval_id, "deny", reason="operator denied via watch CLI",
        )
        return "deny"
    # 's', empty, or anything else → skip
    return "skip"


# ── CLI runner ───────────────────────────────────────────────────────────────

_RECONNECT_DELAY = 3.0


async def _resolve_defer_approval(
    gateway_url: str,
    approval_id: str,
    decision: str,
    *,
    token: str | None = None,
    reason: str | None = None,
) -> bool:
    """Resolve a pending approval through the gateway HTTP API."""

    payload = json.dumps(
        {
            "approval_id": approval_id,
            "decision": decision,
            "reason": reason or "",
        }
    ).encode("utf-8")
    headers = {
        "Content-Type": "application/json",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"

    request = urllib.request.Request(
        f"{gateway_url.rstrip('/')}/ahp/resolve",
        data=payload,
        headers=headers,
        method="POST",
    )

    def _send_request() -> bool:
        with urlopen_gateway(request, timeout=10) as response:
            body = response.read().decode("utf-8")
        if not body:
            return True
        try:
            data = json.loads(body)
        except json.JSONDecodeError:
            return True
        return data.get("status") == "ok"

    loop = asyncio.get_running_loop()
    try:
        return await loop.run_in_executor(None, _send_request)
    except (urllib.error.URLError, OSError):
        return False


def _prepare_interactive_defer_event(event: dict[str, Any]) -> dict[str, Any]:
    """Attach expires_at for prompts when SSE only carries timeout_s."""
    prompt_event = dict(event)
    if prompt_event.get("expires_at") is not None:
        return prompt_event

    timeout_s = prompt_event.get("timeout_s")
    try:
        if timeout_s is not None:
            prompt_event["expires_at"] = int((time.time() + float(timeout_s)) * 1000)
    except (TypeError, ValueError):
        pass
    return prompt_event


def _prefetch_sessions(
    tracker: SessionTracker,
    gateway_url: str,
    headers: dict[str, str],
) -> None:
    """Pre-populate session info from ``/report/sessions`` (best-effort).

    This avoids "Framework: unknown" when ``watch`` connects after sessions
    have already started (CS-024).
    """
    sessions_url = f"{gateway_url.rstrip('/')}/report/sessions"
    try:
        req = urllib.request.Request(sessions_url, headers=headers)
        with urlopen_gateway(req, timeout=3) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        for s in data.get("sessions", []):
            sid = s.get("session_id")
            if not sid:
                continue
            tracker.session_info[sid] = {
                "agent_id": str(s.get("agent_id") or "unknown"),
                "framework": str(
                    s.get("source_framework")
                    or s.get("caller_adapter")
                    or "unknown"
                ),
                "started": _timestamp_hms(s.get("first_event_at")),
            }
    except Exception:
        pass  # Best-effort; watch still works without pre-populated info


def run_watch(
    gateway_url: str,
    token: str | None = None,
    filter_types: str | None = None,
    priority_only: bool = False,
    json_mode: bool = False,
    color: bool = True,
    interactive: bool = False,
    verbose: bool = False,
    no_emoji: bool = False,
    compact: bool = False,
) -> None:
    """Connect to the Gateway SSE stream and print events.

    This is a **blocking** call that runs until interrupted with ``Ctrl-C``.

    Parameters
    ----------
    gateway_url:
        Base URL of the Supervision Gateway (e.g. ``http://localhost:9100``).
    token:
        Optional Bearer token for authentication.
    filter_types:
        Comma-separated event types to subscribe to
        (e.g. ``"decision,alert"``).
    priority_only:
        If ``True``, subscribe to an operator-priority profile and merge
        those types with any explicit ``filter_types``.
    json_mode:
        If ``True``, output raw JSON instead of formatted text.
    color:
        If ``False``, strip ANSI colour codes from output.
    interactive:
        If ``True``, prompt operator to Allow/Deny/Skip on DEFER decisions.
    verbose:
        If ``True``, show detailed info for all decisions (including ALLOW).
    no_emoji:
        If ``True``, disable emoji in output.
    compact:
        If ``True``, use compact session separators instead of Unicode boxes.
    """
    url = _build_stream_url(
        gateway_url,
        filter_types=filter_types,
        priority_only=priority_only,
    )

    headers: dict[str, str] = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    tracker = SessionTracker()

    # CS-024: Pre-populate session info from existing sessions so that
    # "Framework: unknown" doesn't appear when watch connects mid-session.
    _prefetch_sessions(tracker, gateway_url, headers)

    while True:
        try:
            req = urllib.request.Request(url, headers=headers)
            with urlopen_gateway(req) as resp:
                if not json_mode:
                    print(
                        _c("bold", f"Connected to {gateway_url}", color=color),
                        flush=True,
                    )
                for raw_line in resp:
                    line = raw_line.decode("utf-8", errors="replace").rstrip("\n\r")
                    parsed = parse_sse_line(line)
                    if parsed is None:
                        continue

                    if json_mode:
                        output = format_event(parsed, json_mode=True)
                        if output:
                            print(output, flush=True)
                        continue

                    # ── session tracking ─────────────────────────────────
                    was_in_session = tracker.in_session
                    before_text, after_text = tracker.update(
                        parsed, color=color, compact=compact, no_emoji=no_emoji
                    )
                    if before_text:
                        print(before_text, flush=True)

                    # ── format event ─────────────────────────────────────
                    output = format_event(
                        parsed,
                        color=color,
                        json_mode=False,
                        verbose=verbose,
                        no_emoji=no_emoji,
                        compact=compact,
                    )
                    if output:
                        # Determine whether to add "│ " session prefix.
                        # • For session_end (has after_text): use pre-update state.
                        # • For all others: use post-update state.
                        use_prefix = (
                            (after_text is not None and was_in_session)
                            or (after_text is None and tracker.in_session)
                        ) and not compact
                        if use_prefix:
                            lines = output.split("\n")
                            prefixed = "\n".join(
                                f"{_SESSION_PREFIX}{ln}" for ln in lines
                            )
                            print(prefixed, flush=True)
                        else:
                            print(output, flush=True)

                    if interactive and parsed.get("type") == "defer_pending":
                        prompt_event = _prepare_interactive_defer_event(parsed)
                        asyncio.run(
                            handle_defer_interactive(
                                prompt_event,
                                resolve_fn=lambda approval_id, decision, *, reason=None: _resolve_defer_approval(
                                    gateway_url,
                                    approval_id,
                                    decision,
                                    token=token,
                                    reason=reason,
                                ),
                            )
                        )

                    if after_text:
                        print(after_text, flush=True)

        except KeyboardInterrupt:
            if not json_mode:
                # Close any open session box on graceful exit
                if tracker.in_session:
                    footer = tracker._format_footer(color=color, compact=compact)
                    print(footer, flush=True)
                print(
                    _c("bold", "\nDisconnected.", color=color),
                    file=sys.stderr,
                    flush=True,
                )
            break

        except (urllib.error.URLError, OSError) as exc:
            if not json_mode:
                print(
                    _c(
                        "yellow",
                        f"Connection failed: {exc} — retrying in {_RECONNECT_DELAY}s ...",
                        color=color,
                    ),
                    file=sys.stderr,
                    flush=True,
                )
            time.sleep(_RECONNECT_DELAY)
