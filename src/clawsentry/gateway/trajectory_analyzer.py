"""
Multi-step attack trajectory analyzer — detects correlated attack sequences
across session events using sliding window matching.

Design basis: docs/plans/2026-03-23-e4-phase1-design-v1.2.md section 3.3
"""

from __future__ import annotations

import logging
import re
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

_VALID_RISK_LEVELS = frozenset({"low", "medium", "high", "critical"})

@dataclass
class AttackSequence:
    """Definition of a multi-step attack pattern."""
    id: str
    description: str
    risk_level: str  # low / medium / high / critical
    steps: list[dict[str, Any]]
    within_events: int = 10
    within_seconds: float = 60.0

    def __post_init__(self) -> None:
        self.risk_level = self.risk_level.lower()
        if self.risk_level not in _VALID_RISK_LEVELS:
            raise ValueError(f"risk_level must be one of {_VALID_RISK_LEVELS}, got '{self.risk_level}'")


@dataclass
class TrajectoryMatch:
    """Result of a trajectory match."""
    sequence_id: str
    risk_level: str
    matched_event_ids: list[str]
    reason: str


@dataclass
class _BufferedEvent:
    """Lightweight event stored in per-session ring buffer."""
    event_id: str
    tool_name: str
    path: str
    command: str
    ts: float


# ---------------------------------------------------------------------------
# Built-in attack sequences
# ---------------------------------------------------------------------------

# _SENSITIVE_FILE_RE: narrower set used by exfil-credential sequence
# _CREDENTIAL_FILE_RE: broader set used by secret-harvest sequence (includes .p12/.pfx/.jks/.keystore/.aws/.ssh)
_SENSITIVE_FILE_RE = re.compile(
    r"\.env$|\.pem$|\.key$|id_rsa|id_ed25519|credentials|\.secret|\.token|\.password",
    re.IGNORECASE,
)

_NETWORK_TOOLS = {"http_request", "web_fetch", "curl", "wget"}

_DOWNLOAD_RE = re.compile(r"(curl|wget)\s+.*https?://", re.IGNORECASE)
_CHMOD_EXEC_RE = re.compile(r"chmod\s+\+?[0-7]*x", re.IGNORECASE)
_SHELL_CONFIG_RE = re.compile(
    r"\.(bashrc|bash_profile|profile|zshrc|zprofile)$", re.IGNORECASE,
)
_RECON_RE = re.compile(
    r"\b(uname|id|whoami|hostname|cat\s+/etc/(os-release|issue|passwd)|lsb_release|arch)\b",
    re.IGNORECASE,
)
_PRIVESC_RE = re.compile(
    r"\bsudo\b.*\b(chmod|chown|rm|mv|cp|useradd|usermod|visudo|passwd)\b",
    re.IGNORECASE,
)
_CREDENTIAL_FILE_RE = re.compile(
    r"\.(env|pem|key|p12|pfx|jks|keystore)$|id_rsa|id_ed25519|credentials|\.secret|\.token|\.password|\.aws/|\.ssh/",
    re.IGNORECASE,
)
_TMP_PATH_RE = re.compile(r"^/tmp/|^/var/tmp/|^C:\\Temp\\", re.IGNORECASE)
_EXFIL_TMP_RE = re.compile(r"(curl|wget).*(/tmp/|/var/tmp/)", re.IGNORECASE)


def _default_sequences() -> list[AttackSequence]:
    """Return the 5 built-in attack sequences."""
    return [
        AttackSequence(
            id="exfil-credential",
            description="Read sensitive file then make network request",
            risk_level="critical",
            steps=[
                {"type": "sensitive_file_read"},
                {"type": "network_request"},
            ],
            within_events=5,
            within_seconds=60.0,
        ),
        AttackSequence(
            id="backdoor-install",
            description="Download remote script then make executable or write to shell config",
            risk_level="critical",
            steps=[
                {"type": "remote_download"},
                {"type": "make_executable_or_shell_config"},
            ],
            within_events=5,
            within_seconds=60.0,
        ),
        AttackSequence(
            id="recon-then-exploit",
            description="System enumeration followed by privilege escalation",
            risk_level="critical",
            steps=[
                {"type": "recon_command"},
                {"type": "privilege_escalation"},
            ],
            within_events=8,
            within_seconds=120.0,
        ),
        AttackSequence(
            id="secret-harvest",
            description="Multiple credential file reads in short window",
            risk_level="high",
            steps=[
                {"type": "credential_file_read", "min_count": 3},
            ],
            within_events=10,
            within_seconds=30.0,
        ),
        AttackSequence(
            id="staged-exfil",
            description="Write to temp directory then exfiltrate from temp",
            risk_level="high",
            steps=[
                {"type": "tmp_write"},
                {"type": "tmp_exfil"},
            ],
            within_events=10,
            within_seconds=120.0,
        ),
    ]


# ---------------------------------------------------------------------------
# Step matchers
# ---------------------------------------------------------------------------

def _matches_step(step: dict[str, Any], evt: _BufferedEvent) -> bool:
    """Check if a buffered event matches a step definition."""
    step_type = step.get("type", "")

    if step_type == "sensitive_file_read":
        return (
            evt.tool_name.lower() in ("read_file", "read", "cat")
            and bool(_SENSITIVE_FILE_RE.search(evt.path))
        )

    if step_type == "network_request":
        return (
            evt.tool_name.lower() in _NETWORK_TOOLS
            or bool(re.search(r"\b(curl|wget)\b", evt.command, re.IGNORECASE))
        )

    if step_type == "remote_download":
        return bool(_DOWNLOAD_RE.search(evt.command))

    if step_type == "make_executable_or_shell_config":
        return (
            bool(_CHMOD_EXEC_RE.search(evt.command))
            or (
                evt.tool_name.lower() in ("write_file", "write", "edit_file", "edit")
                and bool(_SHELL_CONFIG_RE.search(evt.path))
            )
        )

    if step_type == "recon_command":
        return bool(_RECON_RE.search(evt.command))

    if step_type == "privilege_escalation":
        return bool(_PRIVESC_RE.search(evt.command))

    if step_type == "credential_file_read":
        return (
            evt.tool_name.lower() in ("read_file", "read", "cat")
            and bool(_CREDENTIAL_FILE_RE.search(evt.path))
        )

    if step_type == "tmp_write":
        return (
            evt.tool_name.lower() in ("write_file", "write")
            and bool(_TMP_PATH_RE.search(evt.path))
        )

    if step_type == "tmp_exfil":
        return bool(_EXFIL_TMP_RE.search(evt.command))

    # tool_names check (for custom sequences)
    if "tool_names" in step:
        return evt.tool_name.lower() in [t.lower() for t in step["tool_names"]]

    return False


# ---------------------------------------------------------------------------
# Analyzer
# ---------------------------------------------------------------------------

_DEFAULT_MAX_EVENTS = 50
_DEFAULT_MAX_SESSIONS = 10_000


class TrajectoryAnalyzer:
    """Detects multi-step attack sequences within a session's event history.

    Usage::

        analyzer = TrajectoryAnalyzer()
        matches = analyzer.record(event_dict)
        for m in matches:
            print(m.sequence_id, m.risk_level)
    """

    def __init__(
        self,
        sequences: Optional[list[AttackSequence]] = None,
        max_events_per_session: int = _DEFAULT_MAX_EVENTS,
        max_sessions: int = _DEFAULT_MAX_SESSIONS,
    ) -> None:
        self.sequences = sequences if sequences is not None else _default_sequences()
        self._max_events = max(max_events_per_session, 2)
        self._max_sessions = max(max_sessions, 1)
        self._buffers: dict[str, deque[_BufferedEvent]] = {}
        # Tracks emitted matches to prevent duplicate SSE alerts.
        # Structure: {session_id: {(sequence_id, frozenset(matched_event_ids))}}
        self._emitted: dict[str, set[tuple[str, frozenset[str]]]] = {}

    def record(self, event: dict[str, Any]) -> list[TrajectoryMatch]:
        """Record an event and return any newly matched attack sequences.

        Parameters
        ----------
        event : dict
            Must contain ``session_id``, ``tool_name``, ``event_id``.
            May contain ``occurred_at_ts`` (float), ``payload.path``,
            ``payload.command``.
        """
        session_id = str(event.get("session_id", ""))
        if not session_id:
            return []

        payload = event.get("payload") or {}
        buf_evt = _BufferedEvent(
            event_id=str(event.get("event_id", "")),
            tool_name=str(event.get("tool_name", "")),
            path=str(payload.get("path", payload.get("file_path", ""))),
            command=str(payload.get("command", "")),
            ts=float(event.get("occurred_at_ts", 0.0) or time.time()),
        )

        buf = self._buffers.get(session_id)
        if buf is None:
            buf = deque(maxlen=self._max_events)
            self._buffers[session_id] = buf
            self._evict_if_needed()
        else:
            # Move to end for LRU eviction ordering
            self._buffers[session_id] = self._buffers.pop(session_id)
        buf.append(buf_evt)

        return self._check_sequences(session_id, buf)

    # -- internal -----------------------------------------------------------

    def _evict_if_needed(self) -> None:
        while len(self._buffers) > self._max_sessions:
            oldest = next(iter(self._buffers))
            del self._buffers[oldest]
            self._emitted.pop(oldest, None)

    def _check_sequences(
        self,
        session_id: str,
        buf: deque[_BufferedEvent],
    ) -> list[TrajectoryMatch]:
        matches: list[TrajectoryMatch] = []
        emitted_for_session = self._emitted.setdefault(session_id, set())
        max_dedup_entries = self._max_events * max(len(self.sequences), 1)
        for seq in self.sequences:
            m = self._match_sequence(seq, buf)
            if m is None:
                continue
            dedup_key = (m.sequence_id, frozenset(m.matched_event_ids))
            if dedup_key in emitted_for_session:
                continue
            emitted_for_session.add(dedup_key)
            matches.append(m)
        # Cap dedup set to prevent unbounded memory growth
        if len(emitted_for_session) > max_dedup_entries:
            emitted_for_session.clear()
        return matches

    def _match_sequence(
        self,
        seq: AttackSequence,
        buf: deque[_BufferedEvent],
    ) -> Optional[TrajectoryMatch]:
        if not seq.steps:
            return None

        events = list(buf)
        if not events:
            return None
        current_evt = events[-1]

        # Determine the window
        window_events = events[-seq.within_events:]
        if seq.within_seconds > 0:
            cutoff = current_evt.ts - seq.within_seconds
            window_events = [e for e in window_events if e.ts >= cutoff]

        if len(window_events) < len(seq.steps):
            return None

        # Special case: count-based steps (e.g., secret-harvest)
        if len(seq.steps) == 1 and "min_count" in seq.steps[0]:
            return self._match_count_step(seq, window_events)

        # Ordered multi-step matching
        return self._match_ordered_steps(seq, window_events)

    def _match_count_step(
        self,
        seq: AttackSequence,
        window: list[_BufferedEvent],
    ) -> Optional[TrajectoryMatch]:
        step = seq.steps[0]
        min_count = step.get("min_count", 1)
        matching = [e for e in window if _matches_step(step, e)]
        if len(matching) >= min_count:
            return TrajectoryMatch(
                sequence_id=seq.id,
                risk_level=seq.risk_level,
                matched_event_ids=[e.event_id for e in matching[:min_count]],
                reason=f"{seq.description} ({len(matching)} occurrences)",
            )
        return None

    def _match_ordered_steps(
        self,
        seq: AttackSequence,
        window: list[_BufferedEvent],
    ) -> Optional[TrajectoryMatch]:
        matched_ids: list[str] = []
        step_idx = 0
        for evt in window:
            if step_idx >= len(seq.steps):
                break
            if _matches_step(seq.steps[step_idx], evt):
                matched_ids.append(evt.event_id)
                step_idx += 1

        if step_idx == len(seq.steps):
            return TrajectoryMatch(
                sequence_id=seq.id,
                risk_level=seq.risk_level,
                matched_event_ids=matched_ids,
                reason=seq.description,
            )
        return None
