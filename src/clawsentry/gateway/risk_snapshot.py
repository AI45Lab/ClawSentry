"""
Risk scoring engine — D1-D6 six-dimensional assessment.

Design basis: 04-policy-decision-and-fallback.md section 12-13.
E-4 extension: D6 injection detection multiplier (2026-03-24).
"""

from __future__ import annotations

import re
from typing import Optional

from .detection_config import DetectionConfig
from .injection_detector import score_layer1
from .models import (
    AgentTrustLevel,
    CanonicalEvent,
    ClassifiedBy,
    DecisionContext,
    RiskDimensions,
    RiskLevel,
    RiskSnapshot,
    utc_now_iso,
)


# ---------------------------------------------------------------------------
# D1: Tool type danger (0-3)
# ---------------------------------------------------------------------------

_D1_READONLY_TOOLS = frozenset({
    "read_file", "list_dir", "search", "grep", "glob",
    "list_files", "read", "find", "cat", "head", "tail",
})

_D1_LIMITED_WRITE_TOOLS = frozenset({
    "write_file", "edit_file", "create_file", "edit", "write",
})

_D1_SYSTEM_INTERACTION_TOOLS = frozenset({
    "http_request", "install_package", "fetch", "web_fetch",
})

_D1_HIGH_DANGER_TOOLS = frozenset({
    "exec", "sudo", "chmod", "chown", "mount", "kill", "pkill",
})

# Canonical set of dangerous tools — shared across policy_engine and risk_snapshot
DANGEROUS_TOOLS = frozenset({
    "bash", "shell", "exec", "sudo", "chmod", "chown", "kill", "pkill", "mount",
})

# System paths that elevate bash from D1=2 to D1=3
_SYSTEM_PATHS = re.compile(
    r"(/etc/|/usr/|/var/|/sys/|/proc/|/boot/|/dev/)"
)


def _score_d1(event: CanonicalEvent) -> int:
    """Score tool type dangerousness (0-3)."""
    tool = (event.tool_name or "").lower()
    payload = event.payload or {}

    if not tool:
        return 2  # Conservative fallback per 12.5

    if tool in _D1_READONLY_TOOLS:
        return 0

    if tool in _D1_LIMITED_WRITE_TOOLS:
        return 1

    if tool in _D1_HIGH_DANGER_TOOLS:
        return 3

    if tool in ("bash", "shell", "terminal", "command"):
        command = str(payload.get("command", ""))
        if _has_dangerous_command_pattern(command):
            return 3
        if _SYSTEM_PATHS.search(command):
            return 3
        return 2

    if tool in _D1_SYSTEM_INTERACTION_TOOLS:
        return 2

    # Unknown tool: conservative fallback
    return 2


# ---------------------------------------------------------------------------
# D2: Target path sensitivity (0-3)
# ---------------------------------------------------------------------------

_D2_SYSTEM_CRITICAL = re.compile(
    r"^(/etc/|/usr/|/var/|/sys/|/proc/|/boot/)"
)

_D2_CREDENTIAL_PATTERNS = re.compile(
    r"(\.ssh/|\.gnupg/|credentials|\.pem$|\.key$|\.p12$|\.pfx$|\.jks$)",
    re.IGNORECASE,
)

_D2_CONFIG_PATTERNS = re.compile(
    r"(\.config\.|\.env|\.rc$|Makefile$|Dockerfile$|docker-compose)",
    re.IGNORECASE,
)


def _extract_paths(event: CanonicalEvent) -> list[str]:
    """Extract file paths from event payload."""
    payload = event.payload or {}
    paths = []
    for key in ("path", "file_path", "file", "target", "destination", "source"):
        val = payload.get(key)
        if isinstance(val, str) and val:
            paths.append(val)
    command = str(payload.get("command", ""))
    if command:
        paths.extend(_extract_paths_from_command(command))
    return paths


def _extract_paths_from_command(command: str) -> list[str]:
    """Best-effort path extraction from shell commands."""
    paths = []
    for token in command.split():
        if token.startswith("/") or token.startswith("~"):
            paths.append(token)
        elif "/" in token and not token.startswith("-"):
            paths.append(token)
    return paths


def _score_d2(event: CanonicalEvent) -> int:
    """Score target path sensitivity (0-3)."""
    paths = _extract_paths(event)
    if not paths:
        return 1  # Conservative fallback per 12.5

    max_score = 0
    for p in paths:
        if _D2_SYSTEM_CRITICAL.search(p):
            max_score = max(max_score, 3)
        elif _D2_CREDENTIAL_PATTERNS.search(p):
            max_score = max(max_score, 2)
        elif _D2_CONFIG_PATTERNS.search(p):
            max_score = max(max_score, 1)
    return max_score


# ---------------------------------------------------------------------------
# D3: Command pattern danger (0-3, only bash/exec tools)
# ---------------------------------------------------------------------------

_D3_SAFE_COMMANDS = frozenset({
    "ls", "cat", "echo", "pwd", "whoami", "date", "env", "printenv",
    "hostname", "uname", "id", "wc", "sort", "uniq", "diff",
    "head", "tail", "less", "more", "file", "which", "type",
})

_D3_REGULAR_WRITE = frozenset({
    "cp", "mv", "mkdir", "touch", "git add", "git commit",
    "ln", "rename",
})

_D3_POTENTIAL_DESTRUCTIVE = frozenset({
    "rm", "git push", "git reset", "npm install", "pip install",
    "yarn add", "apt install", "yum install",
})

_D3_HIGH_DANGER_PATTERNS = [
    re.compile(r"rm\s+.*-[^\s]*r[^\s]*f|rm\s+.*-[^\s]*f[^\s]*r|rm\s+-rf"),
    re.compile(r"\bdd\b"),
    re.compile(r"\bmkfs\b"),
    re.compile(r":\(\)\s*\{"),  # Fork bomb
    re.compile(r"curl\s.*\|\s*(sh|bash)"),
    re.compile(r"wget\s.*\|\s*(sh|bash)"),
    re.compile(r">\s*/dev/"),
    re.compile(r"git\s+push\s+.*--force"),
    re.compile(r"chmod\s+777"),
    re.compile(r"\bsudo\b"),
]


def _has_dangerous_command_pattern(command: str) -> bool:
    """Check if a command matches any high-danger pattern."""
    for pat in _D3_HIGH_DANGER_PATTERNS:
        if pat.search(command):
            return True
    return False


def _score_d3(event: CanonicalEvent) -> int:
    """Score command pattern danger (0-3). Only applies to bash/exec tools."""
    tool = (event.tool_name or "").lower()
    if tool not in ("bash", "shell", "terminal", "command", "exec"):
        return 0  # Non-bash tools: fixed 0

    command = str(event.payload.get("command", ""))
    if not command.strip():
        return 2  # Conservative fallback per 12.5

    # Check high danger first
    if _has_dangerous_command_pattern(command):
        return 3

    # Extract first meaningful command word
    first_cmd = command.strip().split()[0] if command.strip() else ""
    # Strip path prefix
    first_cmd = first_cmd.rsplit("/", 1)[-1]

    if first_cmd in _D3_SAFE_COMMANDS:
        return 0

    # Check potential destructive (word-boundary match for single-word patterns)
    for pattern in _D3_POTENTIAL_DESTRUCTIVE:
        if " " in pattern:
            # Multi-word pattern: substring match is appropriate
            if pattern in command:
                return 2
        else:
            # Single-word pattern: use word boundary to avoid false positives
            if re.search(r"\b" + re.escape(pattern) + r"\b", command):
                return 2

    # Check regular write (word-boundary match for single-word patterns)
    for pattern in _D3_REGULAR_WRITE:
        if " " in pattern:
            if pattern in command:
                return 1
        else:
            if re.search(r"\b" + re.escape(pattern) + r"\b", command):
                return 1

    # Unknown command: conservative fallback
    return 2


# ---------------------------------------------------------------------------
# D4: Context risk accumulation (0-2)
# ---------------------------------------------------------------------------

class SessionRiskTracker:
    """
    Track per-session risk accumulation for D4 scoring.

    D4 values per 04 section 12.2:
      0: session high-risk events < 2
      1: session high-risk events in [2, 5)
      2: session high-risk events >= 5

    Bounded: evicts least-recently-used sessions when max_sessions is exceeded.
    """

    DEFAULT_MAX_SESSIONS = 10_000

    def __init__(
        self,
        max_sessions: int = DEFAULT_MAX_SESSIONS,
        d4_high_threshold: int = 5,
        d4_mid_threshold: int = 2,
    ) -> None:
        self._max_sessions = max_sessions
        self._d4_high_threshold = d4_high_threshold
        self._d4_mid_threshold = d4_mid_threshold
        self._high_risk_counts: dict[str, int] = {}

    def record_high_risk_event(self, session_id: str) -> None:
        self._high_risk_counts[session_id] = (
            self._high_risk_counts.get(session_id, 0) + 1
        )
        self._evict_if_needed()

    def _evict_if_needed(self) -> None:
        """Evict oldest entries (by insertion order) when over capacity."""
        while len(self._high_risk_counts) > self._max_sessions:
            oldest_key = next(iter(self._high_risk_counts))
            del self._high_risk_counts[oldest_key]

    def get_d4(self, session_id: str) -> int:
        count = self._high_risk_counts.get(session_id, 0)
        if count >= self._d4_high_threshold:
            return 2
        if count >= self._d4_mid_threshold:
            return 1
        return 0

    def reset_session(self, session_id: str) -> None:
        self._high_risk_counts.pop(session_id, None)


# ---------------------------------------------------------------------------
# D5: Agent trust level (0-2)
# ---------------------------------------------------------------------------

def _score_d5(context: Optional[DecisionContext]) -> int:
    """Score agent trust level (0-2)."""
    if context is None or context.agent_trust_level is None:
        return 2  # Conservative fallback: untrusted

    trust = context.agent_trust_level
    if trust in (AgentTrustLevel.PRIVILEGED, AgentTrustLevel.ELEVATED):
        return 0
    if trust == AgentTrustLevel.STANDARD:
        return 1
    return 2  # UNTRUSTED


# ---------------------------------------------------------------------------
# Composite scoring and risk level classification
# ---------------------------------------------------------------------------

# Short-circuit rules (evaluated before composite scoring)
_SHORT_CIRCUIT_RULES = [
    # SC-1: High-danger tool + sensitive path → critical
    ("SC-1", lambda d: d.d1 == 3 and d.d2 >= 2, RiskLevel.CRITICAL),
    # SC-2: High-danger command pattern → critical
    ("SC-2", lambda d: d.d3 == 3, RiskLevel.CRITICAL),
    # SC-3: Pure read-only on normal path → low
    ("SC-3", lambda d: d.d1 == 0 and d.d2 == 0 and d.d3 == 0, RiskLevel.LOW),
]

# ---------------------------------------------------------------------------
# E-4: New composite scoring with D6 injection multiplier
# ---------------------------------------------------------------------------

def _composite_score_v2(
    dims: RiskDimensions,
    config: Optional[DetectionConfig] = None,
) -> float:
    """E-4 composite score with D6 injection multiplier.

    Returns >= 0.0 (bounded to [0.0, 3.0] with default weights;
    unbounded when custom weights exceed defaults).
    """
    if config is None:
        config = DetectionConfig()
    base_score = (
        config.composite_weight_max_d123 * max(dims.d1, dims.d2, dims.d3)
        + config.composite_weight_d4 * dims.d4
        + config.composite_weight_d5 * dims.d5
    )
    injection_multiplier = 1.0 + config.d6_injection_multiplier * (dims.d6 / 3.0)
    return base_score * injection_multiplier


def _score_to_risk_level_v2(
    score: float,
    config: Optional[DetectionConfig] = None,
) -> RiskLevel:
    """E-4 risk level thresholds."""
    if config is None:
        config = DetectionConfig()
    if score >= config.threshold_critical:
        return RiskLevel.CRITICAL
    if score >= config.threshold_high:
        return RiskLevel.HIGH
    if score >= config.threshold_medium:
        return RiskLevel.MEDIUM
    return RiskLevel.LOW


def _extract_text_for_d6(event: CanonicalEvent) -> str:
    """Extract analyzable text from event payload for D6 scoring."""
    payload = event.payload or {}
    parts: list[str] = []
    for key in ("command", "content", "text", "body", "input", "code"):
        val = payload.get(key)
        if isinstance(val, str) and val:
            parts.append(val)
    if event.risk_hints:
        parts.extend(str(h) for h in event.risk_hints)
    return " ".join(parts)


def compute_risk_snapshot(
    event: CanonicalEvent,
    context: Optional[DecisionContext],
    session_tracker: SessionRiskTracker,
    config: Optional[DetectionConfig] = None,
) -> RiskSnapshot:
    """
    Compute an immutable RiskSnapshot for the given event.

    Algorithm (E-4 revision):
    1. Score each dimension D1-D5.
    2. Score D6 via injection detector (Layer 1 heuristic).
    3. Apply short-circuit rules (before composite scoring).
    4. Compute composite_score via v2 formula (D6 multiplier).
    5. Map to risk_level via v2 thresholds.
    6. D6 forced alert: D6 >= 2.0 and LOW -> MEDIUM.
    """
    if config is None:
        config = DetectionConfig()
    missing_dims: list[str] = []

    # D1
    d1 = _score_d1(event)
    if not event.tool_name:
        missing_dims.append("d1")

    # D2
    d2 = _score_d2(event)
    if not _extract_paths(event):
        missing_dims.append("d2")

    # D3
    tool = (event.tool_name or "").lower()
    if tool in ("bash", "shell", "terminal", "command", "exec"):
        d3 = _score_d3(event)
        cmd = str(event.payload.get("command", ""))
        if not cmd.strip():
            missing_dims.append("d3")
    else:
        d3 = 0

    # D4
    d4 = session_tracker.get_d4(event.session_id)

    # D5
    d5 = _score_d5(context)
    if context is None or context.agent_trust_level is None:
        missing_dims.append("d5")

    # D6: Injection detection
    payload_text = _extract_text_for_d6(event)
    d6 = score_layer1(payload_text, event.tool_name or "") if payload_text else 0.0

    dims = RiskDimensions(d1=d1, d2=d2, d3=d3, d4=d4, d5=d5, d6=d6)

    # Short-circuit rules (priority over scoring)
    sc_rule: Optional[str] = None
    sc_level: Optional[RiskLevel] = None
    for rule_id, predicate, level in _SHORT_CIRCUIT_RULES:
        if predicate(dims):
            sc_rule = rule_id
            sc_level = level
            break

    # Composite scoring (E-4 v2 formula)
    score = _composite_score_v2(dims, config)

    if sc_level is not None:
        risk_level = sc_level
    else:
        risk_level = _score_to_risk_level_v2(score, config)

    # D6 forced alert: high injection score on low-risk event → bump to MEDIUM
    if d6 >= 2.0 and risk_level == RiskLevel.LOW:
        risk_level = RiskLevel.MEDIUM
        sc_rule = None  # D6 override invalidates the short-circuit

    snapshot = RiskSnapshot(
        risk_level=risk_level,
        composite_score=score,
        dimensions=dims,
        short_circuit_rule=sc_rule,
        missing_dimensions=missing_dims,
        classified_by=ClassifiedBy.L1,
        classified_at=utc_now_iso(),
    )

    # Update session tracker if risk >= high
    if risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL):
        session_tracker.record_high_risk_event(event.session_id)

    return snapshot
