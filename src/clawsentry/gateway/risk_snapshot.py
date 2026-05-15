"""
Risk scoring engine — D1-D6 six-dimensional assessment.

Design basis: 04-policy-decision-and-fallback.md section 12-13.
E-4 extension: D6 injection detection multiplier (2026-03-24).
"""

from __future__ import annotations

import re
from collections import deque
from typing import Any, Optional

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
from .risk_signals import (
    build_file_write_persistence_signals,
    has_process_sub_remote_command,
    has_remote_pipe_exec_command,
    is_credential_path,
)


_SECRET_REDACTION_RE = re.compile(
    r"(AKIA[0-9A-Z]{16}|ghp_[a-zA-Z0-9]{20,}|sk-[a-zA-Z0-9_-]{20,}|"
    r"-----BEGIN[A-Z ]*PRIVATE KEY-----.*?-----END[A-Z ]*PRIVATE KEY-----|"
    r"\b[A-Za-z_][A-Za-z0-9_]*(?:SECRET|TOKEN|PASSWORD|API_KEY)[A-Za-z0-9_]*\s*[=:]\s*['\"]?[^'\"\s]+)",
    re.IGNORECASE | re.DOTALL,
)
_PERSISTENCE_EVIDENCE_PREVIEW_CHARS = 512


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
    # Shells
    "bash", "sh", "zsh", "ksh", "dash", "shell", "powershell", "cmd",
    # Execution
    "exec", "eval", "system", "popen", "spawn",
    # Privilege escalation
    "sudo", "su", "pkexec", "doas", "runas",
    # File permission / ownership
    "chmod", "chown", "chgrp", "mount", "umount",
    # Process control
    "kill", "pkill", "killall", "taskkill",
    # macOS system tools
    "launchctl", "pmset", "diskutil", "dscl", "security", "codesign",
    # Windows system tools
    "wmic", "reg", "regedit", "schtasks", "at", "netsh", "sc", "icacls",
    "takeown", "cipher", "diskpart", "msiexec", "rundll32",
    # Network / remote access
    "nc", "ncat", "netcat", "socat", "telnet", "ssh", "ftp",
    # Persistence
    "cron", "crontab", "systemctl",
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

    # R-10: Check expanded dangerous tools set (after bash/shell special case
    # to preserve command-level analysis for those tools)
    if tool in DANGEROUS_TOOLS:
        return 3

    # Unknown tool: conservative fallback
    return 2


# ---------------------------------------------------------------------------
# D2: Target path sensitivity (0-3)
# ---------------------------------------------------------------------------

_D2_SYSTEM_CRITICAL = re.compile(
    r"^(/etc/|/usr/|/var/|/sys/|/proc/|/boot/)"
)

_D2_CONFIG_PATTERNS = re.compile(
    r"(\.config\.|\.env|\.rc$|Makefile$|Dockerfile$|docker-compose)",
    re.IGNORECASE,
)


def _extract_paths(event: CanonicalEvent) -> list[str]:
    """Extract file paths from event payload."""
    payload = event.payload or {}
    paths = []
    for mapping in (payload, payload.get("arguments"), payload.get("tool_input"), payload.get("args")):
        if not isinstance(mapping, dict):
            continue
        for key in ("path", "file_path", "file", "target", "destination", "source"):
            val = mapping.get(key)
            if isinstance(val, str) and val:
                paths.append(val)
        for key in ("command", "cmd", "prompt", "instructions", "description"):
            text = mapping.get(key)
            if isinstance(text, str) and text:
                paths.extend(_extract_paths_from_command(text))
    return paths


def _extract_write_content(event: CanonicalEvent) -> str:
    """Extract content that write/edit tools are about to add to files."""
    payload = event.payload or {}
    parts: list[str] = []

    def add(value: object) -> None:
        if isinstance(value, str) and value:
            parts.append(value)

    def collect_from_mapping(value: object) -> None:
        if not isinstance(value, dict):
            return
        for key in (
            "content",
            "new_string",
            "replacement",
            "body",
            "code",
            "text",
            "prompt",
            "instructions",
            "description",
        ):
            add(value.get(key))
        edits = value.get("edits")
        if isinstance(edits, list):
            for item in edits:
                collect_from_mapping(item)

    collect_from_mapping(payload)
    collect_from_mapping(payload.get("arguments"))
    collect_from_mapping(payload.get("tool_input"))
    collect_from_mapping(payload.get("args"))
    return "\n".join(parts)


def _extract_shell_command(event: CanonicalEvent) -> str:
    """Extract shell command text from direct or nested tool payloads."""
    payload = event.payload or {}
    for mapping in (payload, payload.get("arguments"), payload.get("tool_input"), payload.get("args")):
        if not isinstance(mapping, dict):
            continue
        for key in ("command", "cmd"):
            value = mapping.get(key)
            if isinstance(value, str) and value:
                return value
    return ""


def _redact_evidence_text(value: str, *, max_len: int = _PERSISTENCE_EVIDENCE_PREVIEW_CHARS) -> str:
    compact = " ".join(str(value or "").split())
    compact = _SECRET_REDACTION_RE.sub("[REDACTED_SECRET]", compact)
    if len(compact) > max_len:
        return compact[:max_len] + "...[truncated]"
    return compact


def _path_category(path: str) -> str:
    lowered = path.lower()
    name = lowered.rsplit("/", 1)[-1]
    if name in {"index.html", "app.html"} or lowered.endswith((".html", ".htm")):
        return "html_entrypoint"
    if "bootstrap" in lowered and ("loader" in lowered or "manifest" in lowered):
        return "bootstrap_loader"
    if "startup" in lowered or "autoload" in lowered:
        return "startup_or_autoload"
    if name.endswith((".js", ".mjs", ".cjs")) and "loader" in lowered:
        return "script_loader"
    if name.endswith((".json", ".yaml", ".yml")) and ("manifest" in lowered or "loader" in lowered):
        return "loader_manifest"
    return "write_target"


def _redact_path(path: str) -> str:
    cleaned = str(path or "").strip()
    if not cleaned:
        return ""
    if cleaned.startswith("/"):
        parts = [part for part in cleaned.split("/") if part]
        if len(parts) <= 3:
            return "/" + "/".join(parts)
        return "/.../" + "/".join(parts[-3:])
    if cleaned.startswith("~"):
        parts = [part for part in cleaned.split("/") if part and part != "~"]
        return "~/" + "/".join(parts[-3:])
    return cleaned


def _infer_write_method(tool_name: str, shell_command: str, signals: dict[str, bool]) -> str:
    tool = (tool_name or "").lower()
    command = shell_command.lower()
    if signals.get("delegated_write_action"):
        return "delegated_write"
    if signals.get("shell_file_write_action") or tool in {"bash", "shell", "sh", "zsh"}:
        if re.search(r"\bpython(?:3)?\b|node\b|writefile|write_text|write_bytes|open\(", command):
            return "programmatic_write"
        if re.search(r"\b(cat|tee|echo|printf|dd)\b|[<>]", command):
            return "shell_redirect"
        return "shell_write"
    if signals.get("write_action"):
        return "write_tool"
    return "write"


def _build_persistence_write_evidence(
    *,
    event: CanonicalEvent,
    paths: list[str],
    content_text: str,
    shell_command: str,
    signals: dict[str, bool],
) -> dict[str, Any]:
    trigger_flags = sorted(
        key for key, value in signals.items()
        if value and key != "persistence_write"
    )
    redacted_paths = [_redact_path(path) for path in paths if str(path or "").strip()]
    path_categories = sorted({_path_category(path) for path in paths if str(path or "").strip()})
    preview_source = content_text or shell_command
    return {
        "signal": "persistence_write",
        "short_circuit_rule": "SC-4",
        "tool": event.tool_name or "",
        "write_method": _infer_write_method(event.tool_name or "", shell_command, signals),
        "path_categories": path_categories,
        "matched_paths_redacted": redacted_paths[:12],
        "trigger_flags": trigger_flags,
        "content_preview_redacted": _redact_evidence_text(preview_source),
        "raw_payload_included": False,
    }


def _extract_paths_from_command(command: str) -> list[str]:
    """Best-effort path extraction from shell commands."""
    paths = []
    for token in command.split():
        cleaned = token.strip("'\"`;,)(")
        if cleaned.startswith("/") or cleaned.startswith("~"):
            paths.append(cleaned)
        elif "/" in cleaned and not cleaned.startswith("-"):
            paths.append(cleaned)
    paths.extend(
        match.group(1)
        for match in re.finditer(
            r"['\"]((?:~|/|[A-Za-z]:\\|[A-Za-z0-9_.-]+/)[^'\"\s<>]+)['\"]",
            command,
        )
    )
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
        elif _D2_CONFIG_PATTERNS.search(p):
            max_score = max(max_score, 1)
        elif is_credential_path(p) or ".gnupg/" in p.lower():
            max_score = max(max_score, 2)
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

# Regex patterns that score d3=2 (concerning but not immediately catastrophic)
_D3_POTENTIAL_DESTRUCTIVE_PATTERNS = [
    re.compile(r"launchctl\s+(?:unload|disable)\s+.*(?:/Library|/System)", re.I),
    re.compile(r"icacls\s+.*(?:/grant|/deny)", re.I),
]

_D3_HIGH_DANGER_PATTERNS = [
    re.compile(r"rm\s+.*-[^\s]*r[^\s]*f|rm\s+.*-[^\s]*f[^\s]*r|rm\s+-rf"),
    re.compile(r"\bdd\b.*\bof\s*=\s*/dev/"),
    re.compile(r"\bmkfs\b"),
    re.compile(r":\(\)\s*\{"),  # Fork bomb
    re.compile(r"curl\s.*\|\s*(sh|bash)"),
    re.compile(r"wget\s.*\|\s*(sh|bash)"),
    re.compile(r">\s*/dev/"),
    re.compile(r"git\s+push\s+.*--force"),
    re.compile(r"chmod\s+777"),
    re.compile(r"\bsudo\b"),
    # Windows destructive operations
    re.compile(r"rmdir\s+/s\s+/q", re.I),
    re.compile(r"Remove-Item\s+.*-Recurse\s+.*-Force", re.I),
    re.compile(r"del\s+/[sq]\s+/[sq]", re.I),
    # Privilege escalation
    re.compile(r"Set-ExecutionPolicy\s+(?:Unrestricted|Bypass)", re.I),
    re.compile(r"net\s+(?:user|localgroup)\s+.*\s+/add", re.I),
    # macOS disk destruction
    re.compile(r"diskutil\s+(?:secureErase|eraseVolume|eraseDisk)", re.I),
    # Firewall tampering (flush/delete/reset only, not normal rule additions)
    re.compile(r"iptables\s+(?:-F|-X)\b", re.I),
    re.compile(r"ufw\s+(?:disable|reset)", re.I),
    re.compile(r"netsh\s+(?:advfirewall|firewall)\s+set\s+.*state\s+off", re.I),
    # Log clearing
    re.compile(r"wevtutil\s+cl\s+(?:System|Security|Application)", re.I),
    # R-12: Removed overly broad `rm -f /var/log/` — non-recursive rm on single
    # log files is routine. Recursive `rm -rf /var/log/` is already caught by
    # the rm -rf pattern above.
    # Reverse shell indicators
    re.compile(r"(?:nc|ncat|netcat)\s+.*-e\s+(?:/bin/|cmd)", re.I),
    re.compile(r"\|\s*IEX\s*\(", re.I),
    # Disk destruction / secure erase
    re.compile(r"shred\s+-[a-z]*u", re.I),
    re.compile(r"cipher\s+/w:", re.I),
]


def _has_dangerous_command_pattern(command: str) -> bool:
    """Check if a command matches any high-danger pattern."""
    if has_remote_pipe_exec_command(command):
        return True
    if has_process_sub_remote_command(command):
        return True
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

    # Check potential destructive regex patterns (d3=2)
    for pat in _D3_POTENTIAL_DESTRUCTIVE_PATTERNS:
        if pat.search(command):
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
    Track per-session risk accumulation and tool-call frequency for D4 scoring.

    D4 values per 04 section 12.2 (accumulation):
      0: session high-risk events < 2
      1: session high-risk events in [2, 5)
      2: session high-risk events >= 5

    E-8 frequency detection (three layers):
      burst:      same tool >= N times in T seconds → d4=2
      repetitive: same tool >= N times in T seconds → d4=1
      rate:       all tools >= N per minute         → d4=1

    Final D4 = min(max(accumulation_d4, frequency_d4), 2).

    Bounded: evicts least-recently-used sessions when max_sessions is exceeded.
    """

    DEFAULT_MAX_SESSIONS = 10_000

    def __init__(
        self,
        max_sessions: int = DEFAULT_MAX_SESSIONS,
        d4_high_threshold: int = 5,
        d4_mid_threshold: int = 2,
        # E-8: Frequency detection params
        freq_enabled: bool = True,
        freq_burst_count: int = 10,
        freq_burst_window_s: float = 5.0,
        freq_repetitive_count: int = 20,
        freq_repetitive_window_s: float = 60.0,
        freq_rate_limit_per_min: int = 60,
    ) -> None:
        self._max_sessions = max_sessions
        self._d4_high_threshold = d4_high_threshold
        self._d4_mid_threshold = d4_mid_threshold
        self._high_risk_counts: dict[str, int] = {}

        # E-8: Frequency tracking
        self._freq_enabled = freq_enabled
        self._freq_burst_count = freq_burst_count
        self._freq_burst_window_s = freq_burst_window_s
        self._freq_repetitive_count = freq_repetitive_count
        self._freq_repetitive_window_s = freq_repetitive_window_s
        self._freq_rate_limit_per_min = freq_rate_limit_per_min
        # Per-session → per-tool → deque of timestamps (O(1) popleft)
        self._tool_calls: dict[str, dict[str, deque[float]]] = {}
        # Per-session → deque of all-tool timestamps
        self._all_calls: dict[str, deque[float]] = {}

    def record_high_risk_event(self, session_id: str) -> None:
        self._high_risk_counts[session_id] = (
            self._high_risk_counts.get(session_id, 0) + 1
        )
        self._evict_if_needed()

    def _evict_if_needed(self) -> None:
        """Evict oldest entries (by insertion order) when over capacity."""
        # Check all session dicts to prevent unbounded growth
        all_session_ids = (
            set(self._high_risk_counts)
            | set(self._tool_calls)
            | set(self._all_calls)
        )
        while len(all_session_ids) > self._max_sessions:
            # Prefer evicting from high_risk_counts first (insertion-ordered)
            if self._high_risk_counts:
                oldest_key = next(iter(self._high_risk_counts))
                del self._high_risk_counts[oldest_key]
            elif self._tool_calls:
                oldest_key = next(iter(self._tool_calls))
            elif self._all_calls:
                oldest_key = next(iter(self._all_calls))
            else:
                break
            self._tool_calls.pop(oldest_key, None)
            self._all_calls.pop(oldest_key, None)
            all_session_ids.discard(oldest_key)

    def record_tool_call(self, session_id: str, tool_name: str, now: float | None = None) -> None:
        """Record a tool invocation for frequency analysis."""
        if not self._freq_enabled:
            return
        import time
        ts = now if now is not None else time.monotonic()

        # Per-tool timestamps
        session_tools = self._tool_calls.setdefault(session_id, {})
        if tool_name not in session_tools:
            session_tools[tool_name] = deque()
        tool_ts = session_tools[tool_name]
        tool_ts.append(ts)
        # Trim to repetitive window (the larger window)
        cutoff = ts - self._freq_repetitive_window_s
        while tool_ts and tool_ts[0] < cutoff:
            tool_ts.popleft()

        # All-tool timestamps
        if session_id not in self._all_calls:
            self._all_calls[session_id] = deque()
        all_ts = self._all_calls[session_id]
        all_ts.append(ts)
        rate_cutoff = ts - 60.0
        while all_ts and all_ts[0] < rate_cutoff:
            all_ts.popleft()

        # Evict oldest sessions when over capacity
        self._evict_if_needed()

    def _get_frequency_d4(self, session_id: str, now: float | None = None) -> int:
        """Compute D4 contribution from tool-call frequency."""
        if not self._freq_enabled:
            return 0
        import time
        ts = now if now is not None else time.monotonic()
        freq_d4 = 0

        # Burst detection: same tool >= N in burst window
        session_tools = self._tool_calls.get(session_id, {})
        burst_cutoff = ts - self._freq_burst_window_s
        for tool_ts in session_tools.values():
            count = sum(1 for t in tool_ts if t >= burst_cutoff)
            if count >= self._freq_burst_count:
                freq_d4 = max(freq_d4, 2)
                break

        # Repetitive detection: same tool >= N in repetitive window
        if freq_d4 < 2:
            rep_cutoff = ts - self._freq_repetitive_window_s
            for tool_ts in session_tools.values():
                count = sum(1 for t in tool_ts if t >= rep_cutoff)
                if count >= self._freq_repetitive_count:
                    freq_d4 = max(freq_d4, 1)
                    break

        # Overall rate detection: all tools >= N per minute
        if freq_d4 < 1:
            all_ts = self._all_calls.get(session_id, [])
            rate_cutoff = ts - 60.0
            rate_count = sum(1 for t in all_ts if t >= rate_cutoff)
            if rate_count >= self._freq_rate_limit_per_min:
                freq_d4 = max(freq_d4, 1)

        return freq_d4

    def get_d4(self, session_id: str, now: float | None = None) -> int:
        # Accumulation-based D4
        count = self._high_risk_counts.get(session_id, 0)
        if count >= self._d4_high_threshold:
            accum_d4 = 2
        elif count >= self._d4_mid_threshold:
            accum_d4 = 1
        else:
            accum_d4 = 0

        # E-8: Frequency-based D4
        freq_d4 = self._get_frequency_d4(session_id, now=now)

        return min(max(accum_d4, freq_d4), 2)

    def reset_session(self, session_id: str) -> None:
        self._high_risk_counts.pop(session_id, None)
        self._tool_calls.pop(session_id, None)
        self._all_calls.pop(session_id, None)


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
    for key in (
        "command",
        "content",
        "text",
        "body",
        "input",
        "code",
        "message",
        "transcript",
        "userMessage",
        "user_message",
        "prompt",
        "instructions",
        "description",
    ):
        val = payload.get(key)
        if isinstance(val, str) and val:
            parts.append(val)
    write_content = _extract_write_content(event)
    if write_content:
        parts.append(write_content)
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
    # E-8: Extract content origin from _clawsentry_meta if present
    _meta = (event.payload or {}).get("_clawsentry_meta") or {}
    _content_origin = _meta.get("content_origin") if isinstance(_meta, dict) else None
    d6 = score_layer1(
        payload_text,
        event.tool_name or "",
        content_origin=_content_origin,
        d6_boost=config.external_content_d6_boost,
    ) if payload_text else 0.0

    dims = RiskDimensions(d1=d1, d2=d2, d3=d3, d4=d4, d5=d5, d6=d6)
    extracted_paths = _extract_paths(event)
    write_signal_content = _extract_write_content(event)
    if not write_signal_content:
        write_signal_content = _extract_shell_command(event)
    shell_command = _extract_shell_command(event)
    file_write_signals = build_file_write_persistence_signals(
        tool_name=event.tool_name or "",
        path_text=" ".join(extracted_paths),
        content_text=write_signal_content,
        risk_hints=event.risk_hints,
    )

    # Short-circuit rules (priority over scoring)
    sc_rule: Optional[str] = None
    sc_level: Optional[RiskLevel] = None
    if file_write_signals["persistence_write"]:
        sc_rule = "SC-4"
        sc_level = RiskLevel.HIGH
    else:
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
        risk_evidence=(
            _build_persistence_write_evidence(
                event=event,
                paths=extracted_paths,
                content_text=write_signal_content,
                shell_command=shell_command,
                signals=file_write_signals,
            )
            if sc_rule == "SC-4"
            else {}
        ),
    )

    # Update session tracker if risk >= high
    if risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL):
        session_tracker.record_high_risk_event(event.session_id)

    return snapshot
