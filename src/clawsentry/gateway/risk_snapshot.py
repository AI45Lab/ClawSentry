"""
Risk scoring engine — D1-D6 six-dimensional assessment.

Design basis: 04-policy-decision-and-fallback.md section 12-13.
E-4 extension: D6 injection detection multiplier (2026-03-24).
"""

from __future__ import annotations

import hashlib
import re
import shlex
from collections import deque
from typing import Optional

from .detection_config import DetectionConfig
from .effect_normalizer import normalize_action_effect
from .injection_detector import score_layer1
from .models import (
    AgentTrustLevel,
    CanonicalEvent,
    ClassifiedBy,
    DecisionContext,
    EventType,
    RISK_LEVEL_ORDER,
    RiskDimensions,
    RiskLevel,
    RiskSnapshot,
    utc_now_iso,
)
from .risk_signals import (
    has_process_sub_remote_command,
    has_remote_pipe_exec_command,
    is_credential_path,
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
    r"(/etc/|/usr/|/var/|/sys/|/proc/|/boot/|/dev/(?!null\b))"
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
    re.compile(r">[^\S\r\n]*/dev/(?!null\b)"),
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

    def record_tool_call(
        self,
        session_id: str,
        tool_name: str,
        now: float | None = None,
        config: DetectionConfig | None = None,
    ) -> None:
        """Record a tool invocation for frequency analysis."""
        freq_enabled = config.d4_freq_enabled if config is not None else self._freq_enabled
        if not freq_enabled:
            return
        import time
        ts = now if now is not None else time.monotonic()
        repetitive_window_s = (
            config.d4_freq_repetitive_window_s
            if config is not None
            else self._freq_repetitive_window_s
        )

        # Per-tool timestamps
        session_tools = self._tool_calls.setdefault(session_id, {})
        if tool_name not in session_tools:
            session_tools[tool_name] = deque()
        tool_ts = session_tools[tool_name]
        tool_ts.append(ts)
        # Trim to repetitive window (the larger window)
        cutoff = ts - repetitive_window_s
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

    def _get_frequency_d4(
        self,
        session_id: str,
        now: float | None = None,
        config: DetectionConfig | None = None,
    ) -> int:
        """Compute D4 contribution from tool-call frequency."""
        freq_enabled = config.d4_freq_enabled if config is not None else self._freq_enabled
        if not freq_enabled:
            return 0
        import time
        ts = now if now is not None else time.monotonic()
        freq_d4 = 0
        burst_count = config.d4_freq_burst_count if config is not None else self._freq_burst_count
        burst_window_s = (
            config.d4_freq_burst_window_s
            if config is not None
            else self._freq_burst_window_s
        )
        repetitive_count = (
            config.d4_freq_repetitive_count
            if config is not None
            else self._freq_repetitive_count
        )
        repetitive_window_s = (
            config.d4_freq_repetitive_window_s
            if config is not None
            else self._freq_repetitive_window_s
        )
        rate_limit_per_min = (
            config.d4_freq_rate_limit_per_min
            if config is not None
            else self._freq_rate_limit_per_min
        )

        # Burst detection: same tool >= N in burst window
        session_tools = self._tool_calls.get(session_id, {})
        burst_cutoff = ts - burst_window_s
        for tool_ts in session_tools.values():
            count = sum(1 for t in tool_ts if t >= burst_cutoff)
            if count >= burst_count:
                freq_d4 = max(freq_d4, 2)
                break

        # Repetitive detection: same tool >= N in repetitive window
        if freq_d4 < 2:
            rep_cutoff = ts - repetitive_window_s
            for tool_ts in session_tools.values():
                count = sum(1 for t in tool_ts if t >= rep_cutoff)
                if count >= repetitive_count:
                    freq_d4 = max(freq_d4, 1)
                    break

        # Overall rate detection: all tools >= N per minute
        if freq_d4 < 1:
            all_ts = self._all_calls.get(session_id, [])
            rate_cutoff = ts - 60.0
            rate_count = sum(1 for t in all_ts if t >= rate_cutoff)
            if rate_count >= rate_limit_per_min:
                freq_d4 = max(freq_d4, 1)

        return freq_d4

    def get_d4(
        self,
        session_id: str,
        now: float | None = None,
        config: DetectionConfig | None = None,
    ) -> int:
        # Accumulation-based D4
        count = self._high_risk_counts.get(session_id, 0)
        high_threshold = (
            config.d4_high_threshold if config is not None else self._d4_high_threshold
        )
        mid_threshold = (
            config.d4_mid_threshold if config is not None else self._d4_mid_threshold
        )
        if count >= high_threshold:
            accum_d4 = 2
        elif count >= mid_threshold:
            accum_d4 = 1
        else:
            accum_d4 = 0

        # E-8: Frequency-based D4
        freq_d4 = self._get_frequency_d4(session_id, now=now, config=config)

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

_TAINT_BULK_DESTRUCTIVE = re.compile(
    r"\bfind\b.*(?:-delete|\|\s*xargs\b[^\n;|]*\brm\b)"
    r"|\brm\s+-[^\n;|]*r[^\n;|]*f\s+(?:\*|\./\*|/tmp/\*)",
    re.I,
)
_TAINT_NETWORK_SINK = re.compile(
    r"\b(?:curl|wget|nc|ncat|netcat|scp|rsync)\b.*(?:https?://|@-|--data|-d\s)",
    re.I,
)
_PERSISTENCE_ENTRYPOINT_PATH = re.compile(
    r"(?:"
    r"(?:^|/)\.(?:bashrc|zshrc|profile|bash_profile|zprofile|cshrc|tcshrc)$|"
    r"^/etc/(?:profile|bash\.bashrc|zshrc)$|"
    r"^/etc/profile\.d/[^/]+\.sh$|"
    r"^/etc/(?:crontab|cron\.(?:d|hourly|daily|weekly|monthly)/[^/]+)$|"
    r"^/var/(?:spool/cron|cron/tabs)/[^/]+$|"
    r"^(?:/etc|/usr/lib|/lib)/systemd/(?:system|user)/[^/]+\.(?:service|timer|socket|path)$|"
    r"^(?:~|/Users/[^/]+)?/Library/(?:LaunchAgents|LaunchDaemons)/[^/]+\.plist$|"
    r"^/System/Library/(?:LaunchAgents|LaunchDaemons)/[^/]+\.plist$|"
    r"(?:^|/)(?:preinstall|postinstall|preinst|postinst|prerm|postrm)$|"
    r"(?:^|/)DEBIAN/(?:preinst|postinst|prerm|postrm)$|"
    r"(?:^|/)(?:sitecustomize|usercustomize)\.py$"
    r")",
    re.I,
)
_TAINT_PACKAGE_LIFECYCLE_SCRIPT = re.compile(
    r'"(?:preinstall|install|postinstall|prepare)"\s*:',
    re.I,
)
_TAINT_SPREADSHEET_WRITER = re.compile(
    r"\b(?:openpyxl|xlsxwriter|Workbook|load_workbook)\b|\.xlsx\b",
    re.I,
)
_TAINT_SPREADSHEET_HIDDEN_OR_CACHE = re.compile(
    r"sheet_state\s*=\s*['\"](?:hidden|veryHidden)['\"]|"
    r"\b(?:very_?hidden|hidden)\s+(?:sheet|worksheet)\b|"
    r"\b(?:export|cache|audit|recovery)[_\-\s]*(?:sheet|worksheet|cache)\b",
    re.I,
)
_TAINT_SPREADSHEET_EXTERNAL_FORMULA = re.compile(
    r"=\s*(?:HYPERLINK|WEBSERVICE|IMPORTXML|IMPORTDATA)\s*\([^)]*https?://|"
    r"=\s*['\"]?https?://",
    re.I | re.S,
)
_TEMP_EXEC_PATH = re.compile(r"^(?:/tmp|/var/tmp|/dev/shm|/private/tmp)(?:/|$)")
_RELATIVE_PAYLOAD_EXECUTABLES = frozenset({
    "run",
    "payload",
    "loader",
    "install",
    "install.sh",
    "setup.sh",
    "bootstrap.sh",
    "update.sh",
})
_INTERPRETER_COMMANDS = frozenset({
    "bash",
    "sh",
    "python",
    "python3",
    "node",
    "source",
})

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


def _shell_tokens(segment: str) -> list[str]:
    try:
        return shlex.split(segment)
    except ValueError:
        return segment.split()


def _clean_shell_path(value: str) -> str:
    return value.strip().strip("'\"").rstrip(".,)")


def _command_name(token: str) -> str:
    return _clean_shell_path(token).rsplit("/", 1)[-1]


def _split_shell_segments(command: str) -> list[str]:
    return [segment.strip() for segment in re.split(r"\s*(?:&&|;|\|)\s*", command) if segment.strip()]


def _is_temp_exec_path(path: str) -> bool:
    return bool(_TEMP_EXEC_PATH.search(_clean_shell_path(path)))


def _is_persistence_entrypoint_path(path: str) -> bool:
    return bool(_PERSISTENCE_ENTRYPOINT_PATH.search(_clean_shell_path(path)))


def _segment_mentions_temp_path(segment: str) -> bool:
    return any(_is_temp_exec_path(token) for token in _shell_tokens(segment))


def _is_archive_extract_segment(segment: str) -> bool:
    tokens = _shell_tokens(segment)
    for index, token in enumerate(tokens):
        name = _command_name(token)
        if name == "tar":
            args = tokens[index + 1:]
            return any(
                arg == "--extract"
                or (arg.startswith("-") and "x" in arg and not arg.startswith("--"))
                or (arg and not arg.startswith("-") and "x" in arg[:2])
                for arg in args
            )
        if name == "unzip":
            args = tokens[index + 1:]
            listing_or_test = {"-l", "-t", "-v", "-Z"}
            return not any(arg in listing_or_test for arg in args)
    return False


def _relative_payload_execution(path: str) -> bool:
    cleaned = _clean_shell_path(path)
    if not cleaned.startswith("./"):
        return False
    basename = cleaned.rsplit("/", 1)[-1]
    return basename in _RELATIVE_PAYLOAD_EXECUTABLES


def _archive_payload_execution_arg(path: str) -> bool:
    cleaned = _clean_shell_path(path)
    if _relative_payload_execution(cleaned):
        return True
    if "/" in cleaned:
        return False
    return cleaned in _RELATIVE_PAYLOAD_EXECUTABLES


def _segment_executes_archive_payload(segment: str, risky_context: bool) -> bool:
    tokens = _shell_tokens(segment)
    if not tokens:
        return False

    first = _clean_shell_path(tokens[0])
    first_name = _command_name(first)
    if _is_temp_exec_path(first):
        return True
    if _archive_payload_execution_arg(first):
        return True

    if first_name not in _INTERPRETER_COMMANDS:
        return False
    for arg in tokens[1:]:
        if arg.startswith("-"):
            continue
        if _is_temp_exec_path(arg):
            return True
        if risky_context and _relative_payload_execution(arg):
            return True
        if _archive_payload_execution_arg(arg):
            return True
        return False
    return False


def _archive_extract_then_execute(command: str) -> bool:
    extraction_seen = False
    risky_context = False
    for segment in _split_shell_segments(command):
        if _is_archive_extract_segment(segment):
            extraction_seen = True
            risky_context = risky_context or _segment_mentions_temp_path(segment)
            continue
        if extraction_seen and _segment_executes_archive_payload(segment, risky_context):
            return True
    return False


def _command_writes_persistence_entrypoint(command: str) -> bool:
    for segment in _split_shell_segments(command):
        tokens = _shell_tokens(segment)
        if not tokens:
            continue

        for index, token in enumerate(tokens):
            if (
                token in {">", ">>"}
                and index + 1 < len(tokens)
                and _is_persistence_entrypoint_path(tokens[index + 1])
            ):
                return True
            redirection = re.search(r"(?:^|[^\w])(?:\d*)>{1,2}(.+)$", token)
            if redirection and _is_persistence_entrypoint_path(redirection.group(1)):
                return True

        command_names = [_command_name(token) for token in tokens]
        if "tee" in command_names:
            tee_index = command_names.index("tee")
            for arg in tokens[tee_index + 1:]:
                if not arg.startswith("-") and _is_persistence_entrypoint_path(arg):
                    return True

        if "sed" in command_names and any(arg.startswith("-i") for arg in tokens):
            if any(_is_persistence_entrypoint_path(arg) for arg in tokens):
                return True

        if command_names and command_names[0] == "crontab":
            if not any(arg in {"-l", "-r"} for arg in tokens[1:]):
                return True

    return False


def _taint_flow_summary(event: CanonicalEvent) -> dict[str, object] | None:
    """Return redacted structured L1 taint/compound evidence for replay."""

    payload = event.payload or {}
    command = str(payload.get("command") or "")
    content = str(payload.get("content") or "")
    analyzable_text = "\n".join(part for part in (command, content) if part)
    paths = _extract_paths(event)
    rules: list[dict[str, object]] = []

    if command and (has_remote_pipe_exec_command(command) or has_process_sub_remote_command(command)):
        rules.append({
            "rule_id": "remote_fetch_to_interpreter",
            "severity": "critical",
            "source": "remote_fetch",
            "sink": "interpreter",
        })

    if command and _TAINT_NETWORK_SINK.search(command) and any(
        is_credential_path(path) or ".gnupg/" in path.lower() or ".env" in path.lower()
        for path in paths
    ):
        rules.append({
            "rule_id": "sensitive_source_to_network_sink",
            "severity": "critical",
            "source": "sensitive_local_data",
            "sink": "network",
        })

    if command and _archive_extract_then_execute(command):
        rules.append({
            "rule_id": "archive_extract_then_execute",
            "severity": "high",
            "source": "archive_content",
            "sink": "interpreter",
        })

    if command and _TAINT_BULK_DESTRUCTIVE.search(command):
        rules.append({
            "rule_id": "bulk_destructive_sequence",
            "severity": "critical",
            "source": "bulk_path_selection",
            "sink": "destructive_write",
        })

    if (
        analyzable_text
        and _TAINT_SPREADSHEET_WRITER.search(analyzable_text)
        and _TAINT_SPREADSHEET_HIDDEN_OR_CACHE.search(analyzable_text)
        and _TAINT_SPREADSHEET_EXTERNAL_FORMULA.search(analyzable_text)
    ):
        rules.append({
            "rule_id": "spreadsheet_downstream_payload",
            "severity": "high",
            "source": "spreadsheet_hidden_state",
            "sink": "downstream_interpreter",
        })

    tool = (event.tool_name or "").lower()
    writes_payload_path = tool in {"write_file", "edit_file", "create_file", "edit", "write"}
    writes_package_lifecycle = (
        writes_payload_path
        and any(path.endswith("/package.json") or path == "package.json" for path in paths)
        and _TAINT_PACKAGE_LIFECYCLE_SCRIPT.search(str(payload.get("content") or ""))
    )
    if (
        (command and _command_writes_persistence_entrypoint(command))
        or (writes_payload_path and any(_is_persistence_entrypoint_path(path) for path in paths))
        or writes_package_lifecycle
    ):
        rules.append({
            "rule_id": "persistence_entrypoint_write",
            "severity": "high",
            "source": "local_write",
            "sink": "future_execution_entrypoint",
        })

    if not rules:
        return None

    rule_ids = [str(rule["rule_id"]) for rule in rules]
    return {
        "rules": rules,
        "rule_ids": rule_ids,
        "chain_count": len(rules),
        "command_hash": "sha256:" + hashlib.sha256(command.encode("utf-8")).hexdigest() if command else None,
        "redaction_policy_version": "cs.taint_flow_summary.v1",
    }


_FIRST_USE_SCAN_RULE_BY_STATE = {
    "scan_not_started": "first_use_scan_not_started",
    "scan_running_sync": "first_use_scan_running_sync",
    "scan_pending_budget_exhausted": "first_use_scan_pending_budget_exhausted",
    "scan_failed": "first_use_scan_failed",
}


def skill_trust_first_use_state_rule(skill_trust) -> str | None:
    """Return the first-use scan rule id for unresolved skill identities."""

    if skill_trust is None:
        return None
    if skill_trust.registry_status in {"unknown", "unbound"}:
        pass
    elif (
        skill_trust.registry_status == "matched"
        and skill_trust.trust_list_state in {"greylist", "unlisted", "disabled"}
    ):
        pass
    else:
        return None
    scan = skill_trust.first_use_scan
    if scan is None:
        return None
    return _FIRST_USE_SCAN_RULE_BY_STATE.get(scan.state)


def skill_trust_first_use_action(skill_trust, config: DetectionConfig) -> str | None:
    """Resolve the configured first-use action for the active profile."""

    if skill_trust_first_use_state_rule(skill_trust) is None:
        return None
    mode = str(config.mode or "normal").strip().lower()
    if mode not in {"normal", "benchmark", "strict", "permissive"}:
        mode = "normal"
    return str(getattr(config, f"skill_trust_first_use_{mode}_action", "audit"))


def _skill_trust_evidence(
    event: CanonicalEvent,
    context: Optional[DecisionContext],
    current_level: RiskLevel,
    current_score: float,
    config: DetectionConfig,
) -> tuple[RiskLevel, float, list[str], list[dict]]:
    skill_trust = context.skill_trust if context is not None else None
    if skill_trust is None:
        return current_level, current_score, [], []

    rule_hits: list[str] = []
    findings: list[dict] = []

    if skill_trust.registry_status == "unknown":
        rule_hits.append("unknown_skill_identity")
    elif skill_trust.registry_status == "unbound":
        rule_hits.append("unbound_skill_identity")
    elif skill_trust.registry_status == "ambiguous":
        rule_hits.append("ambiguous_skill_alias")
    elif skill_trust.registry_status == "hash_mismatch":
        rule_hits.append("skill_hash_mismatch")

    for violation in skill_trust.invariant_violations:
        if violation not in rule_hits:
            rule_hits.append(violation)

    if (
        skill_trust.provenance_claim
        and skill_trust.presented_name
        and _skill_identity_normalize(skill_trust.provenance_claim)
        == _skill_identity_normalize(skill_trust.presented_name)
        and skill_trust.provenance_claim != skill_trust.presented_name
    ):
        rule_hits.append("provenance_label_mismatch")

    first_use_rule = skill_trust_first_use_state_rule(skill_trust)
    first_use_action = skill_trust_first_use_action(skill_trust, config)
    if first_use_rule and first_use_rule not in rule_hits:
        rule_hits.append(first_use_rule)

    for rule_id in rule_hits:
        finding = {
            "rule_id": rule_id,
            "registry_status": skill_trust.registry_status,
            "canonical_skill_id": skill_trust.canonical_skill_id,
            "presented_name": skill_trust.presented_name,
            "provenance_claim": skill_trust.provenance_claim,
            "alias_match_type": skill_trust.alias_match_type,
            "admission_scan_id": skill_trust.admission_scan_id,
            "admission_risk": skill_trust.admission_risk,
            "trust_list_state": skill_trust.trust_list_state,
            "policy_fingerprint": skill_trust.policy_fingerprint,
            "decision_affecting": False,
        }
        if rule_id == first_use_rule and skill_trust.first_use_scan is not None:
            finding.update({
                "first_use_scan_state": skill_trust.first_use_scan.state,
                "first_use_action": first_use_action or "audit",
                "first_use_scan_failure_class": skill_trust.first_use_scan.failure_class,
                "first_use_scan_admission_risk": skill_trust.first_use_scan.admission_risk,
            })
        findings.append(finding)

    if event.event_type != EventType.PRE_ACTION:
        return current_level, current_score, rule_hits, findings

    upgrade_level: RiskLevel | None = None
    rule_set = set(rule_hits)
    hard_confidence = (
        "skill_hash_mismatch" in rule_set
        or "blacklisted_skill_identity" in rule_set
        or "revoked_skill_identity" in rule_set
    )
    soft_confidence = (
        {"ambiguous_skill_alias", "provenance_label_conflict"}.issubset(rule_set)
        or {"unknown_skill_identity", "unknown_skill_provenance_rewrite"}.issubset(rule_set)
        or "low_trust_redefined_canonical_tool" in rule_set
    )
    if hard_confidence:
        upgrade_level = RiskLevel.HIGH
    elif soft_confidence:
        mode = str(config.mode or "normal").strip().lower()
        upgrade_level = (
            RiskLevel.HIGH
            if mode in {"benchmark", "strict"}
            else RiskLevel.MEDIUM
        )
    if first_use_action == "block":
        upgrade_level = RiskLevel.HIGH
    if skill_trust.admission_risk == "critical":
        upgrade_level = RiskLevel.CRITICAL

    if upgrade_level is None:
        if first_use_action in {"force_l2", "force_l3", "defer"}:
            for finding in findings:
                if finding.get("rule_id") == first_use_rule:
                    finding["decision_affecting"] = True
        return current_level, current_score, rule_hits, findings

    for finding in findings:
        finding["decision_affecting"] = True
    risk_level = _max_risk_level(current_level, upgrade_level)
    score = max(current_score, _min_score_for_level(risk_level, config))
    return risk_level, score, rule_hits, findings


def _skill_identity_normalize(value: str) -> str:
    return re.sub(r"[\s_-]+", "", value.strip().lower())


def _counts_toward_d4_high_risk(snapshot: RiskSnapshot) -> bool:
    if snapshot.short_circuit_rule is not None:
        return True
    if max(snapshot.dimensions.d1, snapshot.dimensions.d2, snapshot.dimensions.d3) >= 3:
        return True
    if snapshot.taint_flow_summary is not None:
        return True
    rule_hits = set(snapshot.rule_hits)
    if not rule_hits:
        return True
    skill_trust_rules = {
        "ambiguous_skill_alias",
        "blacklisted_skill_identity",
        "greylisted_skill_identity",
        "low_trust_redefined_canonical_tool",
        "provenance_label_conflict",
        "provenance_label_mismatch",
        "revoked_skill_identity",
        "runtime_registry_claim_untrusted",
        "skill_hash_mismatch",
        "unbound_skill_identity",
        "unknown_skill_identity",
        "unknown_skill_provenance_rewrite",
        "first_use_scan_failed",
        "first_use_scan_not_started",
        "first_use_scan_pending_budget_exhausted",
        "first_use_scan_running_sync",
    }
    if not rule_hits.issubset(skill_trust_rules):
        return True
    return any(
        rule in rule_hits
        for rule in {
            "blacklisted_skill_identity",
            "revoked_skill_identity",
            "skill_hash_mismatch",
        }
    )


def _max_risk_level(a: RiskLevel, b: RiskLevel) -> RiskLevel:
    return a if RISK_LEVEL_ORDER[a] >= RISK_LEVEL_ORDER[b] else b


def _min_score_for_level(level: RiskLevel, config: DetectionConfig) -> float:
    if level == RiskLevel.CRITICAL:
        return config.threshold_critical
    if level == RiskLevel.HIGH:
        return config.threshold_high
    if level == RiskLevel.MEDIUM:
        return config.threshold_medium
    return 0.0


def _extract_text_for_d6(event: CanonicalEvent) -> str:
    """Extract analyzable text from event payload for D6 scoring."""
    payload = event.payload or {}
    parts: list[str] = []
    for key in ("command", "content", "text", "body", "input", "code", "message", "transcript", "userMessage", "user_message"):
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
    d4 = session_tracker.get_d4(event.session_id, config=config)

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
    effect_envelope = normalize_action_effect(event, context)
    effect_summary = effect_envelope.to_summary() if effect_envelope.effects or effect_envelope.evidence_rules else None

    # Short-circuit rules (priority over scoring)
    sc_rule: Optional[str] = None
    sc_level: Optional[RiskLevel] = None
    if (
        "disabled_capability_equivalent" in effect_envelope.evidence_rules
        and effect_envelope.confidence == "high"
    ):
        sc_rule = "SC-4"
        sc_level = RiskLevel.HIGH if config.mode in ("strict", "benchmark") else RiskLevel.MEDIUM
    elif (
        (
            "script_analysis_unavailable" in effect_envelope.evidence_rules
            or "wrapper_chain_unresolved" in effect_envelope.evidence_rules
        )
        and config.mode in ("strict", "benchmark")
    ):
        sc_rule = "SC-7"
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

    risk_level, score, rule_hits, skill_trust_findings = _skill_trust_evidence(
        event,
        context,
        risk_level,
        score,
        config,
    )
    for rule_id in effect_envelope.evidence_rules:
        if rule_id not in rule_hits:
            rule_hits.append(rule_id)
    if "disabled_capability_equivalent" in effect_envelope.evidence_rules:
        if config.mode == "normal":
            risk_level = _max_risk_level(risk_level, RiskLevel.MEDIUM)
            score = max(score, _min_score_for_level(risk_level, config))
        elif config.mode in ("strict", "benchmark"):
            risk_level = _max_risk_level(risk_level, RiskLevel.HIGH)
            score = max(score, _min_score_for_level(risk_level, config))
    if (
        sc_rule is None
        and "generated_script_future_exec" in effect_envelope.evidence_rules
        and _has_low_trust_skill_evidence(rule_hits, skill_trust_findings)
    ):
        sc_rule = "SC-8"
        if config.mode in ("strict", "benchmark"):
            risk_level = _max_risk_level(risk_level, RiskLevel.HIGH)
        else:
            risk_level = _max_risk_level(risk_level, RiskLevel.MEDIUM)
        score = max(score, _min_score_for_level(risk_level, config))
    taint_flow_summary = _taint_flow_summary(event)
    if taint_flow_summary is not None:
        taint_rule_hits = [
            str(rule_id)
            for rule_id in taint_flow_summary.get("rule_ids", [])
        ]
        for rule_id in taint_rule_hits:
            if rule_id not in rule_hits:
                rule_hits.append(rule_id)
        if event.event_type == EventType.PRE_ACTION:
            severities = {
                str(rule.get("severity"))
                for rule in taint_flow_summary.get("rules", [])
                if isinstance(rule, dict)
            }
            if "critical" in severities:
                risk_level = _max_risk_level(risk_level, RiskLevel.CRITICAL)
                score = max(score, _min_score_for_level(risk_level, config))
            elif "high" in severities:
                risk_level = _max_risk_level(risk_level, RiskLevel.HIGH)
                score = max(score, _min_score_for_level(risk_level, config))

    snapshot = RiskSnapshot(
        risk_level=risk_level,
        composite_score=score,
        dimensions=dims,
        short_circuit_rule=sc_rule,
        missing_dimensions=missing_dims,
        classified_by=ClassifiedBy.L1,
        classified_at=utc_now_iso(),
        rule_hits=rule_hits,
        skill_trust_findings=skill_trust_findings,
        taint_flow_summary=taint_flow_summary,
        effect_summary=effect_summary,
    )

    # Update session tracker if risk >= high
    if (
        risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL)
        and _counts_toward_d4_high_risk(snapshot)
    ):
        session_tracker.record_high_risk_event(event.session_id)

    return snapshot


def _has_low_trust_skill_evidence(
    rule_hits: list[str],
    skill_trust_findings: list[dict[str, Any]],
) -> bool:
    rule_set = set(rule_hits)
    if rule_set.intersection({
        "low_trust_redefined_canonical_tool",
        "provenance_label_conflict",
        "unknown_skill_provenance_rewrite",
        "blacklisted_skill_identity",
        "revoked_skill_identity",
        "skill_hash_mismatch",
    }):
        return True
    for finding in skill_trust_findings:
        if finding.get("admission_risk") in {"high", "critical"}:
            return True
        if finding.get("trust_list_state") in {"greylist", "blacklist", "revoked", "disabled"}:
            return True
    return False
