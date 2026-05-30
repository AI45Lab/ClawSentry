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
from pathlib import Path
from typing import Any, Optional

from .detection_config import DetectionConfig
from .effect_normalizer import contextual_binding_parts, normalize_action_effect
from .injection_detector import score_layer1
from .managed_benchmark_warnings import WORK5C_WARNING_PROFILE_ID
from .models import (
    AgentTrustLevel,
    CanonicalEvent,
    ClassifiedBy,
    DecisionContext,
    EventType,
    L1AuthorityClass,
    RISK_LEVEL_ORDER,
    RiskDimensions,
    RiskLevel,
    RiskSnapshot,
    ReviewRoutingIntent,
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

FSPR_SCHEMA_VERSION = "clawsentry.first_use_skill_package_review.v1"
_FSPR_ALLOWED_VERDICTS = frozenset({
    "consistent",
    "suspicious",
    "inconsistent",
    "insufficient_evidence",
})
_FSPR_ALLOWED_TIMING_MODES = frozenset({"pre_use_gate", "post_action_incremental_evidence"})
_FSPR_PROVIDER_HEALTH_DEGRADATION_REASONS = frozenset({
    "provider_invalid_json",
    "provider_unavailable",
    "provider_call_timeout",
})

_HARD_BLOCK_RULE_HITS = frozenset({
    "runtime_path_disallowed",
    "runtime_content_mismatch",
    "blocked_skill_lineage_match",
    "denied_effect_repeat",
    "credential_source_to_network_sink",
    "document_input_to_network_sink",
    "document_input_encoded_to_network_sink",
    "subprocess_file_transfer",
    "remote_fetch_to_interpreter",
    "persistence_entrypoint_write",
    "password_protected_archive_creation",
    "encrypted_artifact_creation",
    "wrapper_chain_unresolved",
})

_NON_CLEARABLE_EFFECTS = frozenset({
    "network.fetch",
    "network.upload",
    "package.install",
    "future_execution.entrypoint",
    "encoded_payload.materialization",
    "delegated_effect_request",
})

_REVIEWABLE_CONTEXTUAL_EFFECTS = frozenset({
    "command.exec",
    "filesystem.read",
    "filesystem.write",
    "future_execution.artifact",
})

_CONTEXTUAL_DISQUALIFYING_RULE_FRAGMENTS = (
    "credential",
    "network",
    "package",
    "destructive",
    "persistence",
    "system_path",
    "system-write",
    "wrapper",
    "encoded_payload",
    "encoded-payload",
    "disabled_capability",
    "disabled-capability",
    "blocked_skill_lineage",
)

_WORK5C_RELAXED_READONLY_EFFECTS = frozenset({
    "filesystem.read",
    "filesystem.enumerate",
    "environment.probe",
})
_WORK5C_RELAXED_READONLY_TARGET_ROLES = frozenset({
    "skill_package_read",
    "capability_probe",
})
_WORK5C_RELAXED_READONLY_WORKSPACE_RELATIONS = frozenset({
    "inside_workspace",
    "outside_workspace_or_absolute",
    "process_environment",
})
_WORK5C_TASK_READONLY_EFFECTS = frozenset({
    "filesystem.read",
    "filesystem.enumerate",
})
_WORK5C_TASK_READONLY_TARGET_ROLES = frozenset({
    "benchmark_task_data_read",
})
_WORK5C_TASK_READONLY_WORKSPACE_RELATIONS = frozenset({
    "benchmark_task_data",
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
_TAINT_SEGMENT_SPLIT_RE = re.compile(r"\s*(?:&&|\|\||;)\s*")
_TAINT_ARCHIVE_DELETE_RE = re.compile(
    r"(?:^|[;&]\s*)(?:rm|shred|srm)\s+-?[^;&|]*\b|find\b[^;&|]*\s-delete\b",
    re.IGNORECASE,
)

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


def _taint_shell_segments(command: str) -> list[list[str]]:
    segments: list[list[str]] = []
    for part in _TAINT_SEGMENT_SPLIT_RE.split(command):
        stripped = part.strip()
        if not stripped:
            continue
        try:
            tokens = shlex.split(stripped)
        except ValueError:
            tokens = stripped.split()
        if tokens:
            segments.append(tokens)
    return segments


def _taint_zip_password_creation(tokens: list[str]) -> bool:
    if not tokens or Path(tokens[0]).name.lower() != "zip":
        return False
    if any(token in {"--test", "-T", "--show-files", "-sf", "-h", "--help", "-v", "--version"} for token in tokens[1:]):
        return False
    return any(
        token in {"-P", "--password", "-e", "--encrypt"}
        or token.startswith("-P")
        or (token.startswith("-") and not token.startswith("--") and "e" in token[1:])
        for token in tokens[1:]
    )


def _taint_7z_password_creation(tokens: list[str]) -> bool:
    return (
        len(tokens) >= 3
        and Path(tokens[0]).name.lower() in {"7z", "7za", "7zr"}
        and tokens[1].lower() in {"a", "u"}
        and any(token == "-p" or token.startswith("-p") for token in tokens[2:])
    )


def _taint_encrypted_artifact_creation(tokens: list[str]) -> bool:
    name = Path(tokens[0]).name.lower() if tokens else ""
    if name in {"gpg", "gpg2"}:
        if any(token in {"--decrypt", "-d", "--verify", "--list-packets", "--list-keys"} for token in tokens[1:]):
            return False
        return any(token in {"-c", "--symmetric"} for token in tokens[1:])
    if name == "openssl" and "enc" in tokens[1:]:
        if "-d" in tokens or "-decrypt" in tokens:
            return False
        return "-out" in tokens or any(token.startswith("-out=") for token in tokens)
    return False


def _taint_archive_encrypt_pipeline(command: str) -> bool:
    if "|" not in command:
        return False
    left, right = command.split("|", 1)
    try:
        left_tokens = shlex.split(left.strip())
        right_tokens = shlex.split(right.strip())
    except ValueError:
        left_tokens = left.strip().split()
        right_tokens = right.strip().split()
    return (
        bool(left_tokens)
        and Path(left_tokens[0]).name.lower() == "tar"
        and _taint_encrypted_artifact_creation(right_tokens)
    )


def _encrypted_archive_taint_rule_ids(command: str) -> list[str]:
    rule_ids: list[str] = []
    for tokens in _taint_shell_segments(command):
        if _taint_zip_password_creation(tokens) or _taint_7z_password_creation(tokens):
            if "password_protected_archive_creation" not in rule_ids:
                rule_ids.append("password_protected_archive_creation")
        elif _taint_encrypted_artifact_creation(tokens):
            if "encrypted_artifact_creation" not in rule_ids:
                rule_ids.append("encrypted_artifact_creation")
    if _taint_archive_encrypt_pipeline(command) and "archive_encrypt_pipeline" not in rule_ids:
        rule_ids.append("archive_encrypt_pipeline")
    if rule_ids and _TAINT_ARCHIVE_DELETE_RE.search(command):
        rule_ids.append("encrypted_archive_then_delete_original")
    return rule_ids


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

    if command:
        for rule_id in _encrypted_archive_taint_rule_ids(command):
            if rule_id == "encrypted_archive_then_delete_original":
                rules.append({
                    "rule_id": rule_id,
                    "severity": "critical",
                    "source": "workspace_artifact",
                    "sink": "destructive_lock_in",
                })
            else:
                rules.append({
                    "rule_id": rule_id,
                    "severity": "high",
                    "source": "workspace_artifact",
                    "sink": "encrypted_archive",
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


def _content_evidence_rule_ids(context: DecisionContext | None) -> list[str]:
    envelope = getattr(context, "content_evidence", None) if context is not None else None
    if envelope is None:
        return []
    rule_ids: list[str] = []
    for item in getattr(envelope, "items", []) or []:
        for rule in getattr(item, "derived_rules", []) or []:
            if not isinstance(rule, dict):
                continue
            rule_id = str(rule.get("rule_id") or "")
            if rule_id and rule_id not in rule_ids:
                rule_ids.append(rule_id)
    return rule_ids


def _content_evidence_taint_summary(
    context: DecisionContext | None,
    existing: dict[str, object] | None,
) -> dict[str, object] | None:
    rule_ids = _content_evidence_rule_ids(context)
    content_rules: list[dict[str, object]] = []
    if "document_input_to_network_sink" in rule_ids:
        content_rules.append({
            "rule_id": "document_input_to_network_sink",
            "severity": "high",
            "source": "document_input",
            "sink": "network_upload",
        })
    if "document_input_encoded_to_network_sink" in rule_ids:
        content_rules.append({
            "rule_id": "document_input_encoded_to_network_sink",
            "severity": "high",
            "source": "document_input",
            "sink": "encoded_network_upload",
        })
    if "credential_source_to_network_sink" in rule_ids:
        content_rules.append({
            "rule_id": "credential_source_to_network_sink",
            "severity": "critical",
            "source": "credential_source",
            "sink": "network_upload",
        })
    if "subprocess_file_transfer" in rule_ids:
        content_rules.append({
            "rule_id": "subprocess_file_transfer",
            "severity": "high",
            "source": "workspace_file",
            "sink": "subprocess_file_transfer",
        })
    if not content_rules:
        return existing

    if existing is None:
        rules = content_rules
        command_hash = None
    else:
        rules = list(existing.get("rules", [])) + content_rules
        command_hash = existing.get("command_hash")
    merged_rule_ids: list[str] = []
    for rule in rules:
        if isinstance(rule, dict):
            rule_id = str(rule.get("rule_id") or "")
            if rule_id and rule_id not in merged_rule_ids:
                merged_rule_ids.append(rule_id)
    return {
        "rules": rules,
        "rule_ids": merged_rule_ids,
        "chain_count": len(rules),
        "command_hash": command_hash,
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


def skill_trust_first_use_policy_effect(skill_trust, config: DetectionConfig) -> str | None:
    """Resolve first-use admission policy to a legacy action until policy migration finishes."""

    if skill_trust_first_use_state_rule(skill_trust) is None:
        return None
    mode = str(config.mode or "normal").strip().lower()
    if mode not in {"normal", "benchmark", "strict", "permissive"}:
        mode = "normal"
    policy = str(getattr(config, f"skill_trust_first_use_{mode}_policy", "audit_only"))
    if policy == "block_until_reviewed":
        return "block"
    if policy in {"scan_async_defer", "defer_for_review"}:
        return "defer"
    return "audit"


def skill_trust_runtime_binding_action(skill_trust, config: DetectionConfig) -> str | None:
    """Resolve the configured runtime-binding action for the active profile."""

    if skill_trust is None:
        return None
    runtime_status = getattr(skill_trust, "runtime_path_status", None)
    runtime_content_status = getattr(skill_trust, "runtime_content_status", None)
    if runtime_status not in {
        "disallowed",
        "ambiguous_runtime_source",
        "name_only_unverified",
        "path_fragment_unverified",
    } and runtime_content_status not in {"content_unverified", "content_mismatch"}:
        return None
    mode = str(config.mode or "normal").strip().lower()
    if mode not in {"normal", "benchmark", "strict", "permissive"}:
        mode = "normal"
    condition = None
    if runtime_status == "disallowed":
        condition = "path_disallowed"
    elif runtime_status == "ambiguous_runtime_source":
        condition = "source_ambiguous"
    elif runtime_status in {"name_only_unverified", "path_fragment_unverified"}:
        condition = "path_unverified"
    if runtime_content_status == "content_unverified":
        condition = "content_unverified"
    elif runtime_content_status == "content_mismatch":
        condition = "content_mismatch"
    if condition is None:
        return None
    condition_attr = f"skill_trust_runtime_{condition}_{mode}_action"
    return str(getattr(config, condition_attr, "audit"))


def _skill_trust_runtime_binding_condition(skill_trust) -> str | None:
    runtime_status = getattr(skill_trust, "runtime_path_status", None)
    runtime_content_status = getattr(skill_trust, "runtime_content_status", None)
    if runtime_status == "disallowed":
        return "path_disallowed"
    if runtime_status == "ambiguous_runtime_source":
        return "source_ambiguous"
    if runtime_status in {"name_only_unverified", "path_fragment_unverified"}:
        return "path_unverified"
    if runtime_content_status == "content_unverified":
        return "content_unverified"
    if runtime_content_status == "content_mismatch":
        return "content_mismatch"
    return None


def skill_trust_runtime_binding_review_tier(skill_trust, config: DetectionConfig) -> str:
    """Resolve the policy-owned review tier for runtime-binding evidence."""

    condition = _skill_trust_runtime_binding_condition(skill_trust)
    mode = str(config.mode or "normal").strip().lower()
    if mode not in {"normal", "benchmark", "strict", "permissive"}:
        mode = "normal"
    matrix = {
        "path_disallowed": {
            "normal": "l3",
            "benchmark": "none",
            "strict": "none",
            "permissive": "none",
        },
        "source_ambiguous": {
            "normal": "l3",
            "benchmark": "none",
            "strict": "l3",
            "permissive": "none",
        },
        "path_unverified": {
            "normal": "none",
            "benchmark": "none",
            "strict": "l3",
            "permissive": "none",
        },
        "content_unverified": {
            "normal": "l3",
            "benchmark": "l3",
            "strict": "l3",
            "permissive": "none",
        },
        "content_mismatch": {
            "normal": "l3",
            "benchmark": "none",
            "strict": "none",
            "permissive": "none",
        },
    }
    return matrix.get(condition or "", {}).get(mode, "none")


def _validated_fspr_review(fspr_review: object) -> dict | None:
    if hasattr(fspr_review, "model_dump"):
        fspr_review = fspr_review.model_dump(mode="json")  # type: ignore[union-attr]
    if not isinstance(fspr_review, dict):
        return None
    review = dict(fspr_review)
    forbidden_policy_fields = {
        "recommended_action",
        "recommended_policy_action",
        "recommended_review_tier",
    }
    if any(field in review for field in forbidden_policy_fields):
        review["verdict"] = "insufficient_evidence"
        if str(review.get("timing_mode") or "") not in _FSPR_ALLOWED_TIMING_MODES:
            review["timing_mode"] = "post_action_incremental_evidence"
        review["degraded"] = True
        review["degradation_reason"] = "invalid_policy_field"
        return review
    schema = str(review.get("schema") or "")
    verdict = str(review.get("verdict") or "")
    timing_mode = str(review.get("timing_mode") or "")
    if schema != FSPR_SCHEMA_VERSION:
        review["verdict"] = "insufficient_evidence"
        if timing_mode not in _FSPR_ALLOWED_TIMING_MODES:
            review["timing_mode"] = "post_action_incremental_evidence"
        review["degraded"] = True
        review["degradation_reason"] = "invalid_schema"
        return review
    if timing_mode not in _FSPR_ALLOWED_TIMING_MODES:
        review["verdict"] = "insufficient_evidence"
        review["timing_mode"] = "post_action_incremental_evidence"
        review["degraded"] = True
        review["degradation_reason"] = "invalid_timing_mode"
        return review
    if verdict not in _FSPR_ALLOWED_VERDICTS:
        review["verdict"] = "insufficient_evidence"
        review["degraded"] = True
        review["degradation_reason"] = "invalid_verdict"
    return review


def _normalized_degradation_reason(value: object) -> str:
    return str(value or "").split(":", 1)[0].strip()


def _fspr_finding_is_hard(finding: object) -> bool:
    if not isinstance(finding, dict):
        return False
    return bool(
        finding.get("decision_affecting")
        or str(finding.get("severity") or "").lower() in {"high", "critical"}
    )


def _fspr_role_result_is_hard(role_result: object) -> bool:
    if not isinstance(role_result, dict):
        return False
    verdict = str(role_result.get("verdict") or "").lower()
    severity = str(role_result.get("severity") or "").lower()
    return bool(
        role_result.get("decision_affecting")
        or verdict in {"suspicious", "inconsistent"}
        or severity in {"high", "critical"}
    )


def _fspr_review_has_hard_findings(review: dict[str, Any]) -> bool:
    if str(review.get("severity") or "").lower() in {"high", "critical"}:
        return True
    if any(_fspr_finding_is_hard(item) for item in review.get("final_findings") or []):
        return True
    for role_result in review.get("role_results") or []:
        if not isinstance(role_result, dict):
            continue
        if _fspr_role_result_is_hard(role_result):
            return True
        if any(_fspr_finding_is_hard(item) for item in role_result.get("findings") or []):
            return True
    return False


def is_provider_health_only_degraded_fspr(fspr_review: object) -> bool:
    review = _validated_fspr_review(fspr_review)
    if review is None:
        return False
    if not bool(review.get("degraded")):
        return False
    if str(review.get("verdict") or "") != "insufficient_evidence":
        return False
    if _normalized_degradation_reason(review.get("degradation_reason")) not in _FSPR_PROVIDER_HEALTH_DEGRADATION_REASONS:
        return False
    if review.get("deterministic_findings_preserved") is not True:
        return False
    if review.get("admission_recommendation") is not None:
        return False
    if _fspr_review_has_hard_findings(review):
        return False
    return True


def is_strong_trusted_runtime_binding(skill_trust) -> tuple[bool, str]:
    if skill_trust is None:
        return False, "skill_trust_missing"
    if getattr(skill_trust, "registry_status", None) != "matched":
        return False, "registry_status_not_matched"
    if getattr(skill_trust, "trust_list_state", None) != "allowlist":
        return False, "trust_list_state_not_allowlist"
    if getattr(skill_trust, "admission_risk", None) != "low":
        return False, "admission_risk_not_low"
    runtime_path_status = getattr(skill_trust, "runtime_path_status", None)
    if runtime_path_status not in {"verified_source", "verified_mirror"}:
        return False, "runtime_path_not_verified"
    runtime_content_status = getattr(skill_trust, "runtime_content_status", None)
    if runtime_content_status not in {"content_verified", "trusted_runner_immutable", "not_applicable"}:
        return False, "runtime_content_not_verified"
    if runtime_content_status == "not_applicable" and runtime_path_status != "verified_source":
        return False, "runtime_content_not_applicable_without_source_binding"
    if getattr(skill_trust, "metadata_source", None) != "gateway_owned_metadata":
        return False, "metadata_not_gateway_owned"
    if not getattr(skill_trust, "metadata_record_id", None):
        return False, "metadata_record_id_missing"
    if not getattr(skill_trust, "runtime_evidence_kind", None):
        return False, "runtime_evidence_kind_missing"
    if not getattr(skill_trust, "policy_fingerprint", None):
        return False, "policy_fingerprint_missing"
    if getattr(skill_trust, "invariant_violations", None):
        return False, "invariant_violation_present"
    return True, ""


def skill_trust_fspr_policy_action(
    fspr_review: object,
    config: DetectionConfig,
    skill_trust=None,
) -> str | None:
    """Resolve Gateway-owned policy action from FSPR evidence."""

    review = _validated_fspr_review(fspr_review)
    if review is None:
        return None
    if str(review.get("timing_mode") or "") != "pre_use_gate":
        return "audit"
    strong_binding, _failure_reason = is_strong_trusted_runtime_binding(skill_trust)
    if is_provider_health_only_degraded_fspr(review) and strong_binding:
        return "audit"
    verdict = str(review.get("verdict") or "")
    mode = str(config.mode or "normal").strip().lower()
    if mode not in {"normal", "benchmark", "strict", "permissive"}:
        mode = "normal"
    matrix = {
        "normal": {
            "consistent": "audit",
            "insufficient_evidence": "audit",
            "suspicious": "audit",
            "inconsistent": "defer",
        },
        "benchmark": {
            "consistent": "audit",
            "insufficient_evidence": "block",
            "suspicious": "defer",
            "inconsistent": "block",
        },
        "strict": {
            "consistent": "audit",
            "insufficient_evidence": "defer",
            "suspicious": "defer",
            "inconsistent": "block",
        },
        "permissive": {
            "consistent": "audit",
            "insufficient_evidence": "audit",
            "suspicious": "audit",
            "inconsistent": "audit",
        },
    }
    return matrix[mode].get(verdict, "audit")


def skill_trust_fspr_review_tier(
    fspr_review: object,
    config: DetectionConfig,
    skill_trust=None,
) -> str | None:
    """Resolve Gateway-owned review tier from FSPR evidence."""

    review = _validated_fspr_review(fspr_review)
    if review is None:
        return None
    if str(review.get("timing_mode") or "") != "pre_use_gate":
        return "none"
    strong_binding, _failure_reason = is_strong_trusted_runtime_binding(skill_trust)
    if is_provider_health_only_degraded_fspr(review) and strong_binding:
        return "none"
    verdict = str(review.get("verdict") or "")
    mode = str(config.mode or "normal").strip().lower()
    if mode not in {"normal", "benchmark", "strict", "permissive"}:
        mode = "normal"
    matrix = {
        "normal": {
            "consistent": "none",
            "insufficient_evidence": "none",
            "suspicious": "l3",
            "inconsistent": "l3",
        },
        "benchmark": {
            "consistent": "none",
            "insufficient_evidence": "none",
            "suspicious": "l3",
            "inconsistent": "none",
        },
        "strict": {
            "consistent": "none",
            "insufficient_evidence": "l3",
            "suspicious": "l3",
            "inconsistent": "none",
        },
        "permissive": {
            "consistent": "none",
            "insufficient_evidence": "none",
            "suspicious": "none",
            "inconsistent": "none",
        },
    }
    return matrix[mode].get(verdict, "none")


def _action_to_routing(action: str | None) -> tuple[str, str]:
    if action == "force_l3":
        return "audit", "l3"
    if action == "force_l2":
        return "audit", "l2"
    if action == "defer":
        return "defer", "none"
    if action == "block":
        return "block", "none"
    return "audit", "none"


def _compact_skill_trust_metadata(skill_trust, extra: dict[str, Any] | None = None) -> dict[str, Any]:
    metadata = {
        "registry_status": getattr(skill_trust, "registry_status", None),
        "canonical_skill_id": getattr(skill_trust, "canonical_skill_id", None),
        "presented_name": getattr(skill_trust, "presented_name", None),
        "ref_ordinal": getattr(skill_trust, "ref_ordinal", None),
    }
    if extra:
        metadata.update(extra)
    return {key: value for key, value in metadata.items() if value is not None}


def build_skill_trust_routing_intents(skill_trust, config: DetectionConfig) -> list[ReviewRoutingIntent]:
    """Build policy-owned routing intents from one Skill Trust evidence object."""

    if skill_trust is None:
        return []
    intents: list[ReviewRoutingIntent] = []

    first_use_rule = skill_trust_first_use_state_rule(skill_trust)
    first_use_effect = skill_trust_first_use_policy_effect(skill_trust, config)
    if first_use_rule is not None:
        policy_action, recommended_tier = _action_to_routing(first_use_effect)
        mode = str(config.mode or "normal").strip().lower()
        if mode not in {"normal", "benchmark", "strict", "permissive"}:
            mode = "normal"
        configured_policy = str(getattr(config, f"skill_trust_first_use_{mode}_policy", "audit_only"))
        intents.append(ReviewRoutingIntent(
            source="first_use_admission",
            recommended_tier=recommended_tier,
            policy_action=policy_action,
            reason="first_use_unreviewed_skill",
            source_metadata=_compact_skill_trust_metadata(skill_trust, {
                "first_use_rule": first_use_rule,
                "first_use_scan_state": getattr(getattr(skill_trust, "first_use_scan", None), "state", None),
                "admission_policy": configured_policy,
                "policy_effect": first_use_effect or "audit",
            }),
            routing_affecting=recommended_tier in {"l2", "l3"},
            decision_affecting=policy_action in {"defer", "block"},
        ))

    runtime_action = skill_trust_runtime_binding_action(skill_trust, config)
    if runtime_action is not None:
        policy_action, fallback_tier = _action_to_routing(runtime_action)
        recommended_tier = skill_trust_runtime_binding_review_tier(skill_trust, config)
        if recommended_tier == "none":
            recommended_tier = fallback_tier
        intents.append(ReviewRoutingIntent(
            source="runtime_binding",
            recommended_tier=recommended_tier,
            policy_action=policy_action,
            reason="runtime_binding_identity_conflict",
            source_metadata=_compact_skill_trust_metadata(skill_trust, {
                "runtime_path_status": getattr(skill_trust, "runtime_path_status", None),
                "runtime_content_status": getattr(skill_trust, "runtime_content_status", None),
                "runtime_binding_reason": getattr(skill_trust, "runtime_binding_reason", None),
                "configured_action": runtime_action,
                "review_tier": recommended_tier,
            }),
            routing_affecting=recommended_tier in {"l2", "l3"},
            decision_affecting=policy_action in {"defer", "block"},
        ))

    fspr_review = _validated_fspr_review(getattr(skill_trust, "first_use_package_review", None))
    if fspr_review is not None:
        if str(fspr_review.get("timing_mode") or "") != "pre_use_gate":
            return intents
        policy_action = skill_trust_fspr_policy_action(fspr_review, config, skill_trust) or "audit"
        review_tier = skill_trust_fspr_review_tier(fspr_review, config, skill_trust) or "none"
        strong_binding, strong_binding_failure_reason = is_strong_trusted_runtime_binding(skill_trust)
        provider_health_only = is_provider_health_only_degraded_fspr(fspr_review)
        intents.append(ReviewRoutingIntent(
            source="fspr_package_review",
            recommended_tier=review_tier,
            policy_action=policy_action,
            reason="fspr_package_review",
            source_metadata=_compact_skill_trust_metadata(skill_trust, {
                "verdict": fspr_review.get("verdict"),
                "severity": fspr_review.get("severity"),
                "confidence": fspr_review.get("confidence"),
                "degraded": bool(fspr_review.get("degraded", False)),
                "degradation_reason": fspr_review.get("degradation_reason"),
                "provider_health_only": provider_health_only,
                "strong_runtime_binding": strong_binding,
                "strong_binding_failure_reason": strong_binding_failure_reason,
            }),
            routing_affecting=review_tier in {"l2", "l3"},
            decision_affecting=policy_action in {"defer", "block"},
        ))

    return intents


def build_content_evidence_routing_intents(
    context: DecisionContext | None,
    config: DetectionConfig,
) -> list[ReviewRoutingIntent]:
    """Build Gateway-owned routing intents from request-local content evidence."""

    rule_ids = set(_content_evidence_rule_ids(context))
    if not rule_ids:
        return []
    envelope = getattr(context, "content_evidence", None) if context is not None else None
    source_metadata = {"rule_ids": sorted(rule_ids), "mode": ""}
    exact_refs = list(getattr(envelope, "exact_ref_allowlist", []) or []) if envelope is not None else []
    mode = str(config.mode or "normal").strip().lower()
    if mode not in {"normal", "benchmark", "strict", "permissive"}:
        mode = "normal"
    source_metadata["mode"] = mode
    if exact_refs:
        source_metadata["exact_ref_allowlist"] = exact_refs

    intents: list[ReviewRoutingIntent] = []
    high_confidence_exfil = bool(rule_ids.intersection({
        "document_input_to_network_sink",
        "document_input_encoded_to_network_sink",
        "credential_source_to_network_sink",
        "subprocess_file_transfer",
    }))
    incomplete_with_network = (
        "content_evidence_incomplete" in rule_ids
        and bool(rule_ids.intersection({
            "associated_script_network_sink",
            "document_input_to_network_sink",
            "possible_document_input_to_network_sink",
        }))
    )
    read_content_signal = bool(rule_ids.intersection({
        "read_content_prompt_injection",
        "read_content_hidden_html_instruction",
        "read_content_zero_width_or_bidi",
        "read_content_markdown_beacon",
        "read_content_data_uri_or_base64_payload",
        "sensitive_read_path",
        "credential_read_content_skipped",
        "read_content_execution_or_network_instruction",
        "read_content_unsupported_binary",
        "read_content_oversize",
    }))

    if high_confidence_exfil:
        policy_action = {
            "benchmark": "block",
            "strict": "defer",
            "normal": "defer",
            "permissive": "audit",
        }[mode]
        intents.append(ReviewRoutingIntent(
            source="content_evidence",
            recommended_tier="l3" if mode == "normal" else "none",
            policy_action=policy_action,
            reason="document_input_to_network_sink",
            source_metadata=dict(source_metadata),
            routing_affecting=mode == "normal",
            decision_affecting=policy_action in {"defer", "block"},
        ))
    elif incomplete_with_network:
        policy_action = {
            "benchmark": "block",
            "strict": "defer",
            "normal": "defer",
            "permissive": "audit",
        }[mode]
        intents.append(ReviewRoutingIntent(
            source="content_evidence",
            recommended_tier="l3" if mode in {"normal", "strict"} else "none",
            policy_action=policy_action,
            reason="content_evidence_incomplete",
            source_metadata=dict(source_metadata),
            routing_affecting=mode in {"normal", "strict"},
            decision_affecting=policy_action in {"defer", "block"},
        ))
    elif read_content_signal:
        policy_action = {
            "benchmark": "defer",
            "strict": "defer",
            "normal": "audit",
            "permissive": "audit",
        }[mode]
        intents.append(ReviewRoutingIntent(
            source="content_evidence",
            recommended_tier="l3" if mode == "normal" else "none",
            policy_action=policy_action,
            reason="read_content_evidence",
            source_metadata=dict(source_metadata),
            routing_affecting=mode == "normal",
            decision_affecting=policy_action in {"defer", "block"},
        ))
    return intents


def _skill_trust_routing_intents_for_context(
    context: Optional[DecisionContext],
    config: DetectionConfig,
) -> list[ReviewRoutingIntent]:
    if context is None:
        return []
    refs = list(context.skill_trust_refs or [])
    if context.skill_trust is not None and all(ref is not context.skill_trust for ref in refs):
        refs.append(context.skill_trust)
    intents = [
        intent
        for ref in refs
        for intent in build_skill_trust_routing_intents(ref, config)
    ]
    policy_priority = {"block": 3, "defer": 2, "audit": 1}
    tier_priority = {"l3": 3, "l2": 2, "none": 1}
    return sorted(
        intents,
        key=lambda intent: (
            -policy_priority.get(intent.policy_action, 0),
            -tier_priority.get(intent.recommended_tier, 0),
            intent.source,
            intent.reason,
        ),
    )


def _skill_trust_evidence(
    event: CanonicalEvent,
    context: Optional[DecisionContext],
    current_level: RiskLevel,
    current_score: float,
    config: DetectionConfig,
) -> tuple[RiskLevel, float, list[str], list[dict]]:
    if context is not None and context.skill_trust_refs:
        aggregate_level = current_level
        aggregate_score = current_score
        aggregate_hits: list[str] = []
        aggregate_findings: list[dict] = []
        for ref_context in context.skill_trust_refs:
            level, score, hits, findings = _skill_trust_evidence(
                event,
                DecisionContext(skill_trust=ref_context),
                aggregate_level,
                aggregate_score,
                config,
            )
            aggregate_level = level
            aggregate_score = score
            for hit in hits:
                if hit not in aggregate_hits:
                    aggregate_hits.append(hit)
            aggregate_findings.extend(findings)
        return aggregate_level, aggregate_score, aggregate_hits, aggregate_findings

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

    runtime_status = getattr(skill_trust, "runtime_path_status", None)
    runtime_content_status = getattr(skill_trust, "runtime_content_status", None)
    runtime_rule = {
        "disallowed": "runtime_path_disallowed",
        "ambiguous_runtime_source": "runtime_source_ambiguous",
        "name_only_unverified": "runtime_path_unverified",
        "path_fragment_unverified": "runtime_path_fragment_unverified",
    }.get(runtime_status)
    if runtime_rule and runtime_rule not in rule_hits:
        rule_hits.append(runtime_rule)
    if runtime_content_status == "content_unverified" and "runtime_content_unverified" not in rule_hits:
        rule_hits.append("runtime_content_unverified")
    elif runtime_content_status == "content_mismatch" and "runtime_content_mismatch" not in rule_hits:
        rule_hits.append("runtime_content_mismatch")

    if (
        skill_trust.provenance_claim
        and skill_trust.presented_name
        and _skill_identity_normalize(skill_trust.provenance_claim)
        == _skill_identity_normalize(skill_trust.presented_name)
        and skill_trust.provenance_claim != skill_trust.presented_name
    ):
        rule_hits.append("provenance_label_mismatch")

    first_use_rule = skill_trust_first_use_state_rule(skill_trust)
    first_use_effect = skill_trust_first_use_policy_effect(skill_trust, config)
    runtime_binding_action = skill_trust_runtime_binding_action(skill_trust, config)
    fspr_review = _validated_fspr_review(getattr(skill_trust, "first_use_package_review", None))
    fspr_rule: str | None = None
    fspr_policy_action = (
        skill_trust_fspr_policy_action(fspr_review, config, skill_trust)
        if fspr_review is not None
        else None
    )
    fspr_review_tier = (
        skill_trust_fspr_review_tier(fspr_review, config, skill_trust)
        if fspr_review is not None
        else None
    )
    fspr_decision_affecting = False
    fspr_routing_affecting = False
    if isinstance(fspr_review, dict):
        fspr_verdict = str(fspr_review.get("verdict") or "")
        fspr_timing_mode = str(fspr_review.get("timing_mode") or "")
        fspr_provider_health_only = is_provider_health_only_degraded_fspr(fspr_review)
        fspr_strong_binding, fspr_strong_binding_failure_reason = is_strong_trusted_runtime_binding(skill_trust)
        if fspr_verdict == "inconsistent":
            fspr_rule = "first_use_skill_package_inconsistent"
        elif fspr_verdict == "suspicious":
            fspr_rule = "first_use_skill_package_suspicious"
        elif fspr_verdict == "insufficient_evidence":
            fspr_rule = "first_use_skill_package_insufficient_evidence"
        fspr_decision_affecting = (
            fspr_timing_mode == "pre_use_gate"
            and fspr_policy_action in {"defer", "block"}
        )
        fspr_routing_affecting = (
            fspr_timing_mode == "pre_use_gate"
            and fspr_review_tier in {"l2", "l3"}
        )
        if fspr_rule and fspr_rule not in rule_hits:
            rule_hits.append(fspr_rule)
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
            "runtime_path_status": getattr(skill_trust, "runtime_path_status", None),
            "runtime_root_path_hash": getattr(skill_trust, "runtime_root_path_hash", None),
            "runtime_content_status": getattr(skill_trust, "runtime_content_status", None),
            "runtime_binding_reason": getattr(skill_trust, "runtime_binding_reason", None),
            "metadata_record_id": getattr(skill_trust, "metadata_record_id", None),
            "runtime_evidence_kind": getattr(skill_trust, "runtime_evidence_kind", None),
            "ref_ordinal": getattr(skill_trust, "ref_ordinal", None),
            "policy_fingerprint": skill_trust.policy_fingerprint,
            "decision_affecting": False,
        }
        if rule_id == first_use_rule and skill_trust.first_use_scan is not None:
            finding.update({
                "first_use_scan_state": skill_trust.first_use_scan.state,
                "first_use_admission_policy": str(getattr(
                    config,
                    f"skill_trust_first_use_{str(config.mode or 'normal').strip().lower()}_policy",
                    "audit_only",
                )),
                "first_use_policy_effect": first_use_effect or "audit",
                "first_use_scan_failure_class": skill_trust.first_use_scan.failure_class,
                "first_use_scan_admission_risk": skill_trust.first_use_scan.admission_risk,
            })
        if rule_id in {
            "runtime_path_disallowed",
            "runtime_source_ambiguous",
            "runtime_path_unverified",
            "runtime_path_fragment_unverified",
            "runtime_content_unverified",
            "runtime_content_mismatch",
        }:
            finding["runtime_binding_action"] = runtime_binding_action or "audit"
        if rule_id == fspr_rule and isinstance(fspr_review, dict):
            finding.update({
                "fspr_verdict": fspr_review.get("verdict"),
                "fspr_timing_mode": fspr_review.get("timing_mode"),
                "fspr_severity": fspr_review.get("severity"),
                "fspr_confidence": fspr_review.get("confidence"),
                "deterministic_findings_preserved": fspr_review.get("deterministic_findings_preserved"),
                "fspr_policy_action": fspr_policy_action or "audit",
                "fspr_review_tier": fspr_review_tier or "none",
                "routing_affecting": fspr_routing_affecting,
                "fspr_degraded": bool(fspr_review.get("degraded", False)),
                "fspr_degradation_reason": fspr_review.get("degradation_reason"),
                "provider_health_only": fspr_provider_health_only,
                "strong_runtime_binding": fspr_strong_binding,
                "strong_binding_failure_reason": fspr_strong_binding_failure_reason,
                "decision_affecting": fspr_decision_affecting,
            })
        findings.append(finding)

    fspr_summary = getattr(skill_trust, "fspr_review_summary", None)
    if isinstance(fspr_summary, dict):
        findings.append({
            "rule_id": "fspr_review_summary",
            "registry_status": skill_trust.registry_status,
            "canonical_skill_id": skill_trust.canonical_skill_id,
            "presented_name": skill_trust.presented_name,
            "review_state": fspr_summary.get("review_state"),
            "timing_mode": fspr_summary.get("timing_mode"),
            "verdict": fspr_summary.get("verdict"),
            "severity": fspr_summary.get("severity"),
            "confidence": fspr_summary.get("confidence"),
            "degraded": fspr_summary.get("degraded"),
            "degradation_reason": fspr_summary.get("degradation_reason"),
            "failure_reason": fspr_summary.get("failure_reason"),
            "decision_affecting": False,
        })

    if event.event_type != EventType.PRE_ACTION:
        return current_level, current_score, rule_hits, findings

    upgrade_level: RiskLevel | None = None
    rule_set = set(rule_hits)
    runtime_hard_confidence = bool(
        rule_set.intersection({"runtime_path_disallowed", "runtime_source_ambiguous", "runtime_content_mismatch"})
    )
    runtime_soft_confidence = bool(
        rule_set.intersection({"runtime_path_unverified", "runtime_path_fragment_unverified", "runtime_content_unverified"})
    )
    fspr_inconsistent_pre_use = (
        fspr_decision_affecting
        and "first_use_skill_package_inconsistent" in rule_set
        and fspr_policy_action == "block"
    )
    hard_confidence = (
        "skill_hash_mismatch" in rule_set
        or "blacklisted_skill_identity" in rule_set
        or "revoked_skill_identity" in rule_set
        or runtime_hard_confidence
        or fspr_inconsistent_pre_use
    )
    soft_confidence = (
        {"ambiguous_skill_alias", "provenance_label_conflict"}.issubset(rule_set)
        or {"unknown_skill_identity", "unknown_skill_provenance_rewrite"}.issubset(rule_set)
        or "low_trust_redefined_canonical_tool" in rule_set
    )
    if hard_confidence:
        if runtime_hard_confidence and config.mode not in {"strict", "benchmark"}:
            upgrade_level = RiskLevel.MEDIUM
        else:
            upgrade_level = RiskLevel.HIGH
    elif soft_confidence:
        mode = str(config.mode or "normal").strip().lower()
        upgrade_level = (
            RiskLevel.HIGH
            if mode in {"benchmark", "strict"}
            else RiskLevel.MEDIUM
        )
    elif runtime_soft_confidence and config.mode in {"strict", "benchmark"}:
        upgrade_level = RiskLevel.MEDIUM
    if (
        fspr_decision_affecting
        and "first_use_skill_package_insufficient_evidence" in rule_set
        and config.mode in {"strict", "benchmark"}
    ):
        upgrade_level = _max_risk_level(upgrade_level or current_level, RiskLevel.MEDIUM)
    if fspr_policy_action == "block":
        upgrade_level = RiskLevel.HIGH
    if first_use_effect == "block":
        upgrade_level = RiskLevel.HIGH
    if runtime_binding_action == "block":
        upgrade_level = RiskLevel.HIGH
    if skill_trust.admission_risk == "critical":
        upgrade_level = RiskLevel.CRITICAL

    if upgrade_level is None:
        if first_use_effect in {"force_l2", "force_l3", "defer"}:
            for finding in findings:
                if finding.get("rule_id") == first_use_rule:
                    finding["decision_affecting"] = True
        if runtime_binding_action in {"force_l2", "force_l3", "defer"}:
            for finding in findings:
                if finding.get("runtime_binding_action") == runtime_binding_action:
                    finding["decision_affecting"] = True
        return current_level, current_score, rule_hits, findings

    for finding in findings:
        if finding.get("rule_id") == "fspr_review_summary":
            finding["decision_affecting"] = False
        else:
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
        "native_read_effect",
        "shell_read_probe",
        "shell_enumerate_probe",
        "shell_capability_probe",
        "pure_workspace_read_audit_narrowing",
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


def _is_reviewable_local_effect(
    effect_summary: dict[str, Any],
    context: DecisionContext | None,
    event: CanonicalEvent | None = None,
) -> tuple[bool, list[str]]:
    effects = set(effect_summary.get("effects") or [])
    evidence_rules = {str(rule) for rule in effect_summary.get("evidence_rules") or []}
    analysis_state = str(effect_summary.get("analysis_state") or "complete")
    confidence = str(effect_summary.get("confidence") or "low")
    wrappers = list(effect_summary.get("wrapper_chain") or [])
    targets = list(effect_summary.get("targets") or [])
    reasons: list[str] = []

    if analysis_state != "complete":
        reasons.append(f"analysis_state:{analysis_state}")
    if wrappers:
        reasons.append("wrapper_chain_present")
    if confidence not in {"medium", "high"}:
        reasons.append(f"low_effect_confidence:{confidence}")
    for effect in sorted(effects.intersection(_NON_CLEARABLE_EFFECTS)):
        reasons.append(f"non_clearable_effect:{effect}")
    if effects and not effects.issubset(_REVIEWABLE_CONTEXTUAL_EFFECTS):
        reasons.append("effect_not_reviewable_local")
    for rule_id in sorted(evidence_rules):
        lowered = rule_id.lower()
        if any(fragment in lowered for fragment in _CONTEXTUAL_DISQUALIFYING_RULE_FRAGMENTS):
            reasons.append(f"disqualifying_rule:{rule_id}")

    allowed_roles = {
        "future_execution.artifact",
        "generated_artifact",
        "ver" "ifier_artifact",
        "workspace_file",
        "workspace_directory",
        "document_input",
        "source",
        "input",
    }
    for target in targets:
        if not isinstance(target, dict):
            continue
        role = str(target.get("path_role") or "")
        if role and role not in allowed_roles:
            reasons.append(f"unsupported_target_role:{role}")
        workspace_relation = str(target.get("workspace_relation") or "")
        if workspace_relation == "outside_workspace_or_absolute":
            reasons.append(f"workspace_relation:{workspace_relation}")
    has_inside_workspace_target = any(
        isinstance(target, dict)
        and str(target.get("workspace_relation") or "") == "inside_workspace"
        for target in targets
    )

    payload = event.payload if event is not None else {}
    cwd = str((payload or {}).get("cwd") or (payload or {}).get("working_directory") or "").strip()
    if cwd:
        cwd_path = Path(cwd).expanduser()
        if ".." in cwd_path.parts:
            reasons.append("cwd_outside_workspace")
        elif (
            cwd_path.is_absolute()
            and not (cwd_path == Path("/workspace") or cwd_path.is_relative_to(Path("/workspace")))
            and not has_inside_workspace_target
        ):
            reasons.append("cwd_outside_workspace")

    summary = context.session_risk_summary if context is not None else None
    if isinstance(summary, dict) and summary.get("task_scope_path_escape"):
        reasons.append("task_scope_path_escape")

    return not reasons, reasons


def _is_pure_workspace_read_effect(
    effect_summary: dict[str, Any],
    *,
    event: CanonicalEvent,
    rule_hits: set[str],
    routing_intents: list[ReviewRoutingIntent],
    context: DecisionContext | None,
    dimensions: RiskDimensions,
) -> tuple[bool, list[str]]:
    effects = set(effect_summary.get("effects") or [])
    evidence_rules = {str(rule) for rule in effect_summary.get("evidence_rules") or []}
    analysis_state = str(effect_summary.get("analysis_state") or "complete")
    confidence = str(effect_summary.get("confidence") or "low")
    wrappers = list(effect_summary.get("wrapper_chain") or [])
    targets = list(effect_summary.get("targets") or [])
    reasons: list[str] = []

    pure_effects = {"filesystem.read", "filesystem.enumerate", "environment.probe"}
    if not effects:
        reasons.append("effect_missing")
    elif not effects.issubset(pure_effects):
        reasons.append("effect_not_pure_read")
    if analysis_state != "complete":
        reasons.append(f"analysis_state:{analysis_state}")
    if confidence not in {"medium", "high"}:
        reasons.append(f"low_effect_confidence:{confidence}")
    if wrappers:
        reasons.append("wrapper_chain_present")
    if dimensions.d6 >= 2.0:
        reasons.append("high_d6_injection_signal")
    if rule_hits.intersection(_HARD_BLOCK_RULE_HITS):
        reasons.append("hard_block_rule_present")
    if evidence_rules.intersection(_HARD_BLOCK_RULE_HITS):
        reasons.append("hard_block_effect_rule_present")
    for rule_id in sorted(evidence_rules):
        lowered = rule_id.lower()
        if any(fragment in lowered for fragment in _CONTEXTUAL_DISQUALIFYING_RULE_FRAGMENTS):
            reasons.append(f"disqualifying_rule:{rule_id}")
    for intent in routing_intents:
        if intent.decision_affecting and intent.policy_action in {"block", "defer"}:
            reasons.append(f"decision_affecting_route:{intent.source}")

    allowed_roles = {"workspace_file", "workspace_directory", "capability_probe"}
    allowed_workspace_relations = {"inside_workspace", "process_environment"}
    for target in targets:
        if not isinstance(target, dict):
            reasons.append("malformed_target")
            continue
        role = str(target.get("path_role") or "")
        if role and role not in allowed_roles:
            reasons.append(f"unsupported_target_role:{role}")
        workspace_relation = str(target.get("workspace_relation") or "")
        if workspace_relation and workspace_relation not in allowed_workspace_relations:
            reasons.append(f"workspace_relation:{workspace_relation}")
    has_inside_workspace_target = any(
        isinstance(target, dict)
        and str(target.get("workspace_relation") or "") == "inside_workspace"
        for target in targets
    )

    summary = context.session_risk_summary if context is not None else None
    if isinstance(summary, dict):
        if summary.get("blocked_skill_lineage_match") or summary.get("blocked_skill_lineage_facts"):
            reasons.append("blocked_skill_lineage")
        if summary.get("prior_fspr_hard_block"):
            reasons.append("prior_fspr_hard_block")
        if summary.get("task_scope_path_escape"):
            reasons.append("task_scope_path_escape")
    payload = event.payload if event is not None else {}
    cwd = str((payload or {}).get("cwd") or (payload or {}).get("working_directory") or "").strip()
    if cwd:
        cwd_path = Path(cwd).expanduser()
        if ".." in cwd_path.parts:
            reasons.append("cwd_outside_workspace")
        elif (
            cwd_path.is_absolute()
            and not (cwd_path == Path("/workspace") or cwd_path.is_relative_to(Path("/workspace")))
            and not has_inside_workspace_target
        ):
            reasons.append("cwd_outside_workspace")
    if set(_content_evidence_rule_ids(context)):
        reasons.append("content_evidence_present")

    return not reasons, reasons


def _context_has_prior_fspr_block(context: DecisionContext | None) -> bool:
    summary = context.session_risk_summary if context is not None else None
    if not isinstance(summary, dict):
        return False
    return bool(summary.get("prior_fspr_hard_block") or summary.get("blocked_skill_lineage_facts"))


def _work5c_warning_emitted(context: DecisionContext | None, config: DetectionConfig) -> bool:
    summary = context.session_risk_summary if context is not None else None
    emitted = bool(getattr(config, "work5c_warning_emitted", False))
    profile = str(getattr(config, "work5c_warning_profile_id", "") or "")
    if isinstance(summary, dict):
        emitted = emitted or bool(
            summary.get("work5c_warning_emitted")
            or summary.get("warning_emitted")
        )
        profile = str(
            summary.get("work5c_warning_profile_id")
            or summary.get("warning_profile_id")
            or profile
            or ""
        )
    return emitted and profile == WORK5C_WARNING_PROFILE_ID


def _work5c_relaxed_readonly_gate(context: DecisionContext | None, config: DetectionConfig) -> bool:
    return bool(
        getattr(config, "work5c_warning_relaxed_readonly_enabled", False)
    ) and _work5c_warning_emitted(context, config)


def _work5c_task_readonly_gate(context: DecisionContext | None, config: DetectionConfig) -> bool:
    return bool(
        getattr(config, "work5c_warning_task_readonly_enabled", False)
    ) and _work5c_warning_emitted(context, config)


def _is_work5c_relaxed_readonly_candidate(
    effect_summary: dict[str, Any],
    *,
    routing_intents: list[ReviewRoutingIntent],
    context: DecisionContext | None,
    config: DetectionConfig,
) -> bool:
    if str(config.mode or "normal").strip().lower() != "benchmark":
        return False
    if not _work5c_relaxed_readonly_gate(context, config):
        return False
    has_fspr_decision_affecting_block = False
    for intent in routing_intents:
        if (
            intent.decision_affecting
            and intent.policy_action in {"block", "defer"}
            and intent.source == "fspr_package_review"
        ):
            has_fspr_decision_affecting_block = True
        if (
            intent.decision_affecting
            and intent.policy_action in {"block", "defer"}
            and intent.source != "fspr_package_review"
        ):
            return False
    effects = set(effect_summary.get("effects") or [])
    if not effects or not effects.issubset(_WORK5C_RELAXED_READONLY_EFFECTS):
        return False
    if str(effect_summary.get("analysis_state") or "complete") != "complete":
        return False
    if str(effect_summary.get("confidence") or "low") not in {"medium", "high"}:
        return False
    if effect_summary.get("wrapper_chain"):
        return False
    targets = list(effect_summary.get("targets") or [])
    if not targets:
        return False
    has_skill_package_target = False
    for target in targets:
        if not isinstance(target, dict):
            return False
        role = str(target.get("path_role") or "")
        relation = str(target.get("workspace_relation") or "")
        if role not in _WORK5C_RELAXED_READONLY_TARGET_ROLES:
            return False
        if relation not in _WORK5C_RELAXED_READONLY_WORKSPACE_RELATIONS:
            return False
        has_skill_package_target = has_skill_package_target or role == "skill_package_read"
    if not has_fspr_decision_affecting_block and not has_skill_package_target:
        return False
    return True


def _is_work5c_task_readonly_candidate(
    effect_summary: dict[str, Any],
    *,
    routing_intents: list[ReviewRoutingIntent],
    context: DecisionContext | None,
    config: DetectionConfig,
) -> bool:
    if str(config.mode or "normal").strip().lower() != "benchmark":
        return False
    if not _work5c_task_readonly_gate(context, config):
        return False
    for intent in routing_intents:
        if (
            intent.decision_affecting
            and intent.policy_action in {"block", "defer"}
            and intent.source != "fspr_package_review"
        ):
            return False
    effects = set(effect_summary.get("effects") or [])
    if not effects or not effects.issubset(_WORK5C_TASK_READONLY_EFFECTS):
        return False
    if str(effect_summary.get("analysis_state") or "complete") != "complete":
        return False
    if str(effect_summary.get("confidence") or "low") not in {"medium", "high"}:
        return False
    if effect_summary.get("wrapper_chain"):
        return False
    evidence_rules = {str(rule) for rule in effect_summary.get("evidence_rules") or []}
    if "wrapper_chain_unresolved" in evidence_rules:
        return False
    targets = list(effect_summary.get("targets") or [])
    if not targets:
        return False
    for target in targets:
        if not isinstance(target, dict):
            return False
        role = str(target.get("path_role") or "")
        relation = str(target.get("workspace_relation") or "")
        if role not in _WORK5C_TASK_READONLY_TARGET_ROLES:
            return False
        if relation not in _WORK5C_TASK_READONLY_WORKSPACE_RELATIONS:
            return False
    return True


def _classify_l1_authority(
    *,
    event: CanonicalEvent,
    snapshot_fields: dict[str, Any],
    context: DecisionContext | None,
    config: DetectionConfig,
) -> tuple[L1AuthorityClass, list[str], ReviewRoutingIntent | None]:
    rule_hits = set(snapshot_fields.get("rule_hits") or [])
    routing_intents = list(snapshot_fields.get("routing_intents") or [])
    effect_summary = snapshot_fields.get("effect_summary") or {}
    effects = set(effect_summary.get("effects") or [])
    evidence_rules = set(effect_summary.get("evidence_rules") or [])
    short_circuit_rule = snapshot_fields.get("short_circuit_rule")
    target_roles = {
        str(target.get("path_role"))
        for target in effect_summary.get("targets") or []
        if isinstance(target, dict) and target.get("path_role")
    }
    risk_level = snapshot_fields["risk_level"]
    dimensions = snapshot_fields["dimensions"]
    work5c_relaxed_readonly = "work5c_warning_relaxed_readonly" in rule_hits
    work5c_task_readonly = "work5c_warning_task_readonly" in rule_hits
    work5c_readonly_clearance = work5c_relaxed_readonly or work5c_task_readonly
    summary = context.session_risk_summary if context is not None else None
    blocked_lineage_match = (
        summary.get("blocked_skill_lineage_match")
        if isinstance(summary, dict)
        else None
    )

    reasons: list[str] = []
    blocked_lineage_is_fspr_advisory = (
        work5c_readonly_clearance
        and isinstance(blocked_lineage_match, dict)
        and str(blocked_lineage_match.get("block_source") or "") == "fspr_package_review"
    )
    if blocked_lineage_match and not blocked_lineage_is_fspr_advisory:
        reasons.append("blocked_skill_lineage_match")
    for intent in routing_intents:
        if intent.decision_affecting and intent.policy_action == "block":
            reasons.append(intent.source)

    if event.event_type == EventType.PRE_ACTION:
        if "package.install" in effects:
            reasons.append("package.install")
        if "future_execution.entrypoint" in effects:
            reasons.append("future_execution.entrypoint")
        if target_roles.intersection({"credential_source", "hidden_oracle"}):
            reasons.append("credential_source")
        if "benchmark_control_metadata" in target_roles:
            reasons.append("benchmark_control_metadata")
        if "skill_package_read" in target_roles and not work5c_relaxed_readonly:
            reasons.append("skill_package_read")
        for rule_id in sorted(
            (rule_hits | evidence_rules).intersection({
                "persistence_entrypoint_write",
                "wrapper_chain_unresolved",
            })
        ):
            reasons.append(rule_id)

    reviewable_local, ineligible_reasons = _is_reviewable_local_effect(effect_summary, context, event)
    contextual_session = dimensions.d4 > 0 or _context_has_prior_fspr_block(context)
    if contextual_session and event.event_type == EventType.PRE_ACTION and risk_level in {
        RiskLevel.HIGH,
        RiskLevel.CRITICAL,
    }:
        for rule_id in sorted(rule_hits.intersection(_HARD_BLOCK_RULE_HITS)):
            reasons.append(rule_id)
        for rule_id in sorted(evidence_rules.intersection(_HARD_BLOCK_RULE_HITS)):
            reasons.append(rule_id)
        for effect in sorted(effects.intersection(_NON_CLEARABLE_EFFECTS)):
            reasons.append(effect)
    if (
        event.event_type == EventType.PRE_ACTION
        and risk_level in {RiskLevel.HIGH, RiskLevel.CRITICAL}
        and contextual_session
        and not reviewable_local
    ):
        reasons.extend(ineligible_reasons)

    if reasons:
        return L1AuthorityClass.DETERMINISTIC_HARD_BLOCK, list(dict.fromkeys(reasons)), None

    native_write_requires_contextual = (
        event.event_type == EventType.PRE_ACTION
        and "filesystem.write" in effects
        and "native_write_effect" in evidence_rules
        and not short_circuit_rule
    )
    if native_write_requires_contextual:
        if not reviewable_local:
            return (
                L1AuthorityClass.DETERMINISTIC_HARD_BLOCK,
                list(dict.fromkeys(["native_write_not_reviewable", *ineligible_reasons])),
                None,
            )
        metadata = contextual_binding_parts(event, context)
        metadata.update({
            "event_id": event.event_id,
            "session_id": event.session_id,
            "l1_authority_class": L1AuthorityClass.CONTEXTUAL_REVIEW_REQUIRED.value,
            "l1_block_authority": "contextual_route_only",
            "l2_l3_required": True,
            "recovery_candidate_reason": "native_write_contextual_review",
            "recovery_ineligible_reasons": [],
            "blocked_lineage_match": False,
            "anti_bypass_match": False,
        })
        return (
            L1AuthorityClass.CONTEXTUAL_REVIEW_REQUIRED,
            ["native_write_contextual_review"],
            ReviewRoutingIntent(
                source="contextual_review",
                recommended_tier="l2",
                policy_action="defer",
                reason="native_write_contextual_review",
                source_metadata=metadata,
                routing_affecting=True,
                decision_affecting=False,
            ),
        )

    if (
        event.event_type == EventType.PRE_ACTION
        and risk_level == RiskLevel.HIGH
        and contextual_session
        and reviewable_local
    ):
        metadata = contextual_binding_parts(event, context)
        metadata.update({
            "event_id": event.event_id,
            "session_id": event.session_id,
            "l1_authority_class": L1AuthorityClass.CONTEXTUAL_REVIEW_REQUIRED.value,
            "l1_block_authority": "contextual_route_only",
            "l2_l3_required": True,
            "recovery_candidate_reason": "contextual_high_risk_after_fspr",
            "recovery_ineligible_reasons": [],
            "blocked_lineage_match": False,
            "anti_bypass_match": False,
        })
        return (
            L1AuthorityClass.CONTEXTUAL_REVIEW_REQUIRED,
            ["contextual_high_risk_after_fspr"],
            ReviewRoutingIntent(
                source="contextual_review",
                recommended_tier="l2",
                policy_action="defer",
                reason="contextual_high_risk_after_fspr",
                source_metadata=metadata,
                routing_affecting=True,
                decision_affecting=False,
            ),
        )

    return L1AuthorityClass.ALLOW_OR_AUDIT, [], None


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
    effect_summary = effect_envelope.to_summary()

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
    routing_intents = _skill_trust_routing_intents_for_context(context, config)
    routing_intents.extend(build_content_evidence_routing_intents(context, config))
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
    taint_flow_summary = _content_evidence_taint_summary(context, _taint_flow_summary(event))
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
            content_rule_set = set(_content_evidence_rule_ids(context))
            if "critical" in severities:
                risk_level = _max_risk_level(risk_level, RiskLevel.CRITICAL)
                score = max(score, _min_score_for_level(risk_level, config))
            elif "high" in severities and not (
                content_rule_set.intersection({
                    "document_input_to_network_sink",
                    "document_input_encoded_to_network_sink",
                    "subprocess_file_transfer",
                })
                and str(config.mode or "normal").strip().lower() in {"normal", "permissive"}
            ):
                risk_level = _max_risk_level(risk_level, RiskLevel.HIGH)
                score = max(score, _min_score_for_level(risk_level, config))
            elif content_rule_set.intersection({
                "document_input_to_network_sink",
                "document_input_encoded_to_network_sink",
                "subprocess_file_transfer",
            }):
                risk_level = _max_risk_level(risk_level, RiskLevel.MEDIUM)
                score = max(score, _min_score_for_level(risk_level, config))

    work5c_relaxed_readonly = _is_work5c_relaxed_readonly_candidate(
        effect_summary,
        routing_intents=routing_intents,
        context=context,
        config=config,
    )
    if work5c_relaxed_readonly and event.event_type == EventType.PRE_ACTION:
        risk_level = RiskLevel.MEDIUM
        score = min(score, max(config.threshold_medium, config.threshold_high - 0.01))
        if "work5c_warning_relaxed_readonly" not in rule_hits:
            rule_hits.append("work5c_warning_relaxed_readonly")
        relaxed_intents: list[ReviewRoutingIntent] = []
        for intent in routing_intents:
            if (
                intent.source == "fspr_package_review"
                and intent.decision_affecting
                and intent.policy_action in {"block", "defer"}
            ):
                metadata = dict(intent.source_metadata or {})
                metadata["work5c_warning_relaxed_readonly"] = True
                relaxed_intents.append(intent.model_copy(update={
                    "recommended_tier": "none",
                    "policy_action": "audit",
                    "source_metadata": metadata,
                    "routing_affecting": False,
                    "decision_affecting": False,
                }))
            else:
                relaxed_intents.append(intent)
        routing_intents = relaxed_intents
        for finding in skill_trust_findings:
            if finding.get("rule_id") in {
                "first_use_skill_package_inconsistent",
                "first_use_skill_package_suspicious",
                "first_use_skill_package_insufficient_evidence",
                "fspr_review_summary",
            }:
                finding["decision_affecting"] = False
                finding["work5c_warning_relaxed_readonly"] = True

    work5c_task_readonly = _is_work5c_task_readonly_candidate(
        effect_summary,
        routing_intents=routing_intents,
        context=context,
        config=config,
    )
    if work5c_task_readonly and event.event_type == EventType.PRE_ACTION:
        risk_level = RiskLevel.MEDIUM
        score = min(score, max(config.threshold_medium, config.threshold_high - 0.01))
        if "work5c_warning_task_readonly" not in rule_hits:
            rule_hits.append("work5c_warning_task_readonly")

    pure_read, _pure_read_reasons = _is_pure_workspace_read_effect(
        effect_summary,
        event=event,
        rule_hits=set(rule_hits),
        routing_intents=routing_intents,
        context=context,
        dimensions=dims,
    )
    if (
        pure_read
        and event.event_type == EventType.PRE_ACTION
        and dims.d4 > 0
        and risk_level == RiskLevel.HIGH
        and sc_rule is None
        and taint_flow_summary is None
    ):
        risk_level = RiskLevel.MEDIUM
        score = min(score, max(config.threshold_medium, config.threshold_high - 0.01))
        if "pure_workspace_read_audit_narrowing" not in rule_hits:
            rule_hits.append("pure_workspace_read_audit_narrowing")

    snapshot_fields = {
        "risk_level": risk_level,
        "composite_score": score,
        "dimensions": dims,
        "short_circuit_rule": sc_rule,
        "missing_dimensions": missing_dims,
        "classified_by": ClassifiedBy.L1,
        "classified_at": utc_now_iso(),
        "rule_hits": rule_hits,
        "skill_trust_findings": skill_trust_findings,
        "routing_intents": routing_intents,
        "taint_flow_summary": taint_flow_summary,
        "effect_summary": effect_summary,
    }
    authority_class, authority_reasons, contextual_intent = _classify_l1_authority(
        event=event,
        snapshot_fields=snapshot_fields,
        context=context,
        config=config,
    )
    if contextual_intent is not None:
        routing_intents.append(contextual_intent)
    snapshot_fields["routing_intents"] = routing_intents
    snapshot = RiskSnapshot(
        **snapshot_fields,
        l1_authority_class=authority_class,
        l1_authority_reasons=authority_reasons,
        l1_block_authority=(
            "hard_block"
            if authority_class == L1AuthorityClass.DETERMINISTIC_HARD_BLOCK
            else "contextual_route_only"
            if authority_class == L1AuthorityClass.CONTEXTUAL_REVIEW_REQUIRED
            else "none"
        ),
        blocked_lineage_match=(
            context.session_risk_summary.get("blocked_skill_lineage_match")
            if context is not None and isinstance(context.session_risk_summary, dict)
            else None
        ),
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
