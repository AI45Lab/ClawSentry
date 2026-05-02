"""
Post-action security analyzer — non-blocking analysis of tool outputs.

Public API:
    - detect_instructional_content(text) → float
    - detect_exfiltration(text) → float
    - detect_secret_exposure(text) → float
    - detect_obfuscation(text) → float
    - PostActionAnalyzer.analyze(tool_output, ...) → PostActionFinding

Design basis: internal E4 phase-1 design, section 3
"""

from __future__ import annotations

import logging
import math
import re
import hashlib
from dataclasses import dataclass
from typing import Optional

from .models import PostActionFinding, PostActionResponseTier, SanitizeTarget
from .risk_signals import (
    has_decode_pipe_exec_command,
    has_eval_decode_command,
    has_heredoc_exec_command,
    has_process_sub_remote_command,
    has_remote_pipe_exec_command,
    has_script_encoded_exec_command,
    has_variable_exec_trigger_command,
    has_variable_expansion_command,
)
from .text_utils import normalize_text

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Instructional content detection
# ---------------------------------------------------------------------------

_INSTRUCTIONAL_MARKERS: list[re.Pattern] = [
    re.compile(p, re.IGNORECASE) for p in [
        r"\b(must|should|need to)\b",
        r"\b(do not|don't|never)\b",
        r"\b(step \d+)\b",
        r"(?:now|next|instead)\s+(?:do|execute|run)",
    ]
]


def detect_instructional_content(text: str) -> float:
    """Detect instructional/imperative content in tool output. Returns 0.0-1.0."""
    normalized = normalize_text(text)
    count = sum(1 for p in _INSTRUCTIONAL_MARKERS if p.search(normalized))
    return min(count / len(_INSTRUCTIONAL_MARKERS), 1.0)


# ---------------------------------------------------------------------------
# Exfiltration detection
# ---------------------------------------------------------------------------

EXFILTRATION_PATTERNS: list[re.Pattern] = [
    re.compile(p, re.IGNORECASE) for p in [
        r"curl.*?-d.*?@",
        r"wget.*?--post-data",
        r"nslookup.*?\$\{",
        r"aws\s+s3\s+cp.*?s3://",
        r"ping.*?-p\s+[0-9a-f]{32,}",
        r"ssh.*?-R.*?:\d+:",
        r"(sendmail|mail).*?<.*?@",
        r"torsocks.*?(curl|wget)",
        r"!\[.*?\]\(https?://(?!github\.com|raw\.githubusercontent\.com|img\.shields\.io|shields\.io|badge\.fury\.io).*?\?",
        r"git\s+(clone|push).*?http.*?@",
    ]
]


def detect_exfiltration(text: str) -> float:
    """Detect data exfiltration patterns. Returns 0.0-1.0."""
    normalized = normalize_text(text)
    count = sum(1 for p in EXFILTRATION_PATTERNS if p.search(normalized))
    return min(count * 0.5, 1.0)


# ---------------------------------------------------------------------------
# Secret / credential exposure detection
# ---------------------------------------------------------------------------

_SECRET_PATTERNS: list[re.Pattern] = [
    re.compile(p, re.IGNORECASE) for p in [
        r"(?:AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY)\s*=\s*[A-Za-z0-9/+=]{16,}",
        r"(?:ghp|ghs|ghu|github_pat)_[A-Za-z0-9]{36,}",
        r"-----BEGIN\s+(?:RSA|EC|OPENSSH|DSA|PGP)\s+PRIVATE\s+KEY-----",
        r"(?:password|passwd)\s*[:=]\s*\S{8,}",
        r"(?:api[_-]?key|secret[_-]?key|access[_-]?token)\s*[:=]\s*['\"]?\S{16,}",
        # Bearer tokens (covers Authorization: Bearer and other contexts)
        r"(?:^|[\s,;\"'])Bearer\s+[a-zA-Z0-9._\-]{20,}",
        r"DATABASE_URL\s*=\s*\S+://\S+:\S+@",
        r"OPENAI_API_KEY\s*=\s*sk-[A-Za-z0-9]{20,}",
        # AWS access key IDs (IAM format)
        r"AKIA[A-Z0-9]{16}",
        # Slack tokens (bot, user, workspace, refresh)
        r"xox[bprs]-[a-zA-Z0-9\-]{10,}",
        # Feishu/Lark tokens (context-constrained to avoid bare t- FP)
        r"(?:tenant_access_token|user_access_token|app_access_token)\s*[:=]\s*t-[a-zA-Z0-9]{20,}",
        # Ethereum private key (context-constrained to avoid SHA-256 FP)
        r"(?:private[_\s-]?key|priv[_\s-]?key|wallet[_\s-]?key)\s*[:=]\s*['\"]?0x[a-fA-F0-9]{64}",
    ]
]


def detect_secret_exposure(text: str) -> float:
    """Detect exposed secrets/credentials in tool output. Returns 0.0-1.0."""
    normalized = normalize_text(text)
    count = sum(1 for p in _SECRET_PATTERNS if p.search(normalized))
    return min(count * 0.5, 1.0)


@dataclass(frozen=True)
class SanitizeAdvisory:
    """Capability-honest sanitizer advisory for post-action output."""

    target: SanitizeTarget
    would_sanitize: bool
    original_hash: str
    sanitized_hash: str
    original_preview_redacted: str
    sanitized_preview_redacted: str
    redaction_counts: dict[str, int]
    redaction_types: list[str]
    adapter_outcome: str = "would_sanitize"
    enforcement: str = "advisory_only"

    def to_dict(self) -> dict[str, object]:
        return {
            "target": self.target.value,
            "would_sanitize": self.would_sanitize,
            "original_hash": self.original_hash,
            "sanitized_hash": self.sanitized_hash,
            "original_preview_redacted": self.original_preview_redacted,
            "sanitized_preview_redacted": self.sanitized_preview_redacted,
            "redaction_counts": dict(self.redaction_counts),
            "redaction_types": list(self.redaction_types),
            "adapter_outcome": self.adapter_outcome,
            "enforcement": self.enforcement,
        }


def build_tool_output_sanitize_advisory(text: str) -> SanitizeAdvisory:
    """Return redacted advisory metadata without claiming output enforcement."""

    sanitized, redaction_counts = _redact_sanitizer_text(text)
    redaction_types = sorted(redaction_counts)
    would_sanitize = sanitized != text
    return SanitizeAdvisory(
        target=SanitizeTarget.TOOL_OUTPUT,
        would_sanitize=would_sanitize,
        original_hash=_sha256_label(text),
        sanitized_hash=_sha256_label(sanitized),
        original_preview_redacted=_preview(sanitized),
        sanitized_preview_redacted=_preview(sanitized),
        redaction_counts=redaction_counts,
        redaction_types=redaction_types,
    )


def _sha256_label(text: str) -> str:
    return "sha256:" + hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()


def _preview(text: str, limit: int = 160) -> str:
    if len(text) <= limit:
        return text
    return text[: limit - 1] + "…"


def _redact_sanitizer_text(text: str) -> tuple[str, dict[str, int]]:
    redacted = normalize_text(text)
    counts: dict[str, int] = {}
    for pattern in _SECRET_PATTERNS:
        redacted, count = pattern.subn("[REDACTED:secret]", redacted)
        if count:
            counts["secret"] = counts.get("secret", 0) + count
    return redacted, counts


# ---------------------------------------------------------------------------
# Obfuscation detection
# ---------------------------------------------------------------------------

# Safe URLs known to use curl|bash legitimately
_SAFE_CURL_PIPE_DOMAINS: frozenset[str] = frozenset({
    "brew.sh", "raw.githubusercontent.com",
    "get.pnpm.io", "bun.sh", "sh.rustup.rs",
    "get.docker.com", "install.python-poetry.org",
})

_OBFUSCATION_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(p, f), pid) for p, f, pid in [
        # Escape sequence obfuscation
        (r"\$'(?:[^']*\\[0-7]{3}){2,}", 0, "octal-escape"),
        (r"\$'(?:[^']*\\x[0-9a-fA-F]{2}){2,}", 0, "hex-escape"),
        # Existing patterns preserved
        (r"\[::-1\]", 0, "reverse-slice"),
        (r"\\x[0-9a-f]{2}", re.I, "hex-char"),
    ]
]


def _is_safe_curl_pipe(text: str) -> bool:
    """Check if curl|bash pattern uses a known safe domain (exact match)."""
    from urllib.parse import urlparse
    urls = re.findall(r"https?://[^\s|]+", text)
    if len(urls) != 1:
        return False
    try:
        netloc = urlparse(urls[0]).netloc.split(":")[0]
        return any(
            netloc == domain or netloc.endswith("." + domain)
            for domain in _SAFE_CURL_PIPE_DOMAINS
        )
    except Exception:
        return False


def _shannon_entropy(text: str) -> float:
    """Compute Shannon entropy of text."""
    if not text:
        return 0.0
    freq: dict[str, int] = {}
    for c in text:
        freq[c] = freq.get(c, 0) + 1
    length = len(text)
    return -sum(
        (count / length) * math.log2(count / length)
        for count in freq.values()
    )


def detect_obfuscation(text: str) -> float:
    """Detect obfuscated code patterns. Returns 0.0-1.0."""
    normalized = normalize_text(text)
    hits = 0
    if has_decode_pipe_exec_command(normalized):
        hits += 1
    if has_eval_decode_command(normalized):
        hits += 1
    if has_script_encoded_exec_command(normalized):
        hits += 1
    if has_process_sub_remote_command(normalized):
        hits += 1
    if has_heredoc_exec_command(normalized):
        hits += 1
    if has_variable_expansion_command(normalized):
        hits += 1
    if has_variable_exec_trigger_command(normalized):
        hits += 1
    if has_remote_pipe_exec_command(normalized):
        if not (_is_safe_curl_pipe(text) and _is_safe_curl_pipe(normalized)):
            hits += 1
    for pat, pid in _OBFUSCATION_PATTERNS:
        if pat.search(normalized):
            hits += 1
    pattern_score = hits * 0.3
    entropy = _shannon_entropy(text)
    entropy_score = (
        min((entropy - 5.5) / 2.5, 0.5)
        if len(text) > 50 and entropy > 5.5
        else 0.0
    )
    return min(pattern_score + entropy_score, 1.0)


# ---------------------------------------------------------------------------
# PostActionAnalyzer
# ---------------------------------------------------------------------------

_TIER_EMERGENCY = 0.9
_TIER_ESCALATE = 0.6
_TIER_MONITOR = 0.3

_TIER_RANK: dict[PostActionResponseTier, int] = {
    PostActionResponseTier.LOG_ONLY: 0,
    PostActionResponseTier.MONITOR: 1,
    PostActionResponseTier.ESCALATE: 2,
    PostActionResponseTier.EMERGENCY: 3,
}

_HIGH_SEVERITY_SECRET_PATTERNS: list[re.Pattern] = [
    re.compile(p, re.IGNORECASE) for p in [
        r"(?:AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY)\s*=\s*[A-Za-z0-9/+=]{16,}",
        r"(?:ghp|ghs|ghu|github_pat)_[A-Za-z0-9]{36,}",
        r"-----BEGIN\s+(?:RSA|EC|OPENSSH|DSA|PGP)\s+PRIVATE\s+KEY-----",
        r"(?:^|[\s,;\"'])Bearer\s+[a-zA-Z0-9._\-]{20,}",
        r"DATABASE_URL\s*=\s*\S+://\S+:\S+@",
        r"OPENAI_API_KEY\s*=\s*sk-[A-Za-z0-9]{20,}",
        r"AKIA[A-Z0-9]{16}",
        r"xox[bprs]-[a-zA-Z0-9\-]{10,}",
        r"(?:tenant_access_token|user_access_token|app_access_token)\s*[:=]\s*t-[a-zA-Z0-9]{20,}",
        r"(?:private[_\s-]?key|priv[_\s-]?key|wallet[_\s-]?key)\s*[:=]\s*['\"]?0x[a-fA-F0-9]{64}",
    ]
]


def _max_post_action_tier(
    *tiers: PostActionResponseTier,
) -> PostActionResponseTier:
    return max(tiers, key=lambda tier: _TIER_RANK[tier])


def _has_high_severity_secret(text: str) -> bool:
    normalized = normalize_text(text)
    return any(pattern.search(normalized) for pattern in _HIGH_SEVERITY_SECRET_PATTERNS)


class PostActionAnalyzer:
    """Combined post-action security analyzer."""

    def __init__(
        self,
        whitelist_patterns: Optional[list[str]] = None,
        tier_emergency: float = _TIER_EMERGENCY,
        tier_escalate: float = _TIER_ESCALATE,
        tier_monitor: float = _TIER_MONITOR,
    ) -> None:
        self._whitelist: list[re.Pattern] = []
        if whitelist_patterns:
            for p in whitelist_patterns:
                try:
                    self._whitelist.append(re.compile(p))
                except re.error as exc:
                    logger.warning("Invalid whitelist pattern %r: %s — skipping", p, exc)
        self._tier_emergency = tier_emergency
        self._tier_escalate = tier_escalate
        self._tier_monitor = tier_monitor

    def analyze(
        self,
        tool_output: str,
        tool_name: str,
        event_id: str,
        file_path: Optional[str] = None,
        content_origin: Optional[str] = None,
        external_multiplier: float = 1.0,
    ) -> PostActionFinding:
        """Analyze tool output for security threats.

        Args:
            content_origin: ``"external"`` / ``"user"`` / ``"unknown"`` / ``None``.
            external_multiplier: Score multiplier when *content_origin* is ``"external"``
                                 (configured via ``DetectionConfig.external_content_post_action_multiplier``).
        """
        if file_path and self._is_whitelisted(file_path):
            return PostActionFinding(
                tier=PostActionResponseTier.LOG_ONLY,
                patterns_matched=[],
                score=0.0,
                details={"whitelisted": True, "event_id": event_id},
            )

        # Cap input to 64KB to match event_text() discipline
        if len(tool_output) > 65_536:
            tool_output = tool_output[:65_536]

        patterns_matched: list[str] = []
        scores: list[float] = []

        instr_score = detect_instructional_content(tool_output)
        if instr_score > 0.5:
            patterns_matched.append("indirect_injection")
            scores.append(instr_score)

        exfil_score = detect_exfiltration(tool_output)
        if exfil_score > 0.0:
            patterns_matched.append("exfiltration")
            scores.append(exfil_score)

        secret_score = detect_secret_exposure(tool_output)
        if secret_score > 0.0:
            patterns_matched.append("secret_exposure")
            scores.append(secret_score)

        obfusc_score = detect_obfuscation(tool_output)
        if obfusc_score > 0.1:
            patterns_matched.append("obfuscation")
            scores.append(obfusc_score)

        combined = min(sum(scores), 3.0)

        # E-8: External content multiplier
        if content_origin == "external" and external_multiplier > 1.0:
            combined = min(combined * external_multiplier, 3.0)

        if combined >= self._tier_emergency:
            score_tier = PostActionResponseTier.EMERGENCY
        elif combined >= self._tier_escalate:
            score_tier = PostActionResponseTier.ESCALATE
        elif combined >= self._tier_monitor:
            score_tier = PostActionResponseTier.MONITOR
        else:
            score_tier = PostActionResponseTier.LOG_ONLY

        severity_floor = PostActionResponseTier.LOG_ONLY
        if exfil_score > 0.0:
            severity_floor = _max_post_action_tier(
                severity_floor,
                PostActionResponseTier.ESCALATE,
            )
        if secret_score > 0.0:
            severity_floor = _max_post_action_tier(
                severity_floor,
                (
                    PostActionResponseTier.EMERGENCY
                    if _has_high_severity_secret(tool_output)
                    else PostActionResponseTier.ESCALATE
                ),
            )
        if obfusc_score > 0.1:
            severity_floor = _max_post_action_tier(
                severity_floor,
                (
                    PostActionResponseTier.EMERGENCY
                    if exfil_score > 0.0 or secret_score > 0.0
                    else PostActionResponseTier.MONITOR
                ),
            )

        tier = _max_post_action_tier(score_tier, severity_floor)

        details = {
            "event_id": event_id,
            "tool_name": tool_name,
            "instructional": round(instr_score, 3),
            "exfiltration": round(exfil_score, 3),
            "secret_exposure": round(secret_score, 3),
            "obfuscation": round(obfusc_score, 3),
            "severity_floor": severity_floor.value,
        }
        sanitize_advisory = build_tool_output_sanitize_advisory(tool_output)
        if sanitize_advisory.would_sanitize:
            details["sanitize_advisory"] = sanitize_advisory.to_dict()

        return PostActionFinding(
            tier=tier,
            patterns_matched=patterns_matched,
            score=min(round(combined, 3), 3.0),
            details=details,
        )

    def _is_whitelisted(self, path: str) -> bool:
        return any(p.fullmatch(path) for p in self._whitelist)
