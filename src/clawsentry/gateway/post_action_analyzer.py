"""
Post-action security analyzer — non-blocking analysis of tool outputs.

Public API:
    - detect_instructional_content(text) → float
    - detect_exfiltration(text) → float
    - detect_secret_exposure(text) → float
    - detect_obfuscation(text) → float
    - PostActionAnalyzer.analyze(tool_output, ...) → PostActionFinding

Design basis: docs/plans/2026-03-23-e4-phase1-design-v1.2.md section 3
"""

from __future__ import annotations

import logging
import math
import re
from typing import Optional

from .models import PostActionFinding, PostActionResponseTier

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
    count = sum(1 for p in _INSTRUCTIONAL_MARKERS if p.search(text))
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
    count = sum(1 for p in EXFILTRATION_PATTERNS if p.search(text))
    return min(count * 0.5, 1.0)


# ---------------------------------------------------------------------------
# Secret / credential exposure detection
# ---------------------------------------------------------------------------

_SECRET_PATTERNS: list[re.Pattern] = [
    re.compile(p, re.IGNORECASE) for p in [
        r"(?:AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY)\s*=\s*[A-Za-z0-9/+=]{16,}",
        r"(?:ghp|ghs|ghu|github_pat)_[A-Za-z0-9]{36,}",
        r"-----BEGIN\s+(?:RSA|EC|OPENSSH|DSA|PGP)\s+PRIVATE\s+KEY-----",
        r"(?:password|passwd|pwd)\s*[:=]\s*\S{8,}",
        r"(?:api[_-]?key|secret[_-]?key|access[_-]?token)\s*[:=]\s*['\"]?\S{16,}",
        r"Authorization:\s+Bearer\s+[A-Za-z0-9._-]{20,}",
        r"DATABASE_URL\s*=\s*\S+://\S+:\S+@",
        r"OPENAI_API_KEY\s*=\s*sk-[A-Za-z0-9]{20,}",
    ]
]


def detect_secret_exposure(text: str) -> float:
    """Detect exposed secrets/credentials in tool output. Returns 0.0-1.0."""
    count = sum(1 for p in _SECRET_PATTERNS if p.search(text))
    return min(count * 0.5, 1.0)


# ---------------------------------------------------------------------------
# Obfuscation detection
# ---------------------------------------------------------------------------

_OBFUSCATION_PATTERNS: list[re.Pattern] = [
    re.compile(p, re.IGNORECASE) for p in [
        r"base64\s+-d.*?\|.*?(bash|sh)",
        r"eval.*base64",
        r"\\x[0-9a-f]{2}",
        r"\[::-1\]",
    ]
]


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
    pattern_score = sum(
        1 for p in _OBFUSCATION_PATTERNS if p.search(text)
    ) * 0.3
    entropy = _shannon_entropy(text)
    entropy_score = min((entropy - 5.5) / 2.5, 0.5) if len(text) > 50 and entropy > 5.5 else 0.0
    return min(pattern_score + entropy_score, 1.0)


# ---------------------------------------------------------------------------
# PostActionAnalyzer
# ---------------------------------------------------------------------------

_TIER_EMERGENCY = 0.9
_TIER_ESCALATE = 0.6
_TIER_MONITOR = 0.3


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
    ) -> PostActionFinding:
        """Analyze tool output for security threats."""
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

        if not scores:
            combined = 0.0
        elif len(scores) == 1:
            combined = scores[0]
        else:
            combined = max(scores) + 0.15 * (len(scores) - 1)
        combined = min(combined, 3.0)

        if combined >= self._tier_emergency:
            tier = PostActionResponseTier.EMERGENCY
        elif combined >= self._tier_escalate:
            tier = PostActionResponseTier.ESCALATE
        elif combined >= self._tier_monitor:
            tier = PostActionResponseTier.MONITOR
        else:
            tier = PostActionResponseTier.LOG_ONLY

        return PostActionFinding(
            tier=tier,
            patterns_matched=patterns_matched,
            score=min(round(combined, 3), 3.0),
            details={
                "event_id": event_id,
                "tool_name": tool_name,
                "instructional": round(instr_score, 3),
                "exfiltration": round(exfil_score, 3),
                "secret_exposure": round(secret_score, 3),
                "obfuscation": round(obfusc_score, 3),
            },
        )

    def _is_whitelisted(self, path: str) -> bool:
        return any(p.fullmatch(path) for p in self._whitelist)
