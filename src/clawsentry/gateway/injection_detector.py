"""
D6 Injection Detection — Layer 1 (heuristic regex) + Layer 2 (canary token) + Layer 3 (vector similarity).

Design basis: docs/plans/2026-03-23-e4-phase1-design-v1.2.md section 2.2
"""

from __future__ import annotations

import logging
import re
from typing import Optional, Protocol, runtime_checkable

from .models import CanaryToken

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Layer 1: Heuristic regex patterns
# ---------------------------------------------------------------------------

WEAK_INJECTION_PATTERNS: list[re.Pattern] = [
    re.compile(p, re.IGNORECASE) for p in [
        r"ignore\s+(?:\w+\s+)*(?:previous|above|prior)\s+(?:instructions?|prompts?)",
        r"disregard\s+(?:\w+\s+)*(?:previous|above)",
        r"new (instructions?|task|goal)",
        r"system:\s*you are now",
        r"forget (everything|all|previous)",
        r"start (over|fresh|new)",
        r"from now on",
        r"<\|endoftext\|>",
        r"###\s*Instruction:",
        r"\b(must|should)\b.*\b(now|immediately)\b",
    ]
]

STRONG_INJECTION_PATTERNS: list[re.Pattern] = [
    re.compile(p, re.IGNORECASE | re.DOTALL) for p in [
        r"<script\b",
        r"data:text/html;base64,",
        r"eval\s*\(|exec\s*\(|__import__\s*\(",
        r"<!--[^>]*(?:ignore|disregard)",
        r"\u200b|\u200c|\u200d|\ufeff",
        r"data:[^,]*base64,[^)]*(?:curl|wget)",
        r"\$\{[A-Z_]+\}.*?(curl|wget)",
        r"git\s+push.*?http.*?@",
    ]
]

TOOL_SPECIFIC_PATTERNS: dict[str, list[re.Pattern]] = {
    "read_file": [
        re.compile(r"<!--\s*IMPORTANT.*?-->", re.IGNORECASE | re.DOTALL),
        re.compile(r"!\[.*?\]\(https?://[^)]+\?[^)]+\)"),
    ],
    "http_request": [
        re.compile(r"<script>.*?fetch\(", re.IGNORECASE | re.DOTALL),
        re.compile(r"font-size:\s*0", re.IGNORECASE),
    ],
}

_MAX_SCORE_INPUT_LEN = 65_536  # 64KB cap — matches event_text() limit


def score_layer1(text: str, tool_name: Optional[str] = None) -> float:
    """Score text for injection patterns (Layer 1 heuristic). Returns 0.0-3.0."""
    if len(text) > _MAX_SCORE_INPUT_LEN:
        text = text[:_MAX_SCORE_INPUT_LEN]
    score = 0.0

    # Weak patterns: +0.3 each, max 1.5
    weak_count = sum(1 for p in WEAK_INJECTION_PATTERNS if p.search(text))
    score += min(weak_count * 0.3, 1.5)

    # Strong patterns: +0.8 each, max 2.4
    strong_count = sum(1 for p in STRONG_INJECTION_PATTERNS if p.search(text))
    score += min(strong_count * 0.8, 2.4)

    # Tool-specific: +0.5 each
    tool_key = tool_name.lower() if tool_name else ""
    if tool_key in TOOL_SPECIFIC_PATTERNS:
        tool_count = sum(
            1 for p in TOOL_SPECIFIC_PATTERNS[tool_key] if p.search(text)
        )
        score += min(tool_count * 0.5, 1.0)

    return min(score, 3.0)


# ---------------------------------------------------------------------------
# Layer 3: Vector similarity interface
# ---------------------------------------------------------------------------

@runtime_checkable
class EmbeddingBackend(Protocol):
    """Protocol for pluggable embedding backends.

    Users implement this with their preferred model (e.g. sentence-transformers,
    OpenAI embeddings). The ``max_similarity`` method returns the highest cosine
    similarity between the input text and a corpus of known injection attacks.
    """

    def max_similarity(self, text: str) -> float: ...


_VECTOR_SIMILARITY_THRESHOLD = 0.75


class VectorLayer:
    """Layer 3 vector similarity scoring with pluggable backend.

    When *enabled* is ``False`` or *backend* is ``None``, ``score()`` returns 0.0.
    When enabled, maps similarity above *threshold* to a 0.0-2.0 score range.
    """

    def __init__(
        self,
        backend: Optional[EmbeddingBackend] = None,
        *,
        enabled: bool = True,
        threshold: float = _VECTOR_SIMILARITY_THRESHOLD,
    ) -> None:
        self._backend = backend
        self._enabled = enabled and (backend is not None)
        self._threshold = threshold

    def score(self, text: str) -> float:
        """Score text via vector similarity. Returns 0.0-2.0."""
        if not self._enabled or self._backend is None:
            return 0.0
        try:
            similarity = self._backend.max_similarity(text)
            if similarity <= self._threshold:
                return 0.0
            return min(2.0 * (similarity - self._threshold) / (1.0 - self._threshold), 2.0)
        except Exception as exc:
            logger.warning("VectorLayer scoring failed (%s)", type(exc).__name__, exc_info=True)
            return 0.0


class InjectionDetector:
    """D6 injection detection combining heuristic regex, canary token, and optional vector similarity."""

    def __init__(self, vector_layer: Optional[VectorLayer] = None) -> None:
        self._vector_layer = vector_layer

    def create_canary(self) -> CanaryToken:
        return CanaryToken.generate()

    def score(
        self,
        text: str,
        tool_name: str,
        canary: Optional[CanaryToken] = None,
    ) -> float:
        """Compute D6 injection score (0.0-3.0). Combines Layer 1 + Layer 2 + Layer 3."""
        l1_score = score_layer1(text, tool_name)
        canary_score = 0.0
        if canary is not None:
            canary_score = canary.check_leak(text)
        vector_score = 0.0
        if self._vector_layer is not None:
            vector_score = self._vector_layer.score(text)
        return min(l1_score + canary_score + vector_score, 3.0)
