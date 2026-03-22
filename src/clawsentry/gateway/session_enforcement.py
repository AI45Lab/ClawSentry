"""
Session-level enforcement policy (A-7).

When a session accumulates N high-risk events, all subsequent pre_action
events are forced into DEFER / BLOCK / L3 review until the cooldown expires
or an operator manually releases the session.
"""

from __future__ import annotations

import enum
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional


class EnforcementAction(str, enum.Enum):
    DEFER = "defer"
    BLOCK = "block"
    L3_REQUIRE = "l3_require"


class EnforcementState(str, enum.Enum):
    NORMAL = "normal"
    ENFORCED = "enforced"


@dataclass
class SessionEnforcement:
    """Snapshot of an active enforcement on a session."""
    session_id: str
    action: EnforcementAction
    triggered_at: float
    last_high_risk_at: float
    high_risk_count: int

    def to_dict(self) -> dict[str, Any]:
        def _iso(ts: float) -> str:
            return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()

        return {
            "session_id": self.session_id,
            "state": EnforcementState.ENFORCED.value,
            "action": self.action.value,
            "triggered_at": _iso(self.triggered_at),
            "last_high_risk_at": _iso(self.last_high_risk_at),
            "high_risk_count": self.high_risk_count,
        }


_MAX_TRACKED_SESSIONS = 50_000


class SessionEnforcementPolicy:
    """Track and enforce session-level risk accumulation thresholds."""

    def __init__(
        self,
        *,
        enabled: bool = False,
        threshold: int = 3,
        action: EnforcementAction = EnforcementAction.DEFER,
        cooldown_seconds: int = 600,
    ) -> None:
        self.enabled = enabled
        self.threshold = max(threshold, 1)
        self.action = action
        self.cooldown_seconds = max(cooldown_seconds, 0)
        self._enforced: dict[str, SessionEnforcement] = {}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def check(self, session_id: str) -> Optional[SessionEnforcement]:
        """Return current enforcement if active, auto-release on cooldown expiry."""
        if not self.enabled:
            return None
        enf = self._enforced.get(session_id)
        if enf is None:
            return None
        if self.cooldown_seconds > 0:
            elapsed = time.time() - enf.last_high_risk_at
            if elapsed >= self.cooldown_seconds:
                del self._enforced[session_id]
                return None
        return enf

    def evaluate_threshold(
        self, session_id: str, high_risk_count: int
    ) -> Optional[SessionEnforcement]:
        """Check if threshold is newly breached. Returns enforcement if just triggered."""
        if not self.enabled:
            return None
        if high_risk_count < self.threshold:
            return None
        now = time.time()
        existing = self._enforced.get(session_id)
        if existing is not None:
            # Already enforced — update timestamp for cooldown reset
            existing.last_high_risk_at = now
            existing.high_risk_count = high_risk_count
            return None  # Not a *new* trigger
        enf = SessionEnforcement(
            session_id=session_id,
            action=self.action,
            triggered_at=now,
            last_high_risk_at=now,
            high_risk_count=high_risk_count,
        )
        self._enforced[session_id] = enf
        self._evict_if_needed()
        return enf

    def release(self, session_id: str) -> bool:
        """Manually release enforcement. Returns True if was enforced."""
        return self._enforced.pop(session_id, None) is not None

    def get_status(self, session_id: str) -> dict[str, Any]:
        """Return enforcement status for API queries."""
        enf = self.check(session_id)
        if enf is not None:
            return enf.to_dict()
        return {
            "session_id": session_id,
            "state": EnforcementState.NORMAL.value,
            "action": None,
            "triggered_at": None,
            "last_high_risk_at": None,
            "high_risk_count": None,
        }

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _evict_if_needed(self) -> None:
        while len(self._enforced) > _MAX_TRACKED_SESSIONS:
            oldest_key = next(iter(self._enforced))
            del self._enforced[oldest_key]
