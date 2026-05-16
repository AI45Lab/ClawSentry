"""Approval timeout manager with backward-compatible DEFER helpers.

Tracks pending approvals and auto-resolves them based on configured
timeout action (block or allow) from DetectionConfig.
"""

from __future__ import annotations

import asyncio
import logging
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class ApprovalRecord:
    approval_id: str
    approval_kind: str | None
    approval_state: str
    session_id: str | None = None
    tool_name: str | None = None
    summary: str | None = None
    decision: str = ""
    reason: str = ""
    reason_code: str = ""
    timeout_s: float | None = None
    approval_binding: dict[str, Any] | None = None
    resolution_payload: dict[str, Any] | None = None
    resolver_identity: str | None = None


@dataclass
class _PendingApproval:
    event: asyncio.Event = field(default_factory=asyncio.Event)
    approval_kind: str = "defer"
    approval_state: str = "pending"
    session_id: str | None = None
    tool_name: str | None = None
    summary: str | None = None
    decision: str = ""
    reason: str = ""
    reason_code: str = ""
    timeout_s: float | None = None
    approval_binding: dict[str, Any] | None = None
    resolution_payload: dict[str, Any] | None = None
    resolver_identity: str | None = None


class DeferManager:
    """Manage approval lifecycle with configurable timeout."""

    def __init__(
        self,
        timeout_action: str = "block",
        timeout_s: float = 300.0,
        max_pending: int = 100,
        max_finalized: int = 100,
    ) -> None:
        self.timeout_action = timeout_action
        self.timeout_s = timeout_s
        self.max_pending = max_pending
        self.max_finalized = max_finalized
        self._pending: dict[str, _PendingApproval] = {}
        self._finalized: OrderedDict[str, ApprovalRecord] = OrderedDict()

    @property
    def pending_count(self) -> int:
        return len(self._pending)

    def is_pending(self, request_id: str) -> bool:
        return request_id in self._pending

    def register_approval(
        self,
        approval_id: str,
        *,
        approval_kind: str,
        session_id: str | None = None,
        tool_name: str | None = None,
        summary: str | None = None,
        approval_binding: dict[str, Any] | None = None,
    ) -> bool:
        """Register a new approval. Returns False if queue is full or duplicate."""
        if approval_id in self._pending:
            logger.warning("Approval already pending: %s", approval_id)
            return False
        if self.max_pending > 0 and len(self._pending) >= self.max_pending:
            logger.warning(
                "Approval queue full (%d/%d), rejecting %s",
                len(self._pending), self.max_pending, approval_id,
            )
            return False
        self._finalized.pop(approval_id, None)
        self._pending[approval_id] = _PendingApproval(
            approval_kind=approval_kind,
            session_id=session_id,
            tool_name=tool_name,
            summary=summary,
            timeout_s=self.timeout_s,
            approval_binding=_compact_binding(approval_binding),
        )
        return True

    def register_defer(
        self,
        request_id: str,
        *,
        approval_binding: dict[str, Any] | None = None,
    ) -> bool:
        """Register a new DEFER request. Returns False if queue is full."""
        return self.register_approval(
            request_id,
            approval_kind="defer",
            approval_binding=approval_binding,
        )

    def get_approval(self, approval_id: str) -> ApprovalRecord:
        """Return approval state and metadata for a pending/final/missing ID."""
        pending = self._pending.get(approval_id)
        if pending is not None:
            return self._record_from_pending(approval_id, pending)

        finalized = self._finalized.get(approval_id)
        if finalized is not None:
            return finalized

        return ApprovalRecord(
            approval_id=approval_id,
            approval_kind=None,
            approval_state="not_found",
        )

    def resolve_approval(
        self,
        approval_id: str,
        decision: str,
        reason: str,
        *,
        reason_code: str | None = None,
        resolution_payload: dict[str, Any] | None = None,
        resolver_identity: str | None = None,
        resolution_binding: dict[str, Any] | None = None,
    ) -> None:
        """Resolve a pending approval with an explicit decision."""
        pending = self._pending.pop(approval_id, None)
        if pending is None:
            return
        binding_drift = _binding_drift(pending.approval_binding, resolution_binding)
        pending.approval_state = "resolved"
        if binding_drift and decision in {"allow", "allow-once", "allow-always"}:
            pending.decision = "block"
            pending.reason = f"Approval binding drift: {','.join(binding_drift)}"
            pending.reason_code = "approval_binding_drift"
        else:
            pending.decision = decision
            pending.reason = reason
            pending.reason_code = reason_code or (
                "approval_allowed"
                if decision in {"allow", "allow-once", "allow-always"}
                else "approval_denied"
            )
        pending.resolution_payload = dict(resolution_payload) if resolution_payload else None
        pending.resolver_identity = resolver_identity
        self._store_finalized(approval_id, self._record_from_pending(approval_id, pending))
        pending.event.set()

    def resolve_defer(self, request_id: str, decision: str, reason: str) -> None:
        """Resolve a pending DEFER with an explicit decision."""
        self.resolve_approval(request_id, decision, reason)

    async def wait_for_resolution(
        self, request_id: str,
    ) -> tuple[str, str]:
        """Wait for resolution or timeout. Returns (decision, reason)."""
        pending = self._pending.get(request_id)
        if pending is None:
            finalized = self._finalized.get(request_id)
            if finalized is not None and finalized.approval_state in {
                "resolved", "timeout",
            }:
                return finalized.decision, finalized.reason
            return self.timeout_action, "request not found"

        try:
            await asyncio.wait_for(pending.event.wait(), timeout=self.timeout_s)
            finalized = self._finalized.get(request_id)
            if finalized is not None and finalized.approval_state == "resolved":
                return finalized.decision, finalized.reason
            return pending.decision, pending.reason
        except asyncio.TimeoutError:
            reason = (
                f"DEFER timeout ({self.timeout_s}s): "
                f"auto-{self.timeout_action}"
            )
            logger.warning(
                "DEFER %s timed out, action=%s", request_id, self.timeout_action,
            )
            pending.approval_state = "timeout"
            pending.decision = self.timeout_action
            pending.reason = reason
            pending.reason_code = "approval_timeout"
            self._store_finalized(request_id, self._record_from_pending(request_id, pending))
            return self.timeout_action, reason
        finally:
            self._pending.pop(request_id, None)

    def _record_from_pending(
        self, approval_id: str, pending: _PendingApproval,
    ) -> ApprovalRecord:
        return ApprovalRecord(
            approval_id=approval_id,
            approval_kind=pending.approval_kind,
            approval_state=pending.approval_state,
            session_id=pending.session_id,
            tool_name=pending.tool_name,
            summary=pending.summary,
            decision=pending.decision,
            reason=pending.reason,
            reason_code=pending.reason_code,
            timeout_s=pending.timeout_s,
            approval_binding=(
                dict(pending.approval_binding)
                if pending.approval_binding is not None
                else None
            ),
            resolution_payload=(
                dict(pending.resolution_payload)
                if pending.resolution_payload is not None
                else None
            ),
            resolver_identity=pending.resolver_identity,
        )

    def _store_finalized(self, approval_id: str, record: ApprovalRecord) -> None:
        self._finalized[approval_id] = record
        if self.max_finalized > 0:
            while len(self._finalized) > self.max_finalized:
                self._finalized.popitem(last=False)


def _compact_binding(binding: dict[str, Any] | None) -> dict[str, Any] | None:
    if not binding:
        return None
    allowed = {
        "effect_hash",
        "canonical_argv_hash",
        "raw_payload_hash",
        "cwd_hash",
        "env_fingerprint",
        "profile_fingerprint",
        "session_id",
        "agent_id",
        "capability_profile_id",
        "policy_fingerprint",
    }
    return {str(key): value for key, value in binding.items() if key in allowed and value is not None}


def _binding_drift(
    approved: dict[str, Any] | None,
    resolved: dict[str, Any] | None,
) -> list[str]:
    if not approved:
        return []
    if resolved is None:
        return ["resolution_binding_missing"]
    compact_resolved = _compact_binding(resolved) or {}
    drifted: list[str] = []
    for key, value in approved.items():
        if key not in compact_resolved:
            drifted.append(key)
            continue
        if compact_resolved[key] != value:
            drifted.append(key)
    return drifted
