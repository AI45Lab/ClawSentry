"""Tests for DEFER timeout manager."""

from __future__ import annotations

import asyncio

import pytest

from clawsentry.gateway.defer_manager import DeferManager


class TestDeferManager:

    def test_default_timeout_action_is_block(self):
        dm = DeferManager()
        assert dm.timeout_action == "block"

    def test_custom_timeout_action(self):
        dm = DeferManager(timeout_action="allow", timeout_s=60.0)
        assert dm.timeout_action == "allow"
        assert dm.timeout_s == 60.0

    @pytest.mark.asyncio
    async def test_register_and_resolve_defer(self):
        dm = DeferManager()
        dm.register_defer("req-1")
        assert dm.is_pending("req-1")
        dm.resolve_defer("req-1", "allow", "operator approved")
        assert not dm.is_pending("req-1")

    @pytest.mark.asyncio
    async def test_wait_for_resolution_returns_decision(self):
        dm = DeferManager(timeout_s=5.0)
        dm.register_defer("req-2")

        async def resolve_later():
            await asyncio.sleep(0.05)
            dm.resolve_defer("req-2", "allow", "approved")

        asyncio.create_task(resolve_later())
        decision, reason = await dm.wait_for_resolution("req-2")
        assert decision == "allow"
        assert reason == "approved"

    @pytest.mark.asyncio
    async def test_timeout_returns_block(self):
        dm = DeferManager(timeout_action="block", timeout_s=0.1)
        dm.register_defer("req-3")
        decision, reason = await dm.wait_for_resolution("req-3")
        assert decision == "block"
        assert "timeout" in reason.lower()

    @pytest.mark.asyncio
    async def test_timeout_returns_allow(self):
        dm = DeferManager(timeout_action="allow", timeout_s=0.1)
        dm.register_defer("req-4")
        decision, reason = await dm.wait_for_resolution("req-4")
        assert decision == "allow"
        assert "timeout" in reason.lower()

    def test_pending_count(self):
        dm = DeferManager()
        dm.register_defer("a")
        dm.register_defer("b")
        assert dm.pending_count == 2
        dm.resolve_defer("a", "allow", "ok")
        assert dm.pending_count == 1

    def test_resolve_nonexistent_does_not_raise(self):
        dm = DeferManager()
        dm.resolve_defer("nonexistent", "allow", "ok")  # should not raise

    @pytest.mark.asyncio
    async def test_wait_nonexistent_returns_timeout_action(self):
        dm = DeferManager(timeout_action="block")
        decision, reason = await dm.wait_for_resolution("missing")
        assert decision == "block"
        assert "not found" in reason

    def test_register_approval_tracks_pending_metadata(self):
        dm = DeferManager()

        assert dm.register_approval(
            "approval-1",
            approval_kind="confirmation",
            session_id="sess-1",
            tool_name="bash",
            summary="confirm destructive command",
        ) is True

        approval = dm.get_approval("approval-1")
        assert approval.approval_id == "approval-1"
        assert approval.approval_kind == "confirmation"
        assert approval.approval_state == "pending"
        assert approval.session_id == "sess-1"
        assert approval.tool_name == "bash"
        assert approval.summary == "confirm destructive command"

    def test_register_approval_tracks_effect_binding(self):
        dm = DeferManager()
        binding = {
            "effect_hash": "sha256:effect",
            "canonical_argv_hash": "sha256:argv",
            "cwd_hash": "sha256:cwd",
            "env_fingerprint": "sha256:env",
            "profile_fingerprint": "sha256:profile",
            "session_id": "sess-1",
            "agent_id": "agent-1",
        }

        assert dm.register_approval(
            "approval-bound",
            approval_kind="defer",
            session_id="sess-1",
            tool_name="bash",
            approval_binding=binding,
        ) is True

        approval = dm.get_approval("approval-bound")
        assert approval.approval_binding == binding

    @pytest.mark.asyncio
    async def test_resolved_approval_rejects_effect_binding_drift(self):
        dm = DeferManager(timeout_s=5.0)
        binding = {
            "effect_hash": "sha256:effect-original",
            "canonical_argv_hash": "sha256:argv",
            "cwd_hash": "sha256:cwd",
            "profile_fingerprint": "sha256:profile",
        }
        assert dm.register_approval(
            "approval-drift",
            approval_kind="defer",
            approval_binding=binding,
        ) is True

        wait_task = asyncio.create_task(dm.wait_for_resolution("approval-drift"))
        await asyncio.sleep(0)
        dm.resolve_approval(
            "approval-drift",
            "allow",
            "approved",
            resolution_binding={
                **binding,
                "effect_hash": "sha256:effect-mutated",
            },
        )
        decision, reason = await wait_task

        approval = dm.get_approval("approval-drift")
        assert decision == "block"
        assert approval.reason_code == "approval_binding_drift"
        assert "binding drift" in reason.lower()

    @pytest.mark.asyncio
    async def test_resolved_approval_rejects_missing_resolution_binding(self):
        dm = DeferManager(timeout_s=5.0)
        assert dm.register_approval(
            "approval-missing-binding",
            approval_kind="defer",
            approval_binding={"effect_hash": "sha256:effect-original"},
        ) is True

        wait_task = asyncio.create_task(dm.wait_for_resolution("approval-missing-binding"))
        await asyncio.sleep(0)
        dm.resolve_approval("approval-missing-binding", "allow", "approved")
        decision, reason = await wait_task

        approval = dm.get_approval("approval-missing-binding")
        assert decision == "block"
        assert approval.reason_code == "approval_binding_drift"
        assert "resolution_binding_missing" in reason

    @pytest.mark.asyncio
    async def test_resolved_approval_rejects_partial_resolution_binding(self):
        dm = DeferManager(timeout_s=5.0)
        binding = {
            "effect_hash": "sha256:effect-original",
            "cwd_hash": "sha256:cwd",
        }
        assert dm.register_approval(
            "approval-partial-binding",
            approval_kind="defer",
            approval_binding=binding,
        ) is True

        wait_task = asyncio.create_task(dm.wait_for_resolution("approval-partial-binding"))
        await asyncio.sleep(0)
        dm.resolve_approval(
            "approval-partial-binding",
            "allow",
            "approved",
            resolution_binding={"effect_hash": "sha256:effect-original"},
        )
        decision, reason = await wait_task

        approval = dm.get_approval("approval-partial-binding")
        assert decision == "block"
        assert approval.reason_code == "approval_binding_drift"
        assert "cwd_hash" in reason

    def test_register_defer_populates_defer_kind(self):
        dm = DeferManager()

        assert dm.register_defer("req-defer-1") is True

        approval = dm.get_approval("req-defer-1")
        assert approval.approval_kind == "defer"
        assert approval.approval_state == "pending"

    def test_register_approval_rejects_duplicate_pending_id(self):
        dm = DeferManager()

        assert dm.register_approval("approval-dup", approval_kind="confirmation") is True
        assert dm.register_approval("approval-dup", approval_kind="confirmation") is False
        assert dm.pending_count == 1

    def test_get_approval_returns_not_found_state_for_unknown_id(self):
        dm = DeferManager()

        approval = dm.get_approval("missing-approval")

        assert approval.approval_id == "missing-approval"
        assert approval.approval_state == "not_found"
        assert approval.approval_kind is None

    @pytest.mark.asyncio
    async def test_resolved_approval_state_is_queryable_after_resolution(self):
        dm = DeferManager(timeout_s=5.0)
        assert dm.register_approval(
            "approval-resolved",
            approval_kind="confirmation",
            tool_name="edit_file",
        ) is True

        wait_task = asyncio.create_task(dm.wait_for_resolution("approval-resolved"))
        await asyncio.sleep(0)
        dm.resolve_approval("approval-resolved", "allow", "confirmed")
        decision, reason = await wait_task

        approval = dm.get_approval("approval-resolved")
        assert decision == "allow"
        assert reason == "confirmed"
        assert approval.approval_state == "resolved"
        assert approval.approval_kind == "confirmation"
        assert approval.tool_name == "edit_file"

    @pytest.mark.asyncio
    async def test_timeout_approval_state_is_queryable_after_timeout(self):
        dm = DeferManager(timeout_action="allow", timeout_s=0.01)
        assert dm.register_approval("approval-timeout", approval_kind="confirmation") is True

        decision, reason = await dm.wait_for_resolution("approval-timeout")

        approval = dm.get_approval("approval-timeout")
        assert decision == "allow"
        assert "timeout" in reason.lower()
        assert approval.approval_state == "timeout"
        assert approval.approval_kind == "confirmation"

    def test_finalized_records_evict_oldest_when_over_limit(self):
        dm = DeferManager(max_finalized=2)

        assert dm.register_approval("approval-1", approval_kind="confirmation") is True
        dm.resolve_approval("approval-1", "allow", "ok-1")
        assert dm.register_approval("approval-2", approval_kind="confirmation") is True
        dm.resolve_approval("approval-2", "allow", "ok-2")
        assert dm.register_approval("approval-3", approval_kind="confirmation") is True
        dm.resolve_approval("approval-3", "allow", "ok-3")

        assert dm.get_approval("approval-1").approval_state == "not_found"
        assert dm.get_approval("approval-2").approval_state == "resolved"
        assert dm.get_approval("approval-3").approval_state == "resolved"


class TestDeferMaxPending:
    """P1-5: DEFER must have a max pending limit."""

    def test_register_respects_max_pending(self):
        dm = DeferManager(max_pending=3)
        assert dm.register_defer("r1") is True
        assert dm.register_defer("r2") is True
        assert dm.register_defer("r3") is True
        assert dm.pending_count == 3
        # 4th should be rejected
        assert dm.register_defer("r4") is False
        assert dm.pending_count == 3

    def test_register_returns_true_when_space(self):
        dm = DeferManager(max_pending=10)
        assert dm.register_defer("r1") is True

    def test_default_max_pending(self):
        dm = DeferManager()
        assert dm.max_pending == 100

    def test_max_pending_zero_means_unlimited(self):
        dm = DeferManager(max_pending=0)
        for i in range(200):
            assert dm.register_defer(f"r{i}") is True

    def test_space_freed_after_resolve(self):
        dm = DeferManager(max_pending=2)
        dm.register_defer("r1")
        dm.register_defer("r2")
        assert dm.register_defer("r3") is False
        dm.resolve_defer("r1", "allow", "ok")
        assert dm.register_defer("r3") is True
