"""
Unit tests for gateway/models.py — Gate 1 verification.

Covers: field validation, sentinel values, schema_version format,
conditional fields, enum constraints, SyncDecision envelopes.
"""

import pytest
from pydantic import ValidationError

from clawsentry.gateway.models import (
    CanonicalEvent,
    CanonicalDecision,
    CanaryToken,
    RiskSnapshot,
    RiskDimensions,
    SyncDecisionRequest,
    SyncDecisionResponse,
    SyncDecisionErrorResponse,
    EventType,
    DecisionVerdict,
    DecisionContext,
    DecisionSource,
    RiskLevel,
    FailureClass,
    DecisionTier,
    RPCErrorCode,
    ClassifiedBy,
    AgentTrustLevel,
    AdmissionFinding,
    AdmissionReport,
    FirstUseScanState,
    McpContext,
    PostActionResponseTier,
    PostActionFinding,
    SkillRegistryRecord,
    SkillTrustListEntry,
    SkillTrustTransitionEvent,
    SkillTrustContext,
    LineageEvent,
    CURRENT_SCHEMA_VERSION,
    RPC_VERSION,
    utc_now_iso,
)
from clawsentry.gateway.server import (
    _lineage_event_from_summary,
    _lineage_events_from_summary,
    _lineage_summary_from_event,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _minimal_event(**overrides) -> dict:
    base = {
        "event_id": "evt-001",
        "trace_id": "trace-001",
        "event_type": "pre_action",
        "session_id": "sess-001",
        "agent_id": "agent-001",
        "source_framework": "test",
        "occurred_at": "2026-03-19T12:00:00+00:00",
        "payload": {"tool": "bash", "command": "ls"},
    }
    base.update(overrides)
    return base


def _minimal_decision(**overrides) -> dict:
    base = {
        "decision": "allow",
        "reason": "Safe read-only operation",
        "policy_id": "L1-safe-baseline",
        "risk_level": "low",
        "decision_source": "policy",
    }
    base.update(overrides)
    return base


def test_skill_use_ledger_preserves_safe_runtime_fields():
    lineage = LineageEvent(
        event_id="evt-runtime",
        session_id="sess-runtime",
        occurred_at="2026-05-19T00:00:00+00:00",
        sequence=7,
        ref_ordinal=1,
        dedupe_key="sess-runtime:evt-runtime:1:sha256:record:sha256:runtime:shell_skill_path",
        canonical_skill_id="skill:search-accommodation",
        tool_name="bash",
        observed_name="search-accommodation",
        runtime_path_status="verified_mirror",
        runtime_root_path_hash="sha256:" + "a" * 64,
        runtime_content_status="trusted_runner_immutable",
        metadata_record_id="sha256:" + "b" * 64,
        decision="block",
        risk_level="high",
        invariant_violations=["runtime_content_unverified"],
        output_provenance_label="search-accommodation",
        policy_version="policy-v1",
    )

    dumped = lineage.model_dump(mode="json")

    assert dumped["ref_ordinal"] == 1
    assert dumped["dedupe_key"].startswith("sess-runtime:evt-runtime:1")
    assert dumped["runtime_path_status"] == "verified_mirror"
    assert dumped["runtime_root_path_hash"] == "sha256:" + "a" * 64
    assert dumped["metadata_record_id"] == "sha256:" + "b" * 64
    assert dumped["decision"] == "block"


def test_lineage_redaction_drops_raw_runtime_paths():
    event = {
        "payload": {
            "_clawsentry_meta": {
                "skill_lineage_raw": {
                    "runtime_path_status": "disallowed",
                    "runtime_root_path_hash": "sha256:" + "a" * 64,
                    "metadata_record_id": "sha256:" + "b" * 64,
                    "runtime_evidence_kind": "shell_skill_path",
                    "ref_ordinal": 0,
                    "runtime_root_raw": "/home/user/.codex/skills/private",
                    "runtime_path_raw": "/home/user/.codex/skills/private/scripts/run.py",
                    "raw_command": "python /home/user/.codex/skills/private/scripts/run.py",
                }
            }
        }
    }

    summary = _lineage_summary_from_event(event)

    assert summary is not None
    assert summary["runtime_path_status"] == "disallowed"
    assert summary["runtime_root_path_hash"] == "sha256:" + "a" * 64
    assert summary["metadata_record_id"] == "sha256:" + "b" * 64
    assert "runtime_root_raw" not in summary
    assert "runtime_path_raw" not in summary
    assert "raw_command" not in summary


@pytest.mark.parametrize(
    ("raw_decision", "expected_ledger_decision"),
    [
        ("allow", "allow"),
        ("allow-once", "allow"),
        ("allow-always", "allow"),
        ("block", "block"),
        ("deny", "block"),
        ("defer", "defer"),
        ("error", "error"),
        ("unexpected-host-value", "unknown"),
    ],
)
def test_lineage_event_normalizes_gateway_decisions_to_ledger_enum(
    raw_decision: str,
    expected_ledger_decision: str,
):
    entry = _lineage_event_from_summary(
        event={
            "event_id": "evt-runtime",
            "session_id": "sess-runtime",
            "tool_name": "bash",
        },
        decision={
            "decision": raw_decision,
            "risk_level": "low",
            "policy_version": "policy-v1",
        },
        context=None,
        summary={
            "native_tool_label": "bash",
            "runtime_path_status": "absent",
        },
    )

    assert entry is not None
    assert entry["decision"] == expected_ledger_decision


def test_lineage_events_are_derived_from_all_resolved_runtime_refs():
    safe_ref = SkillTrustContext(
        registry_status="matched",
        canonical_skill_id="skill:safe",
        presented_name="safe",
        runtime_path_status="verified_source",
        runtime_content_status="not_applicable",
        metadata_record_id="sha256:" + "1" * 64,
        runtime_root_path_hash="sha256:" + "2" * 64,
        runtime_evidence_kind="shell_skill_path",
        ref_ordinal=0,
    )
    blocked_ref = SkillTrustContext(
        registry_status="unknown",
        presented_name="blocked",
        runtime_path_status="disallowed",
        metadata_record_id=None,
        runtime_root_path_hash="sha256:" + "3" * 64,
        runtime_evidence_kind="shell_skill_path",
        ref_ordinal=1,
        invariant_violations=["runtime_path_disallowed"],
    )

    entries = _lineage_events_from_summary(
        event={
            "event_id": "evt-runtime",
            "session_id": "sess-runtime",
            "tool_name": "bash",
        },
        decision={
            "decision": "block",
            "risk_level": "high",
            "policy_version": "policy-v1",
        },
        context=DecisionContext(
            skill_trust=safe_ref,
            skill_trust_refs=[safe_ref, blocked_ref],
        ),
        summary={"native_tool_label": "bash"},
    )

    assert len(entries) == 2
    assert [entry["ref_ordinal"] for entry in entries] == [0, 1]
    assert [entry["observed_name"] for entry in entries] == ["safe", "blocked"]
    assert [entry["runtime_path_status"] for entry in entries] == [
        "verified_source",
        "disallowed",
    ]
    assert entries[1]["invariant_violations"] == ["runtime_path_disallowed"]


def _minimal_risk_snapshot(**overrides) -> dict:
    base = {
        "risk_level": "low",
        "composite_score": 0,
        "dimensions": {"d1": 0, "d2": 0, "d3": 0, "d4": 0, "d5": 0},
        "short_circuit_rule": None,
        "missing_dimensions": [],
        "classified_by": "L1",
        "classified_at": "2026-03-19T12:00:00+00:00",
    }
    base.update(overrides)
    return base


# ===========================================================================
# CanonicalEvent Tests
# ===========================================================================

class TestCanonicalEvent:
    def test_valid_minimal_event(self):
        evt = CanonicalEvent(**_minimal_event())
        assert evt.schema_version == CURRENT_SCHEMA_VERSION
        assert evt.event_type == EventType.PRE_ACTION

    def test_all_event_types(self):
        for et in EventType:
            evt = CanonicalEvent(**_minimal_event(event_type=et.value))
            assert evt.event_type == et

    def test_invalid_event_type(self):
        with pytest.raises(ValidationError):
            CanonicalEvent(**_minimal_event(event_type="unknown"))

    def test_schema_version_valid(self):
        evt = CanonicalEvent(**_minimal_event(schema_version="ahp.2.1"))
        assert evt.schema_version == "ahp.2.1"

    def test_schema_version_invalid(self):
        with pytest.raises(ValidationError, match="schema_version"):
            CanonicalEvent(**_minimal_event(schema_version="ahp.v1"))

    def test_schema_version_invalid_format(self):
        with pytest.raises(ValidationError):
            CanonicalEvent(**_minimal_event(schema_version="v1.0"))

    def test_empty_event_id_rejected(self):
        with pytest.raises(ValidationError):
            CanonicalEvent(**_minimal_event(event_id=""))

    def test_empty_trace_id_rejected(self):
        with pytest.raises(ValidationError):
            CanonicalEvent(**_minimal_event(trace_id=""))

    def test_occurred_at_invalid(self):
        with pytest.raises(ValidationError, match="occurred_at"):
            CanonicalEvent(**_minimal_event(occurred_at="not-a-date"))

    def test_occurred_at_with_z_suffix(self):
        evt = CanonicalEvent(**_minimal_event(occurred_at="2026-03-19T12:00:00Z"))
        assert evt.occurred_at == "2026-03-19T12:00:00Z"

    def test_sentinel_session_id(self):
        sid = CanonicalEvent.sentinel_session_id("a3s-code")
        assert sid == "unknown_session:a3s-code"

    def test_sentinel_agent_id(self):
        aid = CanonicalEvent.sentinel_agent_id("openclaw")
        assert aid == "unknown_agent:openclaw"

    def test_a3s_code_requires_event_subtype(self):
        with pytest.raises(ValidationError, match="event_subtype"):
            CanonicalEvent(**_minimal_event(source_framework="a3s-code"))

    def test_a3s_code_with_event_subtype(self):
        evt = CanonicalEvent(**_minimal_event(
            source_framework="a3s-code",
            event_subtype="PreToolUse",
        ))
        assert evt.event_subtype == "PreToolUse"

    def test_openclaw_requires_protocol_and_profile(self):
        with pytest.raises(ValidationError, match="source_protocol_version"):
            CanonicalEvent(**_minimal_event(
                source_framework="openclaw",
                event_subtype="command:new",
            ))

    def test_openclaw_valid(self):
        evt = CanonicalEvent(**_minimal_event(
            source_framework="openclaw",
            event_subtype="command:new",
            source_protocol_version="1.0",
            mapping_profile="openclaw@5625cf4/protocol.v1/profile.v1",
        ))
        assert evt.mapping_profile.startswith("openclaw@")

    def test_openclaw_invalid_mapping_profile_rejected(self):
        with pytest.raises(ValidationError, match="mapping_profile"):
            CanonicalEvent(**_minimal_event(
                source_framework="openclaw",
                event_subtype="command:new",
                source_protocol_version="1.0",
                mapping_profile="openclaw@bad/profile.v1",
            ))

    def test_optional_fields_default(self):
        evt = CanonicalEvent(**_minimal_event())
        assert evt.parent_event_id is None
        assert evt.depth is None
        assert evt.tool_name is None
        assert evt.risk_hints == []
        assert evt.framework_meta is None

    def test_depth_negative_rejected(self):
        with pytest.raises(ValidationError):
            CanonicalEvent(**_minimal_event(depth=-1))


# ===========================================================================
# CanonicalDecision Tests
# ===========================================================================

class TestCanonicalDecision:
    def test_valid_allow(self):
        d = CanonicalDecision(**_minimal_decision())
        assert d.decision == DecisionVerdict.ALLOW
        assert d.final is True  # auto-set for allow

    def test_valid_block(self):
        d = CanonicalDecision(**_minimal_decision(decision="block"))
        assert d.final is True

    def test_allow_final_false_rejected(self):
        with pytest.raises(ValidationError, match="final"):
            CanonicalDecision(**_minimal_decision(final=False))

    def test_block_final_false_rejected(self):
        with pytest.raises(ValidationError, match="final"):
            CanonicalDecision(**_minimal_decision(decision="block", final=False))

    def test_defer_no_final_required(self):
        d = CanonicalDecision(**_minimal_decision(decision="defer"))
        assert d.final is None  # not auto-set for defer

    def test_modify_with_payload(self):
        d = CanonicalDecision(**_minimal_decision(
            decision="modify",
            modified_payload={"sanitized": True},
        ))
        assert d.modified_payload == {"sanitized": True}

    def test_modify_without_payload_rejected(self):
        with pytest.raises(ValidationError, match="modified_payload"):
            CanonicalDecision(**_minimal_decision(decision="modify"))

    def test_all_failure_classes(self):
        for fc in FailureClass:
            d = CanonicalDecision(**_minimal_decision(failure_class=fc.value))
            assert d.failure_class == fc

    def test_all_decision_sources(self):
        for ds in DecisionSource:
            d = CanonicalDecision(**_minimal_decision(decision_source=ds.value))
            assert d.decision_source == ds


# ===========================================================================
# RiskSnapshot Tests
# ===========================================================================

class TestRiskSnapshot:
    def test_valid_minimal(self):
        rs = RiskSnapshot(**_minimal_risk_snapshot())
        assert rs.risk_level == RiskLevel.LOW
        assert rs.composite_score == 0

    def test_all_risk_levels(self):
        for rl in RiskLevel:
            rs = RiskSnapshot(**_minimal_risk_snapshot(risk_level=rl.value))
            assert rs.risk_level == rl

    def test_valid_short_circuit_rules(self):
        for sc in ("SC-1", "SC-2", "SC-3"):
            rs = RiskSnapshot(**_minimal_risk_snapshot(
                short_circuit_rule=sc,
                risk_level="critical",
                composite_score=7,
            ))
            assert rs.short_circuit_rule == sc

    def test_invalid_short_circuit_rule(self):
        with pytest.raises(ValidationError, match="short_circuit_rule"):
            RiskSnapshot(**_minimal_risk_snapshot(short_circuit_rule="SC-99"))

    def test_dimension_bounds(self):
        # d1-d3: 0-3, d4-d5: 0-2
        rs = RiskSnapshot(**_minimal_risk_snapshot(
            dimensions={"d1": 3, "d2": 3, "d3": 3, "d4": 2, "d5": 2},
            composite_score=7,
            risk_level="critical",
        ))
        assert rs.dimensions.d1 == 3

    def test_dimension_d1_out_of_bounds(self):
        with pytest.raises(ValidationError):
            RiskSnapshot(**_minimal_risk_snapshot(
                dimensions={"d1": 4, "d2": 0, "d3": 0, "d4": 0, "d5": 0},
            ))

    def test_dimension_d4_out_of_bounds(self):
        with pytest.raises(ValidationError):
            RiskSnapshot(**_minimal_risk_snapshot(
                dimensions={"d1": 0, "d2": 0, "d3": 0, "d4": 3, "d5": 0},
            ))

    def test_missing_dimensions_list(self):
        rs = RiskSnapshot(**_minimal_risk_snapshot(
            missing_dimensions=["d1", "d5"],
        ))
        assert rs.missing_dimensions == ["d1", "d5"]

    def test_classified_at_invalid(self):
        with pytest.raises(ValidationError, match="classified_at"):
            RiskSnapshot(**_minimal_risk_snapshot(classified_at="bad-date"))

    def test_l1_snapshot_nesting(self):
        inner = _minimal_risk_snapshot()
        rs = RiskSnapshot(**_minimal_risk_snapshot(
            risk_level="high",
            composite_score=4,
            classified_by="L2",
            l1_snapshot=inner,
        ))
        assert rs.l1_snapshot is not None
        assert rs.l1_snapshot.classified_by == ClassifiedBy.L1

    def test_composite_score_negative_rejected(self):
        with pytest.raises(ValidationError):
            RiskSnapshot(**_minimal_risk_snapshot(composite_score=-1))

    def test_composite_score_float_accepted(self):
        rs = RiskSnapshot(**_minimal_risk_snapshot(
            composite_score=8.5,
            risk_level="critical",
            dimensions={"d1": 3, "d2": 3, "d3": 3, "d4": 2, "d5": 2, "d6": 2.5},
        ))
        assert rs.composite_score == 8.5

    def test_composite_score_above_7_valid(self):
        """composite_score can exceed 7 when D6 multiplier is applied."""
        rs = RiskSnapshot(**_minimal_risk_snapshot(
            composite_score=10,
            risk_level="critical",
            dimensions={"d1": 3, "d2": 3, "d3": 3, "d4": 2, "d5": 2, "d6": 3.0},
        ))
        assert rs.composite_score == 10

    def test_skill_trust_evidence_defaults_are_backward_compatible(self):
        rs = RiskSnapshot(**_minimal_risk_snapshot())

        assert rs.rule_hits == []
        assert rs.skill_trust_findings == []
        assert rs.taint_flow_summary is None


class TestSkillTrustModels:
    def test_registry_report_context_and_lineage_serialize(self):
        record = SkillRegistryRecord(
            canonical_skill_id="skill:search-accommodations",
            canonical_name="search-accommodations",
            aliases=["search_accommodations"],
            content_hashes={"SKILL.md": "sha256:skill"},
            source={"framework": "codex", "path_hash": "sha256:path"},
            trust_level="trusted",
            admission_scan_id="scan-1",
            policy_fingerprint="sha256:policy",
            status="trusted",
        )
        finding = AdmissionFinding(
            finding_id="finding-1",
            finding_family="alias",
            severity="low",
            confidence="medium",
            evidence_hashes=["sha256:skill"],
            evidence_summary="alias normalizes close to canonical name",
            policy_fingerprint="sha256:policy",
        )
        report = AdmissionReport(
            scan_id="scan-1",
            skill_root_hash="sha256:root",
            content_hashes={"SKILL.md": "sha256:skill"},
            findings=[finding],
            admission_risk="low",
            policy_fingerprint="sha256:policy",
        )
        context = SkillTrustContext(
            registry_status="matched",
            canonical_skill_id=record.canonical_skill_id,
            presented_name=record.canonical_name,
            alias_match_type="exact",
            provenance_claim=record.canonical_name,
            admission_risk=report.admission_risk.value,
            policy_fingerprint=record.policy_fingerprint,
        )
        lineage = LineageEvent(
            event_id="evt-1",
            session_id="sess-1",
            canonical_skill_id=record.canonical_skill_id,
            tool_name="read_file",
            output_provenance_label=record.canonical_name,
            content_hash="sha256:output",
            policy_version="1.0",
        )

        decision_context = DecisionContext(skill_trust=context)

        assert report.findings[0].decision_affecting is False
        assert decision_context.model_dump(mode="json")["skill_trust"]["registry_status"] == "matched"
        assert lineage.model_dump(mode="json")["canonical_skill_id"] == record.canonical_skill_id


# ===========================================================================
# SyncDecision RPC Tests
# ===========================================================================

class TestSyncDecisionRequest:
    def test_valid_request(self):
        req = SyncDecisionRequest(
            request_id="req-001",
            deadline_ms=100,
            decision_tier=DecisionTier.L1,
            event=CanonicalEvent(**_minimal_event()),
        )
        assert req.rpc_version == RPC_VERSION
        assert req.deadline_ms == 100

    def test_invalid_rpc_version_accepted_at_model_level(self):
        """rpc_version validation moved to gateway level (VERSION_NOT_SUPPORTED)."""
        req = SyncDecisionRequest(
            rpc_version="bad",
            request_id="req-001",
            deadline_ms=100,
            decision_tier=DecisionTier.L1,
            event=CanonicalEvent(**_minimal_event()),
        )
        assert req.rpc_version == "bad"

    def test_deadline_exceeds_hard_limit(self):
        with pytest.raises(ValidationError):
            SyncDecisionRequest(
                request_id="req-001",
                deadline_ms=120001,
                decision_tier=DecisionTier.L1,
                event=CanonicalEvent(**_minimal_event()),
            )

    def test_deadline_zero_rejected(self):
        with pytest.raises(ValidationError):
            SyncDecisionRequest(
                request_id="req-001",
                deadline_ms=0,
                decision_tier=DecisionTier.L1,
                event=CanonicalEvent(**_minimal_event()),
            )

    def test_with_context(self):
        req = SyncDecisionRequest(
            request_id="req-001",
            deadline_ms=100,
            decision_tier=DecisionTier.L1,
            event=CanonicalEvent(**_minimal_event()),
            context={
                "agent_trust_level": "standard",
                "workspace_id": "ws-001",
            },
        )
        assert req.context.agent_trust_level == AgentTrustLevel.STANDARD


class TestSyncDecisionResponse:
    def test_valid_response(self):
        resp = SyncDecisionResponse(
            request_id="req-001",
            decision=CanonicalDecision(**_minimal_decision()),
            actual_tier=DecisionTier.L1,
            served_at="2026-03-19T12:00:00+00:00",
        )
        assert resp.rpc_status == "ok"

    def test_rpc_status_must_be_ok(self):
        with pytest.raises(ValidationError, match="rpc_status"):
            SyncDecisionResponse(
                request_id="req-001",
                rpc_status="error",
                decision=CanonicalDecision(**_minimal_decision()),
                actual_tier=DecisionTier.L1,
                served_at="2026-03-19T12:00:00+00:00",
            )

    def test_served_at_invalid_rejected(self):
        with pytest.raises(ValidationError, match="served_at"):
            SyncDecisionResponse(
                request_id="req-001",
                decision=CanonicalDecision(**_minimal_decision()),
                actual_tier=DecisionTier.L1,
                served_at="not-a-date",
            )


class TestSyncDecisionErrorResponse:
    def test_valid_error_response(self):
        err = SyncDecisionErrorResponse(
            request_id="req-001",
            rpc_error_code=RPCErrorCode.DEADLINE_EXCEEDED,
            rpc_error_message="L2 analysis timed out",
            retry_eligible=True,
            retry_after_ms=50,
        )
        assert err.rpc_status == "error"
        assert err.retry_eligible is True

    def test_retry_eligible_requires_retry_after_ms(self):
        with pytest.raises(ValidationError, match="retry_after_ms"):
            SyncDecisionErrorResponse(
                request_id="req-001",
                rpc_error_code=RPCErrorCode.DEADLINE_EXCEEDED,
                rpc_error_message="timeout",
                retry_eligible=True,
                # missing retry_after_ms
            )

    def test_non_retryable_error(self):
        err = SyncDecisionErrorResponse(
            request_id="req-001",
            rpc_error_code=RPCErrorCode.INVALID_REQUEST,
            rpc_error_message="Missing event field",
            retry_eligible=False,
        )
        assert err.retry_after_ms is None

    def test_all_error_codes(self):
        for code in RPCErrorCode:
            err = SyncDecisionErrorResponse(
                request_id="req-001",
                rpc_error_code=code,
                rpc_error_message="test",
                retry_eligible=False,
            )
            assert err.rpc_error_code == code

    def test_with_fallback_decision(self):
        err = SyncDecisionErrorResponse(
            request_id="req-001",
            rpc_error_code=RPCErrorCode.ENGINE_UNAVAILABLE,
            rpc_error_message="Engine down",
            retry_eligible=True,
            retry_after_ms=100,
            fallback_decision=CanonicalDecision(**_minimal_decision(
                decision="block",
                decision_source="system",
                reason="Engine unavailable, fail-closed",
            )),
        )
        assert err.fallback_decision.decision == DecisionVerdict.BLOCK


# ===========================================================================
# Utility Tests
# ===========================================================================

class TestRiskSnapshotL3Trace:
    def test_risk_snapshot_l3_trace_default_none(self):
        snap = RiskSnapshot(
            risk_level=RiskLevel.LOW,
            composite_score=1,
            dimensions=RiskDimensions(d1=1, d2=0, d3=0, d4=0, d5=0),
            classified_by=ClassifiedBy.L1,
            classified_at="2026-03-21T00:00:00+00:00",
        )
        assert snap.l3_trace is None

    def test_risk_snapshot_l3_trace_excluded_from_dump(self):
        trace = {"trigger_reason": "test", "turns": []}
        snap = RiskSnapshot(
            risk_level=RiskLevel.LOW,
            composite_score=1,
            dimensions=RiskDimensions(d1=1, d2=0, d3=0, d4=0, d5=0),
            classified_by=ClassifiedBy.L1,
            classified_at="2026-03-21T00:00:00+00:00",
            l3_trace=trace,
        )
        assert snap.l3_trace == trace
        dumped = snap.model_dump(mode="json")
        assert "l3_trace" not in dumped


# ===========================================================================
# RiskDimensions D6 Tests
# ===========================================================================

class TestRiskDimensionsD6:
    def test_d6_defaults_to_zero(self):
        dims = RiskDimensions(d1=0, d2=0, d3=0, d4=0, d5=0)
        assert dims.d6 == 0.0

    def test_d6_accepts_float(self):
        dims = RiskDimensions(d1=0, d2=0, d3=0, d4=0, d5=0, d6=1.5)
        assert dims.d6 == 1.5

    def test_d6_max_valid(self):
        dims = RiskDimensions(d1=0, d2=0, d3=0, d4=0, d5=0, d6=3.0)
        assert dims.d6 == 3.0

    def test_d6_exceeds_max_rejected(self):
        with pytest.raises(ValidationError):
            RiskDimensions(d1=0, d2=0, d3=0, d4=0, d5=0, d6=3.1)

    def test_d6_negative_rejected(self):
        with pytest.raises(ValidationError):
            RiskDimensions(d1=0, d2=0, d3=0, d4=0, d5=0, d6=-0.1)


# ===========================================================================
# CanaryToken Tests
# ===========================================================================

class TestCanaryToken:
    def test_generate_format(self):
        ct = CanaryToken.generate()
        assert ct.token.startswith("<!-- ahp-ref:")
        assert ct.token.endswith(" -->")
        # Core hex part should be 16 chars
        core = ct.token.replace("<!-- ahp-ref:", "").replace(" -->", "")
        assert len(core) == 16
        assert ct.injected_at > 0

    def test_generate_unique(self):
        ct1 = CanaryToken.generate()
        ct2 = CanaryToken.generate()
        assert ct1.token != ct2.token

    def test_check_leak_full_match(self):
        ct = CanaryToken(token="<!-- ahp-ref:abc123def456ghij -->", injected_at=0.0)
        text = "Some output containing <!-- ahp-ref:abc123def456ghij --> in response"
        assert ct.check_leak(text) == 1.5

    def test_check_leak_core_match(self):
        ct = CanaryToken(token="<!-- ahp-ref:abc123def456ghij -->", injected_at=0.0)
        text = "Leaked ahp-ref:abc123def456ghij somewhere"
        assert ct.check_leak(text) == 1.0

    def test_check_leak_no_match(self):
        ct = CanaryToken(token="<!-- ahp-ref:abc123def456ghij -->", injected_at=0.0)
        text = "Clean output with no canary tokens"
        assert ct.check_leak(text) == 0.0


# ===========================================================================
# PostAction Types Tests
# ===========================================================================

class TestPostActionResponseTier:
    def test_enum_values(self):
        assert PostActionResponseTier.LOG_ONLY.value == "log_only"
        assert PostActionResponseTier.MONITOR.value == "monitor"
        assert PostActionResponseTier.ESCALATE.value == "escalate"
        assert PostActionResponseTier.EMERGENCY.value == "emergency"

    def test_all_tiers_count(self):
        assert len(PostActionResponseTier) == 4


class TestPostActionFinding:
    def test_creation_minimal(self):
        finding = PostActionFinding(
            tier=PostActionResponseTier.LOG_ONLY,
            patterns_matched=["test-pattern"],
            score=0.5,
        )
        assert finding.tier == PostActionResponseTier.LOG_ONLY
        assert finding.patterns_matched == ["test-pattern"]
        assert finding.score == 0.5
        assert finding.details == {}  # __post_init__ sets empty dict

    def test_creation_with_details(self):
        finding = PostActionFinding(
            tier=PostActionResponseTier.EMERGENCY,
            patterns_matched=["exfil-http", "exfil-dns"],
            score=2.8,
            details={"exfil_target": "https://evil.com"},
        )
        assert finding.details == {"exfil_target": "https://evil.com"}

    def test_to_dict(self):
        finding = PostActionFinding(
            tier=PostActionResponseTier.ESCALATE,
            patterns_matched=["multi-step-attack"],
            score=1.5,
            details={"chain": ["read .env", "curl"]},
        )
        d = finding.to_dict()
        assert d == {
            "tier": "escalate",
            "patterns_matched": ["multi-step-attack"],
            "score": 1.5,
            "details": {"chain": ["read .env", "curl"]},
        }

    def test_to_dict_empty_details(self):
        finding = PostActionFinding(
            tier=PostActionResponseTier.MONITOR,
            patterns_matched=[],
            score=0.0,
        )
        d = finding.to_dict()
        assert d["details"] == {}
        assert d["tier"] == "monitor"


# ===========================================================================
# Utility Tests
# ===========================================================================

class TestUtilities:
    def test_utc_now_iso(self):
        ts = utc_now_iso()
        # Should be parseable and contain timezone info
        from datetime import datetime
        dt = datetime.fromisoformat(ts)
        assert dt.tzinfo is not None


class TestSessionScopeProfileModel:
    def test_scope_profile_schema_validates_base_task_and_provenance(self):
        from clawsentry.gateway.models import (
            DecisionContext,
            SessionScopeBaseRules,
            SessionScopeProfile,
            SessionScopeProvenance,
            SessionScopeSource,
            SessionScopeTaskRules,
        )

        profile = SessionScopeProfile(
            profile_id="scope-docs-1",
            source=SessionScopeSource.PROJECT_TEMPLATE,
            confirmed=True,
            dry_run=False,
            base_rules=SessionScopeBaseRules(
                denied_paths=["~/.ssh", "/etc"],
                denied_domains=["evil.example"],
                denied_command_prefixes=["sudo"],
                denied_skill_ids=["skill:blocked"],
                denied_skill_trust_states=["blacklist", "revoked"],
                denied_mcp_servers=["fetch"],
                denied_mcp_tools=["fetch.fetch"],
            ),
            task_rules=SessionScopeTaskRules(
                allowed_tools=["read_file"],
                allowed_path_prefixes=["docs/"],
                allowed_skill_trust_states=["allowlist"],
                allowed_mcp_servers=["filesystem"],
                allowed_mcp_tools=["filesystem.read_file"],
                queued_categories=["network"],
            ),
            provenance=SessionScopeProvenance(
                user_objective_hash="sha256:docs",
                generated_by="project-template:test",
                confirmed_by="operator:test",
            ),
        )
        context = DecisionContext(session_scope_profile=profile)

        assert context.session_scope_profile is not None
        assert context.session_scope_profile.scope_version == "cs.session_scope.v1"
        assert context.session_scope_profile.base_rules.denied_paths[0] == "~/.ssh"
        assert context.session_scope_profile.base_rules.denied_skill_ids == ["skill:blocked"]
        assert context.session_scope_profile.base_rules.denied_mcp_servers == ["fetch"]
        assert context.session_scope_profile.base_rules.denied_mcp_tools == ["fetch.fetch"]
        assert context.session_scope_profile.task_rules.allowed_path_prefixes == ["docs/"]
        assert context.session_scope_profile.task_rules.allowed_skill_trust_states == ["allowlist"]
        assert context.session_scope_profile.task_rules.allowed_mcp_tools == ["filesystem.read_file"]

    def test_mcp_context_and_skill_trust_state_roundtrip(self):
        context = DecisionContext(
            mcp_context=McpContext(
                server_name="filesystem",
                tool_name="read_file",
                resource_kind="file",
                resource_uri_hash="sha256:resource",
                trust_level="trusted",
                status="allowlist",
            ),
            skill_trust=SkillTrustContext(
                registry_status="matched",
                canonical_skill_id="skill:docs",
                presented_name="docs",
                trust_list_state="allowlist",
                first_use_scan=FirstUseScanState(state="scan_completed", admission_scan_id="scan-1"),
            ),
        )

        dumped = context.model_dump(mode="json")

        assert dumped["mcp_context"]["server_name"] == "filesystem"
        assert dumped["skill_trust"]["trust_list_state"] == "allowlist"
        assert dumped["skill_trust"]["first_use_scan"]["state"] == "scan_completed"
