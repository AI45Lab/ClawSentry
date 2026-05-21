import json

import pytest

from clawsentry.gateway.detection_config import DetectionConfig
from clawsentry.gateway.models import RPC_VERSION
from clawsentry.gateway.server import SupervisionGateway


def _jsonrpc_request(params: dict, rpc_id: int = 1) -> bytes:
    return json.dumps({
        "jsonrpc": "2.0",
        "id": rpc_id,
        "method": "ahp/sync_decision",
        "params": params,
    }).encode()


def _params(*, request_id: str, event_id: str, session_id: str, payload: dict, context: dict | None = None) -> dict:
    return {
        "rpc_version": RPC_VERSION,
        "request_id": request_id,
        "deadline_ms": 1000,
        "decision_tier": "L1",
        "event": {
            "event_id": event_id,
            "trace_id": f"trace-{event_id}",
            "event_type": "pre_action",
            "session_id": session_id,
            "agent_id": "agent-lineage",
            "source_framework": "test",
            "occurred_at": "2026-05-21T00:00:00+00:00",
            "payload": payload,
            "tool_name": "bash",
        },
        "context": context or {},
    }


def _lineage() -> dict:
    return {
        "presented_skill_name": "generic-local-skill",
        "canonical_skill_id": "skill:generic-local-skill",
        "runtime_root_path_hash": "sha256:" + "a" * 64,
        "metadata_record_id": "sha256:" + "b" * 64,
        "content_hash": "sha256:" + "c" * 64,
    }


@pytest.mark.asyncio
async def test_blocked_skill_lineage_match_is_session_hard_boundary():
    gw = SupervisionGateway(detection_config=DetectionConfig(mode="benchmark"))
    session_id = "sess-lineage-boundary"

    first = await gw.handle_jsonrpc(_jsonrpc_request(_params(
        request_id="req-lineage-1",
        event_id="evt-lineage-1",
        session_id=session_id,
        payload={
            "command": "cat /workspace/skills/generic-local-skill/SKILL.md",
            "_clawsentry_meta": {"skill_lineage_raw": _lineage()},
        },
        context={
            "skill_trust": {
                "canonical_skill_id": "skill:generic-local-skill",
                "presented_name": "generic-local-skill",
                "first_use_package_review": {
                    "timing_mode": "pre_use_gate",
                    "verdict": "inconsistent",
                    "severity": "high",
                    "confidence": 0.95,
                },
            }
        },
    )))
    assert first["result"]["decision"]["decision"] == "block"

    second = await gw.handle_jsonrpc(_jsonrpc_request(_params(
        request_id="req-lineage-2",
        event_id="evt-lineage-2",
        session_id=session_id,
        payload={
            "command": "python3 /workspace/project/recovery.py",
            "_clawsentry_meta": {"skill_lineage_raw": _lineage()},
        },
    )))

    assert second["result"]["decision"]["decision"] == "block"
    record = gw.trajectory_store.records[-1]
    snapshot = record["risk_snapshot"]
    assert snapshot["l1_authority_class"] == "deterministic_hard_block"
    assert snapshot["blocked_lineage_match"]["matched_key"] == "runtime_root_path_hash"
    assert "blocked_skill_lineage_match" in snapshot["l1_authority_reasons"]
    assert snapshot.get("contextual_review_clearance") is None
