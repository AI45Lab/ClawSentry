from __future__ import annotations

from clawsentry.gateway.tool_permissions import resolve_tool_permission
from clawsentry.gateway.tool_semantic_registry import (
    ToolSemanticRegistry,
    derive_tool_semantics,
)


def test_tool_semantic_registry_contract_codex_claude_gemini_kimi_openclaw_mcp():
    registry = ToolSemanticRegistry.default()

    cases = [
        (
            {"source_framework": "codex", "tool_name": "Bash", "payload": {"command": "ls"}},
            "bash",
            "command.exec",
            "Bash",
        ),
        (
            {"source_framework": "codex", "tool_name": "apply_patch", "payload": {}},
            "write",
            "filesystem.write",
            "apply_patch",
        ),
        (
            {"source_framework": "claude_code", "tool_name": "Read", "payload": {"file_path": "README.md"}},
            "read_file",
            "filesystem.read",
            "Read",
        ),
        (
            {"source_framework": "gemini", "tool_name": "run_shell_command", "payload": {"command": "pwd"}},
            "bash",
            "command.exec",
            "run_shell_command",
        ),
        (
            {"source_framework": "kimi", "tool_name": "Shell", "payload": {"command": "pwd"}},
            "bash",
            "command.exec",
            "Shell",
        ),
        (
            {
                "source_framework": "openclaw",
                "tool_name": "exec.approval.requested",
                "payload": {"request": {"command": "pwd"}},
            },
            "bash",
            "command.exec",
            "exec.approval.requested",
        ),
        (
            {"source_framework": "codex", "tool_name": "mcp__filesystem__read_file", "payload": {"path": "README.md"}},
            "read_file",
            "filesystem.read",
            "mcp__filesystem__read_file",
        ),
    ]

    for event, canonical_tool, d1_class, raw_name in cases:
        semantics = derive_tool_semantics(event, registry=registry)
        assert semantics is not None
        assert semantics.canonical_tool == canonical_tool
        assert semantics.d1_class == d1_class
        assert semantics.raw_name_field
        assert semantics.native_tool_id == raw_name


def test_tool_semantic_registry_shadow_does_not_change_permission_decisions():
    registry = ToolSemanticRegistry.default()
    before = resolve_tool_permission("bash", session_state="normal")
    semantics = derive_tool_semantics(
        {"source_framework": "codex", "tool_name": "Bash", "payload": {"command": "pwd"}},
        registry=registry,
    )
    after = resolve_tool_permission("bash", session_state="normal")

    assert semantics is not None
    assert before == after


def test_tool_permission_group_overrides_win_over_registry_defaults():
    decision = resolve_tool_permission(
        "bash",
        session_state="critical",
        overrides={"bash": ("read_only",)},
    )

    assert decision.source == "override"
    assert decision.groups == ("read_only",)
    assert decision.action == "allow"


def test_registry_preserves_raw_native_tool_name():
    semantics = derive_tool_semantics(
        {"source_framework": "gemini", "tool_name": "execute_shell", "payload": {"command": "pwd"}},
    )

    assert semantics is not None
    assert semantics.native_tool_id == "execute_shell"
    assert semantics.raw_name_field == "gemini_tool_name"
    assert semantics.shadow_metadata()["native_tool_id"] == "execute_shell"
