from __future__ import annotations

import ast
from pathlib import Path

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
            ("command.exec",),
            "raw_tool_name",
            "Bash",
        ),
        (
            {"source_framework": "codex", "tool_name": "apply_patch", "payload": {}},
            "write",
            "filesystem.write",
            ("filesystem.write",),
            "raw_tool_name",
            "apply_patch",
        ),
        (
            {"source_framework": "claude-code", "tool_name": "Read", "payload": {"file_path": "README.md"}},
            "read_file",
            "filesystem.read",
            ("filesystem.read",),
            "raw_tool_name",
            "Read",
        ),
        (
            {"source_framework": "claude-code", "tool_name": "Bash", "payload": {"command": "pwd"}},
            "bash",
            "command.exec",
            ("command.exec",),
            "raw_tool_name",
            "Bash",
        ),
        (
            {"source_framework": "claude-code", "tool_name": "Write", "payload": {"file_path": "out.txt"}},
            "write",
            "filesystem.write",
            ("filesystem.write",),
            "raw_tool_name",
            "Write",
        ),
        (
            {"source_framework": "kimi-cli", "tool_name": "Shell", "payload": {"command": "pwd"}},
            "bash",
            "command.exec",
            ("command.exec",),
            "kimi_tool_name",
            "Shell",
        ),
        (
            {"source_framework": "kimi-cli", "tool_name": "run_command", "payload": {"command": "pwd"}},
            "bash",
            "command.exec",
            ("command.exec",),
            "kimi_tool_name",
            "run_command",
        ),
        (
            {"source_framework": "gemini-cli", "tool_name": "run_shell_command", "payload": {"command": "pwd"}},
            "bash",
            "command.exec",
            ("command.exec",),
            "gemini_tool_name",
            "run_shell_command",
        ),
        (
            {"source_framework": "gemini-cli", "tool_name": "ShellTool", "payload": {"command": "pwd"}},
            "bash",
            "command.exec",
            ("command.exec",),
            "gemini_tool_name",
            "ShellTool",
        ),
        (
            {"source_framework": "gemini-cli", "tool_name": "Shell", "payload": {"command": "pwd"}},
            "bash",
            "command.exec",
            ("command.exec",),
            "gemini_tool_name",
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
            ("command.exec",),
            "raw_tool_name",
            "exec.approval.requested",
        ),
        (
            {"source_framework": "codex", "tool_name": "mcp__filesystem__read_file", "payload": {"path": "README.md"}},
            "read_file",
            "filesystem.read",
            ("filesystem.read",),
            "raw_tool_name",
            "mcp__filesystem__read_file",
        ),
    ]

    for event, canonical_tool, d1_class, effect_capabilities, raw_name_field, raw_name in cases:
        semantics = derive_tool_semantics(event, registry=registry)
        assert semantics is not None
        assert semantics.canonical_tool == canonical_tool
        assert semantics.d1_class == d1_class
        assert semantics.effect_capabilities == effect_capabilities
        assert semantics.raw_name_field == raw_name_field
        assert semantics.native_tool_id == raw_name
        assert semantics.display_label == raw_name


def test_tool_semantic_registry_tolerates_source_framework_aliases():
    registry = ToolSemanticRegistry.default()

    cases = [
        ("claude_code", "Read", "read_file"),
        ("claude-code-cli", "Edit", "write"),
        ("gemini", "run_shell_command", "bash"),
        ("gemini_cli", "ShellTool", "bash"),
        ("kimi", "Shell", "bash"),
        ("kimi_cli", "run_command", "bash"),
    ]

    for framework, tool_name, canonical_tool in cases:
        semantics = registry.resolve(framework=framework, tool_name=tool_name, payload={"command": "pwd"})
        assert semantics is not None
        assert semantics.canonical_tool == canonical_tool


def test_tool_semantic_registry_matrix_includes_real_framework_read_list_write_aliases():
    registry = ToolSemanticRegistry.default()

    cases = [
        ("codex", "Read", "read_file", "filesystem.read"),
        ("codex", "List", "list_files", "filesystem.enumerate"),
        ("claude-code", "Glob", "list_files", "filesystem.enumerate"),
        ("claude-code", "Edit", "write", "filesystem.write"),
        ("kimi-cli", "Read", "read_file", "filesystem.read"),
        ("kimi-cli", "Write", "write", "filesystem.write"),
        ("gemini-cli", "read_file", "read_file", "filesystem.read"),
        ("gemini-cli", "write_file", "write", "filesystem.write"),
    ]

    for framework, tool_name, canonical_tool, effect in cases:
        semantics = registry.resolve(
            framework=framework,
            tool_name=tool_name,
            payload={"path": "docs/plan.md"},
        )
        assert semantics is not None
        assert semantics.framework == framework
        assert semantics.canonical_tool == canonical_tool
        assert semantics.effect_capabilities == (effect,)
        assert semantics.native_tool_id == tool_name


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
        {"source_framework": "gemini-cli", "tool_name": "execute_shell", "payload": {"command": "pwd"}},
    )

    assert semantics is not None
    assert semantics.native_tool_id == "execute_shell"
    assert semantics.raw_name_field == "gemini_tool_name"
    assert semantics.shadow_metadata()["native_tool_id"] == "execute_shell"
    assert semantics.shadow_metadata()["display_label"] == "execute_shell"


def test_policy_files_do_not_branch_on_raw_native_tool_ids():
    repo_root = Path(__file__).resolve().parents[3]
    policy_files = [
        repo_root / "src" / "clawsentry" / "gateway" / "risk_snapshot.py",
        repo_root / "src" / "clawsentry" / "gateway" / "policy_engine.py",
        repo_root / "src" / "clawsentry" / "gateway" / "server.py",
    ]
    forbidden_string_constants = {
        "apply_patch",
        "Bash",
        "Read",
        "ShellTool",
        "run_shell_command",
        "kimi_tool_name",
        "gemini_tool_name",
    }
    forbidden_identifiers = {"kimi_tool_name", "gemini_tool_name"}

    offenders: list[str] = []
    for path in policy_files:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        docstring_nodes = {
            node.body[0]
            for node in ast.walk(tree)
            if isinstance(node, (ast.Module, ast.ClassDef, ast.AsyncFunctionDef, ast.FunctionDef))
            and node.body
            and isinstance(node.body[0], ast.Expr)
            and isinstance(node.body[0].value, ast.Constant)
            and isinstance(node.body[0].value.value, str)
        }
        for node in ast.walk(tree):
            if node in docstring_nodes:
                continue
            if isinstance(node, ast.Constant) and isinstance(node.value, str) and node.value in forbidden_string_constants:
                offenders.append(f"{path.relative_to(repo_root)}:{node.lineno}:{node.value}")
            if isinstance(node, ast.Name) and node.id in forbidden_identifiers:
                offenders.append(f"{path.relative_to(repo_root)}:{node.lineno}:{node.id}")
            if isinstance(node, ast.Attribute) and node.attr in forbidden_identifiers:
                offenders.append(f"{path.relative_to(repo_root)}:{node.lineno}:{node.attr}")

    assert offenders == []
