"""Framework-native tool semantics in Gateway-owned shadow mode."""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Any, Iterable


@dataclass(frozen=True)
class ToolSemanticEntry:
    framework: str
    native_tool_names: tuple[str, ...]
    canonical_tool: str
    permission_groups: tuple[str, ...]
    d1_class: str
    action_kinds: tuple[str, ...]
    effect_capabilities: tuple[str, ...]
    payload_fields: tuple[str, ...]
    content_surfaces: tuple[str, ...]
    path_fields: tuple[str, ...]
    network_fields: tuple[str, ...]
    enforcement_strength: str
    raw_name_field: str
    native_tool_id: str = ""
    display_label: str = ""
    notes_or_rule_id: str = ""

    def with_native_tool_id(self, native_tool_id: str, raw_name_field: str | None = None) -> "ToolSemanticEntry":
        return replace(
            self,
            native_tool_id=native_tool_id,
            raw_name_field=raw_name_field or self.raw_name_field,
            display_label=self.display_label or native_tool_id,
        )

    def shadow_metadata(self) -> dict[str, object]:
        return {
            "framework": self.framework,
            "native_tool_id": self.native_tool_id,
            "raw_name_field": self.raw_name_field,
            "display_label": self.display_label,
            "canonical_tool": self.canonical_tool,
            "permission_groups": list(self.permission_groups),
            "d1_class": self.d1_class,
            "action_kinds": list(self.action_kinds),
            "effect_capabilities": list(self.effect_capabilities),
            "content_surfaces": list(self.content_surfaces),
            "path_fields": list(self.path_fields),
            "enforcement_strength": self.enforcement_strength,
            "notes_or_rule_id": self.notes_or_rule_id,
        }


class ToolSemanticRegistry:
    """Small immutable lookup table for framework-native tool semantics."""

    def __init__(self, entries: Iterable[ToolSemanticEntry]) -> None:
        self._entries = tuple(entries)

    @classmethod
    def default(cls) -> "ToolSemanticRegistry":
        return cls(_default_entries())

    def resolve(self, *, framework: str | None, tool_name: str | None, payload: dict[str, Any] | None = None) -> ToolSemanticEntry | None:
        framework_l = _canonical_framework(framework)
        tool = str(tool_name or "").strip()
        tool_l = _normalize(tool)
        payload = payload or {}

        openclaw_command = payload.get("request")
        if tool_l == "exec.approval.requested" and isinstance(openclaw_command, dict):
            return _bash_entry("openclaw", ("exec.approval.requested",), "raw_tool_name").with_native_tool_id(tool)

        if tool_l.startswith("mcp__") or _looks_like_mcp_dotted(tool_l):
            canonical = _canonical_mcp(tool_l)
            return canonical.with_native_tool_id(tool, "raw_tool_name")

        for entry in self._entries:
            if entry.framework != "*" and framework_l and entry.framework != framework_l:
                continue
            if tool_l in {_normalize(name) for name in entry.native_tool_names}:
                return entry.with_native_tool_id(tool, entry.raw_name_field)

        return None


def derive_tool_semantics(
    event: Any,
    *,
    registry: ToolSemanticRegistry | None = None,
) -> ToolSemanticEntry | None:
    """Return registry semantics for audit/debug shadow use only."""

    registry = registry or ToolSemanticRegistry.default()
    if isinstance(event, dict):
        framework = event.get("source_framework")
        tool_name = event.get("tool_name") or event.get("tool") or event.get("command")
        payload = event.get("payload") if isinstance(event.get("payload"), dict) else {}
    else:
        framework = getattr(event, "source_framework", None)
        tool_name = getattr(event, "tool_name", None)
        payload = getattr(event, "payload", None) or {}
    return registry.resolve(framework=framework, tool_name=tool_name, payload=payload)


def _default_entries() -> tuple[ToolSemanticEntry, ...]:
    return (
        _bash_entry("codex", ("bash", "Bash"), "raw_tool_name"),
        _write_entry("codex", ("apply_patch", "Edit", "Write")),
        _read_entry("codex", ("Read", "read_file")),
        _enumerate_entry("codex", ("Glob", "Grep", "List", "Search", "LS")),
        _read_entry("claude-code", ("Read", "read_file")),
        _enumerate_entry("claude-code", ("Glob", "Grep", "LS", "List")),
        _write_entry("claude-code", ("Write", "Edit", "MultiEdit")),
        _read_entry("a3s", ("Read", "read_file")),
        _bash_entry("claude-code", ("Bash", "bash"), "raw_tool_name"),
        _bash_entry("a3s", ("Bash", "bash", "command"), "raw_tool_name"),
        _read_entry("gemini-cli", ("Read", "read_file")),
        _enumerate_entry("gemini-cli", ("Glob", "Grep", "List", "Search", "LS")),
        _write_entry("gemini-cli", ("Write", "Edit", "write_file", "edit_file")),
        _bash_entry(
            "gemini-cli",
            ("run_shell_command", "shell_command", "execute_shell", "run_command", "ShellTool", "Shell"),
            "gemini_tool_name",
        ),
        _read_entry("kimi-cli", ("Read", "read_file")),
        _enumerate_entry("kimi-cli", ("Glob", "Grep", "List", "Search", "LS")),
        _write_entry("kimi-cli", ("Write", "Edit", "write_file", "edit_file")),
        _bash_entry("kimi-cli", ("Shell", "shell", "run_command"), "kimi_tool_name", enforcement_strength="native_allow_block_only"),
        _bash_entry("openclaw", ("exec.approval.requested",), "raw_tool_name"),
        _read_entry("*", ("filesystem.read_file", "read_file")),
    )


def _bash_entry(
    framework: str,
    names: tuple[str, ...],
    raw_name_field: str,
    *,
    enforcement_strength: str = "gateway_shadow_only",
) -> ToolSemanticEntry:
    return ToolSemanticEntry(
        framework=framework,
        native_tool_names=names,
        canonical_tool="bash",
        permission_groups=("destructive",),
        d1_class="command.exec",
        action_kinds=("execute",),
        effect_capabilities=("command.exec",),
        payload_fields=("command", "cmd", "request.command"),
        content_surfaces=(),
        path_fields=(),
        network_fields=(),
        enforcement_strength=enforcement_strength,
        raw_name_field=raw_name_field,
        notes_or_rule_id="native_command_exec",
    )


def _write_entry(framework: str, names: tuple[str, ...]) -> ToolSemanticEntry:
    return ToolSemanticEntry(
        framework=framework,
        native_tool_names=names,
        canonical_tool="write",
        permission_groups=("write",),
        d1_class="filesystem.write",
        action_kinds=("write",),
        effect_capabilities=("filesystem.write",),
        payload_fields=("path", "file_path", "content"),
        content_surfaces=("write_file",),
        path_fields=("path", "file_path"),
        network_fields=(),
        enforcement_strength="gateway_shadow_only",
        raw_name_field="raw_tool_name",
        notes_or_rule_id="native_write_effect",
    )


def _enumerate_entry(framework: str, names: tuple[str, ...]) -> ToolSemanticEntry:
    return ToolSemanticEntry(
        framework=framework,
        native_tool_names=names,
        canonical_tool="list_files",
        permission_groups=("read_only",),
        d1_class="filesystem.enumerate",
        action_kinds=("enumerate",),
        effect_capabilities=("filesystem.enumerate",),
        payload_fields=("path", "directory", "pattern"),
        content_surfaces=("local_file_listing",),
        path_fields=("path", "directory"),
        network_fields=(),
        enforcement_strength="gateway_shadow_only",
        raw_name_field="raw_tool_name",
        notes_or_rule_id="native_enumerate_effect",
    )


def _read_entry(framework: str, names: tuple[str, ...]) -> ToolSemanticEntry:
    return ToolSemanticEntry(
        framework=framework,
        native_tool_names=names,
        canonical_tool="read_file",
        permission_groups=("read_only",),
        d1_class="filesystem.read",
        action_kinds=("read",),
        effect_capabilities=("filesystem.read",),
        payload_fields=("path", "file_path", "relative_path"),
        content_surfaces=("local_file_read",),
        path_fields=("path", "file_path", "relative_path"),
        network_fields=(),
        enforcement_strength="gateway_shadow_only",
        raw_name_field="raw_tool_name",
        notes_or_rule_id="native_read_content",
    )


def _canonical_mcp(tool_l: str) -> ToolSemanticEntry:
    server_tool = tool_l.replace(".", "__")
    if "read" in server_tool or "get" in server_tool or "query" in server_tool:
        return _read_entry("mcp", (tool_l,))
    if any(token in server_tool for token in ("write", "create", "update", "edit")):
        return _write_entry("mcp", (tool_l,))
    return ToolSemanticEntry(
        framework="mcp",
        native_tool_names=(tool_l,),
        canonical_tool=tool_l,
        permission_groups=("unknown",),
        d1_class="mcp.tool",
        action_kinds=("mcp",),
        effect_capabilities=(),
        payload_fields=(),
        content_surfaces=(),
        path_fields=(),
        network_fields=(),
        enforcement_strength="gateway_shadow_only",
        raw_name_field="raw_tool_name",
        notes_or_rule_id="mcp_token_heuristic",
    )


def _normalize(value: object) -> str:
    return str(value or "").strip().lower()


def _canonical_framework(value: object) -> str:
    framework = _normalize(value).replace("_", "-")
    if framework in {"claude-code", "claude-code-cli"}:
        return "claude-code"
    if framework in {"gemini", "gemini-cli"}:
        return "gemini-cli"
    if framework in {"kimi", "kimi-cli"}:
        return "kimi-cli"
    if framework == "codex-cli":
        return "codex"
    return framework


def _looks_like_mcp_dotted(tool_l: str) -> bool:
    if "." not in tool_l:
        return False
    server, tool = tool_l.split(".", 1)
    return bool(server and tool and server not in {"filesystem"})
