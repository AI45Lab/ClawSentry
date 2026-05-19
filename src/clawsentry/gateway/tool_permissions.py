"""Gateway-owned tool permission group resolution."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Sequence


_RESTRICTIVENESS = {
    "read_only": 0,
    "write": 1,
    "network": 2,
    "credentialed": 3,
    "destructive": 4,
    "mcp_admin": 5,
    "unknown": 6,
}

TOOL_PERMISSION_GROUPS = frozenset(_RESTRICTIVENESS)

_DEFAULT_TOOL_GROUPS: dict[str, tuple[str, ...]] = {
    "read_file": ("read_only",),
    "list_dir": ("read_only",),
    "search": ("read_only",),
    "grep": ("read_only",),
    "write_file": ("write",),
    "edit_file": ("write",),
    "create_file": ("write",),
    "fetch": ("network",),
    "http_request": ("network",),
    "mcp_config": ("mcp_admin",),
    "bash": ("destructive",),
    "shell": ("destructive",),
}

_MCP_ADMIN_OPERATIONS = frozenset({
    "admin",
    "alter",
    "auth",
    "config",
    "connect",
    "database",
    "datasource",
    "data_source",
    "drop",
    "grant",
    "install",
    "integration",
    "oauth",
    "permission",
    "permissions",
    "policy",
    "revoke",
    "schema",
    "secret",
    "source",
    "team",
    "token",
    "user",
})
_MCP_WRITE_OPERATIONS = frozenset({
    "add",
    "append",
    "copy",
    "create",
    "edit",
    "move",
    "patch",
    "post",
    "put",
    "rename",
    "set",
    "submit",
    "update",
    "upload",
    "write",
})
_MCP_READ_OPERATIONS = frozenset({
    "find",
    "get",
    "list",
    "query",
    "read",
    "search",
    "select",
    "show",
})
_MCP_NETWORK_OPERATIONS = frozenset({
    "browse",
    "download",
    "fetch",
    "http",
    "request",
    "web",
})
_MCP_DESTRUCTIVE_OPERATIONS = frozenset({
    "delete",
    "destroy",
    "remove",
    "trash",
})


@dataclass(frozen=True)
class ToolPermissionOverrideConfig:
    overrides: dict[str, tuple[str, ...]]
    findings: list[dict[str, str]]


@dataclass(frozen=True)
class ToolPermissionDecision:
    tool_name: str
    group: str
    groups: tuple[str, ...]
    source: str
    action: str
    reason: str

    def to_dict(self) -> dict[str, object]:
        return {
            "tool_name": self.tool_name,
            "group": self.group,
            "groups": list(self.groups),
            "source": self.source,
            "action": self.action,
            "reason": self.reason,
        }


def _most_restrictive(groups: tuple[str, ...]) -> str:
    return max(groups, key=lambda group: _RESTRICTIVENESS.get(group, _RESTRICTIVENESS["unknown"]))


def _mcp_identity_parts(normalized: str) -> tuple[str, str] | None:
    if normalized.startswith("mcp__"):
        parts = normalized.split("__", 2)
        if len(parts) == 3 and parts[1] and parts[2]:
            return parts[1], parts[2]
    if "." in normalized:
        server, tool = normalized.split(".", 1)
        if server and tool:
            return server, tool
    return None


def _tokenize_mcp_name(name: str) -> set[str]:
    normalized_name = name.replace("-", "_").replace(".", "_")
    return {token for token in normalized_name.split("_") if token}


def _default_mcp_groups(normalized: str) -> tuple[str, ...] | None:
    parts = _mcp_identity_parts(normalized)
    if not parts:
        return None
    server, tool = parts
    tokens = _tokenize_mcp_name(server) | _tokenize_mcp_name(tool)
    if tokens & _MCP_ADMIN_OPERATIONS:
        return ("mcp_admin",)
    if tokens & _MCP_DESTRUCTIVE_OPERATIONS:
        return ("destructive",)
    if tokens & _MCP_WRITE_OPERATIONS:
        return ("write",)
    if tokens & _MCP_NETWORK_OPERATIONS:
        return ("network",)
    if tokens & _MCP_READ_OPERATIONS:
        return ("read_only",)
    return None


def parse_tool_permission_group_overrides(raw: str | None) -> ToolPermissionOverrideConfig:
    """Parse operator-provided ``tool=group,group;...`` overrides."""

    overrides: dict[str, tuple[str, ...]] = {}
    findings: list[dict[str, str]] = []
    if not raw:
        return ToolPermissionOverrideConfig(overrides=overrides, findings=findings)
    for entry in str(raw).split(";"):
        item = entry.strip()
        if not item:
            continue
        if "=" not in item:
            findings.append({
                "code": "invalid_tool_permission_entry",
                "entry": item,
                "message": "tool permission override entries must use tool=group[,group]",
            })
            continue
        tool, groups_text = item.split("=", 1)
        normalized_tool = tool.strip().lower()
        groups = tuple(group.strip().lower() for group in groups_text.split(",") if group.strip())
        if not normalized_tool:
            findings.append({
                "code": "missing_tool_permission_tool",
                "entry": item,
                "message": "tool permission override is missing a tool name",
            })
            continue
        invalid_groups = [group for group in groups if group not in _RESTRICTIVENESS]
        if invalid_groups or not groups:
            findings.append({
                "code": "invalid_tool_permission_group",
                "entry": item,
                "message": "unknown tool permission group: " + ",".join(invalid_groups or ["<empty>"]),
            })
            continue
        overrides[normalized_tool] = groups
    return ToolPermissionOverrideConfig(overrides=overrides, findings=findings)


def resolve_tool_permission(
    tool_name: str | None,
    *,
    session_state: str = "critical",
    overrides: dict[str, Sequence[str]] | None = None,
) -> ToolPermissionDecision:
    """Resolve a host tool into a Gateway-owned permission group decision."""

    normalized = (tool_name or "unknown").strip().lower() or "unknown"
    mapping = dict(_DEFAULT_TOOL_GROUPS)
    override_keys: set[str] = set()
    if overrides:
        override_mapping = {
            key.strip().lower(): tuple(str(group).strip().lower() for group in value if str(group).strip())
            for key, value in overrides.items()
        }
        override_keys = set(override_mapping)
        mapping.update(override_mapping)
    groups = mapping.get(normalized)
    source = "default"
    if normalized in override_keys:
        source = "override"
    if not groups:
        groups = _default_mcp_groups(normalized)
        source = "default_mcp" if groups else "default_unknown"
    if not groups:
        groups = ("unknown",)
    group = _most_restrictive(groups)
    critical_denied = {"write", "network", "credentialed", "destructive", "mcp_admin", "unknown"}
    action = "deny" if session_state == "critical" and group in critical_denied else "allow"
    return ToolPermissionDecision(
        tool_name=normalized,
        group=group,
        groups=groups,
        source=source,
        action=action,
        reason=f"{session_state}:{group}:{action}",
    )
