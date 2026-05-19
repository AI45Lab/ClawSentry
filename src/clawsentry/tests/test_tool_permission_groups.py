import json

from clawsentry.cli.scope_command import run_scope_preview
from clawsentry.gateway.models import (
    CanonicalEvent,
    DecisionContext,
    EventType,
    SessionScopeProfile,
)
from clawsentry.gateway.session_scope import evaluate_session_scope
from clawsentry.gateway.tool_permissions import (
    parse_tool_permission_group_overrides,
    resolve_tool_permission,
)


def test_tool_permission_unknown_denied_in_critical():
    decision = resolve_tool_permission("new_host_tool", session_state="critical")

    assert decision.group == "unknown"
    assert decision.action == "deny"
    assert decision.source == "default_unknown"


def test_tool_permission_override_uses_most_restrictive_group():
    parsed = parse_tool_permission_group_overrides(
        "publish_site=network,credentialed; local_notes=read_only"
    )

    assert parsed.findings == []
    decision = resolve_tool_permission(
        "publish_site",
        session_state="critical",
        overrides=parsed.overrides,
    )
    assert decision.groups == ("network", "credentialed")
    assert decision.group == "credentialed"
    assert decision.action == "deny"
    assert decision.source == "override"


def test_tool_permission_default_mcp_identity_mapping_uses_specific_group():
    write_decision = resolve_tool_permission("mcp__filesystem__write_file", session_state="critical")
    admin_decision = resolve_tool_permission("mcp__notion__update_data_source", session_state="critical")
    read_decision = resolve_tool_permission("filesystem.read_file", session_state="critical")

    assert write_decision.group == "write"
    assert write_decision.source == "default_mcp"
    assert write_decision.action == "deny"
    assert admin_decision.group == "mcp_admin"
    assert admin_decision.source == "default_mcp"
    assert read_decision.group == "read_only"
    assert read_decision.source == "default_mcp"


def test_tool_permission_exact_override_wins_over_default_mcp_mapping():
    decision = resolve_tool_permission(
        "mcp__filesystem__write_file",
        session_state="critical",
        overrides={"mcp__filesystem__write_file": ("read_only",)},
    )

    assert decision.group == "read_only"
    assert decision.source == "override"
    assert decision.action == "allow"


def test_invalid_tool_permission_override_becomes_config_finding():
    parsed = parse_tool_permission_group_overrides(
        "publish_site=network,root_access; =read_only; broken"
    )

    assert parsed.overrides == {}
    assert [finding["code"] for finding in parsed.findings] == [
        "invalid_tool_permission_group",
        "missing_tool_permission_tool",
        "invalid_tool_permission_entry",
    ]


def test_session_scope_consumes_context_tool_permission_overrides():
    profile = SessionScopeProfile(
        profile_id="custom-read-scope",
        confirmed=True,
        dry_run=False,
        base_rules={},
        task_rules={"allowed_tool_permission_groups": ["read_only"]},
    )
    event = CanonicalEvent(
        event_id="evt-custom-read",
        trace_id="trace-custom-read",
        event_type=EventType.PRE_ACTION,
        session_id="sess-custom-read",
        agent_id="agent-custom-read",
        source_framework="codex",
        occurred_at="2026-05-19T00:00:00+00:00",
        tool_name="custom_notes_reader",
        payload={},
    )
    context = DecisionContext(
        session_scope_profile=profile,
        tool_permission_group_overrides={"custom_notes_reader": ["read_only"]},
    )

    evaluation = evaluate_session_scope(event, context)

    assert evaluation is not None
    summary = evaluation.summary()
    assert summary.verdict.value == "allow"
    assert "scope_allow:tool_permission_group read_only" in summary.reason_codes


def test_scope_preview_reports_tool_groups(tmp_path, capsys):
    profile_path = tmp_path / "scope.json"
    profile_path.write_text(
        json.dumps(
            {
                "profile_id": "critical-preview",
                "confirmed": True,
                "dry_run": False,
                "base_rules": {},
                "task_rules": {},
            }
        ),
        encoding="utf-8",
    )
    event_path = tmp_path / "event.json"
    event_path.write_text(
        json.dumps(
            {
                "event_id": "evt-preview",
                "trace_id": "trace-preview",
                "event_type": "pre_action",
                "session_id": "sess-preview",
                "agent_id": "agent-preview",
                "source_framework": "codex",
                "occurred_at": "2026-05-19T00:00:00+00:00",
                "tool_name": "write_file",
                "payload": {"path": "/workspace/out.txt"},
            }
        ),
        encoding="utf-8",
    )

    exit_code = run_scope_preview(
        profile_path=profile_path,
        event_path=event_path,
        confirm=True,
        json_mode=True,
    )

    payload = json.loads(capsys.readouterr().out)
    assert exit_code == 0
    assert payload["tool_permission"]["group"] == "write"
    assert payload["tool_permission"]["action"] == "deny"
