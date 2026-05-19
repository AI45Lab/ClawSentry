"""Env-first configuration resolver tests."""

from __future__ import annotations

from clawsentry.cli.dotenv_loader import parse_env_file, resolve_explicit_env_file
from clawsentry.gateway.env_config import (
    config_to_child_env,
    parse_enabled_frameworks,
    resolve_effective_config,
)


def _repo_root():
    from pathlib import Path

    return Path(__file__).resolve().parents[3]


def test_skill_trust_docs_include_operator_examples():
    text = (_repo_root() / "site-docs" / "advanced" / "skill-trust.md").read_text(
        encoding="utf-8"
    )

    required_phrases = [
        "artifact provenance validation is generic and post-action",
        "FSPR evidence-only",
        "cannot mutate allowlist, greylist, blacklist, revoked, disabled, or restore",
        "verified mirror example",
        "disallowed same-name path example",
        "ambiguous name-only example",
        "final provenance mismatch example",
        "blacklist-to-greylist override example",
        "revoked-to-allowlist trusted migration example",
        "disabled/restore example",
        "critical capability narrowing example",
        "unsupported-host feedback fallback example",
    ]

    missing = [phrase for phrase in required_phrases if phrase not in text]
    assert missing == []


def test_env_file_selector_cli_wins_over_env_var(tmp_path):
    env_selected = tmp_path / "env-selected.env"
    cli_selected = tmp_path / "cli-selected.env"
    env_selected.write_text("CS_MODE=strict\n", encoding="utf-8")
    cli_selected.write_text("CS_MODE=benchmark\n", encoding="utf-8")

    parsed = resolve_explicit_env_file(
        cli_env_file=cli_selected,
        environ={"CLAWSENTRY_ENV_FILE": str(env_selected)},
    )

    assert parsed.path == cli_selected
    assert parsed.values["CS_MODE"] == "benchmark"


def test_resolver_precedence_cli_process_env_env_file_defaults(tmp_path):
    env_file = tmp_path / "local.env"
    env_file.write_text(
        "CS_MODE=benchmark\nCS_LLM_PROVIDER=env-file\nCS_LLM_MODEL=env-file-model\n",
        encoding="utf-8",
    )
    parsed = parse_env_file(env_file)

    effective = resolve_effective_config(
        environ={"CS_LLM_PROVIDER": "process"},
        env_file=parsed,
        cli_overrides={"project.mode": "strict"},
    )

    assert effective.values["project.mode"] == "strict"
    assert effective.sources["project.mode"] == "cli"
    assert effective.values["llm.provider"] == "process"
    assert effective.sources["llm.provider"] == "process-env"
    assert effective.values["llm.model"] == "env-file-model"
    assert effective.sources["llm.model"] == "env-file"
    assert effective.values["project.preset"] == "medium"
    assert effective.sources["project.preset"] == "default"


def test_secret_redaction_preserves_source_detail(tmp_path):
    env_file = tmp_path / "local.env"
    env_file.write_text("CS_LLM_PROVIDER=openai\nCS_LLM_API_KEY" + "=sk-test-secret-value\n", encoding="utf-8")
    parsed = parse_env_file(env_file)

    effective = resolve_effective_config(environ={}, env_file=parsed)

    assert effective.values["llm.api_key"] != "sk-test-secret-value"
    assert effective.values["llm.api_key"].startswith("sk-t")
    assert effective.sources["llm.api_key"] == "env-file"
    assert effective.source_detail_for("llm.api_key") == f"{env_file}:2"


def test_capability_narrowing_and_agent_feedback_are_visible_config_fields(tmp_path):
    env_file = tmp_path / "local.env"
    env_file.write_text(
        "CS_CAPABILITY_NARROWING_ENABLED=true\n"
        "CS_CAPABILITY_NARROWING_TRIGGER_RISK=critical\n"
        "CS_CAPABILITY_NARROWING_ALLOWED_TOOL_PERMISSION_GROUPS=read_only,write\n"
        "CS_CAPABILITY_NARROWING_DENIED_TOOL_PERMISSION_GROUPS=network,credentialed,destructive\n"
        "CS_CAPABILITY_NARROWING_ALLOWED_SKILL_TRUST_STATES=allowlist,greylist\n"
        "CS_CAPABILITY_NARROWING_DENIED_SKILL_TRUST_STATES=blacklist,revoked\n"
        "CS_CAPABILITY_NARROWING_ALLOWED_MCP_SERVERS=filesystem,fetch\n"
        "CS_CAPABILITY_NARROWING_DENIED_MCP_SERVERS=evil\n"
        "CS_CAPABILITY_NARROWING_ALLOWED_MCP_TOOLS=filesystem.read_file,fetch.fetch\n"
        "CS_CAPABILITY_NARROWING_DENIED_MCP_TOOLS=fetch.fetch\n"
        "CS_CAPABILITY_NARROWING_ALLOWED_MCP_STATUSES=allowlist,greylist\n"
        "CS_CAPABILITY_NARROWING_DENIED_MCP_STATUSES=blacklist,revoked\n"
        "CS_CAPABILITY_NARROWING_ALLOWED_MCP_TRUST_LEVELS=trusted,local_unreviewed\n"
        "CS_CAPABILITY_NARROWING_DENIED_MCP_TRUST_LEVELS=untrusted\n"
        "CS_CAPABILITY_NARROWING_ALLOWED_CAPABILITIES=filesystem.write\n"
        "CS_CAPABILITY_NARROWING_DENIED_CAPABILITIES=future_execution.entrypoint\n"
        "CS_CAPABILITY_NARROWING_QUEUED_CAPABILITIES=network.fetch\n"
        "CS_CAPABILITY_NARROWING_AUDIT_VERBOSITY=verbose\n"
        "CS_CAPABILITY_NARROWING_GREYLIST_ACTION=block\n"
        "CS_AGENT_SAFETY_FEEDBACK_ENABLED=true\n",
        encoding="utf-8",
    )
    parsed = parse_env_file(env_file)

    effective = resolve_effective_config(environ={}, env_file=parsed)

    assert effective.values["features.capability_narrowing"] is True
    assert effective.sources["features.capability_narrowing"] == "env-file"
    assert effective.source_detail_for("features.capability_narrowing") == f"{env_file}:1"
    assert effective.values["capability_narrowing.trigger_risk"] == "critical"
    assert effective.values["capability_narrowing.allowed_tool_permission_groups"] == "read_only,write"
    assert effective.values["capability_narrowing.denied_tool_permission_groups"] == "network,credentialed,destructive"
    assert effective.values["capability_narrowing.allowed_skill_trust_states"] == "allowlist,greylist"
    assert effective.values["capability_narrowing.denied_skill_trust_states"] == "blacklist,revoked"
    assert effective.values["capability_narrowing.allowed_mcp_servers"] == "filesystem,fetch"
    assert effective.values["capability_narrowing.denied_mcp_servers"] == "evil"
    assert effective.values["capability_narrowing.allowed_mcp_tools"] == "filesystem.read_file,fetch.fetch"
    assert effective.values["capability_narrowing.denied_mcp_tools"] == "fetch.fetch"
    assert effective.values["capability_narrowing.allowed_mcp_statuses"] == "allowlist,greylist"
    assert effective.values["capability_narrowing.denied_mcp_statuses"] == "blacklist,revoked"
    assert effective.values["capability_narrowing.allowed_mcp_trust_levels"] == "trusted,local_unreviewed"
    assert effective.values["capability_narrowing.denied_mcp_trust_levels"] == "untrusted"
    assert effective.values["capability_narrowing.allowed_capabilities"] == "filesystem.write"
    assert effective.values["capability_narrowing.denied_capabilities"] == "future_execution.entrypoint"
    assert effective.values["capability_narrowing.queued_capabilities"] == "network.fetch"
    assert effective.values["capability_narrowing.audit_verbosity"] == "verbose"
    assert effective.values["capability_narrowing.greylist_action"] == "block"
    assert effective.values["features.agent_safety_feedback"] is True
    assert effective.sources["features.agent_safety_feedback"] == "env-file"
    assert effective.source_detail_for("features.agent_safety_feedback") == f"{env_file}:20"


def test_tool_permission_group_override_config_reports_invalid_groups(tmp_path):
    env_file = tmp_path / "local.env"
    env_file.write_text(
        "CS_TOOL_PERMISSION_GROUP_OVERRIDES=custom_read=read_only;publish=root_access\n",
        encoding="utf-8",
    )
    parsed = parse_env_file(env_file)

    effective = resolve_effective_config(environ={}, env_file=parsed)

    assert effective.values["tool_permissions.group_overrides"] == (
        "custom_read=read_only;publish=root_access"
    )
    assert effective.sources["tool_permissions.group_overrides"] == "env-file"
    assert any("invalid_tool_permission_group" in warning for warning in effective.warnings)


def test_capability_narrowing_config_reports_invalid_values(tmp_path):
    env_file = tmp_path / "local.env"
    env_file.write_text(
        "CS_CAPABILITY_NARROWING_TRIGGER_RISK=severe\n"
        "CS_CAPABILITY_NARROWING_ALLOWED_TOOL_PERMISSION_GROUPS=read_only,root_access\n"
        "CS_CAPABILITY_NARROWING_DENIED_TOOL_PERMISSION_GROUPS=kernel\n"
        "CS_CAPABILITY_NARROWING_ALLOWED_SKILL_TRUST_STATES=allowlist,root\n"
        "CS_CAPABILITY_NARROWING_DENIED_SKILL_TRUST_STATES=kernel\n"
        "CS_CAPABILITY_NARROWING_ALLOWED_MCP_STATUSES=allowlist,root\n"
        "CS_CAPABILITY_NARROWING_DENIED_MCP_STATUSES=kernel\n"
        "CS_CAPABILITY_NARROWING_ALLOWED_MCP_TRUST_LEVELS=trusted,root\n"
        "CS_CAPABILITY_NARROWING_DENIED_MCP_TRUST_LEVELS=kernel\n"
        "CS_CAPABILITY_NARROWING_AUDIT_VERBOSITY=noisy\n"
        "CS_CAPABILITY_NARROWING_GREYLIST_ACTION=escalate\n",
        encoding="utf-8",
    )
    parsed = parse_env_file(env_file)

    effective = resolve_effective_config(environ={}, env_file=parsed)

    assert effective.values["capability_narrowing.trigger_risk"] == "high"
    assert effective.values["capability_narrowing.allowed_tool_permission_groups"] == "read_only"
    assert effective.values["capability_narrowing.denied_tool_permission_groups"] == (
        "write,network,credentialed,destructive,mcp_admin,unknown"
    )
    assert effective.values["capability_narrowing.allowed_skill_trust_states"] == "allowlist"
    assert effective.values["capability_narrowing.denied_skill_trust_states"] == "blacklist,revoked"
    assert effective.values["capability_narrowing.allowed_mcp_statuses"] == "allowlist"
    assert effective.values["capability_narrowing.denied_mcp_statuses"] == "blacklist,revoked,disabled"
    assert effective.values["capability_narrowing.allowed_mcp_trust_levels"] == "trusted"
    assert effective.values["capability_narrowing.denied_mcp_trust_levels"] == "untrusted,unknown,local_unreviewed"
    assert effective.values["capability_narrowing.audit_verbosity"] == "summary"
    assert effective.values["capability_narrowing.greylist_action"] == "defer"
    assert any("capability_narrowing.trigger_risk invalid" in warning for warning in effective.warnings)
    assert any("capability_narrowing.allowed_tool_permission_groups invalid" in warning for warning in effective.warnings)
    assert any("capability_narrowing.denied_tool_permission_groups invalid" in warning for warning in effective.warnings)
    assert any("capability_narrowing.allowed_skill_trust_states invalid" in warning for warning in effective.warnings)
    assert any("capability_narrowing.denied_skill_trust_states invalid" in warning for warning in effective.warnings)
    assert any("capability_narrowing.allowed_mcp_statuses invalid" in warning for warning in effective.warnings)
    assert any("capability_narrowing.denied_mcp_statuses invalid" in warning for warning in effective.warnings)
    assert any("capability_narrowing.allowed_mcp_trust_levels invalid" in warning for warning in effective.warnings)
    assert any("capability_narrowing.denied_mcp_trust_levels invalid" in warning for warning in effective.warnings)
    assert any("capability_narrowing.audit_verbosity invalid" in warning for warning in effective.warnings)
    assert any("capability_narrowing.greylist_action invalid" in warning for warning in effective.warnings)


def test_skill_trust_control_plane_inputs_are_visible_config_fields(tmp_path):
    env_file = tmp_path / "local.env"
    env_file.write_text(
        "CS_SKILL_TRUST_REGISTRY_PATH=/tmp/registry.json\n"
        "CS_SKILL_TRUST_METADATA_PATH=/tmp/metadata.json\n"
        "CS_SKILL_TRUST_FIRST_USE_STRICT_ACTION=block\n",
        encoding="utf-8",
    )
    parsed = parse_env_file(env_file)

    effective = resolve_effective_config(environ={}, env_file=parsed)

    assert effective.values["skill_trust.registry_path"] == "/tmp/registry.json"
    assert effective.values["skill_trust.metadata_path"] == "/tmp/metadata.json"
    assert effective.values["skill_trust.first_use_strict_action"] == "block"
    assert effective.source_detail_for("skill_trust.metadata_path") == f"{env_file}:2"


def test_provenance_validator_inputs_are_visible_config_fields(tmp_path):
    env_file = tmp_path / "local.env"
    env_file.write_text(
        "CS_SKILL_TRUST_PROVENANCE_ENABLED=true\n"
        "CS_SKILL_TRUST_PROVENANCE_POLICY_PATH=/tmp/provenance.json\n"
        "CS_SKILL_TRUST_PROVENANCE_MAX_ARTIFACT_BYTES=4096\n"
        "CS_SKILL_TRUST_PROVENANCE_WORKSPACE_ROOT=/tmp/provenance-workspace\n",
        encoding="utf-8",
    )
    parsed = parse_env_file(env_file)

    effective = resolve_effective_config(environ={}, env_file=parsed)

    assert effective.values["skill_trust.provenance_enabled"] is True
    assert effective.values["skill_trust.provenance_policy_path"] == "/tmp/provenance.json"
    assert effective.values["skill_trust.provenance_max_artifact_bytes"] == 4096
    assert effective.values["skill_trust.provenance_workspace_root"] == "/tmp/provenance-workspace"


def test_skill_trust_config_docs_include_runtime_binding_fields():
    source = (_repo_root() / "site-docs" / "advanced" / "skill-trust.md").read_text(
        encoding="utf-8"
    )

    for term in [
        "runtime_path_status",
        "runtime_root_path_hash",
        "runtime_content_status",
        "metadata_record_id",
        "verified_source",
        "verified_mirror",
        "ambiguous_runtime_source",
        "path_fragment_unverified",
        "CS_SKILL_TRUST_RUNTIME_NORMAL_ACTION",
        "CS_SKILL_TRUST_RUNTIME_BENCHMARK_ACTION",
        "CS_SKILL_TRUST_MIRROR_HASH_MAX_FILES",
        "CS_SKILL_TRUST_MIRROR_HASH_MAX_FILE_BYTES",
        "CS_SKILL_TRUST_MIRROR_HASH_MAX_TOTAL_MS",
        "CS_SKILL_TRUST_FSPR_ENABLED",
        "CS_SKILL_TRUST_FSPR_TIMEOUT_MS",
    ]:
        assert term in source


def test_runtime_binding_actions_are_visible_config_fields():
    effective = resolve_effective_config(
        environ={
            "CS_SKILL_TRUST_RUNTIME_NORMAL_ACTION": "defer",
            "CS_SKILL_TRUST_RUNTIME_BENCHMARK_ACTION": "block",
            "CS_SKILL_TRUST_RUNTIME_STRICT_ACTION": "block",
            "CS_SKILL_TRUST_RUNTIME_PERMISSIVE_ACTION": "audit",
            "CS_SKILL_TRUST_RUNTIME_PATH_DISALLOWED_NORMAL_ACTION": "defer",
            "CS_SKILL_TRUST_RUNTIME_CONTENT_MISMATCH_NORMAL_ACTION": "block",
            "CS_SKILL_TRUST_MIRROR_HASH_MAX_FILES": "12",
            "CS_SKILL_TRUST_MIRROR_HASH_MAX_FILE_BYTES": "2048",
            "CS_SKILL_TRUST_MIRROR_HASH_MAX_TOTAL_MS": "75",
        },
    )

    assert effective.values["skill_trust.runtime_normal_action"] == "defer"
    assert effective.values["skill_trust.runtime_benchmark_action"] == "block"
    assert effective.values["skill_trust.runtime_strict_action"] == "block"
    assert effective.values["skill_trust.runtime_permissive_action"] == "audit"
    assert effective.values["skill_trust.runtime_path_disallowed_normal_action"] == "defer"
    assert effective.values["skill_trust.runtime_content_mismatch_normal_action"] == "block"
    assert effective.values["skill_trust.mirror_hash_max_files"] == 12
    assert effective.values["skill_trust.mirror_hash_max_file_bytes"] == 2048
    assert effective.values["skill_trust.mirror_hash_max_total_ms"] == 75


def test_fspr_settings_are_visible_config_fields():
    effective = resolve_effective_config(
        environ={
            "CS_SKILL_TRUST_FSPR_ENABLED": "true",
            "CS_SKILL_TRUST_FSPR_PRE_USE_ENABLED": "true",
            "CS_SKILL_TRUST_FSPR_POST_ACTION_ENABLED": "true",
            "CS_SKILL_TRUST_FSPR_ROLE_SET": "identity-only",
            "CS_SKILL_TRUST_FSPR_TIMEOUT_MS": "2500",
            "CS_SKILL_TRUST_FSPR_CACHE_ENABLED": "false",
            "CS_SKILL_TRUST_FSPR_PROVIDER_ENABLED": "true",
            "CS_SKILL_TRUST_FSPR_STRICT_ACTION": "block",
            "CS_SKILL_TRUST_FSPR_INCONSISTENT_STRICT_ACTION": "defer",
            "CS_SKILL_TRUST_FSPR_SUSPICIOUS_NORMAL_ACTION": "force_l2",
            "CS_SKILL_TRUST_FSPR_INSUFFICIENT_EVIDENCE_BENCHMARK_ACTION": "block",
        },
    )

    assert effective.values["skill_trust.fspr_enabled"] is True
    assert effective.values["skill_trust.fspr_pre_use_enabled"] is True
    assert effective.values["skill_trust.fspr_post_action_enabled"] is True
    assert effective.values["skill_trust.fspr_role_set"] == "identity-only"
    assert effective.values["skill_trust.fspr_timeout_ms"] == 2500
    assert effective.values["skill_trust.fspr_cache_enabled"] is False
    assert effective.values["skill_trust.fspr_provider_enabled"] is True
    assert effective.values["skill_trust.fspr_strict_action"] == "block"
    assert effective.values["skill_trust.fspr_inconsistent_strict_action"] == "defer"
    assert effective.values["skill_trust.fspr_suspicious_normal_action"] == "force_l2"
    assert effective.values["skill_trust.fspr_insufficient_evidence_benchmark_action"] == "block"


def test_scope_profile_file_deprecated_alias_resolves_from_process_env():
    effective = resolve_effective_config(
        environ={"CS_SESSION_SCOPE_PROFILE": "scope.json"},
    )

    assert effective.values["scope.profile_file"] == "scope.json"
    assert effective.sources["scope.profile_file"] == "deprecated-env-alias"
    assert "Deprecated CS_SESSION_SCOPE_PROFILE" in "\n".join(effective.warnings)


def test_scope_profile_file_deprecated_alias_resolves_from_env_file(tmp_path):
    env_file = tmp_path / "local.env"
    env_file.write_text("CS_SESSION_SCOPE_PROFILE=scope-from-file.json\n", encoding="utf-8")
    parsed = parse_env_file(env_file)

    effective = resolve_effective_config(environ={}, env_file=parsed)

    assert effective.values["scope.profile_file"] == "scope-from-file.json"
    assert effective.sources["scope.profile_file"] == "deprecated-env-file-alias"
    assert effective.source_detail_for("scope.profile_file") == f"{env_file}:1"


def test_frameworks_parse_from_env_without_toml(tmp_path):
    legacy_toml = tmp_path / (".clawsentry" + ".toml")
    legacy_toml.write_text('[frameworks]\nenabled = ["openclaw"]\n', encoding="utf-8")

    frameworks, default = parse_enabled_frameworks(
        {"CS_ENABLED_FRAMEWORKS": "a3s-code,codex", "CS_FRAMEWORK": "codex"}
    )

    assert frameworks == ["a3s-code", "codex"]
    assert default == "codex"


def test_child_env_layers_env_file_process_then_cli(tmp_path):
    env_file = tmp_path / "local.env"
    env_file.write_text("CS_MODE=benchmark\nCS_AUTH_TOKEN" + "=file-token\n", encoding="utf-8")
    parsed = parse_env_file(env_file)

    child = config_to_child_env(
        environ={"CS_AUTH_TOKEN": "process-token"},
        env_file=parsed,
        cli_overrides={"project.mode": "strict"},
    )

    assert child["CS_MODE"] == "strict"
    assert child["CS_AUTH_TOKEN"] == "process-token"
