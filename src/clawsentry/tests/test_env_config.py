"""Env-first configuration resolver tests."""

from __future__ import annotations

from clawsentry.cli.dotenv_loader import parse_env_file, resolve_explicit_env_file
from clawsentry.gateway.env_config import (
    config_to_child_env,
    parse_enabled_frameworks,
    resolve_effective_config,
)


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
