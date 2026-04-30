"""Tests for explicit, non-mutating ClawSentry env-file handling."""

import os

import pytest

from clawsentry.cli.dotenv_loader import (
    EnvFileError,
    discover_local_env_files,
    format_env_file_hint,
    load_dotenv,
    overlay_env_file,
    parse_env_file,
    resolve_explicit_env_file,
)


def test_parse_env_file_returns_isolated_map(tmp_path, monkeypatch):
    env_file = tmp_path / ".clawsentry.env.local"
    env_file.write_text("# comment\nCS_AUTH_TOKEN" + "=from-file\nQUOTED='hello world'\n")
    monkeypatch.delenv("CS_AUTH_TOKEN", raising=False)

    parsed = parse_env_file(env_file)

    assert parsed.values == {"CS_AUTH_TOKEN": "from-file", "QUOTED": "hello world"}
    assert parsed.source_detail_for("CS_AUTH_TOKEN") == f"{env_file}:2"
    assert "CS_AUTH_TOKEN" not in os.environ


def test_no_global_cli_dotenv_autoload(tmp_path, monkeypatch):
    (tmp_path / ".env.clawsentry").write_text("CS_LLM_PROVIDER=from-dotenv\n")
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("CS_LLM_PROVIDER", raising=False)

    assert load_dotenv() == 0
    assert "CS_LLM_PROVIDER" not in os.environ


def test_no_default_cwd_env_autoload(tmp_path, monkeypatch):
    (tmp_path / ".env.clawsentry").write_text("CS_LLM_PROVIDER=from-dotenv\n")
    monkeypatch.chdir(tmp_path)

    parsed = resolve_explicit_env_file(environ={})

    assert parsed.path is None
    assert parsed.values == {}


def test_explicit_env_file_loads(tmp_path):
    env_file = tmp_path / ".clawsentry.env.local"
    env_file.write_text("CS_LLM_PROVIDER=openai\n")

    parsed = resolve_explicit_env_file(cli_env_file=env_file, environ={})

    assert parsed.values["CS_LLM_PROVIDER"] == "openai"
    assert parsed.source_detail_for("CS_LLM_PROVIDER") == f"{env_file}:1"


def test_env_file_does_not_override_process_env(tmp_path):
    env_file = tmp_path / ".clawsentry.env.local"
    env_file.write_text("CS_AUTH_TOKEN" + "=from-file\n")
    parsed = parse_env_file(env_file)

    merged = overlay_env_file({"CS_AUTH_TOKEN": "from-process"}, parsed)

    assert merged["CS_AUTH_TOKEN"] == "from-process"


def test_missing_explicit_env_file_errors(tmp_path):
    with pytest.raises(EnvFileError, match="Explicit env file not found"):
        parse_env_file(tmp_path / "missing.env")


def test_legacy_env_filename_only_when_explicit(tmp_path):
    env_file = tmp_path / ".env.clawsentry"
    env_file.write_text("CS_AUTH_TOKEN" + "=legacy-token\n")

    parsed = resolve_explicit_env_file(cli_env_file=env_file, environ={})

    assert parsed.values["CS_AUTH_TOKEN"] == "legacy-token"
    assert any(".env.clawsentry is a legacy name" in warning for warning in parsed.warnings)


def test_local_env_discovery_is_hint_only(tmp_path):
    local = tmp_path / ".clawsentry.env.local"
    template = tmp_path / ".clawsentry.env.example"
    local.write_text("CS_AUTH_TOKEN=local-token\n")
    template.write_text("CS_FRAMEWORK=codex\n")

    discovery = discover_local_env_files(tmp_path)
    hint = "\n".join(format_env_file_hint(discovery, command="clawsentry start"))

    assert discovery.local == local
    assert discovery.template == template
    assert "no env file was loaded automatically" in hint
    assert "clawsentry start --env-file .clawsentry.env.local" in hint
