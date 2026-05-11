"""Tests for env-first clawsentry start command."""

from __future__ import annotations

import json
import os
import tomllib
from unittest.mock import MagicMock, patch

import pytest

from clawsentry.cli.start_command import (
    detect_framework,
    ensure_init,
    ensure_integrations,
    run_start,
)


@pytest.fixture(autouse=True)
def _isolate_start_command_tests(tmp_path, monkeypatch):
    with patch.dict(os.environ, {}, clear=False):
        monkeypatch.chdir(tmp_path)
        for key in (
            "CS_AUTH_TOKEN",
            "CS_FRAMEWORK",
            "CS_ENABLED_FRAMEWORKS",
            "CS_CODEX_WATCH_ENABLED",
            "CS_CODEX_SESSION_DIR",
            "CODEX_HOME",
            "CS_GEMINI_HOOKS_ENABLED",
            "CS_GEMINI_SETTINGS_PATH",
            "CS_KIMI_HOOKS_ENABLED",
            "CS_KIMI_CONFIG_PATH",
            "KIMI_SHARE_DIR",
            "CLAWSENTRY_ENV_FILE",
        ):
            monkeypatch.delenv(key, raising=False)
        monkeypatch.setenv("CODEX_HOME", str(tmp_path / ".codex"))
        yield


class TestDetectFramework:
    def test_env_framework_takes_priority_over_project_file(self, tmp_path, monkeypatch):
        (tmp_path / (".clawsentry" + ".toml")).write_text('[frameworks]\nenabled=["openclaw"]\n')
        monkeypatch.chdir(tmp_path)
        monkeypatch.setenv("CS_FRAMEWORK", "codex")
        assert detect_framework() == "codex"

    def test_enabled_frameworks_ignores_unknown_entries(self, monkeypatch):
        monkeypatch.setenv("CS_ENABLED_FRAMEWORKS", "unknown,codex")
        assert detect_framework() == "codex"

    def test_returns_none_when_nothing_explicit_found(self, tmp_path):
        assert detect_framework(openclaw_home=tmp_path / "nope", a3s_dir=tmp_path / "nope2") is None

    def test_detects_a3s_code_project_marker(self, tmp_path):
        a3s_dir = tmp_path / ".a3s-code"
        a3s_dir.mkdir()
        (a3s_dir / "settings.json").write_text("{}")
        assert detect_framework(a3s_dir=a3s_dir) == "a3s-code"

    def test_detects_codex_from_explicit_env_and_sessions_dir(self, tmp_path, monkeypatch):
        codex_home = tmp_path / ".codex"
        (codex_home / "sessions").mkdir(parents=True)
        monkeypatch.setenv("CS_CODEX_WATCH_ENABLED", "true")
        assert detect_framework(codex_home=codex_home) == "codex"

    def test_detects_kimi_cli_from_explicit_env_and_config_path(self, tmp_path, monkeypatch):
        config_path = tmp_path / ".kimi" / "config.toml"
        config_path.parent.mkdir()
        config_path.write_text("[[hooks]]\n")
        monkeypatch.setenv("CS_KIMI_HOOKS_ENABLED", "true")
        monkeypatch.setenv("CS_KIMI_CONFIG_PATH", str(config_path))
        assert detect_framework() == "kimi-cli"

    def test_detects_gemini_cli_from_explicit_env_and_project_settings(self, tmp_path, monkeypatch):
        settings_path = tmp_path / ".gemini" / "settings.json"
        settings_path.parent.mkdir()
        settings_path.write_text("{}")
        monkeypatch.setenv("CS_GEMINI_HOOKS_ENABLED", "true")
        assert detect_framework() == "gemini-cli"


class TestNoProjectConfigAutoInit:
    def test_ensure_init_is_no_side_effect_env_first(self, tmp_path):
        assert ensure_init(framework="openclaw", target_dir=tmp_path) is False
        assert not (tmp_path / (".clawsentry" + ".toml")).exists()

    def test_ensure_integrations_is_no_side_effect_env_first(self, tmp_path):
        initialized = ensure_integrations(frameworks=["a3s-code", "codex"], target_dir=tmp_path)
        assert initialized == []
        assert not (tmp_path / (".clawsentry" + ".toml")).exists()


class TestRunStart:
    def test_start_uses_explicit_env_file_and_cli_framework_without_project_file(self, tmp_path, capsys):
        env_file = tmp_path / ".clawsentry.env.local"
        env_file.write_text("CS_AUTH_TOKEN" + "=file-token\nCS_LLM_PROVIDER=openai\nCS_LLM_MODEL=example-model\n")
        proc = MagicMock()
        proc.pid = 12345
        proc.poll.return_value = None
        with (
            patch("clawsentry.cli.start_command.launch_gateway", return_value=proc) as launch,
            patch("clawsentry.cli.start_command.wait_for_health", return_value=True),
        ):
            run_start(framework="codex", target_dir=tmp_path, no_watch=True, env_file=env_file)

        out = capsys.readouterr().out
        assert "Framework:  codex" in out
        assert "Auth token: explicit env-file" in out
        assert "clawsentry watch --token file-token" in out
        assert not (tmp_path / (".clawsentry" + ".toml")).exists()
        child_env = launch.call_args.kwargs["extra_env"]
        assert child_env["CS_AUTH_TOKEN"] == "file-token"
        assert child_env["CS_FRAMEWORK"] == "codex"
        assert child_env["CS_ENABLED_FRAMEWORKS"] == "codex"

    def test_start_codex_installs_native_hooks_by_default(self, tmp_path, monkeypatch, capsys):
        codex_home = tmp_path / ".codex"
        monkeypatch.setenv("CODEX_HOME", str(codex_home))
        proc = MagicMock()
        proc.pid = 12345
        proc.poll.return_value = None
        with (
            patch("clawsentry.cli.start_command.launch_gateway", return_value=proc),
            patch("clawsentry.cli.start_command.wait_for_health", return_value=True),
        ):
            run_start(framework="codex", target_dir=tmp_path, no_watch=True)

        out = capsys.readouterr().out
        hooks = json.loads((codex_home / "hooks.json").read_text(encoding="utf-8"))
        config = tomllib.loads((codex_home / "config.toml").read_text(encoding="utf-8"))
        assert "clawsentry harness --framework codex" in str(hooks)
        assert len(config["hooks"]["state"]) == 11
        assert (codex_home / "sessions").is_dir()
        assert "Codex hooks: installed" in out
        assert "clawsentry init codex --uninstall" in out
        assert "codex: ready" in out

    def test_start_multiple_frameworks_installs_codex_hooks_by_default(self, tmp_path, monkeypatch):
        codex_home = tmp_path / ".codex"
        monkeypatch.setenv("CODEX_HOME", str(codex_home))
        proc = MagicMock()
        proc.pid = 12345
        proc.poll.return_value = None
        with (
            patch("clawsentry.cli.start_command.launch_gateway", return_value=proc) as launch,
            patch("clawsentry.cli.start_command.wait_for_health", return_value=True),
        ):
            run_start(
                framework="a3s-code",
                enabled_frameworks=["a3s-code", "codex"],
                target_dir=tmp_path,
                no_watch=True,
            )

        assert (codex_home / "hooks.json").exists()
        assert "clawsentry harness --framework codex" in (codex_home / "hooks.json").read_text(encoding="utf-8")
        assert launch.call_args.kwargs["extra_env"]["CS_CODEX_WATCH_ENABLED"] == "true"

    def test_start_non_codex_does_not_install_codex_hooks(self, tmp_path, monkeypatch):
        codex_home = tmp_path / ".codex"
        monkeypatch.setenv("CODEX_HOME", str(codex_home))
        proc = MagicMock()
        proc.pid = 12345
        proc.poll.return_value = None
        with (
            patch("clawsentry.cli.start_command.launch_gateway", return_value=proc),
            patch("clawsentry.cli.start_command.wait_for_health", return_value=True),
        ):
            run_start(framework="a3s-code", target_dir=tmp_path, no_watch=True)

        assert not codex_home.exists()

    def test_start_frameworks_cli_sets_multiple_frameworks(self, tmp_path):
        proc = MagicMock()
        proc.pid = 12345
        proc.poll.return_value = None
        with (
            patch("clawsentry.cli.start_command.launch_gateway", return_value=proc) as launch,
            patch("clawsentry.cli.start_command.wait_for_health", return_value=True),
        ):
            run_start(framework="a3s-code", enabled_frameworks=["a3s-code", "codex"], target_dir=tmp_path, no_watch=True)
        child_env = launch.call_args.kwargs["extra_env"]
        assert child_env["CS_ENABLED_FRAMEWORKS"] == "a3s-code,codex"
        assert not (tmp_path / (".clawsentry" + ".toml")).exists()

    def test_start_warns_about_unloaded_local_env_file_without_loading_it(self, tmp_path, capsys):
        (tmp_path / ".clawsentry.env.local").write_text("CS_AUTH_TOKEN=file-token\n")
        proc = MagicMock()
        proc.pid = 12345
        proc.poll.return_value = None
        with (
            patch("clawsentry.cli.start_command.launch_gateway", return_value=proc) as launch,
            patch("clawsentry.cli.start_command.wait_for_health", return_value=True),
        ):
            run_start(framework="codex", target_dir=tmp_path, no_watch=True)

        out = capsys.readouterr().out
        assert "Env-file hint: no env file was loaded automatically." in out
        assert "clawsentry start --framework codex --env-file .clawsentry.env.local" in out
        child_env = launch.call_args.kwargs["extra_env"]
        assert child_env["CS_AUTH_TOKEN"] != "file-token"

    def test_start_explains_template_must_be_copied_to_local_env(self, tmp_path, capsys):
        (tmp_path / ".clawsentry.env.example").write_text("CS_FRAMEWORK=codex\n")
        proc = MagicMock()
        proc.pid = 12345
        proc.poll.return_value = None
        with (
            patch("clawsentry.cli.start_command.launch_gateway", return_value=proc),
            patch("clawsentry.cli.start_command.wait_for_health", return_value=True),
        ):
            run_start(framework="codex", target_dir=tmp_path, no_watch=True)

        out = capsys.readouterr().out
        assert ".clawsentry.env.example; it is a commit-safe template, not a runtime input" in out
        assert "Copy it to .clawsentry.env.local" in out
