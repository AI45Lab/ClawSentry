"""Tests for env-first clawsentry config CLI commands."""

from __future__ import annotations

import pytest

from clawsentry.cli.config_command import (
    run_config_init,
    run_config_show,
    run_config_set,
    run_config_disable,
    run_config_enable,
    run_config_wizard,
)


class TestConfigInit:
    def test_creates_env_template_with_default_preset(self, tmp_path):
        run_config_init(target_dir=tmp_path)
        env_path = tmp_path / ".clawsentry.env.example"
        assert env_path.exists()
        assert not (tmp_path / (".clawsentry" + ".toml")).exists()
        content = env_path.read_text()
        assert "CS_PRESET=medium" in content

    def test_creates_env_template_with_specified_preset(self, tmp_path):
        run_config_init(target_dir=tmp_path, preset="strict")
        content = (tmp_path / ".clawsentry.env.example").read_text()
        assert "CS_PRESET=strict" in content

    def test_no_overwrite_without_force(self, tmp_path):
        run_config_init(target_dir=tmp_path)
        with pytest.raises(FileExistsError):
            run_config_init(target_dir=tmp_path)

    def test_overwrite_with_force(self, tmp_path):
        run_config_init(target_dir=tmp_path, preset="low")
        run_config_init(target_dir=tmp_path, preset="high", force=True)
        assert "CS_PRESET=high" in (tmp_path / ".clawsentry.env.example").read_text()


class TestConfigShow:
    def test_show_defaults_when_no_env(self, tmp_path, capsys):
        run_config_show(target_dir=tmp_path)
        out = capsys.readouterr().out
        assert "project.preset: medium" in out
        assert "No project TOML is read" in out

    def test_effective_show_uses_explicit_env_file_source_and_redacts(self, tmp_path, capsys):
        env_file = tmp_path / ".clawsentry.env.local"
        env_file.write_text("CS_LLM_PROVIDER=openai\nCS_LLM_API_KEY" + "=sk-secret-value\n")

        run_config_show(target_dir=tmp_path, effective=True, env_file=env_file)

        out = capsys.readouterr().out
        assert "source=env-file:" in out
        assert "sk-secret-value" not in out
        assert "llm.api_key" in out

    def test_show_hints_when_local_env_exists_but_is_not_loaded(self, tmp_path, capsys):
        (tmp_path / ".clawsentry.env.local").write_text("CS_LLM_PROVIDER=openai\n")

        run_config_show(target_dir=tmp_path, effective=True)

        out = capsys.readouterr().out
        assert "Hints:" in out
        assert "no env file was loaded automatically" in out
        assert "clawsentry config show --effective --env-file .clawsentry.env.local" in out


class TestConfigSet:
    def test_set_without_target_prints_export_and_creates_no_file(self, tmp_path, capsys):
        run_config_set(target_dir=tmp_path, preset="high")
        out = capsys.readouterr().out
        assert "export CS_PRESET=high" in out
        assert not (tmp_path / (".clawsentry" + ".toml")).exists()
        assert not (tmp_path / ".clawsentry.env.local").exists()

    def test_set_with_explicit_env_file_updates_file(self, tmp_path):
        env_file = tmp_path / ".clawsentry.env.local"
        run_config_set(target_dir=tmp_path, key="project.mode", value="benchmark", env_file=env_file)
        assert "CS_MODE=benchmark" in env_file.read_text()
        assert env_file.stat().st_mode & 0o777 == 0o600

    def test_set_invalid_preset_raises(self, tmp_path):
        with pytest.raises(ValueError):
            run_config_set(target_dir=tmp_path, preset="nonexistent")


class TestConfigDisableEnable:
    def test_disable_enable_print_env_instructions_without_files(self, tmp_path, capsys):
        run_config_disable(target_dir=tmp_path)
        run_config_enable(target_dir=tmp_path)
        out = capsys.readouterr().out
        assert "CS_PROJECT_ENABLED=false" in out
        assert "CS_PROJECT_ENABLED=true" in out
        assert not (tmp_path / (".clawsentry" + ".toml")).exists()


class TestConfigWizard:
    def test_interactive_wizard_labels_runtime_boundaries(self, tmp_path, monkeypatch, capsys):
        answers = iter(["codex", "normal", "openai", "gpt-4o-mini", "", "y", "n", "1000"])
        monkeypatch.setattr("sys.stdin.isatty", lambda: True)

        def fake_input(prompt=""):
            print(prompt, end="")
            return next(answers)

        monkeypatch.setattr("builtins.input", fake_input)
        run_config_wizard(target_dir=tmp_path, interactive=True)
        out = capsys.readouterr().out
        assert "project TOML is not read or written" in out
        assert "process env > explicit env-file > defaults" in out
        assert "config show --effective --env-file" in out

    def test_interactive_wizard_prompts_and_writes_env_choices(self, tmp_path, monkeypatch, capsys):
        answers = iter(["claude-code", "strict", "openai", "gpt-4o-mini", "https://llm.example/v1", "y", "y", "250000"])
        monkeypatch.setattr("sys.stdin.isatty", lambda: True)
        monkeypatch.setattr("builtins.input", lambda prompt="": (print(prompt, end=""), next(answers))[1])

        run_config_wizard(target_dir=tmp_path, interactive=True)

        out = capsys.readouterr().out
        text = (tmp_path / ".clawsentry.env.example").read_text(encoding="utf-8")
        assert "ClawSentry Env-First Setup" in out
        assert "Step 1/5" in out
        assert "Next: pass the template explicitly" in out
        assert "CS_MODE=strict" in text
        assert "CS_LLM_PROVIDER=openai" in text
        assert "CS_LLM_MODEL=gpt-4o-mini" in text
        assert "CS_LLM_BASE_URL=https://llm.example/v1" in text
        assert "CS_L2_ENABLED=true" in text
        assert "CS_L3_ENABLED=true" in text
        assert "CS_LLM_DAILY_TOKEN_BUDGET=250000" in text
        assert "CS_FRAMEWORK=claude-code" in text
        assert not (tmp_path / (".clawsentry" + ".toml")).exists()

    def test_non_tty_ci_wizard_is_deterministic_and_plain(self, tmp_path, monkeypatch, capsys):
        monkeypatch.setattr("sys.stdin.isatty", lambda: False)
        monkeypatch.setenv("CI", "true")
        monkeypatch.setenv("NO_COLOR", "1")

        run_config_wizard(target_dir=tmp_path, framework="codex", llm_provider="none")

        out = capsys.readouterr().out
        assert "Non-interactive/CI-safe wizard path" in out
        assert "Step 1/5" not in out
        assert "\x1b[" not in out
        assert (tmp_path / ".clawsentry.env.example").is_file()
        assert not (tmp_path / (".clawsentry" + ".toml")).exists()

    def test_explicit_interactive_wizard_requires_tty(self, tmp_path, monkeypatch):
        monkeypatch.setattr("sys.stdin.isatty", lambda: False)
        with pytest.raises(RuntimeError, match="requires a TTY"):
            run_config_wizard(target_dir=tmp_path, interactive=True)


class TestEnvTemplateSecretSafety:
    def test_env_template_is_secret_safe(self, tmp_path):
        run_config_init(target_dir=tmp_path)
        text = (tmp_path / ".clawsentry.env.example").read_text(encoding="utf-8")
        assert "sk-" not in text
        assert "CS_LLM_API_KEY" + "=" not in text
        assert "Set CS_LLM_API_KEY in local env/secrets manager" in text
