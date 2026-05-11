"""Tests for Codex initializer under env-first config model."""

from __future__ import annotations

import json
import tomllib

from clawsentry.cli.initializers.codex import CodexInitializer
from clawsentry.cli.start_command import detect_framework


class TestCodexInitializer:
    def test_generate_config_reports_env_vars_not_project_file(self, tmp_path):
        result = CodexInitializer().generate_config(tmp_path)
        assert not (tmp_path / (".clawsentry" + ".toml")).exists()
        assert not (tmp_path / ".env.clawsentry").exists()
        assert result.env_vars == {"CS_FRAMEWORK": "codex", "CS_ENABLED_FRAMEWORKS": "codex"}
        assert result.files_created == []

    def test_rerun_remains_side_effect_free(self, tmp_path):
        CodexInitializer().generate_config(tmp_path)
        CodexInitializer().generate_config(tmp_path, force=True)
        assert list(tmp_path.iterdir()) == []

    def test_next_steps_use_explicit_env_file_language(self, tmp_path):
        result = CodexInitializer().generate_config(tmp_path)
        assert any("--env-file .clawsentry.env.local" in step for step in result.next_steps)
        assert not any("source" in step and ".env.clawsentry" in step for step in result.next_steps)


class TestCodexDetectFramework:
    def test_detect_codex_from_process_env(self, monkeypatch):
        monkeypatch.setenv("CS_FRAMEWORK", "codex")
        assert detect_framework() == "codex"

    def test_legacy_env_file_is_not_auto_discovered(self, tmp_path, monkeypatch):
        (tmp_path / ".env.clawsentry").write_text("CS_FRAMEWORK=codex\n")
        monkeypatch.chdir(tmp_path)
        assert detect_framework(a3s_dir=tmp_path / "missing") is None


class TestCodexInitializerHooks:
    def test_setup_codex_hooks_dry_run_does_not_write(self, tmp_path):
        init = CodexInitializer()
        result = init.setup_codex_hooks(codex_home=tmp_path / ".codex", dry_run=True)
        assert result.dry_run is True
        assert not (tmp_path / ".codex").exists()

    def test_setup_codex_hooks_writes_managed_entries_to_temp_home(self, tmp_path):
        codex_home = tmp_path / ".codex"
        init = CodexInitializer()
        result = init.setup_codex_hooks(codex_home=codex_home, dry_run=False)
        assert (codex_home / "config.toml").exists()
        assert (codex_home / "hooks.json").exists()
        assert result.files_modified
        hooks = json.loads((codex_home / "hooks.json").read_text())
        assert "clawsentry harness --framework codex" in str(hooks)
        config = tomllib.loads((codex_home / "config.toml").read_text(encoding="utf-8"))
        hook_state = config["hooks"]["state"]
        assert len(hook_state) == 11
        assert all(
            isinstance(state.get("trusted_hash"), str)
            and state["trusted_hash"].startswith("sha256:")
            for state in hook_state.values()
        )

    def test_setup_codex_hooks_writes_current_feature_flag_without_deprecated_alias(self, tmp_path):
        codex_home = tmp_path / ".codex"
        CodexInitializer().setup_codex_hooks(codex_home=codex_home, dry_run=False)

        config_text = (codex_home / "config.toml").read_text(encoding="utf-8")
        config_lines = set(config_text.splitlines())

        assert "hooks = true" in config_lines
        assert "codex_hooks = true" not in config_lines

    def test_setup_codex_hooks_covers_current_codex_hook_surface(self, tmp_path):
        codex_home = tmp_path / ".codex"
        CodexInitializer().setup_codex_hooks(codex_home=codex_home, dry_run=False)

        payload = json.loads((codex_home / "hooks.json").read_text(encoding="utf-8"))
        hooks = payload["hooks"]

        assert hooks["SessionStart"][0]["matcher"] == "startup|resume|clear"
        assert "PreCompact" in hooks
        assert "PostCompact" in hooks
        assert any(
            entry.get("matcher") == "apply_patch|Edit|Write|mcp__.*"
            for entry in hooks["PreToolUse"]
        )
        assert any(
            entry.get("matcher") == "apply_patch|Edit|Write|mcp__.*"
            for entry in hooks["PermissionRequest"]
        )
        assert any(
            entry.get("matcher") == "apply_patch|Edit|Write|mcp__.*"
            for entry in hooks["PostToolUse"]
        )

    def test_uninstall_removes_only_clawsentry_hooks_from_temp_home(self, tmp_path):
        codex_home = tmp_path / ".codex"
        init = CodexInitializer()
        init.setup_codex_hooks(codex_home=codex_home, dry_run=False)
        result = init.uninstall(codex_home=codex_home)
        assert result.next_steps
        assert "clawsentry harness --framework codex" not in (codex_home / "hooks.json").read_text()
        config = tomllib.loads((codex_home / "config.toml").read_text(encoding="utf-8"))
        assert config.get("hooks", {}).get("state", {}) == {}

    def test_uninstall_preserves_user_codex_hooks_and_unrelated_config(self, tmp_path):
        codex_home = tmp_path / ".codex"
        hooks_path = codex_home / "hooks.json"
        config_path = codex_home / "config.toml"
        codex_home.mkdir()
        config_path.write_text(
            "[features]\nexperimental_widget = true\n\n"
            f"[hooks.state.\"{hooks_path}:pre_tool_use:0:0\"]\n"
            'trusted_hash = "sha256:user"\n',
            encoding="utf-8",
        )
        hooks_path.write_text(
            json.dumps(
                {
                    "hooks": {
                        "PreToolUse": [
                            {
                                "matcher": "Bash",
                                "hooks": [
                                    {
                                        "type": "command",
                                        "command": "python /tmp/user-hook.py",
                                    }
                                ],
                            }
                        ]
                    }
                }
            ),
            encoding="utf-8",
        )

        init = CodexInitializer()
        init.setup_codex_hooks(codex_home=codex_home, dry_run=False)
        init.uninstall(codex_home=codex_home)

        hooks = json.loads(hooks_path.read_text(encoding="utf-8"))
        config = tomllib.loads(config_path.read_text(encoding="utf-8"))
        assert hooks["hooks"]["PreToolUse"] == [
            {
                "matcher": "Bash",
                "hooks": [
                    {
                        "type": "command",
                        "command": "python /tmp/user-hook.py",
                    }
                ],
            }
        ]
        assert config["features"]["experimental_widget"] is True
        assert config["hooks"]["state"][f"{hooks_path}:pre_tool_use:0:0"]["trusted_hash"] == "sha256:user"
        assert all("clawsentry" not in str(state).lower() for state in config["hooks"]["state"].values())
