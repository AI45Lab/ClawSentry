"""Claude Code initializer env-first tests."""

from __future__ import annotations

import json

from clawsentry.cli.initializers.claude_code import ClaudeCodeInitializer


def test_claude_generate_config_reports_env_and_uses_temp_home(tmp_path):
    claude_home = tmp_path / "claude-home"
    result = ClaudeCodeInitializer().generate_config(tmp_path, claude_home=claude_home)
    assert result.env_vars["CS_FRAMEWORK"] == "claude-code"
    assert result.env_vars["CS_ENABLED_FRAMEWORKS"] == "claude-code"
    assert (claude_home / "settings.json").exists()
    assert not (tmp_path / (".clawsentry" + ".toml")).exists()
    assert "CS_AUTH_TOKEN" not in json.dumps(result.env_vars)


def test_claude_generate_config_installs_prompt_submit_hook(tmp_path):
    claude_home = tmp_path / "claude-home"
    ClaudeCodeInitializer().generate_config(tmp_path, claude_home=claude_home)

    settings = json.loads((claude_home / "settings.json").read_text(encoding="utf-8"))
    prompt_hooks = settings["hooks"]["UserPromptSubmit"]

    assert prompt_hooks == [
        {
            "matcher": "",
            "hooks": [
                {
                    "type": "command",
                    "command": "clawsentry-harness --framework claude-code",
                }
            ],
        }
    ]


def test_claude_uninstall_removes_managed_hooks_from_temp_home(tmp_path):
    claude_home = tmp_path / "claude-home"
    init = ClaudeCodeInitializer()
    init.generate_config(tmp_path, claude_home=claude_home)
    result = init.uninstall(claude_home=claude_home)
    assert result.next_steps
