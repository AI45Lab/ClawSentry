"""Gemini initializer env-first tests."""

from __future__ import annotations

import json

from clawsentry.cli.initializers.gemini_cli import GeminiCLIInitializer


def test_gemini_generate_config_reports_env_without_project_file(tmp_path):
    result = GeminiCLIInitializer().generate_config(tmp_path)
    assert result.env_vars["CS_FRAMEWORK"] == "gemini-cli"
    assert result.env_vars["CS_ENABLED_FRAMEWORKS"] == "gemini-cli"
    assert result.env_vars["CS_GEMINI_SETTINGS_PATH"].endswith(".gemini/settings.json")
    assert not (tmp_path / (".clawsentry" + ".toml")).exists()


def test_gemini_setup_uses_project_temp_settings(tmp_path):
    result = GeminiCLIInitializer().setup_gemini_hooks(target_dir=tmp_path)
    assert (tmp_path / ".gemini" / "settings.json").exists()
    assert result.files_modified == [tmp_path / ".gemini" / "settings.json"]
    payload = json.loads((tmp_path / ".gemini" / "settings.json").read_text(encoding="utf-8"))
    assert payload["hooksConfig"]["enabled"] is True
    assert "enabled" not in payload["hooks"]


def test_gemini_hook_commands_resolve_user_local_clawsentry(tmp_path):
    GeminiCLIInitializer().setup_gemini_hooks(target_dir=tmp_path)

    payload = json.loads((tmp_path / ".gemini" / "settings.json").read_text(encoding="utf-8"))
    before_tool_command = payload["hooks"]["BeforeTool"][0]["hooks"][0]["command"]
    notification_command = payload["hooks"]["Notification"][0]["hooks"][0]["command"]

    assert 'PATH="${HOME}/.local/bin:${PATH}"' in before_tool_command
    assert 'PATH="${HOME}/.local/bin:${PATH}"' in notification_command
    assert "clawsentry harness --framework gemini-cli" in before_tool_command


def test_gemini_setup_removes_legacy_inline_hooks_enabled(tmp_path):
    settings = tmp_path / ".gemini" / "settings.json"
    settings.parent.mkdir()
    settings.write_text(
        json.dumps(
            {
                "hooksConfig": {"enabled": False},
                "hooks": {
                    "enabled": True,
                    "BeforeTool": [
                        {
                            "hooks": [
                                {
                                    "type": "command",
                                    "name": "user-hook",
                                    "command": "echo user",
                                }
                            ]
                        }
                    ],
                },
            }
        ),
        encoding="utf-8",
    )

    GeminiCLIInitializer().setup_gemini_hooks(target_dir=tmp_path)

    payload = json.loads(settings.read_text(encoding="utf-8"))
    assert payload["hooksConfig"]["enabled"] is True
    assert "enabled" not in payload["hooks"]
    assert any(
        entry.get("hooks", [{}])[0].get("name") == "user-hook"
        for entry in payload["hooks"]["BeforeTool"]
    )


def test_gemini_uninstall_preserves_user_hooks_and_other_settings(tmp_path):
    settings_path = tmp_path / ".gemini" / "settings.json"
    settings_path.parent.mkdir()
    settings_path.write_text(
        json.dumps(
            {
                "theme": "light",
                "hooksConfig": {"enabled": False},
                "hooks": {
                    "BeforeTool": [
                        {
                            "hooks": [
                                {
                                    "type": "command",
                                    "name": "user-hook",
                                    "command": "python /tmp/user-hook.py",
                                }
                            ]
                        }
                    ]
                },
            }
        ),
        encoding="utf-8",
    )

    init = GeminiCLIInitializer()
    init.setup_gemini_hooks(target_dir=tmp_path)
    init.uninstall(target_dir=tmp_path)

    payload = json.loads(settings_path.read_text(encoding="utf-8"))
    assert payload["theme"] == "light"
    assert payload["hooksConfig"]["enabled"] is True
    assert payload["hooks"]["BeforeTool"] == [
        {
            "hooks": [
                {
                    "type": "command",
                    "name": "user-hook",
                    "command": "python /tmp/user-hook.py",
                }
            ]
        }
    ]
    assert "clawsentry harness --framework gemini-cli" not in str(payload)
