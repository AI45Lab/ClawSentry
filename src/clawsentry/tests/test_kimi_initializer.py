"""Kimi initializer env-first tests."""

from __future__ import annotations

from clawsentry.cli.initializers.kimi_cli import KimiCLIInitializer


def test_kimi_generate_config_reports_env_without_project_file(tmp_path):
    result = KimiCLIInitializer().generate_config(tmp_path, kimi_home=tmp_path / "kimi-home")
    assert result.env_vars["CS_FRAMEWORK"] == "kimi-cli"
    assert result.env_vars["CS_ENABLED_FRAMEWORKS"] == "kimi-cli"
    assert result.env_vars["CS_KIMI_HOOKS_ENABLED"] == "true"
    assert not (tmp_path / (".clawsentry" + ".toml")).exists()


def test_kimi_setup_uses_temp_home(tmp_path):
    kimi_home = tmp_path / "kimi-home"
    result = KimiCLIInitializer().setup_kimi_hooks(target_dir=tmp_path, kimi_home=kimi_home)
    assert kimi_home.joinpath("config.toml").exists()
    assert result.files_modified == [kimi_home / "config.toml"]


def test_kimi_uninstall_preserves_user_hook_blocks_and_other_toml(tmp_path):
    kimi_home = tmp_path / "kimi-home"
    config_path = kimi_home / "config.toml"
    config_path.parent.mkdir()
    config_path.write_text(
        "\n".join(
            [
                'model = "kimi-k2.5"',
                "",
                "[[hooks]]",
                'event = "PreToolUse"',
                'matcher = "Shell"',
                "command = 'python /tmp/user-hook.py'",
                "timeout = 7",
                "",
            ]
        ),
        encoding="utf-8",
    )

    init = KimiCLIInitializer()
    init.setup_kimi_hooks(target_dir=tmp_path, kimi_home=kimi_home)
    init.uninstall(target_dir=tmp_path, kimi_home=kimi_home)

    text = config_path.read_text(encoding="utf-8")
    assert 'model = "kimi-k2.5"' in text
    assert "python /tmp/user-hook.py" in text
    assert "clawsentry harness --framework kimi-cli" not in text
