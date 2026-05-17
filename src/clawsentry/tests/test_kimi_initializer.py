"""Kimi initializer env-first tests."""

from __future__ import annotations

import tomllib

from clawsentry.cli.initializers.kimi_cli import KimiCLIInitializer


def test_kimi_generate_config_reports_env_without_project_file(tmp_path):
    result = KimiCLIInitializer().generate_config(tmp_path, kimi_home=tmp_path / "kimi-home")
    assert result.env_vars["CS_FRAMEWORK"] == "kimi-cli"
    assert result.env_vars["CS_ENABLED_FRAMEWORKS"] == "kimi-cli"
    assert result.env_vars["CS_KIMI_HOOKS_ENABLED"] == "true"
    assert not (tmp_path / (".clawsentry" + ".toml")).exists()


def test_kimi_runtime_context_uses_real_skill_path_and_skill_trust_artifacts(tmp_path, monkeypatch):
    home = tmp_path / "home"
    kimi_home = tmp_path / "kimi-home"
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.delenv("CS_KIMI_SKILLS_DIR", raising=False)
    monkeypatch.delenv("CS_SKILL_TRUST_REGISTRY_PATH", raising=False)
    monkeypatch.delenv("CS_SKILL_TRUST_METADATA_PATH", raising=False)

    result = KimiCLIInitializer().generate_config(tmp_path, kimi_home=kimi_home)

    expected_skills_dir = home / ".claude" / "skills"
    expected_registry = kimi_home / "clawsentry" / "skill-registry.json"
    expected_metadata = kimi_home / "clawsentry" / "skill-trust-raw.json"
    assert result.env_vars["CS_KIMI_SKILLS_DIR"] == str(expected_skills_dir)
    assert result.env_vars["CS_SKILL_TRUST_REGISTRY_PATH"] == str(expected_registry)
    assert result.env_vars["CS_SKILL_TRUST_METADATA_PATH"] == str(expected_metadata)

    KimiCLIInitializer().setup_kimi_hooks(target_dir=tmp_path, kimi_home=kimi_home)

    config = tomllib.loads((kimi_home / "config.toml").read_text(encoding="utf-8"))
    commands = {hook["event"]: hook["command"] for hook in config["hooks"]}
    pretool_command = commands["PreToolUse"]
    assert f'CS_KIMI_SKILLS_DIR="${{CS_KIMI_SKILLS_DIR:-{expected_skills_dir}}}"' in pretool_command
    assert (
        f'CS_SKILL_TRUST_REGISTRY_PATH="${{CS_SKILL_TRUST_REGISTRY_PATH:-{expected_registry}}}"'
        in pretool_command
    )
    assert (
        f'CS_SKILL_TRUST_METADATA_PATH="${{CS_SKILL_TRUST_METADATA_PATH:-{expected_metadata}}}"'
        in pretool_command
    )
    assert "clawsentry harness --framework kimi-cli" in pretool_command


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
                'model = "custom-kimi-model"',
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
    assert 'model = "custom-kimi-model"' in text
    assert "python /tmp/user-hook.py" in text
    assert "clawsentry harness --framework kimi-cli" not in text
