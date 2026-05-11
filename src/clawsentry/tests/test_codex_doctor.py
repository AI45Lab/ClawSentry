"""Tests for Codex doctor checks."""

from __future__ import annotations

import json

from clawsentry.cli.doctor_command import check_codex_config, check_codex_native_hooks
from clawsentry.cli.initializers.codex import CodexInitializer


class TestDoctorCodexCheck:

    def test_codex_not_configured_skips(self, monkeypatch):
        monkeypatch.delenv("CS_FRAMEWORK", raising=False)
        result = check_codex_config()
        assert result.status == "PASS"
        assert "skipped" in result.message.lower()

    def test_codex_configured_with_token(self, monkeypatch):
        monkeypatch.setenv("CS_FRAMEWORK", "codex")
        monkeypatch.setenv("CS_AUTH_TOKEN", "a-strong-token-value")
        result = check_codex_config()
        assert result.status == "PASS"
        assert "/ahp/codex" in result.message

    def test_codex_configured_via_enabled_frameworks_with_token(self, monkeypatch):
        monkeypatch.setenv("CS_FRAMEWORK", "openclaw")
        monkeypatch.setenv("CS_ENABLED_FRAMEWORKS", "openclaw,codex")
        monkeypatch.setenv("CS_AUTH_TOKEN", "a-strong-token-value")
        result = check_codex_config()
        assert result.status == "PASS"
        assert "/ahp/codex" in result.message

    def test_codex_configured_without_token(self, monkeypatch):
        monkeypatch.setenv("CS_FRAMEWORK", "codex")
        monkeypatch.delenv("CS_AUTH_TOKEN", raising=False)
        result = check_codex_config()
        assert result.status == "WARN"
        assert "CS_AUTH_TOKEN" in result.message

    def test_codex_custom_port(self, monkeypatch):
        monkeypatch.setenv("CS_FRAMEWORK", "codex")
        monkeypatch.setenv("CS_AUTH_TOKEN", "tok")
        monkeypatch.setenv("CS_HTTP_PORT", "9090")
        result = check_codex_config()
        assert result.status == "PASS"
        assert "9090" in result.message

    def test_codex_check_in_all_checks(self):
        from clawsentry.cli.doctor_command import ALL_CHECKS
        assert check_codex_config in ALL_CHECKS

    def test_codex_native_hooks_skip_when_not_codex(self, monkeypatch):
        monkeypatch.delenv("CS_FRAMEWORK", raising=False)
        result = check_codex_native_hooks()
        assert result.status == "PASS"
        assert "skipped" in result.message.lower()

    def test_codex_native_hooks_warn_when_not_installed(self, tmp_path, monkeypatch):
        monkeypatch.setenv("CS_FRAMEWORK", "codex")
        monkeypatch.setenv("CODEX_HOME", str(tmp_path / ".codex"))
        result = check_codex_native_hooks()
        assert result.status == "WARN"
        assert "native hooks" in result.message.lower()

    def test_codex_native_hooks_pass_when_managed_entries_present(self, tmp_path, monkeypatch):
        codex_home = tmp_path / ".codex"
        CodexInitializer().setup_codex_hooks(codex_home=codex_home)
        monkeypatch.setenv("CS_FRAMEWORK", "codex")
        monkeypatch.setenv("CODEX_HOME", str(codex_home))

        result = check_codex_native_hooks()

        assert result.status == "PASS"
        assert "hooks.json" in result.message
        assert "trusted" in result.message
        assert "PreToolUse(Bash)" in result.message
        assert "PreToolUse(Bash): sync" in result.detail
        assert "PreToolUse(apply_patch|Edit|Write|mcp__.*): async" in result.detail
        assert "PermissionRequest(Bash): sync" in result.detail
        assert "PermissionRequest(apply_patch|Edit|Write|mcp__.*): sync" in result.detail
        assert "PostToolUse(Bash): async" in result.detail
        assert "PostToolUse(apply_patch|Edit|Write|mcp__.*): async" in result.detail
        assert "UserPromptSubmit: async" in result.detail
        assert "Stop: async" in result.detail
        assert "SessionStart(startup|resume|clear): async" in result.detail
        assert "PreCompact: async" in result.detail
        assert "PostCompact: async" in result.detail

    def test_codex_native_hooks_accept_current_feature_flag_without_legacy_alias(
        self,
        tmp_path,
        monkeypatch,
    ):
        codex_home = tmp_path / ".codex"
        CodexInitializer().setup_codex_hooks(codex_home=codex_home)
        config_path = codex_home / "config.toml"
        config_text = config_path.read_text(encoding="utf-8")
        config_path.write_text(
            config_text.replace("codex_hooks = true\n", ""),
            encoding="utf-8",
        )
        monkeypatch.setenv("CS_FRAMEWORK", "codex")
        monkeypatch.setenv("CODEX_HOME", str(codex_home))

        result = check_codex_native_hooks()

        assert result.status == "PASS"

    def test_codex_native_hooks_warn_when_managed_entries_are_untrusted(self, tmp_path, monkeypatch):
        codex_home = tmp_path / ".codex"
        CodexInitializer().setup_codex_hooks(codex_home=codex_home)
        config_path = codex_home / "config.toml"
        config_path.write_text("[features]\nhooks = true\n", encoding="utf-8")
        monkeypatch.setenv("CS_FRAMEWORK", "codex")
        monkeypatch.setenv("CODEX_HOME", str(codex_home))

        result = check_codex_native_hooks()

        assert result.status == "WARN"
        assert "untrusted" in result.detail

    def test_codex_native_hooks_warn_when_pretool_bash_is_async(self, tmp_path, monkeypatch):
        codex_home = tmp_path / ".codex"
        CodexInitializer().setup_codex_hooks(codex_home=codex_home)
        hooks_path = codex_home / "hooks.json"
        payload = json.loads(hooks_path.read_text(encoding="utf-8"))
        payload["hooks"]["PreToolUse"][0]["hooks"][0]["command"] = (
            "clawsentry harness --framework codex --async"
        )
        hooks_path.write_text(json.dumps(payload), encoding="utf-8")
        monkeypatch.setenv("CS_FRAMEWORK", "codex")
        monkeypatch.setenv("CODEX_HOME", str(codex_home))

        result = check_codex_native_hooks()

        assert result.status == "WARN"
        assert "PreToolUse(Bash)" in result.detail
        assert "synchronous" in result.detail

    def test_codex_native_hooks_warn_when_non_pre_event_is_sync(self, tmp_path, monkeypatch):
        codex_home = tmp_path / ".codex"
        CodexInitializer().setup_codex_hooks(codex_home=codex_home)
        hooks_path = codex_home / "hooks.json"
        payload = json.loads(hooks_path.read_text(encoding="utf-8"))
        payload["hooks"]["UserPromptSubmit"][0]["hooks"][0]["command"] = (
            "clawsentry harness --framework codex"
        )
        hooks_path.write_text(json.dumps(payload), encoding="utf-8")
        monkeypatch.setenv("CS_FRAMEWORK", "codex")
        monkeypatch.setenv("CODEX_HOME", str(codex_home))

        result = check_codex_native_hooks()

        assert result.status == "WARN"
        assert "UserPromptSubmit" in result.detail
        assert "--async" in result.detail

    def test_codex_native_hooks_warn_when_permission_request_is_async(self, tmp_path, monkeypatch):
        codex_home = tmp_path / ".codex"
        CodexInitializer().setup_codex_hooks(codex_home=codex_home)
        hooks_path = codex_home / "hooks.json"
        payload = json.loads(hooks_path.read_text(encoding="utf-8"))
        payload["hooks"]["PermissionRequest"][0]["hooks"][0]["command"] = (
            "clawsentry harness --framework codex --async"
        )
        hooks_path.write_text(json.dumps(payload), encoding="utf-8")
        monkeypatch.setenv("CS_FRAMEWORK", "codex")
        monkeypatch.setenv("CODEX_HOME", str(codex_home))

        result = check_codex_native_hooks()

        assert result.status == "WARN"
        assert "PermissionRequest(Bash)" in result.detail
        assert "synchronous" in result.detail

    def test_codex_native_hooks_warn_when_required_event_missing(self, tmp_path, monkeypatch):
        codex_home = tmp_path / ".codex"
        CodexInitializer().setup_codex_hooks(codex_home=codex_home)
        hooks_path = codex_home / "hooks.json"
        payload = json.loads(hooks_path.read_text(encoding="utf-8"))
        del payload["hooks"]["Stop"]
        hooks_path.write_text(json.dumps(payload), encoding="utf-8")
        monkeypatch.setenv("CS_FRAMEWORK", "codex")
        monkeypatch.setenv("CODEX_HOME", str(codex_home))

        result = check_codex_native_hooks()

        assert result.status == "WARN"
        assert "Stop" in result.detail

    def test_codex_native_hooks_check_in_all_checks(self):
        from clawsentry.cli.doctor_command import ALL_CHECKS
        assert check_codex_native_hooks in ALL_CHECKS
