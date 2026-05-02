"""Tests for G-8: init openclaw --setup (auto-configure OpenClaw)."""

from __future__ import annotations

import json
import os
from pathlib import Path
from unittest.mock import patch

import pytest

from clawsentry.cli.initializers.base import SetupResult
from clawsentry.cli.initializers.openclaw import OpenClawInitializer
from clawsentry.cli.init_command import run_init


class TestSetupResult:
    """Sanity-check the SetupResult dataclass."""

    def test_fields(self):
        r = SetupResult(
            changes_applied=["a"],
            files_modified=[Path("/x")],
            files_backed_up=[Path("/y")],
            warnings=["w"],
            dry_run=False,
        )
        assert r.changes_applied == ["a"]
        assert r.files_modified == [Path("/x")]
        assert r.files_backed_up == [Path("/y")]
        assert r.warnings == ["w"]
        assert r.dry_run is False


# ------------------------------------------------------------------ #
# Helpers
# ------------------------------------------------------------------ #

def _make_openclaw_dir(base: Path) -> Path:
    d = base / ".openclaw"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _write_json(path: Path, data: dict) -> None:
    path.write_text(json.dumps(data, indent=2))


# ------------------------------------------------------------------ #
# OpenClawInitializer.setup_openclaw_config tests
# ------------------------------------------------------------------ #

class TestSetupOpenClawConfig:

    # 1. test_setup_modifies_openclaw_json
    def test_setup_modifies_openclaw_json(self, tmp_path: Path):
        """Empty config -> sets tools.exec.host = 'gateway'."""
        oc_dir = _make_openclaw_dir(tmp_path)
        _write_json(oc_dir / "openclaw.json", {})

        init = OpenClawInitializer()
        result = init.setup_openclaw_config(openclaw_home=oc_dir)

        config = json.loads((oc_dir / "openclaw.json").read_text())
        assert config["tools"]["exec"]["host"] == "gateway"
        assert any("tools.exec.host" in c for c in result.changes_applied)
        assert oc_dir / "openclaw.json" in result.files_modified

    # 2. test_setup_modifies_exec_approvals
    def test_setup_modifies_exec_approvals(self, tmp_path: Path):
        """Empty config -> sets security='allowlist', ask='always'."""
        oc_dir = _make_openclaw_dir(tmp_path)
        _write_json(oc_dir / "openclaw.json", {})
        _write_json(oc_dir / "exec-approvals.json", {})

        init = OpenClawInitializer()
        result = init.setup_openclaw_config(openclaw_home=oc_dir)

        ea = json.loads((oc_dir / "exec-approvals.json").read_text())
        assert ea["security"] == "allowlist"
        assert ea["ask"] == "always"
        assert any("security" in c for c in result.changes_applied)
        assert any("ask" in c for c in result.changes_applied)
        assert oc_dir / "exec-approvals.json" in result.files_modified

    # 3. test_setup_creates_backup
    def test_setup_creates_backup(self, tmp_path: Path):
        """Modified files should have .bak backups."""
        oc_dir = _make_openclaw_dir(tmp_path)
        _write_json(oc_dir / "openclaw.json", {"existing": True})
        _write_json(oc_dir / "exec-approvals.json", {"old_key": "old_val"})

        init = OpenClawInitializer()
        result = init.setup_openclaw_config(openclaw_home=oc_dir)

        bak_oc = oc_dir / "openclaw.json.bak"
        bak_ea = oc_dir / "exec-approvals.json.bak"
        assert bak_oc.exists()
        assert bak_ea.exists()
        assert bak_oc in result.files_backed_up
        assert bak_ea in result.files_backed_up

        # Backup should contain original data
        assert json.loads(bak_oc.read_text()) == {"existing": True}
        assert json.loads(bak_ea.read_text()) == {"old_key": "old_val"}

    # 4. test_setup_skips_already_configured
    def test_setup_skips_already_configured(self, tmp_path: Path):
        """Already correct config -> no files modified, 'already configured' messages."""
        oc_dir = _make_openclaw_dir(tmp_path)
        _write_json(oc_dir / "openclaw.json", {
            "tools": {"exec": {"host": "gateway"}},
        })
        _write_json(oc_dir / "exec-approvals.json", {
            "security": "allowlist",
            "ask": "always",
        })

        init = OpenClawInitializer()
        result = init.setup_openclaw_config(openclaw_home=oc_dir)

        assert len(result.files_modified) == 0
        assert len(result.files_backed_up) == 0
        assert any("already configured" in c.lower() for c in result.changes_applied)
        # No .bak files created
        assert not (oc_dir / "openclaw.json.bak").exists()
        assert not (oc_dir / "exec-approvals.json.bak").exists()

    # 5. test_setup_dry_run_no_write
    def test_setup_dry_run_no_write(self, tmp_path: Path):
        """dry-run mode does not write files."""
        oc_dir = _make_openclaw_dir(tmp_path)
        _write_json(oc_dir / "openclaw.json", {})

        init = OpenClawInitializer()
        result = init.setup_openclaw_config(openclaw_home=oc_dir, dry_run=True)

        assert result.dry_run is True
        # Changes described but not applied
        assert len(result.changes_applied) > 0
        assert len(result.files_modified) == 0
        assert len(result.files_backed_up) == 0

        # Original file untouched
        config = json.loads((oc_dir / "openclaw.json").read_text())
        assert "tools" not in config

        # No backup created
        assert not (oc_dir / "openclaw.json.bak").exists()

    # 6. test_setup_preserves_existing_fields
    def test_setup_preserves_existing_fields(self, tmp_path: Path):
        """Existing fields in configs must not be deleted."""
        oc_dir = _make_openclaw_dir(tmp_path)
        _write_json(oc_dir / "openclaw.json", {
            "gateway": {"auth": {"token": "keep-me"}, "port": 19000},
            "models": {"providers": ["anthropic"]},
        })
        _write_json(oc_dir / "exec-approvals.json", {
            "custom_field": "preserved",
            "security": "deny",
        })

        init = OpenClawInitializer()
        init.setup_openclaw_config(openclaw_home=oc_dir)

        oc_config = json.loads((oc_dir / "openclaw.json").read_text())
        assert oc_config["gateway"]["auth"]["token"] == "keep-me"
        assert oc_config["gateway"]["port"] == 19000
        assert oc_config["models"]["providers"] == ["anthropic"]
        assert oc_config["tools"]["exec"]["host"] == "gateway"

        ea_config = json.loads((oc_dir / "exec-approvals.json").read_text())
        assert ea_config["custom_field"] == "preserved"
        assert ea_config["security"] == "allowlist"
        assert ea_config["ask"] == "always"

    # 7. test_setup_missing_openclaw_dir
    def test_setup_missing_openclaw_dir(self, tmp_path: Path):
        """Non-existent ~/.openclaw/ -> warning, no crash."""
        oc_dir = tmp_path / ".openclaw"
        # Do NOT create the dir

        init = OpenClawInitializer()
        result = init.setup_openclaw_config(openclaw_home=oc_dir)

        assert len(result.warnings) > 0
        assert any("not found" in w.lower() or "not exist" in w.lower()
                    for w in result.warnings)
        assert len(result.files_modified) == 0

    def test_restore_reverts_files_from_backups(self, tmp_path: Path):
        """restore should copy .bak files back over OpenClaw config files."""
        oc_dir = _make_openclaw_dir(tmp_path)
        original_oc = {"tools": {"exec": {"host": "sandbox"}}, "keep": True}
        original_ea = {"security": "deny", "ask": "never"}
        _write_json(oc_dir / "openclaw.json", original_oc)
        _write_json(oc_dir / "exec-approvals.json", original_ea)

        init = OpenClawInitializer()
        init.setup_openclaw_config(openclaw_home=oc_dir)
        result = init.restore_openclaw_config(openclaw_home=oc_dir)

        assert json.loads((oc_dir / "openclaw.json").read_text()) == original_oc
        assert json.loads((oc_dir / "exec-approvals.json").read_text()) == original_ea
        assert oc_dir / "openclaw.json" in result.files_modified
        assert oc_dir / "exec-approvals.json" in result.files_modified
        assert any("restored" in change.lower() for change in result.changes_applied)

    def test_restore_dry_run_does_not_write_files(self, tmp_path: Path):
        """restore dry-run should describe backup restoration without writing."""
        oc_dir = _make_openclaw_dir(tmp_path)
        _write_json(oc_dir / "openclaw.json", {"tools": {"exec": {"host": "sandbox"}}})
        _write_json(oc_dir / "openclaw.json.bak", {"original": True})

        init = OpenClawInitializer()
        result = init.restore_openclaw_config(openclaw_home=oc_dir, dry_run=True)

        assert result.dry_run is True
        assert json.loads((oc_dir / "openclaw.json").read_text()) == {
            "tools": {"exec": {"host": "sandbox"}}
        }
        assert result.files_modified == []
        assert any("would restore" in change.lower() for change in result.changes_applied)

    def test_restore_missing_backups_warns_without_writing(self, tmp_path: Path):
        """restore should be safe when no backup files exist."""
        oc_dir = _make_openclaw_dir(tmp_path)
        _write_json(oc_dir / "openclaw.json", {"tools": {"exec": {"host": "gateway"}}})

        init = OpenClawInitializer()
        result = init.restore_openclaw_config(openclaw_home=oc_dir)

        assert result.files_modified == []
        assert result.warnings
        assert "backup" in " ".join(result.warnings).lower()

    # 8. test_setup_implies_auto_detect
    def test_setup_implies_auto_detect(self, tmp_path: Path, capsys):
        """--setup should imply --auto-detect in run_init()."""
        oc_dir = _make_openclaw_dir(tmp_path)
        oc_config = {
            "gateway": {"auth": {"token": "my-token-123"}},
            "tools": {"exec": {"host": "gateway"}},
        }
        _write_json(oc_dir / "openclaw.json", oc_config)
        _write_json(oc_dir / "exec-approvals.json", {
            "security": "allowlist",
            "ask": "always",
        })

        exit_code = run_init(
            framework="openclaw",
            target_dir=tmp_path,
            force=False,
            setup=True,
            dry_run=False,
            openclaw_home=oc_dir,
        )
        assert exit_code == 0

        # auto_detect should have been implicitly enabled for setup, while
        # framework enablement and OpenClaw operator secrets are reported as
        # env-first values instead of being written into project files.
        captured = capsys.readouterr()
        assert "CS_FRAMEWORK=openclaw" in captured.out
        assert "CS_ENABLED_FRAMEWORKS=openclaw" in captured.out
        assert "OPENCLAW_OPERATOR_TOKEN=my-token-123" in captured.out
        assert not (tmp_path / (".clawsentry" + ".toml")).exists()
        assert not (tmp_path / ".env.clawsentry").exists()


class TestSetupExecApprovalsCreation:
    """exec-approvals.json may not exist initially; setup should create it."""

    def test_setup_creates_exec_approvals_if_missing(self, tmp_path: Path):
        oc_dir = _make_openclaw_dir(tmp_path)
        _write_json(oc_dir / "openclaw.json", {})
        # No exec-approvals.json

        init = OpenClawInitializer()
        result = init.setup_openclaw_config(openclaw_home=oc_dir)

        ea_path = oc_dir / "exec-approvals.json"
        assert ea_path.exists()
        ea = json.loads(ea_path.read_text())
        assert ea["security"] == "allowlist"
        assert ea["ask"] == "always"

        # No backup for exec-approvals since it didn't exist before
        assert oc_dir / "exec-approvals.json.bak" not in result.files_backed_up


class TestSetupCLIIntegration:
    """Test that --setup and --dry-run flags work through CLI main."""

    def test_cli_main_openclaw_init_does_not_setup_by_default(self, tmp_path: Path):
        from clawsentry.cli.main import main

        oc_dir = _make_openclaw_dir(tmp_path)
        _write_json(oc_dir / "openclaw.json", {})

        with patch.dict(os.environ, {}, clear=True):
            with pytest.raises(SystemExit) as exc:
                main([
                    "init",
                    "openclaw",
                    "--dir",
                    str(tmp_path),
                    "--openclaw-home",
                    str(oc_dir),
                ])

        assert exc.value.code == 0
        openclaw_config = json.loads((oc_dir / "openclaw.json").read_text())
        assert openclaw_config == {}

    def test_run_init_setup_prints_changes(self, tmp_path: Path, capsys):
        oc_dir = _make_openclaw_dir(tmp_path)
        _write_json(oc_dir / "openclaw.json", {})

        exit_code = run_init(
            framework="openclaw",
            target_dir=tmp_path,
            force=False,
            setup=True,
            dry_run=False,
            openclaw_home=oc_dir,
        )
        assert exit_code == 0
        captured = capsys.readouterr()
        assert "OpenClaw configuration updated" in captured.out
        assert "tools.exec.host" in captured.out

    def test_run_init_dry_run_prints_preview(self, tmp_path: Path, capsys):
        oc_dir = _make_openclaw_dir(tmp_path)
        _write_json(oc_dir / "openclaw.json", {})

        exit_code = run_init(
            framework="openclaw",
            target_dir=tmp_path,
            force=False,
            setup=True,
            dry_run=True,
            openclaw_home=oc_dir,
        )
        assert exit_code == 0
        captured = capsys.readouterr()
        assert "DRY RUN" in captured.out

    def test_run_init_setup_ignored_for_a3s_code(self, tmp_path: Path, capsys):
        """--setup for a3s-code should not error, just skip setup step."""
        exit_code = run_init(
            framework="a3s-code",
            target_dir=tmp_path,
            force=False,
            setup=True,
            dry_run=False,
        )
        assert exit_code == 0
        captured = capsys.readouterr()
        # No setup output for a3s-code
        assert "OpenClaw configuration updated" not in captured.out
        assert "CS_FRAMEWORK=a3s-code" in captured.out
        assert "CS_ENABLED_FRAMEWORKS=a3s-code" in captured.out
        assert not (tmp_path / (".clawsentry" + ".toml")).exists()
        assert not (tmp_path / ".env.clawsentry").exists()

    def test_init_codex_reports_framework_env_only(self, tmp_path: Path, capsys):
        exit_code = run_init(
            framework="codex",
            target_dir=tmp_path,
            force=False,
            setup=False,
            dry_run=False,
        )

        assert exit_code == 0
        captured = capsys.readouterr()
        assert "CS_FRAMEWORK=codex" in captured.out
        assert "CS_ENABLED_FRAMEWORKS=codex" in captured.out
        assert "CS_AUTH_TOKEN" not in captured.out
        assert not (tmp_path / (".clawsentry" + ".toml")).exists()
        assert not (tmp_path / ".env.clawsentry").exists()

    def test_cli_main_restore_openclaw_dispatch(self, tmp_path: Path, capsys):
        """CLI --restore should restore OpenClaw files from backups."""
        from clawsentry.cli.main import main

        oc_dir = _make_openclaw_dir(tmp_path)
        _write_json(oc_dir / "openclaw.json", {"tools": {"exec": {"host": "gateway"}}})
        _write_json(oc_dir / "openclaw.json.bak", {"tools": {"exec": {"host": "sandbox"}}})

        with patch.dict(os.environ, {}, clear=True):
            with pytest.raises(SystemExit) as exc:
                main([
                    "init",
                    "openclaw",
                    "--restore",
                    "--openclaw-home",
                    str(oc_dir),
                ])

        assert exc.value.code == 0
        assert json.loads((oc_dir / "openclaw.json").read_text()) == {
            "tools": {"exec": {"host": "sandbox"}}
        }
        assert "restore" in capsys.readouterr().out.lower()


class TestSetupPartiallyConfigured:
    """Only one file needs changes; the other is already correct."""

    def test_only_openclaw_json_needs_update(self, tmp_path: Path):
        oc_dir = _make_openclaw_dir(tmp_path)
        _write_json(oc_dir / "openclaw.json", {})
        _write_json(oc_dir / "exec-approvals.json", {
            "security": "allowlist",
            "ask": "always",
        })

        init = OpenClawInitializer()
        result = init.setup_openclaw_config(openclaw_home=oc_dir)

        assert oc_dir / "openclaw.json" in result.files_modified
        assert oc_dir / "exec-approvals.json" not in result.files_modified

    def test_only_exec_approvals_needs_update(self, tmp_path: Path):
        oc_dir = _make_openclaw_dir(tmp_path)
        _write_json(oc_dir / "openclaw.json", {
            "tools": {"exec": {"host": "gateway"}},
        })
        _write_json(oc_dir / "exec-approvals.json", {"security": "deny"})

        init = OpenClawInitializer()
        result = init.setup_openclaw_config(openclaw_home=oc_dir)

        assert oc_dir / "openclaw.json" not in result.files_modified
        assert oc_dir / "exec-approvals.json" in result.files_modified


class TestOpenClawHardenedProfile:
    def test_hardened_profile_dry_run_writes_nothing(self, tmp_path: Path):
        oc_dir = _make_openclaw_dir(tmp_path)
        original = {"tools": {"exec": {"host": "sandbox"}}, "keep": True}
        _write_json(oc_dir / "openclaw.json", original)

        result = OpenClawInitializer().setup_openclaw_config(
            openclaw_home=oc_dir,
            dry_run=True,
            hardened_profile=True,
        )

        assert result.dry_run is True
        assert result.files_modified == []
        assert result.files_backed_up == []
        assert json.loads((oc_dir / "openclaw.json").read_text()) == original
        assert not (oc_dir / "openclaw.json.bak").exists()
        assert any("hardened profile" in change for change in result.changes_applied)

    def test_hardened_profile_is_marker_managed_and_restore_reversible(self, tmp_path: Path):
        oc_dir = _make_openclaw_dir(tmp_path)
        original = {"tools": {"exec": {"host": "sandbox"}}, "keep": True}
        _write_json(oc_dir / "openclaw.json", original)
        _write_json(oc_dir / "exec-approvals.json", {"security": "deny", "ask": "never"})

        init = OpenClawInitializer()
        result = init.setup_openclaw_config(
            openclaw_home=oc_dir,
            hardened_profile=True,
        )
        config = json.loads((oc_dir / "openclaw.json").read_text())

        assert oc_dir / "openclaw.json" in result.files_modified
        assert oc_dir / "openclaw.json.bak" in result.files_backed_up
        assert config["tools"]["exec"]["host"] == "gateway"
        assert config["tools"]["native"]["deny"] == [
            "exec", "write", "edit", "apply_patch", "process"
        ]
        hardened = config["clawsentry"]["hardened_profile"]
        assert hardened["marker"] == "clawsentry.hardened_profile.v1"
        assert hardened["mode"] == "ahp_mediated_wrappers"
        assert hardened["reversible"] is True

        restore = init.restore_openclaw_config(openclaw_home=oc_dir)

        assert oc_dir / "openclaw.json" in restore.files_modified
        assert json.loads((oc_dir / "openclaw.json").read_text()) == original

    def test_cli_hardened_profile_dry_run_preview_uses_temp_openclaw_home(self, tmp_path: Path, capsys):
        oc_dir = _make_openclaw_dir(tmp_path)
        _write_json(oc_dir / "openclaw.json", {})

        exit_code = run_init(
            framework="openclaw",
            target_dir=tmp_path,
            force=False,
            setup=True,
            dry_run=True,
            hardened_profile=True,
            openclaw_home=oc_dir,
        )

        assert exit_code == 0
        captured = capsys.readouterr()
        assert "DRY RUN" in captured.out
        assert "hardened profile" in captured.out
        assert json.loads((oc_dir / "openclaw.json").read_text()) == {}

    def test_hardened_profile_preserves_existing_native_denies(self, tmp_path: Path):
        oc_dir = _make_openclaw_dir(tmp_path)
        _write_json(oc_dir / "openclaw.json", {"tools": {"native": {"deny": ["dangerous_custom"]}}})

        OpenClawInitializer().setup_openclaw_config(
            openclaw_home=oc_dir,
            hardened_profile=True,
        )
        config = json.loads((oc_dir / "openclaw.json").read_text())

        deny = config["tools"]["native"]["deny"]
        assert deny[0] == "dangerous_custom"
        assert "dangerous_custom" in deny
        assert "exec" in deny
        assert config["clawsentry"]["hardened_profile"]["native_tool_policy"]["deny"] == deny
