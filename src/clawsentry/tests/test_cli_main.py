"""Tests for unified CLI entry point."""

from __future__ import annotations

import importlib
import os
import subprocess
import sys
from pathlib import Path


def _cli_env() -> dict[str, str]:
    env = os.environ.copy()
    src_path = str(Path(__file__).parents[2])
    existing = env.get("PYTHONPATH", "")
    env["PYTHONPATH"] = src_path if not existing else f"{src_path}:{existing}"
    return env


class TestCLIParsing:
    def test_no_args_shows_help(self):
        proc = subprocess.run(
            [sys.executable, "-m", "clawsentry", "--help"],
            capture_output=True, text=True, timeout=10, env=_cli_env(),
        )
        assert proc.returncode == 0
        assert "init" in proc.stdout
        assert "gateway" in proc.stdout
        assert "rules" in proc.stdout

    def test_init_subcommand_help(self):
        proc = subprocess.run(
            [sys.executable, "-m", "clawsentry", "init", "--help"],
            capture_output=True, text=True, timeout=10, env=_cli_env(),
        )
        assert proc.returncode == 0
        assert "framework" in proc.stdout.lower()

    def test_init_unknown_framework(self):
        proc = subprocess.run(
            [sys.executable, "-m", "clawsentry", "init", "nonexistent"],
            capture_output=True, text=True, timeout=10, env=_cli_env(),
        )
        assert proc.returncode != 0

    def test_init_openclaw_in_tmpdir(self, tmp_path):
        proc = subprocess.run(
            [
                sys.executable, "-m", "clawsentry",
                "init", "openclaw", "--dir", str(tmp_path),
            ],
            capture_output=True, text=True, timeout=10, env=_cli_env(),
        )
        assert proc.returncode == 0
        assert not (tmp_path / (".clawsentry" + ".toml")).exists()
        assert not (tmp_path / ".env.clawsentry").exists()

    def test_init_a3s_code_in_tmpdir(self, tmp_path):
        proc = subprocess.run(
            [
                sys.executable, "-m", "clawsentry",
                "init", "a3s-code", "--dir", str(tmp_path),
            ],
            capture_output=True, text=True, timeout=10, env=_cli_env(),
        )
        assert proc.returncode == 0
        assert not (tmp_path / (".clawsentry" + ".toml")).exists()
        assert not (tmp_path / ".env.clawsentry").exists()

    def test_init_codex_setup_writes_native_hooks(self, tmp_path):
        codex_home = tmp_path / ".codex"
        proc = subprocess.run(
            [
                sys.executable, "-m", "clawsentry",
                "init", "codex",
                "--dir", str(tmp_path),
                "--setup",
                "--codex-home", str(codex_home),
            ],
            capture_output=True, text=True, timeout=10, env=_cli_env(),
        )
        assert proc.returncode == 0
        assert (codex_home / "config.toml").exists()
        assert (codex_home / "hooks.json").exists()
        assert "Codex native hooks updated" in proc.stdout

    def test_init_gemini_cli_setup_writes_project_local_hooks(self, tmp_path):
        proc = subprocess.run(
            [
                sys.executable, "-m", "clawsentry",
                "init", "gemini-cli",
                "--dir", str(tmp_path),
                "--setup",
            ],
            capture_output=True, text=True, timeout=10, env=_cli_env(),
        )
        assert proc.returncode == 0
        assert (tmp_path / ".gemini" / "settings.json").exists()
        assert "Gemini CLI native hooks updated" in proc.stdout

    def test_rules_subcommand_help(self):
        proc = subprocess.run(
            [sys.executable, "-m", "clawsentry", "rules", "--help"],
            capture_output=True, text=True, timeout=10, env=_cli_env(),
        )
        assert proc.returncode == 0
        assert "lint" in proc.stdout
        assert "dry-run" in proc.stdout
        assert "report" in proc.stdout

    def test_l3_full_review_subcommand_help(self):
        proc = subprocess.run(
            [sys.executable, "-m", "clawsentry", "l3", "full-review", "--help"],
            capture_output=True, text=True, timeout=10, env=_cli_env(),
        )
        assert proc.returncode == 0
        assert "--session" in proc.stdout
        assert "--queue-only" in proc.stdout
        assert "--runner" in proc.stdout

    def test_rules_subcommand_requires_nested_command(self):
        proc = subprocess.run(
            [sys.executable, "-m", "clawsentry", "rules"],
            capture_output=True, text=True, timeout=10, env=_cli_env(),
        )
        assert proc.returncode != 0
        assert "usage: clawsentry rules" in (proc.stderr or proc.stdout)

    def test_rules_lint_rejects_unknown_arguments(self):
        proc = subprocess.run(
            [sys.executable, "-m", "clawsentry", "rules", "lint", "--bogus"],
            capture_output=True, text=True, timeout=10, env=_cli_env(),
        )
        assert proc.returncode != 0
        assert "--bogus" in (proc.stderr or proc.stdout)

    def test_service_validate_from_cli(self, tmp_path):
        env_file = tmp_path / "gateway.env"
        env_file.write_text(
            "CS_AUTH_TOKEN" + "=abcdefghijklmnopqrstuvwxyz123456\n"
            "CS_HTTP_PORT=8080\n"
            "CS_LLM_TOKEN_BUDGET_ENABLED=false\n"
            "CS_LLM_DAILY_TOKEN_BUDGET=0\n",
            encoding="utf-8",
        )

        proc = subprocess.run(
            [
                sys.executable, "-m", "clawsentry",
                "service", "validate",
                "--env-file", str(env_file),
            ],
            capture_output=True, text=True, timeout=10, env=_cli_env(),
        )

        assert proc.returncode == 0
        assert "PASS: service deployment validation succeeded" in proc.stdout
        assert "abcdefghijklmnopqrstuvwxyz123456" not in proc.stdout

    def test_start_without_framework_hints_unloaded_local_env_file(self, tmp_path):
        (tmp_path / ".clawsentry.env.local").write_text("CS_FRAMEWORK=codex\n")
        proc = subprocess.run(
            [sys.executable, "-m", "clawsentry", "start", "--no-watch"],
            cwd=tmp_path,
            capture_output=True,
            text=True,
            timeout=10,
            env=_cli_env(),
        )

        assert proc.returncode == 1
        assert "Env-file hint: no env file was loaded automatically." in proc.stderr
        assert "clawsentry start --env-file .clawsentry.env.local" in proc.stderr

    def test_rules_report_writes_artifact_from_cli(self, tmp_path):
        output_path = tmp_path / "rules-report.json"

        proc = subprocess.run(
            [
                sys.executable, "-m", "clawsentry",
                "rules", "report",
                "--output", str(output_path),
            ],
            capture_output=True, text=True, timeout=10, env=_cli_env(),
        )

        assert proc.returncode == 0
        assert output_path.exists()
        assert "PASS: wrote rules report" in proc.stdout

    def test_rules_report_writes_markdown_dashboard_from_cli(self, tmp_path):
        output_path = tmp_path / "rules-report.json"
        dashboard_path = tmp_path / "rules-dashboard.md"

        proc = subprocess.run(
            [
                sys.executable, "-m", "clawsentry",
                "rules", "report",
                "--output", str(output_path),
                "--summary-markdown", str(dashboard_path),
            ],
            capture_output=True, text=True, timeout=10, env=_cli_env(),
        )

        assert proc.returncode == 0
        assert output_path.exists()
        assert dashboard_path.exists()
        assert "# ClawSentry Rules Governance Dashboard" in dashboard_path.read_text(
            encoding="utf-8"
        )
        assert str(dashboard_path) in proc.stdout



class TestWatchDefaults:
    """G-1: watch default URL must align with gateway default port."""

    def test_watch_default_url_matches_gateway_port(self):
        """Without env override, watch should default to port 8080."""
        # Re-import to ensure fresh module state
        import clawsentry.cli.main as cli_mod
        importlib.reload(cli_mod)
        parser = cli_mod._build_parser()
        args, _ = parser.parse_known_args(["watch"])
        assert "8080" in args.gateway_url

    def test_watch_default_url_reads_env(self, monkeypatch):
        """CS_HTTP_PORT env var should override the default port in watch."""
        monkeypatch.setenv("CS_HTTP_PORT", "9999")
        # Must reload so the env var is picked up at parser construction time
        import clawsentry.cli.main as cli_mod
        importlib.reload(cli_mod)
        parser = cli_mod._build_parser()
        args, _ = parser.parse_known_args(["watch"])
        assert "9999" in args.gateway_url
