"""CLI tests for deterministic session-scope preview/validation."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from clawsentry.cli.main import main


def _write_json(path: Path, payload: dict) -> Path:
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def _profile_payload(**overrides) -> dict:
    payload = {
        "profile_id": "docs-only",
        "source": "operator",
        "confirmed": False,
        "dry_run": True,
        "base_rules": {"denied_paths": ["~/.ssh"]},
        "task_rules": {
            "allowed_tools": ["read_file"],
            "allowed_path_prefixes": ["./docs"],
            "allowed_domains": ["docs.example"],
        },
    }
    payload.update(overrides)
    return payload


def _event_payload(**overrides) -> dict:
    payload = {
        "event_id": "evt-scope-cli",
        "trace_id": "trace-scope-cli",
        "event_type": "pre_action",
        "session_id": "sess-scope-cli",
        "agent_id": "agent-scope-cli",
        "source_framework": "test",
        "occurred_at": "2026-05-02T00:00:00+00:00",
        "tool_name": "read_file",
        "payload": {"path": "~/.ssh/id_rsa"},
    }
    payload.update(overrides)
    return payload


def _run_cli(argv: list[str]) -> None:
    with pytest.raises(SystemExit) as exc_info:
        main(argv)
    assert exc_info.value.code == 0


def test_scope_validate_json_reports_dry_run_boundary(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    profile_path = _write_json(tmp_path / "scope.json", _profile_payload())

    _run_cli(["scope", "validate", "--profile", str(profile_path), "--json"])

    result = json.loads(capsys.readouterr().out)
    assert result["valid"] is True
    assert result["profile_id"] == "docs-only"
    assert result["dry_run"] is True
    assert result["enforced"] is False
    assert "Protected today:" in result["protection_statement"]
    assert "Not protected today:" in result["protection_statement"]


def test_scope_preview_json_shows_deny_reason_without_enforcing_dry_run(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    profile_path = _write_json(tmp_path / "scope.json", _profile_payload())
    event_path = _write_json(tmp_path / "event.json", _event_payload())

    _run_cli([
        "scope",
        "preview",
        "--profile",
        str(profile_path),
        "--event",
        str(event_path),
        "--json",
    ])

    result = json.loads(capsys.readouterr().out)
    assert result["scope_evaluation"]["verdict"] == "deny"
    assert result["scope_evaluation"]["enforced"] is False
    assert "scope_deny:path ~/.ssh" in result["scope_evaluation"]["reason_codes"]
    assert result["mode"] == "dry_run_only"


def test_scope_preview_confirm_option_enforces_profile_for_preview(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    profile_path = _write_json(tmp_path / "scope.json", _profile_payload())
    event_path = _write_json(tmp_path / "event.json", _event_payload())

    _run_cli([
        "scope",
        "preview",
        "--profile",
        str(profile_path),
        "--event",
        str(event_path),
        "--confirm",
        "--json",
    ])

    result = json.loads(capsys.readouterr().out)
    assert result["scope_evaluation"]["verdict"] == "deny"
    assert result["scope_evaluation"]["confirmed"] is True
    assert result["scope_evaluation"]["dry_run"] is False
    assert result["scope_evaluation"]["enforced"] is True
    assert result["mode"] == "enforced"
