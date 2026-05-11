"""Tests for the real Codex -> Gateway daemon smoke helper."""

from __future__ import annotations

import json
import sys
from pathlib import Path

from clawsentry.devtools.codex_gateway_e2e_smoke import (
    SmokeResult,
    _build_evidence,
    _required_evidence_pass,
    build_clawsentry_wrapper,
    build_codex_exec_command,
    render_validation_report,
)


def test_build_clawsentry_wrapper_forces_repo_src_imports(tmp_path: Path) -> None:
    repo_root = tmp_path / "repo"
    src_root = repo_root / "src"
    src_root.mkdir(parents=True)

    wrapper = build_clawsentry_wrapper(
        repo_root=repo_root,
        python_executable=sys.executable,
    )

    assert f'PYTHONPATH="{src_root}' in wrapper
    assert f'exec "{sys.executable}" -m clawsentry.cli.main "$@"' in wrapper


def test_build_codex_exec_command_is_json_and_workspace_bounded(tmp_path: Path) -> None:
    codex_home = tmp_path / "codex-home"
    work_dir = tmp_path / "work"
    prompt = "Use the shell to run exactly: grep -R \"api_key\" ."

    command = build_codex_exec_command(
        codex_bin="codex",
        codex_home=codex_home,
        work_dir=work_dir,
        prompt=prompt,
    )

    assert command[:2] == ["codex", "exec"]
    assert "--json" in command
    assert "--sandbox" in command
    assert command[command.index("--sandbox") + 1] == "workspace-write"
    assert "--skip-git-repo-check" in command
    assert command[command.index("-C") + 1] == str(work_dir)
    assert command[-1] == prompt


def test_render_validation_report_redacts_private_paths(tmp_path: Path) -> None:
    result = SmokeResult(
        status="pass",
        codex_version="codex-cli 0.121.0",
        root=tmp_path / "smoke-root",
        codex_home=tmp_path / "smoke-root" / "codex-home",
        work_dir=tmp_path / "smoke-root" / "work",
        uds_path=tmp_path / "smoke-root" / "clawsentry.sock",
        trajectory_db_path=tmp_path / "smoke-root" / "trajectory.sqlite3",
        gateway_log_path=tmp_path / "smoke-root" / "gateway.log",
        codex_sandbox="workspace-write",
        codex_returncode=0,
        codex_stdout_jsonl=[
            json.dumps(
                {
                    "type": "item.completed",
                    "item": {
                        "type": "agent_message",
                        "text": "Command blocked by PreToolUse hook.",
                    },
                }
            )
        ],
        codex_stderr=(
            "Command blocked by PreToolUse hook: [ClawSentry] blocked\n"
            f"extra path: {Path.home() / '.codex' / 'auth.json'}"
        ),
        gateway_summary={"total_decisions": 1},
        report_sessions={"sessions": [{"session_id": "sess-1", "risk_level": "critical"}]},
        evidence={
            "codex_blocked": True,
            "gateway_recorded_decision": True,
            "deny_contract_seen": True,
        },
    )

    report = render_validation_report(result)

    assert str(tmp_path) not in report
    assert str(Path.home()) not in report
    assert "<SMOKE_ROOT>" in report
    assert "<HOME>" in report
    assert "Codex -> Gateway daemon E2E Smoke Validation" in report
    assert "PASS" in report


def test_build_evidence_accepts_current_gateway_report_schema() -> None:
    evidence = _build_evidence(
        codex_returncode=0,
        codex_stdout_lines=[
            json.dumps(
                {
                    "type": "item.completed",
                    "item": {
                        "type": "agent_message",
                        "text": "The requested command was blocked by the environment’s PreToolUse security hook.",
                    },
                }
            )
        ],
        codex_stderr="Command blocked by PreToolUse hook: [ClawSentry] High risk",
        direct_hook_stdout="",
        direct_hook_stderr="",
        direct_hook_returncode=None,
        gateway_summary={
            "total_records": 4,
            "by_decision": {"allow": 3, "block": 1},
            "by_risk_level": {"medium": 3, "high": 1},
        },
        report_sessions={
            "sessions": [
                {
                    "session_id": "sess-1",
                    "current_risk_level": "medium",
                }
            ]
        },
    )

    assert evidence == {
        "codex_process_completed": True,
        "codex_host_pretool_hook_blocked": True,
        "direct_native_hook_blocked": False,
        "deny_contract_seen": True,
        "gateway_recorded_decision": True,
        "gateway_recorded_session": True,
        "gateway_saw_block": True,
    }


def test_build_evidence_accepts_direct_native_hook_block_when_host_hook_is_not_dispatched() -> None:
    evidence = _build_evidence(
        codex_returncode=0,
        codex_stdout_lines=[
            json.dumps(
                {
                    "type": "item.completed",
                    "item": {"type": "agent_message", "text": "real Codex API completed"},
                }
            )
        ],
        codex_stderr="",
        direct_hook_stdout=json.dumps(
            {
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": "deny",
                    "permissionDecisionReason": "[ClawSentry] blocked",
                }
            }
        ),
        direct_hook_stderr="",
        direct_hook_returncode=0,
        gateway_summary={
            "total_records": 1,
            "by_decision": {"block": 1},
            "by_risk_level": {"high": 1},
        },
        report_sessions={"sessions": [{"session_id": "sess-direct-hook"}]},
    )

    assert evidence == {
        "codex_process_completed": True,
        "codex_host_pretool_hook_blocked": False,
        "direct_native_hook_blocked": True,
        "deny_contract_seen": True,
        "gateway_recorded_decision": True,
        "gateway_recorded_session": True,
        "gateway_saw_block": True,
    }
    assert _required_evidence_pass(evidence) is False


def test_build_evidence_rejects_malformed_direct_native_hook_output() -> None:
    evidence = _build_evidence(
        codex_returncode=0,
        codex_stdout_lines=[],
        codex_stderr="",
        direct_hook_stdout="permissionDecision deny",
        direct_hook_stderr="",
        direct_hook_returncode=0,
        gateway_summary={"total_records": 1, "by_decision": {"block": 1}},
        report_sessions={"sessions": [{"session_id": "sess-direct-hook"}]},
    )

    assert evidence["direct_native_hook_blocked"] is False
    assert evidence["deny_contract_seen"] is False
