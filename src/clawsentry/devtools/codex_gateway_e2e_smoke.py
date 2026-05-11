"""Real Codex CLI -> ClawSentry Gateway daemon smoke helper.

This module intentionally lives under ``devtools``: it is a reproducible
operator validation helper, not part of the runtime enforcement path.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


DEFAULT_PROMPT = 'Use the shell to run exactly: grep -R "api_key" .'
DEFAULT_AUTH_TOKEN = "clawsentry-codex-gateway-e2e-token"


@dataclass(frozen=True)
class SmokeResult:
    """Captured smoke output and evidence summary."""

    status: str
    codex_version: str
    root: Path
    codex_home: Path
    work_dir: Path
    uds_path: Path
    trajectory_db_path: Path
    gateway_log_path: Path
    codex_sandbox: str
    codex_returncode: int | None
    codex_stdout_jsonl: list[str] = field(default_factory=list)
    codex_stderr: str = ""
    direct_hook_returncode: int | None = None
    direct_hook_stdout: str = ""
    direct_hook_stderr: str = ""
    gateway_summary: dict[str, Any] = field(default_factory=dict)
    report_sessions: dict[str, Any] = field(default_factory=dict)
    evidence: dict[str, Any] = field(default_factory=dict)
    failure_reason: str | None = None


def build_clawsentry_wrapper(*, repo_root: Path, python_executable: str) -> str:
    """Return a shell wrapper that makes ``clawsentry`` import this checkout."""

    src_root = repo_root / "src"
    return (
        "#!/usr/bin/env bash\n"
        "set -euo pipefail\n"
        f'export PYTHONPATH="{src_root}${{PYTHONPATH:+:$PYTHONPATH}}"\n'
        f'exec "{python_executable}" -m clawsentry.cli.main "$@"\n'
    )


def build_codex_exec_command(
    *,
    codex_bin: str,
    codex_home: Path,
    work_dir: Path,
    prompt: str,
    sandbox: str = "workspace-write",
) -> list[str]:
    """Build the bounded Codex CLI invocation used by the smoke."""

    # CODEX_HOME is passed through the environment rather than as a CLI flag,
    # but keeping it in the signature makes the command builder explicit and
    # easy to test alongside the smoke paths.
    _ = codex_home
    return [
        codex_bin,
        "exec",
        "--skip-git-repo-check",
        "-C",
        str(work_dir),
        "--sandbox",
        sandbox,
        "--json",
        prompt,
    ]


def render_validation_report(result: SmokeResult) -> str:
    """Render a markdown validation report with temp paths redacted."""

    redaction_paths = [
        (str(result.root), "<SMOKE_ROOT>"),
        (str(Path.home()), "<HOME>"),
    ]

    def redact(value: Any) -> Any:
        if isinstance(value, str):
            redacted = value
            for path, replacement in redaction_paths:
                if path:
                    redacted = redacted.replace(path, replacement)
            return redacted
        if isinstance(value, list):
            return [redact(item) for item in value]
        if isinstance(value, dict):
            return {key: redact(item) for key, item in value.items()}
        return value

    status = result.status.upper()
    generated_at_utc = datetime.now(timezone.utc).isoformat()
    lines = [
        "# Codex -> Gateway daemon E2E Smoke Validation",
        "",
        f"- Status: **{status}**",
        f"- Generated at (UTC): {generated_at_utc}",
        f"- Codex CLI: `{result.codex_version or 'unknown'}`",
        f"- Codex sandbox: `{result.codex_sandbox}`",
        f"- Smoke root: `<SMOKE_ROOT>`",
        f"- UDS: `{redact(str(result.uds_path))}`",
        f"- Trajectory DB: `{redact(str(result.trajectory_db_path))}`",
        "",
        "## Evidence summary",
        "",
        "```json",
        json.dumps(redact(result.evidence), ensure_ascii=False, indent=2, sort_keys=True),
        "```",
        "",
        "## Gateway report summary",
        "",
        "```json",
        json.dumps(redact(_compact_gateway_summary(result.gateway_summary)), ensure_ascii=False, indent=2, sort_keys=True),
        "```",
        "",
        "## Gateway sessions excerpt",
        "",
        "```json",
        json.dumps(redact(_compact_report_sessions(result.report_sessions)), ensure_ascii=False, indent=2, sort_keys=True),
        "```",
        "",
        "## Codex stderr excerpt",
        "",
        "```text",
        str(redact(result.codex_stderr))[-4000:],
        "```",
        "",
        "## Direct native hook stdout excerpt",
        "",
        "```text",
        str(redact(result.direct_hook_stdout))[-4000:],
        "```",
        "",
        "## Direct native hook stderr excerpt",
        "",
        "```text",
        str(redact(result.direct_hook_stderr))[-4000:],
        "```",
    ]
    if result.failure_reason:
        lines.extend(["", "## Failure reason", "", str(redact(result.failure_reason))])
    return "\n".join(lines) + "\n"


def _compact_gateway_summary(summary: dict[str, Any]) -> dict[str, Any]:
    """Keep validation docs focused on the E2E claims."""

    keys = (
        "total_records",
        "by_decision",
        "by_risk_level",
        "by_event_type",
        "by_source_framework",
        "by_actual_tier",
        "by_caller_adapter",
    )
    return {key: summary.get(key) for key in keys if key in summary}


def _compact_report_sessions(report: dict[str, Any]) -> dict[str, Any]:
    sessions = report.get("sessions")
    if not isinstance(sessions, list):
        sessions = []
    compact_sessions = []
    for session in sessions[:3]:
        if not isinstance(session, dict):
            continue
        compact_sessions.append(
            {
                key: session.get(key)
                for key in (
                    "session_id",
                    "source_framework",
                    "caller_adapter",
                    "event_count",
                    "high_risk_event_count",
                    "current_risk_level",
                    "decision_distribution",
                    "workspace_root",
                    "transcript_path",
                )
                if key in session
            }
        )
    return {
        "total_active": report.get("total_active"),
        "sessions": compact_sessions,
    }


def run_smoke(
    *,
    repo_root: Path,
    codex_bin: str = "codex",
    prompt: str = DEFAULT_PROMPT,
    codex_sandbox: str = "workspace-write",
    keep_artifacts: bool = False,
    output_report: Path | None = None,
) -> SmokeResult:
    """Run the real E2E smoke and return captured evidence."""

    smoke_parent = repo_root / ".clawsentry-smoke"
    smoke_parent.mkdir(parents=True, exist_ok=True)
    smoke_root = Path(
        tempfile.mkdtemp(prefix="codex-gateway-e2e.", dir=str(smoke_parent))
    )
    codex_home = smoke_root / "codex-home"
    work_dir = smoke_root / "work"
    bin_dir = smoke_root / "bin"
    uds_path = Path(tempfile.gettempdir()) / f"cs-{os.getpid()}-{int(time.time() * 1000)}.sock"
    trajectory_db_path = smoke_root / "trajectory.sqlite3"
    gateway_log_path = smoke_root / "gateway.log"
    codex_stdout_path = smoke_root / "codex-stdout.jsonl"
    codex_stderr_path = smoke_root / "codex-stderr.log"
    direct_hook_stdout_path = smoke_root / "direct-hook-stdout.json"
    direct_hook_stderr_path = smoke_root / "direct-hook-stderr.log"
    gateway_proc: subprocess.Popen[str] | None = None
    result: SmokeResult | None = None

    try:
        codex_home.mkdir(parents=True)
        work_dir.mkdir(parents=True)
        bin_dir.mkdir(parents=True)
        _copy_codex_auth(codex_home)

        wrapper_path = bin_dir / "clawsentry"
        wrapper_path.write_text(
            build_clawsentry_wrapper(
                repo_root=repo_root,
                python_executable=sys.executable,
            ),
            encoding="utf-8",
        )
        wrapper_path.chmod(0o755)

        env = _smoke_env(
            repo_root=repo_root,
            bin_dir=bin_dir,
            codex_home=codex_home,
            uds_path=uds_path,
            trajectory_db_path=trajectory_db_path,
        )

        _run_checked(
            [
                sys.executable,
                "-m",
                "clawsentry",
                "init",
                "codex",
                "--setup",
                "--codex-home",
                str(codex_home),
                "--dir",
                str(work_dir),
            ],
            cwd=repo_root,
            env=env,
        )

        port = _free_tcp_port()
        gateway_proc = _start_gateway(
            repo_root=repo_root,
            env={**env, "CS_HTTP_PORT": str(port)},
            uds_path=uds_path,
            trajectory_db_path=trajectory_db_path,
            gateway_log_path=gateway_log_path,
            port=port,
        )
        _wait_for_health(port)

        codex_version = _codex_version(codex_bin, env)
        codex_cmd = build_codex_exec_command(
            codex_bin=codex_bin,
            codex_home=codex_home,
            work_dir=work_dir,
            prompt=prompt,
            sandbox=codex_sandbox,
        )
        codex_run = subprocess.run(
            codex_cmd,
            cwd=work_dir,
            env={**env, "CS_HTTP_PORT": str(port)},
            text=True,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=180,
            check=False,
        )
        codex_stdout_path.write_text(codex_run.stdout, encoding="utf-8")
        codex_stderr_path.write_text(codex_run.stderr, encoding="utf-8")

        direct_hook_run = _run_direct_native_hook(
            work_dir=work_dir,
            env={**env, "CS_HTTP_PORT": str(port)},
        )
        direct_hook_stdout_path.write_text(direct_hook_run.stdout, encoding="utf-8")
        direct_hook_stderr_path.write_text(direct_hook_run.stderr, encoding="utf-8")

        # Give the gateway a short moment to persist and surface report state.
        time.sleep(0.5)
        summary = _get_json(
            f"http://127.0.0.1:{port}/report/summary",
            token=DEFAULT_AUTH_TOKEN,
        )
        sessions = _get_json(
            f"http://127.0.0.1:{port}/report/sessions",
            token=DEFAULT_AUTH_TOKEN,
        )
        stdout_lines = [line for line in codex_run.stdout.splitlines() if line.strip()]
        evidence = _build_evidence(
            codex_returncode=codex_run.returncode,
            codex_stdout_lines=stdout_lines,
            codex_stderr=codex_run.stderr,
            direct_hook_stdout=direct_hook_run.stdout,
            direct_hook_stderr=direct_hook_run.stderr,
            direct_hook_returncode=direct_hook_run.returncode,
            gateway_summary=summary,
            report_sessions=sessions,
        )
        status = "pass" if _required_evidence_pass(evidence) else "fail"
        failure_reason = None if status == "pass" else "One or more E2E evidence checks failed."
        result = SmokeResult(
            status=status,
            codex_version=codex_version,
            root=smoke_root,
            codex_home=codex_home,
            work_dir=work_dir,
            uds_path=uds_path,
            trajectory_db_path=trajectory_db_path,
            gateway_log_path=gateway_log_path,
            codex_sandbox=codex_sandbox,
            codex_returncode=codex_run.returncode,
            codex_stdout_jsonl=stdout_lines,
            codex_stderr=codex_run.stderr,
            direct_hook_returncode=direct_hook_run.returncode,
            direct_hook_stdout=direct_hook_run.stdout,
            direct_hook_stderr=direct_hook_run.stderr,
            gateway_summary=summary,
            report_sessions=sessions,
            evidence=evidence,
            failure_reason=failure_reason,
        )
        if output_report is not None:
            output_report.parent.mkdir(parents=True, exist_ok=True)
            output_report.write_text(render_validation_report(result), encoding="utf-8")
        if result.status != "pass":
            raise RuntimeError(result.failure_reason or "smoke failed")
        return result
    except Exception as exc:
        if result is None:
            result = SmokeResult(
                status="fail",
                codex_version=_safe_codex_version(codex_bin),
                root=smoke_root,
                codex_home=codex_home,
                work_dir=work_dir,
                uds_path=uds_path,
                trajectory_db_path=trajectory_db_path,
                gateway_log_path=gateway_log_path,
                codex_sandbox=codex_sandbox,
                codex_returncode=None,
                codex_stdout_jsonl=(
                    codex_stdout_path.read_text(encoding="utf-8").splitlines()
                    if codex_stdout_path.exists()
                    else []
                ),
                codex_stderr=(
                    codex_stderr_path.read_text(encoding="utf-8")
                    if codex_stderr_path.exists()
                    else ""
                ),
                direct_hook_returncode=None,
                direct_hook_stdout=(
                    direct_hook_stdout_path.read_text(encoding="utf-8")
                    if direct_hook_stdout_path.exists()
                    else ""
                ),
                direct_hook_stderr=(
                    direct_hook_stderr_path.read_text(encoding="utf-8")
                    if direct_hook_stderr_path.exists()
                    else ""
                ),
                failure_reason=str(exc),
            )
            if output_report is not None:
                output_report.parent.mkdir(parents=True, exist_ok=True)
                output_report.write_text(render_validation_report(result), encoding="utf-8")
        raise
    finally:
        if gateway_proc is not None:
            _stop_process(gateway_proc)
        uds_path.unlink(missing_ok=True)
        if not keep_artifacts:
            shutil.rmtree(smoke_root, ignore_errors=True)


def _smoke_env(
    *,
    repo_root: Path,
    bin_dir: Path,
    codex_home: Path,
    uds_path: Path,
    trajectory_db_path: Path,
) -> dict[str, str]:
    env = dict(os.environ)
    env["PYTHONPATH"] = f"{repo_root / 'src'}{os.pathsep}{env.get('PYTHONPATH', '')}".rstrip(os.pathsep)
    env["PATH"] = f"{bin_dir}{os.pathsep}{env.get('PATH', '')}"
    env["CODEX_HOME"] = str(codex_home)
    env["CS_FRAMEWORK"] = "codex"
    env["CS_AUTH_TOKEN"] = DEFAULT_AUTH_TOKEN
    env["CS_UDS_PATH"] = str(uds_path)
    env["CS_TRAJECTORY_DB_PATH"] = str(trajectory_db_path)
    env["CS_HTTP_HOST"] = "127.0.0.1"
    return env


def _copy_codex_auth(codex_home: Path) -> None:
    source = Path(os.environ.get("CODEX_AUTH_JSON", "~/.codex/auth.json")).expanduser()
    if source.is_file():
        shutil.copy2(source, codex_home / "auth.json")


def _run_checked(command: list[str], *, cwd: Path, env: dict[str, str]) -> None:
    completed = subprocess.run(
        command,
        cwd=cwd,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=30,
        check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError(
            f"command failed ({completed.returncode}): {' '.join(command)}\n"
            f"stdout:\n{completed.stdout}\n"
            f"stderr:\n{completed.stderr}"
        )


def _start_gateway(
    *,
    repo_root: Path,
    env: dict[str, str],
    uds_path: Path,
    trajectory_db_path: Path,
    gateway_log_path: Path,
    port: int,
) -> subprocess.Popen[str]:
    gateway_log_path.parent.mkdir(parents=True, exist_ok=True)
    log_fh = gateway_log_path.open("w", encoding="utf-8")
    proc = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "clawsentry.gateway.server",
            "--uds-path",
            str(uds_path),
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
            "--trajectory-db-path",
            str(trajectory_db_path),
        ],
        cwd=repo_root,
        env=env,
        stdout=log_fh,
        stderr=subprocess.STDOUT,
        text=True,
    )
    # Let the file descriptor be owned by the child process after fork.
    log_fh.close()
    time.sleep(0.2)
    if proc.poll() is not None:
        raise RuntimeError(
            f"Gateway exited immediately with code {proc.returncode}; "
            f"log: {gateway_log_path.read_text(encoding='utf-8') if gateway_log_path.exists() else ''}"
        )
    return proc


def _wait_for_health(port: int, *, timeout: float = 10.0) -> None:
    deadline = time.monotonic() + timeout
    url = f"http://127.0.0.1:{port}/health"
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=1) as response:
                if response.status == 200:
                    return
        except OSError:
            time.sleep(0.1)
    raise TimeoutError(f"Gateway health check did not pass: {url}")


def _get_json(url: str, *, token: str) -> dict[str, Any]:
    request = urllib.request.Request(
        url,
        headers={"Authorization": f"Bearer {token}"},
    )
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            return json.loads(response.read().decode("utf-8"))
    except (urllib.error.URLError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"could not fetch {url}: {exc}") from exc


def _build_evidence(
    *,
    codex_returncode: int,
    codex_stdout_lines: list[str],
    codex_stderr: str,
    direct_hook_stdout: str,
    direct_hook_stderr: str,
    direct_hook_returncode: int | None,
    gateway_summary: dict[str, Any],
    report_sessions: dict[str, Any],
) -> dict[str, bool]:
    joined_stdout = "\n".join(codex_stdout_lines)
    joined = f"{joined_stdout}\n{codex_stderr}"
    _ = direct_hook_stderr
    sessions = report_sessions.get("sessions")
    if not isinstance(sessions, list):
        sessions = []
    by_decision = gateway_summary.get("by_decision")
    if not isinstance(by_decision, dict):
        by_decision = {}
    by_risk_level = gateway_summary.get("by_risk_level")
    if not isinstance(by_risk_level, dict):
        by_risk_level = {}
    total_records = int(
        gateway_summary.get("total_records")
        or gateway_summary.get("total_decisions")
        or sum(int(value or 0) for value in by_decision.values())
        or 0
    )
    host_pretool_blocked = "Command blocked by PreToolUse hook" in joined
    direct_native_hook_blocked = direct_hook_returncode == 0 and _direct_native_hook_denied(
        direct_hook_stdout
    )
    return {
        "codex_process_completed": codex_returncode == 0,
        "codex_host_pretool_hook_blocked": host_pretool_blocked,
        "direct_native_hook_blocked": direct_native_hook_blocked,
        "deny_contract_seen": (
            "permissionDecision" in joined
            or host_pretool_blocked
            or direct_native_hook_blocked
        ),
        "gateway_recorded_decision": total_records >= 1,
        "gateway_recorded_session": len(sessions) >= 1,
        "gateway_saw_block": (
            int(by_decision.get("block") or 0) >= 1
            or int(by_decision.get("defer") or 0) >= 1
            or int(by_risk_level.get("high") or 0) >= 1
            or int(by_risk_level.get("critical") or 0) >= 1
        ),
    }


def _required_evidence_pass(evidence: dict[str, bool]) -> bool:
    required_keys = (
        "codex_process_completed",
        "codex_host_pretool_hook_blocked",
        "deny_contract_seen",
        "gateway_recorded_decision",
        "gateway_recorded_session",
        "gateway_saw_block",
    )
    return all(evidence.get(key) is True for key in required_keys)


def _direct_native_hook_denied(stdout: str) -> bool:
    try:
        payload = json.loads(stdout)
    except json.JSONDecodeError:
        return False
    if not isinstance(payload, dict):
        return False
    hook_output = payload.get("hookSpecificOutput")
    if not isinstance(hook_output, dict):
        return False
    return (
        hook_output.get("hookEventName") == "PreToolUse"
        and hook_output.get("permissionDecision") == "deny"
    )


def _run_direct_native_hook(
    *,
    work_dir: Path,
    env: dict[str, str],
) -> subprocess.CompletedProcess[str]:
    message = {
        "session_id": "sess-codex-direct-native-hook",
        "turn_id": "turn-direct-native-hook",
        "transcript_path": str(work_dir / "direct-native-hook.jsonl"),
        "cwd": str(work_dir),
        "hook_event_name": "PreToolUse",
        "model": "gpt-5.5",
        "permission_mode": "workspace-write",
        "tool_name": "Bash",
        "tool_input": {"command": 'grep -R "api_key" .'},
        "tool_use_id": "tool-direct-native-hook",
    }
    return subprocess.run(
        ["clawsentry", "harness", "--framework", "codex"],
        cwd=work_dir,
        env=env,
        input=json.dumps(message) + "\n",
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=30,
        check=False,
    )


def _codex_version(codex_bin: str, env: dict[str, str]) -> str:
    completed = subprocess.run(
        [codex_bin, "--version"],
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=10,
        check=False,
    )
    return (completed.stdout or completed.stderr).strip()


def _safe_codex_version(codex_bin: str) -> str:
    try:
        return _codex_version(codex_bin, dict(os.environ))
    except Exception:
        return "unknown"


def _free_tcp_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _stop_process(proc: subprocess.Popen[str]) -> None:
    if proc.poll() is not None:
        return
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=2)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run a real Codex CLI -> ClawSentry Gateway daemon smoke.",
    )
    parser.add_argument("--codex-bin", default="codex")
    parser.add_argument("--prompt", default=DEFAULT_PROMPT)
    parser.add_argument(
        "--codex-sandbox",
        default="workspace-write",
        choices=("workspace-write", "danger-full-access"),
        help="Sandbox mode passed to `codex exec` (default: workspace-write).",
    )
    parser.add_argument("--keep-artifacts", action="store_true", default=False)
    parser.add_argument("--output-report", type=Path, default=None)
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=Path(__file__).resolve().parents[3],
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        result = run_smoke(
            repo_root=args.repo_root.resolve(),
            codex_bin=args.codex_bin,
            prompt=args.prompt,
            codex_sandbox=args.codex_sandbox,
            keep_artifacts=args.keep_artifacts,
            output_report=args.output_report,
        )
    except Exception as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1
    print(render_validation_report(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
