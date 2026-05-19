import hashlib
import json
from pathlib import Path

from clawsentry.devtools.skilltrust_surface_acceptance import (
    REQUIRED_FRAMEWORKS,
    validate_acceptance_report,
)


def _artifact(tmp_path: Path, framework: str, row: dict) -> Path:
    artifact = tmp_path / f"{framework}.json"
    artifact.write_text(
        json.dumps({
            "framework": framework,
            "case_id": row["case_id"],
            "command": row["command"],
            "raw_response": {"decision": "block"},
            "replay_record": {"decision": {"decision": "block"}},
        }),
        encoding="utf-8",
    )
    return artifact


def _row(tmp_path: Path, framework: str) -> dict:
    row = {
        "framework": framework,
        "command": ["python3", "scripts/run_skilltrust_surface_acceptance.py"],
        "case_id": f"surface-{framework}-critical-block",
        "artifact_path": "",
        "artifact_sha256": "",
        "observed_decision_metadata": {
            "decision": "block",
            "risk_level": "critical",
            "source_framework": framework,
            "agent_safety_feedback_delivery": "response",
            "agent_safety_feedback_schema": "clawsentry.agent_safety_feedback.v1",
            "skill_trust_rule_hit": "runtime_path_disallowed",
            "skill_use_ledger_decision": "block",
            "skill_use_ledger_runtime_status": "disallowed",
        },
        "pass": True,
    }
    artifact = _artifact(tmp_path, framework, row)
    row["artifact_path"] = str(artifact)
    row["artifact_sha256"] = "sha256:" + hashlib.sha256(artifact.read_bytes()).hexdigest()
    return {
        **row,
    }


def test_skilltrust_surface_acceptance_report_requires_all_framework_evidence(tmp_path: Path):
    incomplete = {"frameworks": [_row(tmp_path, "a3s-code")]}

    problems = validate_acceptance_report(incomplete)

    assert any("missing framework codex" in problem for problem in problems)
    assert any("missing framework openclaw" in problem for problem in problems)


def test_skilltrust_surface_acceptance_report_accepts_complete_evidence(tmp_path: Path):
    report = {"frameworks": [_row(tmp_path, framework) for framework in REQUIRED_FRAMEWORKS]}

    assert validate_acceptance_report(report) == []


def test_skilltrust_surface_acceptance_report_rejects_missing_metadata_fields(tmp_path: Path):
    row = _row(tmp_path, "codex")
    del row["observed_decision_metadata"]["risk_level"]
    report = {
        "frameworks": [
            _row(tmp_path, framework)
            for framework in REQUIRED_FRAMEWORKS
            if framework != "codex"
        ] + [row]
    }

    problems = validate_acceptance_report(report)

    assert any("codex missing observed_decision_metadata.risk_level" in problem for problem in problems)


def test_skilltrust_surface_acceptance_report_rejects_synthetic_or_stale_artifacts(
    tmp_path: Path,
):
    row = _row(tmp_path, "gemini-cli")
    artifact = Path(row["artifact_path"])
    artifact.write_text(
        json.dumps({
            "framework": "gemini-cli",
            "case_id": "wrong-case",
            "command": row["command"],
            "raw_response": {},
            "replay_record": {},
        }),
        encoding="utf-8",
    )
    report = {
        "frameworks": [
            _row(tmp_path, framework)
            for framework in REQUIRED_FRAMEWORKS
            if framework != "gemini-cli"
        ] + [row]
    }

    problems = validate_acceptance_report(report)

    assert any("gemini-cli artifact_sha256 mismatch" in problem for problem in problems)
    assert any("gemini-cli artifact case_id mismatch" in problem for problem in problems)


def test_skilltrust_surface_acceptance_report_rejects_raw_replay_runtime_paths(
    tmp_path: Path,
):
    row = _row(tmp_path, "codex")
    artifact = Path(row["artifact_path"])
    payload = json.loads(artifact.read_text(encoding="utf-8"))
    payload["replay_record"] = {
        "event": {
            "payload": {
                "_clawsentry_meta": {
                    "_gateway_observed": {
                        "runtime_skill_refs": [
                            {
                                "runtime_path_raw": (
                                    "/tmp/clawsentry-surface-runtime/skills/"
                                    "surface-guard/scripts/check.py"
                                )
                            }
                        ]
                    }
                }
            }
        }
    }
    artifact.write_text(json.dumps(payload), encoding="utf-8")
    row["artifact_sha256"] = "sha256:" + hashlib.sha256(artifact.read_bytes()).hexdigest()
    report = {
        "frameworks": [
            _row(tmp_path, framework)
            for framework in REQUIRED_FRAMEWORKS
            if framework != "codex"
        ] + [row]
    }

    problems = validate_acceptance_report(report)

    assert any("codex artifact replay_record contains raw surface runtime root" in problem for problem in problems)
