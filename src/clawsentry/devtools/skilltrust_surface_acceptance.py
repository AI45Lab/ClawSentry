"""Cross-framework Skill Trust surface acceptance helper.

This devtool records a current, reproducible surface-level Gateway check for
the Skill Trust runtime-binding plan.  It exercises the real Gateway UDS path
and framework adapters/harnesses, then writes per-framework artifacts plus a
summary report with the fields required by the plan acceptance gate.
"""

from __future__ import annotations

import argparse
import asyncio
import copy
import hashlib
import json
import os
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from clawsentry.adapters.a3s_adapter import A3SCodeAdapter
from clawsentry.adapters.a3s_gateway_harness import A3SGatewayHarness
from clawsentry.adapters.openclaw_gateway_client import OpenClawGatewayClient
from clawsentry.gateway.detection_config import DetectionConfig
from clawsentry.gateway.models import (
    AgentTrustLevel,
    CanonicalEvent,
    DecisionContext,
    DecisionTier,
    EventType,
    SkillTrustContext,
)
from clawsentry.gateway.server import SupervisionGateway, start_uds_server


REQUIRED_FRAMEWORKS = (
    "a3s-code",
    "codex",
    "claude-code",
    "kimi-cli",
    "gemini-cli",
    "openclaw",
)

_REQUIRED_ROW_FIELDS = (
    "framework",
    "command",
    "case_id",
    "artifact_path",
    "artifact_sha256",
    "observed_decision_metadata",
    "pass",
)

_REQUIRED_METADATA_FIELDS = (
    "decision",
    "risk_level",
    "source_framework",
    "agent_safety_feedback_delivery",
    "skill_trust_rule_hit",
    "skill_use_ledger_decision",
    "skill_use_ledger_runtime_status",
)


@dataclass(frozen=True)
class SurfaceCase:
    framework: str
    case_id: str
    command: list[str]
    raw_response: Any
    replay_record: dict[str, Any]
    artifact_path: Path


def validate_acceptance_report(report: dict[str, Any]) -> list[str]:
    """Return schema/coverage problems for a surface acceptance report."""

    rows = report.get("frameworks")
    if not isinstance(rows, list):
        return ["frameworks must be a list"]

    problems: list[str] = []
    by_framework = {
        str(row.get("framework")): row for row in rows if isinstance(row, dict)
    }
    for framework in REQUIRED_FRAMEWORKS:
        row = by_framework.get(framework)
        if row is None:
            problems.append(f"missing framework {framework}")
            continue
        for field in _REQUIRED_ROW_FIELDS:
            if field not in row:
                problems.append(f"{framework} missing {field}")
        artifact_path = row.get("artifact_path")
        artifact_sha256 = row.get("artifact_sha256")
        if isinstance(artifact_path, str) and artifact_path:
            artifact = Path(artifact_path)
            if not artifact.is_file():
                problems.append(f"{framework} artifact_path does not exist")
            else:
                actual_sha256 = _sha256_file(artifact)
                if artifact_sha256 != actual_sha256:
                    problems.append(f"{framework} artifact_sha256 mismatch")
                try:
                    artifact_payload = json.loads(artifact.read_text(encoding="utf-8"))
                except (OSError, json.JSONDecodeError):
                    problems.append(f"{framework} artifact is not valid JSON")
                else:
                    if artifact_payload.get("framework") != framework:
                        problems.append(f"{framework} artifact framework mismatch")
                    if artifact_payload.get("case_id") != row.get("case_id"):
                        problems.append(f"{framework} artifact case_id mismatch")
                    if artifact_payload.get("command") != row.get("command"):
                        problems.append(f"{framework} artifact command mismatch")
                    if not isinstance(artifact_payload.get("replay_record"), dict):
                        problems.append(f"{framework} artifact missing replay_record")
                    if "raw_response" not in artifact_payload:
                        problems.append(f"{framework} artifact missing raw_response")
                    raw_material_problem = _artifact_raw_runtime_material_problem(artifact_payload)
                    if raw_material_problem:
                        problems.append(f"{framework} {raw_material_problem}")
        if not isinstance(artifact_sha256, str) or not artifact_sha256.startswith("sha256:"):
            problems.append(f"{framework} missing artifact_sha256")
        metadata = row.get("observed_decision_metadata")
        if not isinstance(metadata, dict):
            problems.append(f"{framework} observed_decision_metadata must be an object")
            continue
        for field in _REQUIRED_METADATA_FIELDS:
            if metadata.get(field) in (None, ""):
                problems.append(f"{framework} missing observed_decision_metadata.{field}")
        if metadata.get("decision") != "block":
            problems.append(f"{framework} expected block decision")
        if metadata.get("risk_level") != "critical":
            problems.append(f"{framework} expected critical risk")
        if metadata.get("agent_safety_feedback_schema") != "clawsentry.agent_safety_feedback.v1":
            problems.append(f"{framework} missing agent safety feedback schema")
        if metadata.get("skill_trust_rule_hit") != "runtime_path_disallowed":
            problems.append(f"{framework} missing runtime_path_disallowed skill trust evidence")
        if metadata.get("skill_use_ledger_decision") != "block":
            problems.append(f"{framework} missing blocked skill-use ledger decision")
        if metadata.get("skill_use_ledger_runtime_status") != "disallowed":
            problems.append(f"{framework} missing disallowed runtime status in skill-use ledger")
    return problems


async def run_surface_acceptance(output_dir: Path) -> dict[str, Any]:
    """Run all framework surface checks and write artifacts."""

    output_dir.mkdir(parents=True, exist_ok=True)
    metadata_path = output_dir / "skill-trust-runtime.json"
    metadata_path.write_text(
        json.dumps(_surface_skill_metadata_bundle(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    uds_path = Path(tempfile.gettempdir()) / (
        f"clawsentry-skilltrust-surface-{os.getpid()}.sock"
    )
    gateway = SupervisionGateway(
        detection_config=DetectionConfig(
            mode="strict",
            agent_safety_feedback_enabled=True,
        )
    )
    previous_metadata_path = os.environ.get("CS_SKILL_TRUST_METADATA_PATH")
    os.environ["CS_SKILL_TRUST_METADATA_PATH"] = str(metadata_path)
    server = await start_uds_server(gateway, str(uds_path))
    try:
        cases: list[SurfaceCase] = []
        for framework in ("a3s-code", "codex", "claude-code", "kimi-cli", "gemini-cli"):
            cases.append(
            await _run_harness_surface_case(
                    gateway=gateway,
                    uds_path=uds_path,
                    output_dir=output_dir,
                    framework=framework,
                )
            )
        cases.append(
            await _run_openclaw_surface_case(
                gateway=gateway,
                uds_path=uds_path,
                output_dir=output_dir,
            )
        )
    finally:
        server.close()
        await server.wait_closed()
        uds_path.unlink(missing_ok=True)
        if previous_metadata_path is None:
            os.environ.pop("CS_SKILL_TRUST_METADATA_PATH", None)
        else:
            os.environ["CS_SKILL_TRUST_METADATA_PATH"] = previous_metadata_path

    report = {
        "schema": "clawsentry.skilltrust_surface_acceptance.v1",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "frameworks": [_row_from_case(case) for case in cases],
    }
    report["problems"] = validate_acceptance_report(report)
    report["pass"] = not report["problems"] and all(
        bool(row.get("pass")) for row in report["frameworks"]
    )
    (output_dir / "report.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    (output_dir / "report.md").write_text(_render_markdown(report), encoding="utf-8")
    return report


async def _run_harness_surface_case(
    *,
    gateway: SupervisionGateway,
    uds_path: Path,
    output_dir: Path,
    framework: str,
) -> SurfaceCase:
    adapter = A3SCodeAdapter(
        uds_path=str(uds_path),
        default_deadline_ms=1000,
        source_framework=framework,
    )
    harness = A3SGatewayHarness(adapter=adapter)
    case_id = f"surface-{framework}-critical-block"
    session_id = f"sess-{case_id}"
    command = _command_for_framework(framework)
    response = await harness.dispatch_async(_message_for_framework(framework, session_id))
    record = _redacted_surface_replay_record(_latest_record(gateway, session_id))
    artifact_path = output_dir / f"{framework}.json"
    artifact_path.write_text(
        json.dumps(
            {
                "framework": framework,
                "case_id": case_id,
                "command": command,
                "raw_response": response,
                "replay_record": record,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    return SurfaceCase(
        framework=framework,
        case_id=case_id,
        command=command,
        raw_response=response,
        replay_record=record,
        artifact_path=artifact_path,
    )


async def _run_openclaw_surface_case(
    *,
    gateway: SupervisionGateway,
    uds_path: Path,
    output_dir: Path,
) -> SurfaceCase:
    framework = "openclaw"
    case_id = "surface-openclaw-critical-block"
    session_id = f"sess-{case_id}"
    command = [
        "python3",
        "scripts/run_skilltrust_surface_acceptance.py",
        "--framework",
        framework,
    ]
    skill_command = _surface_skill_command(framework)
    event = CanonicalEvent(
        schema_version="ahp.1.0",
        event_id="evt-openclaw-surface-critical-block",
        trace_id="trace-openclaw-surface-critical-block",
        event_type=EventType.PRE_ACTION,
        session_id=session_id,
        agent_id="agent-surface-openclaw",
        source_framework=framework,
        event_subtype="exec.approval.requested",
        source_protocol_version="1.0",
        mapping_profile="openclaw@surface/protocol.v1.0/profile.v1",
        occurred_at=datetime.now(timezone.utc).isoformat(),
        tool_name="bash",
        payload={
            "tool": "bash",
            "tool_name": "bash",
            "command": skill_command,
            "_clawsentry_meta": {
                "skill_lineage_raw": {
                    "native_tool_label": "bash",
                    "observed_name": _SURFACE_SKILL_NAME,
                    "runtime_evidence_kind": "shell_skill_path",
                    "runtime_path_status": "disallowed",
                    "runtime_root_path_hash": _runtime_root_path_hash(_SURFACE_RUNTIME_ROOT),
                    "metadata_record_id": _SURFACE_METADATA_RECORD_ID,
                    "ref_ordinal": 0,
                }
            },
        },
    )
    client = OpenClawGatewayClient(
        uds_path=str(uds_path),
        default_deadline_ms=1000,
        max_rpc_retries=0,
    )
    decision = await client.request_decision(
        event,
        context=DecisionContext(
            agent_trust_level=AgentTrustLevel.STANDARD,
            skill_trust=SkillTrustContext(
                registry_status="matched",
                canonical_skill_id=f"skill:{_SURFACE_SKILL_NAME}",
                presented_name=_SURFACE_SKILL_NAME,
                provenance_claim=_SURFACE_SKILL_NAME,
                trust_list_state="allowlist",
                runtime_path_status="disallowed",
                runtime_root_path_hash=_runtime_root_path_hash(_SURFACE_RUNTIME_ROOT),
                runtime_evidence_kind="shell_skill_path",
                metadata_record_id=_SURFACE_METADATA_RECORD_ID,
                ref_ordinal=0,
                invariant_violations=["runtime_path_disallowed"],
            ),
        ),
        decision_tier=DecisionTier.L1,
    )
    record = _redacted_surface_replay_record(_latest_record(gateway, session_id))
    artifact_path = output_dir / "openclaw.json"
    artifact_path.write_text(
        json.dumps(
            {
                "framework": framework,
                "case_id": case_id,
                "command": command,
                "raw_response": {
                    "decision": decision.model_dump(mode="json"),
                    "adapter_response_metadata": client.last_decision_response_metadata,
                },
                "replay_record": record,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    return SurfaceCase(
        framework=framework,
        case_id=case_id,
        command=command,
        raw_response=decision.model_dump(mode="json"),
        replay_record=record,
        artifact_path=artifact_path,
    )


def _message_for_framework(framework: str, session_id: str) -> dict[str, Any]:
    if framework == "a3s-code":
        return {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "ahp/event",
            "params": {
                "event_type": "pre_action",
                "session_id": session_id,
                "agent_id": f"agent-surface-{framework}",
                "tool_name": "bash",
                "payload": {
                    "tool": "bash",
                    "tool_name": "bash",
                    "command": _surface_skill_command(framework),
                },
            },
        }

    hook_event_name = "BeforeTool" if framework == "gemini-cli" else "PreToolUse"
    tool_name = "run_shell_command" if framework == "gemini-cli" else "Bash"
    return {
        "hook_event_name": hook_event_name,
        "session_id": session_id,
        "agent_id": f"agent-surface-{framework}",
        "cwd": "/tmp",
        "tool_name": tool_name,
        "tool_input": {
            "command": _surface_skill_command(framework)
        },
    }


def _command_for_framework(framework: str) -> list[str]:
    if framework == "a3s-code":
        return [
            "python3",
            "scripts/run_skilltrust_surface_acceptance.py",
            "--framework",
            framework,
            "--transport",
            "ahp-jsonrpc-uds",
        ]
    return [
        "python3",
        "scripts/run_skilltrust_surface_acceptance.py",
        "--framework",
        framework,
        "--transport",
        "native-harness-uds",
    ]


def _latest_record(gateway: SupervisionGateway, session_id: str) -> dict[str, Any]:
    replay = gateway.replay_session(session_id)
    records = replay.get("records") if isinstance(replay, dict) else None
    if not records:
        raise RuntimeError(f"no replay record for {session_id}")
    return records[-1]


def _redacted_surface_replay_record(record: dict[str, Any]) -> dict[str, Any]:
    """Return a replay artifact copy without raw runtime paths or commands."""

    redacted = copy.deepcopy(record)
    event = redacted.get("event")
    if not isinstance(event, dict):
        return redacted
    payload = event.get("payload")
    if not isinstance(payload, dict):
        return redacted
    _redact_command_fields(payload)
    args = payload.get("arguments")
    if isinstance(args, dict):
        _redact_command_fields(args)
    meta = payload.get("_clawsentry_meta")
    if isinstance(meta, dict):
        observed = meta.get("_gateway_observed")
        if isinstance(observed, dict):
            refs = observed.get("runtime_skill_refs")
            if isinstance(refs, list):
                for ref in refs:
                    if not isinstance(ref, dict):
                        continue
                    root_hash = ref.get("observed_runtime_root_path_hash")
                    for raw_key in (
                        "runtime_path",
                        "runtime_path_raw",
                        "runtime_root",
                        "runtime_root_raw",
                    ):
                        ref.pop(raw_key, None)
                    if root_hash is not None:
                        ref["runtime_root_path_hash"] = root_hash
    return redacted


def _redact_command_fields(payload: dict[str, Any]) -> None:
    command = payload.pop("command", None)
    if isinstance(command, str):
        payload["command_sha256"] = "sha256:" + hashlib.sha256(command.encode("utf-8")).hexdigest()
        payload["command_redacted"] = True


def _artifact_raw_runtime_material_problem(artifact_payload: dict[str, Any]) -> str | None:
    replay_record = artifact_payload.get("replay_record")
    if not isinstance(replay_record, dict):
        return None
    material = json.dumps(replay_record, sort_keys=True)
    if _SURFACE_RUNTIME_ROOT in material:
        return "artifact replay_record contains raw surface runtime root"
    if "/tmp/clawsentry-surface-" in material:
        return "artifact replay_record contains raw surface command target"
    for field_name in ("runtime_path_raw", "runtime_root_raw", "runtime_path", "runtime_root"):
        if f'"{field_name}"' in material:
            return f"artifact replay_record contains raw {field_name}"
    return None


def _row_from_case(case: SurfaceCase) -> dict[str, Any]:
    observed = _observed_metadata(case.replay_record)
    return {
        "framework": case.framework,
        "command": case.command,
        "case_id": case.case_id,
        "artifact_path": str(case.artifact_path),
        "artifact_sha256": _sha256_file(case.artifact_path),
        "observed_decision_metadata": observed,
        "pass": observed.get("decision") == "block"
        and observed.get("risk_level") == "critical",
    }


def _sha256_file(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def _observed_metadata(record: dict[str, Any]) -> dict[str, Any]:
    decision = record.get("decision") if isinstance(record.get("decision"), dict) else {}
    event = record.get("event") if isinstance(record.get("event"), dict) else {}
    meta = record.get("meta") if isinstance(record.get("meta"), dict) else {}
    snapshot = record.get("risk_snapshot") if isinstance(record.get("risk_snapshot"), dict) else {}
    feedback = meta.get("agent_safety_feedback")
    if not isinstance(feedback, dict):
        feedback = {}
    ledger = meta.get("skill_use_ledger")
    ledger_entries = ledger.get("entries") if isinstance(ledger, dict) else []
    first_ledger_entry = (
        ledger_entries[0]
        if isinstance(ledger_entries, list)
        and ledger_entries
        and isinstance(ledger_entries[0], dict)
        else {}
    )
    rule_hits = snapshot.get("rule_hits")
    if not isinstance(rule_hits, list):
        rule_hits = []
    return {
        "decision": decision.get("decision"),
        "risk_level": decision.get("risk_level") or meta.get("risk_level"),
        "policy_id": decision.get("policy_id") or meta.get("policy_id"),
        "source_framework": event.get("source_framework"),
        "caller_adapter": meta.get("caller_adapter"),
        "agent_safety_feedback_delivery": feedback.get("delivery") or "absent",
        "agent_safety_feedback_schema": feedback.get("schema"),
        "skill_trust_rule_hit": (
            "runtime_path_disallowed"
            if "runtime_path_disallowed" in rule_hits
            else None
        ),
        "skill_use_ledger_decision": first_ledger_entry.get("decision"),
        "skill_use_ledger_runtime_status": first_ledger_entry.get("runtime_path_status"),
    }


_SURFACE_SKILL_NAME = "surface-guard"
_SURFACE_RUNTIME_ROOT = "/tmp/clawsentry-surface-runtime/skills/surface-guard"
_SURFACE_METADATA_RECORD_ID = "sha256:" + "7" * 64


def _runtime_root_path_hash(path: str) -> str:
    return "sha256:" + hashlib.sha256(path.encode("utf-8")).hexdigest()


def _surface_skill_command(framework: str) -> str:
    return (
        f"python3 {_SURFACE_RUNTIME_ROOT}/scripts/check.py "
        f"--framework {framework} && "
        f"rm -rf /tmp/clawsentry-surface-{framework}-target"
    )


def _surface_skill_metadata_bundle() -> dict[str, Any]:
    return {
        "schema_version": "clawsentry.skill_trust_runtime_metadata.v1",
        "framework": "codex",
        "metadata_records": [
            {
                "metadata_record_id": _SURFACE_METADATA_RECORD_ID,
                "presented_name": _SURFACE_SKILL_NAME,
                "canonical_skill_id": f"skill:{_SURFACE_SKILL_NAME}",
                "canonical_name": _SURFACE_SKILL_NAME,
                "aliases": [],
                "source_root_path": f"/workspace/.codex/skills/{_SURFACE_SKILL_NAME}",
                "source_root_path_hash": _runtime_root_path_hash(
                    f"/workspace/.codex/skills/{_SURFACE_SKILL_NAME}"
                ),
                "allowed_runtime_roots": [
                    f"/workspace/.codex/skills/{_SURFACE_SKILL_NAME}",
                ],
                "allowed_runtime_root_hashes": [
                    _runtime_root_path_hash(f"/workspace/.codex/skills/{_SURFACE_SKILL_NAME}"),
                ],
                "trust_level": "trusted",
                "status": "trusted",
                "list_state": "allowlist",
                "mirror_integrity_mode": "content_hash",
                "policy_fingerprint": "sha256:surface-policy",
            }
        ],
    }


def _render_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# Skill Trust Surface Acceptance",
        "",
        f"- Generated at: `{report.get('generated_at')}`",
        f"- Status: `{'PASS' if report.get('pass') else 'FAIL'}`",
        "",
        "| Framework | Case | Pass | Artifact | Decision | Risk | Feedback delivery |",
        "|---|---|---:|---|---|---|---|",
    ]
    for row in report.get("frameworks", []):
        metadata = row.get("observed_decision_metadata", {})
        lines.append(
            "| {framework} | `{case}` | {passed} | `{artifact}` | `{decision}` | `{risk}` | `{delivery}` |".format(
                framework=row.get("framework"),
                case=row.get("case_id"),
                passed="yes" if row.get("pass") else "no",
                artifact=row.get("artifact_path"),
                decision=metadata.get("decision"),
                risk=metadata.get("risk_level"),
                delivery=metadata.get("agent_safety_feedback_delivery"),
            )
        )
    if report.get("problems"):
        lines.extend(["", "## Problems", ""])
        lines.extend(f"- {problem}" for problem in report["problems"])
    return "\n".join(lines) + "\n"


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run Skill Trust runtime-binding surface acceptance checks.",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("artifacts/skilltrust-surface-acceptance"),
    )
    parser.add_argument(
        "--framework",
        choices=REQUIRED_FRAMEWORKS,
        default=None,
        help="Recorded in per-framework commands; the runner currently executes all frameworks.",
    )
    parser.add_argument("--transport", default=None, help=argparse.SUPPRESS)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    report = asyncio.run(run_surface_acceptance(args.output_dir))
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report.get("pass") else 1


if __name__ == "__main__":
    raise SystemExit(main())
