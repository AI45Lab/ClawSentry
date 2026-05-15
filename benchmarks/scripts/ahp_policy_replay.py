#!/usr/bin/env python3
"""Replay canonical AHP fixture rows through the production L1 policy engine."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from statistics import mean
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[2]
SRC_ROOT = REPO_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))


SCHEMA_VERSION = "clawsentry.ahp_policy_replay.v1"
METRIC_SCOPE_NOTE = (
    "These metrics are offline AHP policy regression proxies over canonical "
    "fixture rows; they are not ASR/TSR/TFR and must not be reported as "
    "end-to-end benchmark success rates."
)
EVIDENCE_RISK_FIELDS = (
    "risk_level",
    "composite_score",
    "dimensions",
    "classified_by",
    "classified_at",
    "rule_hits",
    "skill_trust_findings",
    "taint_flow_summary",
    "l2_l3_summary",
)
EVIDENCE_DECISION_FIELDS = (
    "policy_id",
    "policy_version",
    "failure_class",
)
UNIVERSAL_METRIC_CELL_TRACEABILITY_FIELDS = (
    "request_ids",
    "fallback_paths",
)
CONDITIONAL_METRIC_CELL_TRACEABILITY_FIELDS = (
    "rule_evidence",
    "registry_states",
    "adapter_effect_result_ids",
)


def _json_default(value: Any) -> str:
    return str(value)


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True, default=_json_default)
        + "\n",
        encoding="utf-8",
    )


def _write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "".join(
            json.dumps(row, ensure_ascii=False, sort_keys=True, default=_json_default) + "\n"
            for row in rows
        ),
        encoding="utf-8",
    )


def _rate(numerator: int, denominator: int) -> float:
    if denominator <= 0:
        return 1.0
    return round(numerator / denominator, 6)


def _rate_or_none(numerator: int, denominator: int) -> float | None:
    if denominator <= 0:
        return None
    return round(numerator / denominator, 6)


def _load_fixture_rows(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            raw = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Invalid JSONL fixture line {line_number}: {exc}") from exc
        if not isinstance(raw, dict):
            raise ValueError(f"Invalid fixture line {line_number}: row must be an object")
        rows.append(_validate_fixture_row(raw, line_number))
    if not rows:
        raise ValueError("AHP policy replay fixture must contain at least one fixture row")
    return rows


def _validate_fixture_row(row: dict[str, Any], line_number: int) -> dict[str, Any]:
    required = ("case_id", "event", "expected")
    for key in required:
        if key not in row:
            raise ValueError(f"Invalid fixture line {line_number}: missing required {key}")
    if not str(row.get("case_id") or "").strip():
        raise ValueError(f"Invalid fixture line {line_number}: case_id must be non-empty")
    if not isinstance(row.get("event"), dict):
        raise ValueError(f"Invalid fixture line {line_number}: event must be an object")
    if not isinstance(row.get("expected"), dict):
        raise ValueError(f"Invalid fixture line {line_number}: expected must be an object")
    if "context" in row and row["context"] is not None and not isinstance(row["context"], dict):
        raise ValueError(f"Invalid fixture line {line_number}: context must be an object")
    return row


def _expected_decision(expected: dict[str, Any]) -> str | None:
    value = expected.get("decision")
    return str(value).lower() if value is not None else None


def _expected_risk_level(expected: dict[str, Any]) -> str | None:
    value = expected.get("risk_level")
    return str(value).lower() if value is not None else None


def _safety_label(expected: dict[str, Any]) -> str:
    return str(expected.get("safety_label") or expected.get("label") or "unknown").lower()


def _workspace_root_for_row(row: dict[str, Any]) -> str:
    event = row.get("event") if isinstance(row.get("event"), dict) else {}
    payload = event.get("payload") if isinstance(event.get("payload"), dict) else {}
    for key in ("workspace_root", "workspace", "cwd", "working_directory", "path", "file_path"):
        value = event.get(key)
        if value is None:
            value = payload.get(key)
        text = str(value or "").strip()
        if text:
            return text
    return "unbound"


def _registry_states(snapshot_dict: dict[str, Any]) -> list[str]:
    states: set[str] = set()
    findings = snapshot_dict.get("skill_trust_findings")
    if isinstance(findings, list):
        for finding in findings:
            if not isinstance(finding, dict):
                continue
            for key in (
                "registry_state",
                "registry_status",
                "status",
                "trust_level",
                "list_state",
                "trust_list_state",
            ):
                value = str(finding.get(key) or "").strip()
                if value:
                    states.add(value)
    return sorted(states)


def _rule_family(rule_id: str) -> str:
    lowered = rule_id.lower()
    if "skill" in lowered or "registry" in lowered or "alias" in lowered:
        return "skill_trust"
    structured_taint_rules = {
        "remote_fetch_to_interpreter",
        "archive_extract_then_execute",
        "bulk_destructive_sequence",
        "spreadsheet_downstream_payload",
        "persistence_entrypoint_write",
        "sensitive_source_to_network_sink",
    }
    if (
        lowered in structured_taint_rules
        or "taint" in lowered
        or "flow" in lowered
        or "secret" in lowered
        or "exfil" in lowered
    ):
        return "taint_flow"
    if "scope" in lowered or "session" in lowered or "mcp" in lowered:
        return "session_scope"
    if "trajectory" in lowered:
        return "trajectory"
    return "general"


def _rule_families(snapshot_dict: dict[str, Any]) -> list[str]:
    hits = [str(item) for item in (snapshot_dict.get("rule_hits") or [])]
    if snapshot_dict.get("skill_trust_findings"):
        hits.append("skill_trust_findings")
    return sorted({_rule_family(hit) for hit in hits} or {"general"})


def _case_traceability(
    *,
    row: dict[str, Any],
    snapshot_dict: dict[str, Any],
    fallback_dict: dict[str, Any],
) -> dict[str, Any]:
    event = row["event"]
    rule_hits = [str(item) for item in (snapshot_dict.get("rule_hits") or [])]
    if snapshot_dict.get("short_circuit_rule"):
        rule_hits.append(str(snapshot_dict["short_circuit_rule"]))
    expected = row.get("expected") if isinstance(row.get("expected"), dict) else {}
    adapter_effects_applicable = bool(
        row.get("adapter_effect_results")
        or row.get("adapter_effects_applicable")
        or expected.get("adapter_effects_applicable")
    )
    return {
        "request_id": str(row.get("request_id") or event.get("request_id") or event.get("event_id")),
        "event_id": event.get("event_id"),
        "workspace_root": _workspace_root_for_row(row),
        "source_framework": event.get("source_framework") or "unknown",
        "session_id": event.get("session_id") or "unknown",
        "registry_states": _registry_states(snapshot_dict),
        "rule_evidence": rule_hits,
        "fallback_path": str(
            fallback_dict.get("policy_id")
            or fallback_dict.get("decision_source")
            or "local_fallback"
        ),
        "adapter_effect_result_ids": [
            str(effect.get("effect_id") or effect.get("id"))
            for effect in row.get("adapter_effect_results", [])
            if isinstance(effect, dict) and (effect.get("effect_id") or effect.get("id"))
        ],
        "adapter_effects_applicable": adapter_effects_applicable,
    }


def _fallback_expected_decision(expected: dict[str, Any]) -> str | None:
    for key in ("fallback_decision", "fallback_expected_decision"):
        value = expected.get(key)
        if value is not None:
            return str(value).lower()
    return None


def _is_fallback_correct(
    fallback_dict: dict[str, Any],
    fallback_decision: str,
    expected: dict[str, Any],
) -> bool | None:
    explicit = _fallback_expected_decision(expected)
    if explicit is not None:
        if fallback_decision != explicit:
            return False
        expected_failure = expected.get("fallback_failure_class")
        if expected_failure is not None:
            return str(fallback_dict.get("failure_class") or "").lower() == str(expected_failure).lower()
        return True

    explicit_bool = expected.get("fallback_should_be_correct")
    if explicit_bool is not None:
        if not bool(explicit_bool):
            return False
        label = _safety_label(expected)
        if label == "unsafe":
            return fallback_decision in {"block", "defer"}
        if label == "safe":
            return fallback_decision in {"allow", "defer"}
        return True

    label = _safety_label(expected)
    if label == "unsafe":
        return fallback_decision in {"block", "defer"}
    if label == "safe":
        return fallback_decision in {"allow", "defer"}
    return None


def _evidence_complete(
    decision_dict: dict[str, Any],
    snapshot_dict: dict[str, Any],
    fallback_dict: dict[str, Any],
    expected: dict[str, Any],
) -> bool:
    for key in EVIDENCE_RISK_FIELDS:
        if key not in snapshot_dict:
            return False
        value = snapshot_dict.get(key)
        if value in (None, ""):
            if key != "taint_flow_summary":
                return False
        if key == "dimensions" and not isinstance(value, dict):
            return False
        if key in {"rule_hits", "skill_trust_findings"} and not isinstance(value, list):
            return False
        if key == "l2_l3_summary" and not isinstance(value, dict):
            return False
    for key in EVIDENCE_DECISION_FIELDS:
        if decision_dict.get(key) in (None, ""):
            return False
    for key in ("decision", "policy_id", "policy_version", "failure_class"):
        if fallback_dict.get(key) in (None, ""):
            return False
    required_rules = expected.get("required_rule_hits") or []
    if required_rules and not set(map(str, required_rules)).issubset(set(map(str, snapshot_dict.get("rule_hits") or []))):
        return False
    required_taint_rules = expected.get("required_taint_rule_ids") or []
    if required_taint_rules:
        taint = snapshot_dict.get("taint_flow_summary")
        if not isinstance(taint, dict):
            return False
        if not set(map(str, required_taint_rules)).issubset(set(map(str, taint.get("rule_ids") or []))):
            return False
    required_skill_rules = expected.get("required_skill_trust_rule_ids") or []
    if required_skill_rules:
        skill_rules = {
            str(item.get("rule_id"))
            for item in snapshot_dict.get("skill_trust_findings") or []
            if isinstance(item, dict)
        }
        if not set(map(str, required_skill_rules)).issubset(skill_rules):
            return False
    return True


def _schema_sync_complete(
    decision_dict: dict[str, Any],
    snapshot_dict: dict[str, Any],
    fallback_dict: dict[str, Any],
    expected: dict[str, Any],
) -> bool:
    return _evidence_complete(decision_dict, snapshot_dict, fallback_dict, expected)


def _build_case_result(
    *,
    row: dict[str, Any],
    decision_dict: dict[str, Any],
    snapshot_dict: dict[str, Any],
    actual_tier: str,
    fallback_dict: dict[str, Any],
) -> dict[str, Any]:
    expected = row["expected"]
    actual_decision = str(decision_dict["decision"]).lower()
    expected_decision = _expected_decision(expected)
    actual_risk = str(snapshot_dict["risk_level"]).lower()
    expected_risk = _expected_risk_level(expected)
    fallback_correct = _is_fallback_correct(fallback_dict, str(fallback_dict["decision"]).lower(), expected)
    baseline = row.get("baseline") if isinstance(row.get("baseline"), dict) else {}
    baseline_decision = str(baseline.get("decision")).lower() if baseline.get("decision") else None
    baseline_fallback = (
        str(baseline.get("fallback_decision")).lower()
        if baseline.get("fallback_decision")
        else None
    )

    decision_match = expected_decision is None or actual_decision == expected_decision
    risk_level_match = expected_risk is None or actual_risk == expected_risk
    evidence_complete = _evidence_complete(decision_dict, snapshot_dict, fallback_dict, expected)
    schema_sync_complete = _schema_sync_complete(decision_dict, snapshot_dict, fallback_dict, expected)
    traceability = _case_traceability(
        row=row,
        snapshot_dict=snapshot_dict,
        fallback_dict=fallback_dict,
    )

    return {
        "case_id": row["case_id"],
        "source": row.get("source"),
        "profile": row.get("profile"),
        "split": row.get("split") or "training",
        "expected": expected,
        "event_id": row["event"].get("event_id"),
        "event_type": row["event"].get("event_type"),
        "tool_name": row["event"].get("tool_name"),
        "decision": decision_dict,
        "risk_snapshot": snapshot_dict,
        "actual_tier": actual_tier,
        "fallback_decision": fallback_dict,
        "decision_match": decision_match,
        "risk_level_match": risk_level_match,
        "fallback_correct": fallback_correct,
        "baseline": baseline,
        "has_decision_baseline": baseline_decision is not None,
        "has_fallback_baseline": baseline_fallback is not None,
        "decision_drift": baseline_decision is not None and baseline_decision != actual_decision,
        "fallback_drift": baseline_fallback is not None and baseline_fallback != str(fallback_dict["decision"]).lower(),
        "evidence_complete": evidence_complete,
        "schema_sync_complete": schema_sync_complete,
        "rule_hits": list(snapshot_dict.get("rule_hits") or []),
        "l2_l3_summary": snapshot_dict.get("l2_l3_summary"),
        "rule_families": _rule_families(snapshot_dict),
        "traceability": traceability,
        "latency_ms": decision_dict.get("decision_latency_ms"),
        "safety_label": _safety_label(expected),
    }


def _summarize(rows: list[dict[str, Any]]) -> dict[str, Any]:
    expected_decision_rows = [
        row for row in rows if _expected_decision(row.get("expected") or {}) is not None
    ]
    unsafe_rows = [row for row in rows if row.get("safety_label") == "unsafe"]
    safe_rows = [row for row in rows if row.get("safety_label") == "safe"]
    fallback_rows = [row for row in rows if row.get("fallback_correct") is not None]
    baseline_decision_rows = [row for row in rows if row.get("has_decision_baseline")]
    baseline_fallback_rows = [row for row in rows if row.get("has_fallback_baseline")]
    decision_drift_rows = [row for row in rows if row.get("decision_drift")]
    fallback_drift_rows = [row for row in rows if row.get("fallback_drift")]
    latencies = [
        float(row["latency_ms"])
        for row in rows
        if isinstance(row.get("latency_ms"), (int, float))
    ]
    rule_eligible_rows = [
        row for row in rows if row["risk_snapshot"].get("risk_level") in ("high", "critical")
    ]

    unsafe_pass_proxy = _rate_or_none(
        sum(1 for row in unsafe_rows if row["decision"]["decision"] == "allow"),
        len(unsafe_rows),
    )
    overblock_proxy = _rate_or_none(
        sum(
            1
            for row in safe_rows
            if row["decision"]["decision"] in {"block", "defer"}
            and row["decision"]["decision"] not in set(row["expected"].get("allowed_decisions") or [row["expected"].get("decision") or "allow"])
        ),
        len(safe_rows),
    )
    metrics = {
        "decision_match_rate": _rate(
            sum(1 for row in expected_decision_rows if row["decision_match"]),
            len(expected_decision_rows),
        ),
        "unsafe_pass_proxy": unsafe_pass_proxy,
        "unsafe_pass_proxy_state": "ok" if unsafe_pass_proxy is not None else "not_applicable",
        "overblock_proxy": overblock_proxy,
        "overblock_proxy_state": "ok" if overblock_proxy is not None else "not_applicable",
        "fallback_correctness": _rate(
            sum(1 for row in fallback_rows if row["fallback_correct"]),
            len(fallback_rows),
        ),
        "decision_drift_rate": _rate_or_none(
            len(decision_drift_rows),
            len(baseline_decision_rows),
        ),
        "decision_drift_rate_state": "ok" if baseline_decision_rows else "not_applicable",
        "fallback_drift_rate": _rate_or_none(
            len(fallback_drift_rows),
            len(baseline_fallback_rows),
        ),
        "fallback_drift_rate_state": "ok" if baseline_fallback_rows else "not_applicable",
        "rule_coverage": _rate_or_none(
            sum(
                1
                for row in rule_eligible_rows
                if row.get("rule_hits") or row["risk_snapshot"].get("short_circuit_rule")
            ),
            len(rule_eligible_rows),
        ),
        "rule_coverage_state": "ok" if rule_eligible_rows else "not_applicable",
        "policy_latency_ms": {
            "mean": round(mean(latencies), 3) if latencies else 0.0,
            "max": round(max(latencies), 3) if latencies else 0.0,
        },
        "evidence_coverage": _rate(
            sum(1 for row in rows if row["evidence_complete"]),
            len(rows),
        ),
        "schema_sync_coverage": _rate(
            sum(1 for row in rows if row["schema_sync_complete"]),
            len(rows),
        ),
    }
    return metrics


def _fixture_splits(rows: list[dict[str, Any]]) -> dict[str, Any]:
    split_names = sorted({str(row.get("split") or "training") for row in rows})
    return {
        "counts": {
            split: sum(1 for row in rows if str(row.get("split") or "training") == split)
            for split in split_names
        },
        "metrics_by_split": {
            split: _summarize([
                row for row in rows
                if str(row.get("split") or "training") == split
            ])
            for split in split_names
        },
    }


def _policy_drift_by_cell(rows: list[dict[str, Any]]) -> dict[str, Any]:
    cells: dict[tuple[str, str, str, str], dict[str, Any]] = {}
    for row in rows:
        trace = row.get("traceability") if isinstance(row.get("traceability"), dict) else {}
        for family in row.get("rule_families") or ["general"]:
            key = (
                str(trace.get("workspace_root") or "unbound"),
                str(trace.get("source_framework") or "unknown"),
                str(trace.get("session_id") or "unknown"),
                str(family),
            )
            cell = cells.setdefault(
                key,
                {
                    "workspace_root": key[0],
                    "source_framework": key[1],
                    "session_id": key[2],
                    "rule_family": key[3],
                    "actual_decision_distribution": {},
                    "baseline_decision_distribution": {},
                    "decision_drift_cases": [],
                    "traceability": {
                        "request_ids": set(),
                        "event_ids": set(),
                        "registry_states": set(),
                        "rule_evidence": set(),
                        "fallback_paths": set(),
                        "adapter_effect_result_ids": set(),
                    },
                    "traceability_applicability": {
                        "rule_evidence": key[3] != "general",
                        "registry_states": key[3] == "skill_trust",
                        "adapter_effect_result_ids": False,
                    },
                },
            )
            if str(family) != "general":
                cell["traceability_applicability"]["rule_evidence"] = True
            if str(family) == "skill_trust":
                cell["traceability_applicability"]["registry_states"] = True
            if trace.get("adapter_effects_applicable"):
                cell["traceability_applicability"]["adapter_effect_result_ids"] = True
            actual = str(row["decision"].get("decision") or "unknown")
            cell["actual_decision_distribution"][actual] = (
                int(cell["actual_decision_distribution"].get(actual, 0)) + 1
            )
            if row.get("has_decision_baseline"):
                baseline_decision = str((row.get("baseline") or {}).get("decision") or "").lower()
                if baseline_decision:
                    cell["baseline_decision_distribution"][baseline_decision] = (
                        int(cell["baseline_decision_distribution"].get(baseline_decision, 0)) + 1
                    )
            if row.get("decision_drift"):
                cell["decision_drift_cases"].append(row["case_id"])
            for source_key, target_key in (
                ("request_id", "request_ids"),
                ("event_id", "event_ids"),
                ("fallback_path", "fallback_paths"),
            ):
                value = str(trace.get(source_key) or "").strip()
                if value:
                    cell["traceability"][target_key].add(value)
            for source_key, target_key in (
                ("registry_states", "registry_states"),
                ("rule_evidence", "rule_evidence"),
                ("adapter_effect_result_ids", "adapter_effect_result_ids"),
            ):
                for value in trace.get(source_key) or []:
                    text = str(value).strip()
                    if text:
                        cell["traceability"][target_key].add(text)

    finalized: list[dict[str, Any]] = []
    for cell in cells.values():
        actual_count = sum(int(value) for value in cell["actual_decision_distribution"].values())
        baseline_count = sum(int(value) for value in cell["baseline_decision_distribution"].values())
        actual_block_rate = (
            int(cell["actual_decision_distribution"].get("block", 0)) / actual_count
            if actual_count
            else 0.0
        )
        baseline_block_rate = (
            int(cell["baseline_decision_distribution"].get("block", 0)) / baseline_count
            if baseline_count
            else 0.0
        )
        finalized.append({
            "workspace_root": cell["workspace_root"],
            "source_framework": cell["source_framework"],
            "session_id": cell["session_id"],
            "rule_family": cell["rule_family"],
            "actual_decision_distribution": cell["actual_decision_distribution"],
            "baseline_decision_distribution": cell["baseline_decision_distribution"],
            "decision_drift_cases": list(cell["decision_drift_cases"]),
            "block_rate_delta": round(actual_block_rate - baseline_block_rate, 6),
            "traceability": {
                key: sorted(values)
                for key, values in cell["traceability"].items()
            },
            "traceability_applicability": dict(cell["traceability_applicability"]),
        })
    finalized.sort(
        key=lambda item: (
            -abs(float(item["block_rate_delta"])),
            item["workspace_root"],
            item["source_framework"],
            item["session_id"],
            item["rule_family"],
        )
    )
    return {
        "grouping_dimensions": [
            "workspace_root",
            "source_framework",
            "session_id",
            "rule_family",
        ],
        "cells": finalized,
    }


def _required_metric_cell_traceability_fields(cell: dict[str, Any]) -> list[str]:
    fields = list(UNIVERSAL_METRIC_CELL_TRACEABILITY_FIELDS)
    rule_family = str(cell.get("rule_family") or "general")
    applicability = (
        cell.get("traceability_applicability")
        if isinstance(cell.get("traceability_applicability"), dict)
        else {}
    )
    if rule_family != "general" or applicability.get("rule_evidence"):
        fields.append("rule_evidence")
    if rule_family == "skill_trust" or applicability.get("registry_states"):
        fields.append("registry_states")
    if (
        applicability.get("adapter_effect_result_ids")
        or applicability.get("adapter_effects_applicable")
    ):
        fields.append("adapter_effect_result_ids")
    return fields


def _metric_cell_traceability(policy_drift: dict[str, Any]) -> dict[str, Any]:
    cells = policy_drift.get("cells") if isinstance(policy_drift, dict) else []
    complete_count = 0
    incomplete_cells: list[dict[str, Any]] = []
    for cell in cells or []:
        if not isinstance(cell, dict):
            continue
        trace = cell.get("traceability") if isinstance(cell.get("traceability"), dict) else {}
        required_fields = _required_metric_cell_traceability_fields(cell)
        missing = [
            field
            for field in required_fields
            if not trace.get(field)
        ]
        if missing:
            incomplete_cells.append({
                "workspace_root": cell.get("workspace_root"),
                "source_framework": cell.get("source_framework"),
                "session_id": cell.get("session_id"),
                "rule_family": cell.get("rule_family"),
                "missing_fields": missing,
            })
        else:
            complete_count += 1
    total = len([cell for cell in cells or [] if isinstance(cell, dict)])
    return {
        "required_fields": list(UNIVERSAL_METRIC_CELL_TRACEABILITY_FIELDS),
        "conditional_fields": list(CONDITIONAL_METRIC_CELL_TRACEABILITY_FIELDS),
        "cell_count": total,
        "complete_cell_count": complete_count,
        "coverage": _rate(complete_count, total),
        "passed": total > 0 and not incomplete_cells,
        "incomplete_cells": incomplete_cells,
    }


def _policy_fingerprint(policy_ids: list[str], policy_versions: list[str], rows: list[dict[str, Any]]) -> str:
    payload = {
        "policy_ids": policy_ids,
        "policy_versions": policy_versions,
        "rule_hits": sorted({rule for row in rows for rule in row.get("rule_hits", [])}),
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def _write_summary_markdown(report: dict[str, Any], output_dir: Path) -> None:
    metrics = report["metrics"]
    lines = [
        "# AHP Policy Replay Summary",
        "",
        METRIC_SCOPE_NOTE,
        "",
        f"- Cases: `{report['cases']}`",
        f"- `decision_match_rate`: `{metrics['decision_match_rate']}`",
        f"- `unsafe_pass_proxy`: `{metrics['unsafe_pass_proxy']}`",
        f"- `overblock_proxy`: `{metrics['overblock_proxy']}`",
        f"- `fallback_correctness`: `{metrics['fallback_correctness']}`",
        f"- `policy_latency_ms.mean`: `{metrics['policy_latency_ms']['mean']}`",
        f"- `policy_latency_ms.max`: `{metrics['policy_latency_ms']['max']}`",
        f"- `evidence_coverage`: `{metrics['evidence_coverage']}`",
        f"- `schema_sync_coverage`: `{metrics['schema_sync_coverage']}`",
        "",
        "## Evidence Coverage Fields",
        "",
    ]
    for field in EVIDENCE_RISK_FIELDS:
        lines.append(f"- `risk_snapshot.{field}`")
    for field in EVIDENCE_DECISION_FIELDS:
        lines.append(f"- `decision.{field}`")
    lines.extend(
        [
            "",
            "The runner evaluates fixture events with `L1PolicyEngine.evaluate` and",
            "does not load benchmark submodules, call LLM providers, or use case ids",
            "as policy inputs.",
        ]
    )
    (output_dir / "summary.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def _config_for_profile(profile: Any):
    from clawsentry.gateway.detection_config import DetectionConfig

    profile_name = str(profile or "normal").strip().lower()
    if profile_name in {"benchmark", "benchmark-strict"}:
        return DetectionConfig(mode="benchmark")
    if profile_name in {"strict", "high", "strict-l2-l3"}:
        return DetectionConfig(mode="strict")
    if profile_name in {"permissive", "audit"}:
        return DetectionConfig(mode="permissive")
    return DetectionConfig(mode="normal")


def replay_fixture(fixture_path: Path | str, output_dir: Path | str) -> dict[str, Any]:
    """Replay JSONL fixture cases and write regression artifacts."""
    from clawsentry.gateway.models import CanonicalEvent, DecisionContext
    from clawsentry.gateway.policy_engine import L1PolicyEngine, make_fallback_decision

    fixture = Path(fixture_path)
    out = Path(output_dir)
    rows = _load_fixture_rows(fixture)
    case_results: list[dict[str, Any]] = []

    engine = L1PolicyEngine()
    try:
        for row in rows:
            event = CanonicalEvent.model_validate(row["event"])
            context_payload = row.get("context") or {}
            context = DecisionContext.model_validate(context_payload)
            config = _config_for_profile(row.get("profile"))
            decision, snapshot, actual_tier = engine.evaluate(event, context, config=config)
            fallback = make_fallback_decision(event)
            case_results.append(
                _build_case_result(
                    row=row,
                    decision_dict=decision.model_dump(mode="json"),
                    snapshot_dict=snapshot.model_dump(mode="json"),
                    actual_tier=actual_tier.value,
                    fallback_dict=fallback.model_dump(mode="json"),
                )
            )
    finally:
        engine.shutdown()

    metrics = _summarize(case_results)
    policy_drift = _policy_drift_by_cell(case_results)
    metric_cell_traceability = _metric_cell_traceability(policy_drift)
    policy_ids = sorted(
        {
            str(row["decision"].get("policy_id"))
            for row in case_results
            if row["decision"].get("policy_id")
        }
    )
    policy_versions = sorted(
        {
            str(row["decision"].get("policy_version"))
            for row in case_results
            if row["decision"].get("policy_version")
        }
    )
    report = {
        "schema_version": SCHEMA_VERSION,
        "fixture": str(fixture),
        "cases": len(case_results),
        "metric_scope_note": METRIC_SCOPE_NOTE,
        "metrics": metrics,
        "fixture_splits": _fixture_splits(case_results),
        "policy_drift": policy_drift,
        "metric_cell_traceability": metric_cell_traceability,
        "policy": {
            "engine": "L1PolicyEngine.evaluate",
            "policy_id": policy_ids[0] if len(policy_ids) == 1 else policy_ids,
            "policy_version": policy_versions[0] if len(policy_versions) == 1 else policy_versions,
            "policy_fingerprint": _policy_fingerprint(policy_ids, policy_versions, case_results),
        },
        "profiles": sorted({str(row.get("profile") or "normal") for row in case_results}),
        "artifacts": {
            "replay_report": str(out / "replay_report.json"),
            "per_case_results": str(out / "per_case_results.jsonl"),
            "metric_cell_traceability": str(out / "metric_cell_traceability.json"),
            "summary": str(out / "summary.md"),
        },
    }

    out.mkdir(parents=True, exist_ok=True)
    _write_json(out / "replay_report.json", report)
    _write_jsonl(out / "per_case_results.jsonl", case_results)
    _write_json(out / "metric_cell_traceability.json", metric_cell_traceability)
    _write_summary_markdown(report, out)
    return report


def replay_gate_passed(
    report: dict[str, Any],
    *,
    fail_under_decision_match: float,
    max_unsafe_pass: float,
    max_overblock: float,
) -> bool:
    traceability = report.get("metric_cell_traceability")
    if isinstance(traceability, dict) and traceability.get("passed") is False:
        return False
    metrics_sets = [report.get("metrics") or {}]
    split_metrics = (
        (report.get("fixture_splits") or {}).get("metrics_by_split")
        if isinstance(report.get("fixture_splits"), dict)
        else None
    )
    if isinstance(split_metrics, dict):
        for split in ("training", "holdout", "canary", "false_positive"):
            metrics = split_metrics.get(split)
            if isinstance(metrics, dict):
                metrics_sets.append(metrics)

    for metrics in metrics_sets:
        if not _replay_metrics_gate_passed(
            metrics,
            fail_under_decision_match=fail_under_decision_match,
            max_unsafe_pass=max_unsafe_pass,
            max_overblock=max_overblock,
        ):
            return False
    return True


def _replay_metrics_gate_passed(
    metrics: dict[str, Any],
    *,
    fail_under_decision_match: float,
    max_unsafe_pass: float,
    max_overblock: float,
) -> bool:
    decision_match = metrics.get("decision_match_rate")
    unsafe_pass = metrics.get("unsafe_pass_proxy")
    overblock = metrics.get("overblock_proxy")
    if decision_match is not None and float(decision_match) < fail_under_decision_match:
        return False
    if unsafe_pass is not None and float(unsafe_pass) > max_unsafe_pass:
        return False
    if overblock is not None and float(overblock) > max_overblock:
        return False
    return True


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Replay AHP policy JSONL fixtures.")
    parser.add_argument("fixture", type=Path, help="Path to AHP replay JSONL fixture.")
    parser.add_argument("output_dir", nargs="?", type=Path, help="Directory for replay artifacts.")
    parser.add_argument("--out-dir", type=Path, dest="out_dir", help="Directory for replay artifacts.")
    parser.add_argument("--fail-under-decision-match", type=float, default=1.0)
    parser.add_argument("--max-unsafe-pass", type=float, default=0.0)
    parser.add_argument("--max-overblock", type=float, default=0.0)
    args = parser.parse_args(argv)
    output_dir = args.out_dir or args.output_dir
    if output_dir is None:
        parser.error("output_dir or --out-dir is required")

    report = replay_fixture(args.fixture, output_dir)
    print(json.dumps(report, ensure_ascii=False, sort_keys=True, default=_json_default))
    return 0 if replay_gate_passed(
        report,
        fail_under_decision_match=args.fail_under_decision_match,
        max_unsafe_pass=args.max_unsafe_pass,
        max_overblock=args.max_overblock,
    ) else 1


if __name__ == "__main__":
    raise SystemExit(main())
