"""``clawsentry skill-trust`` — admission scan and registry utilities."""

from __future__ import annotations

import json
import os
import re
import sys
import tempfile
from pathlib import Path
from typing import Any

from clawsentry.gateway.models import RiskLevel, SkillRegistryRecord
from clawsentry.gateway.skill_trust import (
    AdmissionScanner,
    POLICY_FINGERPRINT,
    apply_trust_list_state,
    build_skill_trust_bundle,
    transition_trust_list_state,
)

_FRONTMATTER_NAME = re.compile(r"^name:\s*[\"']?([^\"'\n]+)[\"']?\s*$", re.M)
_FRONTMATTER_ALIASES = re.compile(r"^aliases:\s*\[([^\]]*)\]\s*$", re.M)


def _sha256_text(value: str) -> str:
    import hashlib

    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


def _read_registry(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {
            "schema_version": "clawsentry.skill_registry.v1",
            "records": [],
            "transition_events": [],
        }
    payload = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(payload, list):
        return {
            "schema_version": "clawsentry.skill_registry.v1",
            "records": payload,
            "transition_events": [],
            "migrated_from": "list",
        }
    if not isinstance(payload, dict):
        raise ValueError("skill registry must be a JSON object")
    if "skills" in payload and "records" not in payload:
        payload["records"] = payload.get("skills")
        payload["migrated_from"] = "skills"
    payload.setdefault("schema_version", "clawsentry.skill_registry.v1")
    payload.setdefault("records", [])
    payload.setdefault("transition_events", [])
    if not isinstance(payload["records"], list):
        raise ValueError("skill registry records must be a list")
    if not isinstance(payload["transition_events"], list):
        raise ValueError("skill registry transition_events must be a list")
    return payload


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    data = json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    with tempfile.NamedTemporaryFile(
        "w",
        encoding="utf-8",
        dir=path.parent,
        prefix=f".{path.name}.",
        suffix=".tmp",
        delete=False,
    ) as handle:
        temp_name = handle.name
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temp_name, path)


def _skill_identity(skill_root: Path) -> tuple[str, list[str]]:
    text = (skill_root / "SKILL.md").read_text(encoding="utf-8") if (skill_root / "SKILL.md").exists() else ""
    name_match = _FRONTMATTER_NAME.search(text)
    canonical_name = name_match.group(1).strip() if name_match else skill_root.name
    aliases: list[str] = []
    aliases_match = _FRONTMATTER_ALIASES.search(text)
    if aliases_match:
        aliases = [
            item.strip().strip("\"'")
            for item in aliases_match.group(1).split(",")
            if item.strip()
        ]
    return canonical_name, aliases


def _validate_skill_root(skill_root: Path) -> None:
    if not skill_root.is_dir():
        raise ValueError(f"skill root must be a directory containing SKILL.md: {skill_root}")
    if not (skill_root / "SKILL.md").is_file():
        raise ValueError(f"skill root must contain SKILL.md: {skill_root}")


def _registry_record_for_scan(
    *,
    skill_root: Path,
    framework: str,
    scope: str,
    list_state: str,
    from_state: str = "unlisted",
    operator_override: str | None = None,
) -> tuple[SkillRegistryRecord, dict[str, Any]]:
    _validate_skill_root(skill_root)
    scanner = AdmissionScanner()
    report = scanner.scan(skill_root)
    canonical_name, aliases = _skill_identity(skill_root)
    canonical_skill_id = _sha256_text(f"{framework}:{canonical_name}")
    evidence_hashes = sorted(
        {
            *report.content_hashes.values(),
            *(
                evidence
                for finding in report.findings
                for evidence in finding.evidence_hashes
            ),
        }
    )
    base_record = SkillRegistryRecord(
        canonical_skill_id=canonical_skill_id,
        canonical_name=canonical_name,
        aliases=aliases,
        content_hashes=report.content_hashes,
        source={
            "framework": framework,
            "path_hash": _sha256_text(str(skill_root.resolve())),
            "skill_root_hash": report.skill_root_hash,
            "scope": scope,
        },
        trust_level="unknown",
        admission_scan_id=report.scan_id,
        policy_fingerprint=report.policy_fingerprint or POLICY_FINGERPRINT,
        list_state="unlisted",
        status="unknown",
    )
    target_state = list_state
    if target_state == "auto":
        target_state = "allowlist" if report.admission_risk == RiskLevel.LOW else "greylist"
    if (
        target_state == "allowlist"
        and report.admission_risk != RiskLevel.LOW
        and not operator_override
    ):
        raise ValueError("risky admission report requires operator override before allowlist")
    reason_code = "admission_review_required"
    actor_type = "policy"
    override_id = None
    if target_state == "allowlist":
        if operator_override:
            reason_code = "operator_override"
            actor_type = "operator"
            override_id = operator_override
        else:
            reason_code = "clean_admission_report"
    record = apply_trust_list_state(
        base_record,
        target_state,
        reason_code=reason_code,
    )
    transition = transition_trust_list_state(
        canonical_skill_id=record.canonical_skill_id,
        from_state=from_state,
        to_state=target_state,
        reason_code=reason_code,
        evidence_hashes=evidence_hashes or [report.skill_root_hash],
        scope=scope,
        actor_type=actor_type,
        policy_fingerprint=report.policy_fingerprint or POLICY_FINGERPRINT,
        override_id=override_id,
    )
    scan_payload = {
        "skill_root": str(skill_root),
        "scan_id": report.scan_id,
        "admission_report": report.model_dump(mode="json"),
    }
    return record, {
        "scan": scan_payload,
        "transition": transition.model_dump(mode="json"),
    }


def _record_integrity_changed(existing: dict[str, Any] | None, record: SkillRegistryRecord) -> bool:
    if not isinstance(existing, dict):
        return False
    return (
        existing.get("content_hashes") != record.content_hashes
        or existing.get("source", {}).get("skill_root_hash") != record.source.get("skill_root_hash")
        or existing.get("admission_scan_id") != record.admission_scan_id
    )


def _merge_registry_records(
    existing_payload: dict[str, Any],
    bundle_records: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    existing_by_id = {
        str(row.get("canonical_skill_id")): row
        for row in existing_payload.get("records", [])
        if isinstance(row, dict) and row.get("canonical_skill_id")
    }
    merged: list[dict[str, Any]] = []
    for row in bundle_records:
        record = SkillRegistryRecord.model_validate(row)
        existing = existing_by_id.get(record.canonical_skill_id)
        if isinstance(existing, dict):
            existing_state = str(existing.get("list_state") or "")
            preserved = {}
            if existing_state in {"blacklist", "revoked", "disabled"}:
                preserved = {
                    key: existing.get(key)
                    for key in ("trust_level", "list_state", "status")
                    if existing.get(key) is not None
                }
            row = {
                **record.model_dump(mode="json"),
                **preserved,
                "source": {
                    **record.source,
                    "previous_skill_root_hash": existing.get("source", {}).get("skill_root_hash"),
                },
            }
        merged.append(row)
    existing_ids = {str(row.get("canonical_skill_id")) for row in bundle_records}
    for row in existing_payload.get("records", []):
        if isinstance(row, dict) and str(row.get("canonical_skill_id")) not in existing_ids:
            merged.append(row)
    return sorted(merged, key=lambda item: str(item.get("canonical_name") or ""))


def _transition_reason_for_state(list_state: str) -> str:
    if list_state == "allowlist":
        return "clean_admission_report"
    if list_state == "greylist":
        return "admission_review_required"
    if list_state == "disabled":
        return "policy_disable"
    return "registry_rescan"


def _record_evidence_hashes(record: SkillRegistryRecord) -> list[str]:
    values = {
        value
        for value in record.content_hashes.values()
        if isinstance(value, str) and value.strip()
    }
    for key in ("skill_root_hash", "path_hash", "previous_skill_root_hash"):
        value = record.source.get(key)
        if isinstance(value, str) and value.strip():
            values.add(value)
    return sorted(values)


def _register_dir_transition_events(
    *,
    existing_payload: dict[str, Any],
    merged_records: list[dict[str, Any]],
    bundle_records: list[dict[str, Any]],
    scope: str,
) -> list[dict[str, Any]]:
    existing_by_id = {
        str(row.get("canonical_skill_id")): row
        for row in existing_payload.get("records", [])
        if isinstance(row, dict) and row.get("canonical_skill_id")
    }
    bundle_ids = {
        str(row.get("canonical_skill_id"))
        for row in bundle_records
        if isinstance(row, dict) and row.get("canonical_skill_id")
    }
    events: list[dict[str, Any]] = []
    for row in merged_records:
        if not isinstance(row, dict):
            continue
        canonical_skill_id = str(row.get("canonical_skill_id") or "")
        if canonical_skill_id not in bundle_ids:
            continue
        record = SkillRegistryRecord.model_validate(row)
        existing = existing_by_id.get(canonical_skill_id)
        from_state = str((existing or {}).get("list_state") or "unlisted")
        to_state = str(record.list_state)
        state_changed = from_state != to_state
        integrity_changed = _record_integrity_changed(existing, record)
        if existing is not None and not state_changed and not integrity_changed:
            continue
        event = transition_trust_list_state(
            canonical_skill_id=canonical_skill_id,
            from_state=from_state,
            to_state=to_state,
            reason_code=_transition_reason_for_state(to_state),
            evidence_hashes=_record_evidence_hashes(record),
            scope=scope,
            actor_type="policy",
            policy_fingerprint=record.policy_fingerprint or POLICY_FINGERPRINT,
            previous_policy_fingerprint=(
                str(existing.get("policy_fingerprint"))
                if isinstance(existing, dict) and existing.get("policy_fingerprint")
                else None
            ),
        )
        events.append(event.model_dump(mode="json"))
    return events


def run_skill_trust_scan(
    *,
    skill_root: Path,
    output: Path | None = None,
    json_mode: bool = False,
) -> int:
    _validate_skill_root(skill_root)
    report = AdmissionScanner().scan(skill_root)
    payload = {
        "schema_version": "clawsentry.skill_admission_report.v1",
        "skill_root": str(skill_root),
        "scan_id": report.scan_id,
        "admission_report": report.model_dump(mode="json"),
    }
    if output is not None:
        _write_json(output, payload)
    if json_mode:
        print(json.dumps(payload, ensure_ascii=False, sort_keys=True))
    else:
        print(f"scan_id: {report.scan_id}")
        print(f"admission_risk: {report.admission_risk.value}")
        print(f"findings: {len(report.findings)}")
        if output is not None:
            print(f"wrote: {output}")
    return 0


def run_skill_trust_register(
    *,
    skill_root: Path,
    registry: Path,
    framework: str = "codex",
    scope: str = "workspace",
    list_state: str = "auto",
    operator_override: str | None = None,
    json_mode: bool = False,
) -> int:
    _validate_skill_root(skill_root)
    payload = _read_registry(registry)
    canonical_name, _aliases = _skill_identity(skill_root)
    canonical_skill_id = _sha256_text(f"{framework}:{canonical_name}")
    existing_record = next(
        (
            row for row in payload["records"]
            if isinstance(row, dict) and row.get("canonical_skill_id") == canonical_skill_id
        ),
        None,
    )
    from_state = str((existing_record or {}).get("list_state") or "unlisted")
    record, scan_and_transition = _registry_record_for_scan(
        skill_root=skill_root,
        framework=framework,
        scope=scope,
        list_state=list_state,
        from_state=from_state,
        operator_override=operator_override,
    )
    same_state_transition = (
        scan_and_transition["transition"]["from_state"]
        == scan_and_transition["transition"]["to_state"]
    )
    integrity_changed = _record_integrity_changed(existing_record, record)
    records = [
        row
        for row in payload["records"]
        if isinstance(row, dict) and row.get("canonical_skill_id") != record.canonical_skill_id
    ]
    records.append(record.model_dump(mode="json"))
    payload["records"] = sorted(records, key=lambda row: str(row.get("canonical_name") or ""))
    if not same_state_transition or integrity_changed:
        payload["transition_events"].append(scan_and_transition["transition"])
    payload["latest_scan"] = scan_and_transition["scan"]
    _write_json(registry, payload)
    result = {
        "registered": record.model_dump(mode="json"),
        "transition": scan_and_transition["transition"],
        "registry": str(registry),
    }
    if json_mode:
        print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    else:
        print(f"registered: {record.canonical_name}")
        print(f"list_state: {record.list_state}")
        print(f"registry: {registry}")
    return 0


def run_skill_trust_register_dir(
    *,
    skills_dir: Path,
    registry: Path,
    metadata: Path,
    framework: str = "codex",
    scope: str = "workspace",
    json_mode: bool = False,
) -> int:
    if not skills_dir.is_dir():
        raise ValueError(f"skills-dir must be a directory: {skills_dir}")
    bundle = build_skill_trust_bundle(skills_dir, framework=framework, scope=scope)
    existing_payload = _read_registry(registry)
    merged_records = _merge_registry_records(existing_payload, bundle["records"])
    registry_payload = {
        "schema_version": "clawsentry.skill_registry.v1",
        "records": merged_records,
        "transition_events": [
            *existing_payload.get("transition_events", []),
            *_register_dir_transition_events(
                existing_payload=existing_payload,
                merged_records=merged_records,
                bundle_records=bundle["records"],
                scope=scope,
            ),
        ],
        "source": {
            "framework": framework,
            "scope": scope,
            "skills_dir": str(skills_dir),
            "bundle_schema_version": bundle["schema_version"],
        },
    }
    metadata_payload = {
        "schema_version": bundle["schema_version"],
        "framework": framework,
        "skill_parent": bundle["skill_parent"],
        "raw_metadata_by_skill": bundle["raw_metadata_by_skill"],
        "preflight_actions": bundle["preflight_actions"],
    }
    _write_json(registry, registry_payload)
    _write_json(metadata, metadata_payload)
    result = {
        "registry": str(registry),
        "metadata": str(metadata),
        "record_count": len(bundle["records"]),
        "preflight_action_count": len(bundle["preflight_actions"]),
    }
    if json_mode:
        print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    else:
        print(f"registry: {registry}")
        print(f"metadata: {metadata}")
        print(f"records: {len(bundle['records'])}")
        print(f"preflight_actions: {len(bundle['preflight_actions'])}")
    return 0


def run_skill_trust_command(args: Any) -> int:
    try:
        if args.skill_trust_command == "scan":
            return run_skill_trust_scan(
                skill_root=args.skill_root,
                output=args.output,
                json_mode=args.json,
            )
        if args.skill_trust_command == "register":
            return run_skill_trust_register(
                skill_root=args.skill_root,
                registry=args.registry,
                framework=args.framework,
                scope=args.scope,
                list_state=args.list_state,
                operator_override=args.operator_override,
                json_mode=args.json,
            )
        if args.skill_trust_command == "register-dir":
            return run_skill_trust_register_dir(
                skills_dir=args.skills_dir,
                registry=args.registry,
                metadata=args.metadata,
                framework=args.framework,
                scope=args.scope,
                json_mode=args.json,
            )
    except Exception as exc:
        print(f"clawsentry skill-trust: {exc}", file=sys.stderr)
        return 2
    print("Usage: clawsentry skill-trust {scan,register,register-dir}", file=sys.stderr)
    return 2
