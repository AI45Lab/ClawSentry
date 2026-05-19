"""``clawsentry skill-trust`` — admission scan and registry utilities."""

from __future__ import annotations

import json
import os
import re
import sys
import tempfile
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from clawsentry.gateway.models import RiskLevel, SkillRegistryRecord
from clawsentry.gateway.skill_trust import (
    AdmissionScanner,
    POLICY_FINGERPRINT,
    apply_trust_list_state,
    build_skill_trust_bundle,
    record_with_skill_trust_grade,
    transition_trust_list_state,
)
from clawsentry.gateway.skill_trust_lifecycle import (
    apply_expired_lifecycle_windows,
    apply_lifecycle_transition,
)

_FRONTMATTER_NAME = re.compile(r"^name:\s*[\"']?([^\"'\n]+)[\"']?\s*$", re.M)
_FRONTMATTER_ALIASES = re.compile(r"^aliases:\s*\[([^\]]*)\]\s*$", re.M)
_REGISTRY_LOCKS: dict[str, threading.RLock] = {}
_REGISTRY_LOCKS_GUARD = threading.Lock()


def _sha256_text(value: str) -> str:
    import hashlib

    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


def _registry_lock(path: Path) -> threading.RLock:
    key = str(path.expanduser().resolve(strict=False))
    with _REGISTRY_LOCKS_GUARD:
        lock = _REGISTRY_LOCKS.get(key)
        if lock is None:
            lock = threading.RLock()
            _REGISTRY_LOCKS[key] = lock
        return lock


def _transition_sidecar_path(path: Path) -> Path:
    return path.with_name(f"{path.name}.transitions.jsonl")


def _transition_event_id(event: Any) -> str:
    if isinstance(event, dict):
        return str(event.get("transition_id") or "")
    return ""


def _read_transition_sidecar(path: Path) -> list[dict[str, Any]]:
    sidecar = _transition_sidecar_path(path)
    if not sidecar.exists():
        return []
    rows: list[dict[str, Any]] = []
    for line_number, line in enumerate(
        sidecar.read_text(encoding="utf-8").splitlines(),
        start=1,
    ):
        if not line.strip():
            continue
        row = json.loads(line)
        if not isinstance(row, dict):
            raise ValueError(
                f"skill registry transition sidecar row {line_number} must be a JSON object"
            )
        rows.append(row)
    return rows


def _merge_transition_events(
    embedded_events: list[Any],
    sidecar_events: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    sidecar_ids = {
        event_id for event_id in (_transition_event_id(event) for event in sidecar_events)
        if event_id
    }
    merged: list[dict[str, Any]] = [
        event
        for event in embedded_events
        if isinstance(event, dict)
        and (
            not _transition_event_id(event)
            or _transition_event_id(event) not in sidecar_ids
        )
    ]
    merged.extend(sidecar_events)
    return merged


def _write_transition_sidecar(path: Path, events: list[Any]) -> None:
    event_rows = [event for event in events if isinstance(event, dict)]
    if not event_rows:
        return
    sidecar = _transition_sidecar_path(path)
    existing_rows = _read_transition_sidecar(path)
    existing_ids = {
        event_id for event_id in (_transition_event_id(row) for row in existing_rows)
        if event_id
    }
    rows = list(existing_rows)
    for event in event_rows:
        event_id = _transition_event_id(event)
        if event_id and event_id in existing_ids:
            continue
        rows.append(event)
        if event_id:
            existing_ids.add(event_id)
    if len(rows) == len(existing_rows):
        return
    sidecar.parent.mkdir(parents=True, exist_ok=True)
    data = "".join(
        json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n"
        for row in rows
    )
    with tempfile.NamedTemporaryFile(
        "w",
        encoding="utf-8",
        dir=sidecar.parent,
        prefix=f".{sidecar.name}.",
        suffix=".tmp",
        delete=False,
    ) as handle:
        temp_name = handle.name
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temp_name, sidecar)


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
    payload["transition_events"] = _merge_transition_events(
        payload["transition_events"],
        _read_transition_sidecar(path),
    )
    payload["records"] = [
        record_with_skill_trust_grade(row) if isinstance(row, dict) else row
        for row in payload["records"]
    ]
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


def _registry_snapshot_id(payload: dict[str, Any]) -> str:
    records = [
        {key: value for key, value in row.items() if key != "skill_trust_grade"}
        if isinstance(row, dict)
        else row
        for row in payload.get("records", [])
    ]
    material = {
        "schema_version": payload.get("schema_version"),
        "records": records,
        "transition_events": payload.get("transition_events", []),
    }
    return _sha256_text(json.dumps(material, ensure_ascii=False, sort_keys=True))


def _write_registry(
    path: Path,
    payload: dict[str, Any],
    *,
    expected_registry_snapshot_id: str | None = None,
) -> None:
    with _registry_lock(path):
        if expected_registry_snapshot_id is not None:
            current_payload = _read_registry(path)
            current_snapshot = _registry_snapshot_id(current_payload)
            if current_snapshot != expected_registry_snapshot_id:
                raise ValueError(
                    "registry snapshot mismatch: "
                    f"expected {expected_registry_snapshot_id}, current {current_snapshot}"
                )
        payload = dict(payload)
        payload["records"] = [
            record_with_skill_trust_grade(row) if isinstance(row, dict) else row
            for row in payload.get("records", [])
        ]
        payload["registry_snapshot_id"] = _registry_snapshot_id(payload)
        _write_json(path, payload)
        _write_transition_sidecar(path, payload.get("transition_events", []))


def _consume_expired_lifecycle_windows(
    registry: Path,
    payload: dict[str, Any],
) -> dict[str, Any]:
    records = [
        SkillRegistryRecord.model_validate(row)
        for row in payload.get("records", [])
        if isinstance(row, dict)
    ]
    updated_records, events = apply_expired_lifecycle_windows(
        records,
        now=datetime.now(timezone.utc).isoformat(),
        policy_fingerprint=POLICY_FINGERPRINT,
    )
    if not events:
        return payload
    updated_payload = dict(payload)
    updated_payload["records"] = [
        record.model_dump(mode="json") for record in updated_records
    ]
    updated_payload["transition_events"] = [
        *payload.get("transition_events", []),
        *(event.model_dump(mode="json") for event in events),
    ]
    _write_registry(
        registry,
        updated_payload,
        expected_registry_snapshot_id=_registry_snapshot_id(payload),
    )
    return _read_registry(registry)


def _transition_optional_str(value: Any) -> str | None:
    return str(value) if value else None


def _transition_idempotency_reason(
    *,
    target_state: str,
    reason_code: str,
    override_id: str | None,
) -> str:
    if override_id and target_state == "allowlist" and reason_code != "trusted_migration":
        return "operator_override"
    return reason_code


def _find_transition_event_by_idempotency_key(
    payload: dict[str, Any],
    idempotency_key: str,
) -> dict[str, Any] | None:
    for event in payload.get("transition_events", []):
        if isinstance(event, dict) and str(event.get("idempotency_key") or "") == idempotency_key:
            return event
    return None


def _transition_idempotency_matches(
    event: dict[str, Any],
    *,
    canonical_skill_id: str,
    target_state: str,
    reason_code: str,
    operator_id_hash: str | None,
    override_id: str | None,
    override_indefinite_reason: str | None,
    expires_at: str | None,
    disabled_until: str | None,
    restore_target_state: str | None,
) -> bool:
    expected = {
        "canonical_skill_id": canonical_skill_id,
        "to_state": target_state,
        "reason_code": _transition_idempotency_reason(
            target_state=target_state,
            reason_code=reason_code,
            override_id=override_id,
        ),
        "operator_id_hash": operator_id_hash,
        "override_id": override_id,
        "override_indefinite_reason": override_indefinite_reason,
        "expires_at": expires_at,
        "disabled_until": disabled_until,
        "restore_target_state": restore_target_state,
    }
    for key, value in expected.items():
        actual = event.get(key)
        if _transition_optional_str(actual) != _transition_optional_str(value):
            return False
    return True


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
        sbom=report.sbom,
        checksum_evidence=report.checksum_evidence,
        signature_evidence=report.signature_evidence,
        advisory_evidence=report.advisory_evidence,
        source={
            "framework": framework,
            "path_hash": _sha256_text(str(skill_root.resolve())),
            "skill_root_hash": report.skill_root_hash,
            "scope": scope,
            "admission_risk": report.admission_risk.value,
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
    _write_registry(registry, payload)
    result = {
        "registered": record_with_skill_trust_grade(record),
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
    allowed_runtime_parents: list[Path] | None = None,
    json_mode: bool = False,
) -> int:
    if not skills_dir.is_dir():
        raise ValueError(f"skills-dir must be a directory: {skills_dir}")
    bundle = build_skill_trust_bundle(
        skills_dir,
        framework=framework,
        scope=scope,
        allowed_runtime_parents=allowed_runtime_parents or (),
    )
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
        "metadata_records": bundle.get("metadata_records", []),
        "metadata_by_normalized_name": bundle.get("metadata_by_normalized_name", {}),
        "raw_metadata_by_skill": bundle["raw_metadata_by_skill"],
        "preflight_actions": bundle["preflight_actions"],
    }
    _write_registry(registry, registry_payload)
    _write_json(metadata, metadata_payload)
    written_payload = _read_registry(registry)
    result = {
        "registry": str(registry),
        "metadata": str(metadata),
        "record_count": len(bundle["records"]),
        "records": written_payload.get("records", []),
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


def run_skill_trust_transition(
    *,
    registry: Path,
    canonical_skill_id: str,
    target_state: str,
    reason_code: str,
    expected_registry_snapshot_id: str,
    idempotency_key: str,
    operator_id_hash: str | None = None,
    override_id: str | None = None,
    override_indefinite_reason: str | None = None,
    expires_at: str | None = None,
    disabled_until: str | None = None,
    restore_target_state: str | None = None,
    json_mode: bool = False,
) -> int:
    payload = _read_registry(registry)
    payload = _consume_expired_lifecycle_windows(registry, payload)
    current_snapshot = _registry_snapshot_id(payload)
    records = [
        row
        for row in payload["records"]
        if isinstance(row, dict)
    ]
    record_row = next(
        (
            row for row in records
            if str(row.get("canonical_skill_id") or "") == canonical_skill_id
        ),
        None,
    )
    if record_row is None:
        raise ValueError(f"skill not found in registry: {canonical_skill_id}")
    record = SkillRegistryRecord.model_validate(record_row)
    effective_restore_target_state = restore_target_state
    if target_state == "restore":
        effective_restore_target_state = (
            restore_target_state
            or str((record.source or {}).get("previous_active_state") or "")
            or None
        )
        if effective_restore_target_state not in {
            "allowlist",
            "greylist",
            "blacklist",
            "unlisted",
        }:
            raise ValueError("restore requires a previous or explicit active target state")
        target_state = effective_restore_target_state
    replay_event = _find_transition_event_by_idempotency_key(payload, idempotency_key)
    if replay_event is not None:
        if not _transition_idempotency_matches(
            replay_event,
            canonical_skill_id=canonical_skill_id,
            target_state=target_state,
            reason_code=reason_code,
            operator_id_hash=operator_id_hash,
            override_id=override_id,
            override_indefinite_reason=override_indefinite_reason,
            expires_at=expires_at,
            disabled_until=disabled_until,
            restore_target_state=effective_restore_target_state,
        ):
            raise ValueError("idempotency key conflict")
        result = {
            "record": record_row,
            "transition": replay_event,
            "registry": str(registry),
            "registry_snapshot_id": current_snapshot,
            "idempotent_replay": True,
        }
        if json_mode:
            print(json.dumps(result, ensure_ascii=False, sort_keys=True))
        else:
            print(f"transition replayed: {record.canonical_name}")
            print(f"list_state: {record.list_state}")
            print(f"registry: {registry}")
        return 0
    if expected_registry_snapshot_id != current_snapshot:
        raise ValueError(
            "registry snapshot mismatch: "
            f"expected {expected_registry_snapshot_id}, current {current_snapshot}"
        )
    updated, event = apply_lifecycle_transition(
        record,
        target_state=target_state,
        reason_code=reason_code,
        actor_type="operator",
        operator_id_hash=operator_id_hash,
        override_id=override_id,
        override_indefinite_reason=override_indefinite_reason,
        evidence_hashes=_record_evidence_hashes(record),
        evidence_refs=[],
        expected_registry_snapshot_id=current_snapshot,
        idempotency_key=idempotency_key,
        policy_fingerprint=record.policy_fingerprint or POLICY_FINGERPRINT,
        expires_at=expires_at,
        disabled_until=disabled_until,
        restore_target_state=effective_restore_target_state,
    )
    updated_rows = [
        row for row in records
        if str(row.get("canonical_skill_id") or "") != canonical_skill_id
    ]
    updated_rows.append(updated.model_dump(mode="json"))
    payload["records"] = sorted(updated_rows, key=lambda row: str(row.get("canonical_name") or ""))
    payload["transition_events"].append(event.model_dump(mode="json"))
    _write_registry(
        registry,
        payload,
        expected_registry_snapshot_id=current_snapshot,
    )
    result = {
        "record": record_with_skill_trust_grade(updated),
        "transition": event.model_dump(mode="json"),
        "registry": str(registry),
        "registry_snapshot_id": json.loads(registry.read_text(encoding="utf-8"))["registry_snapshot_id"],
        "idempotent_replay": False,
    }
    if json_mode:
        print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    else:
        print(f"transitioned: {updated.canonical_name}")
        print(f"list_state: {updated.list_state}")
        print(f"registry: {registry}")
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
                allowed_runtime_parents=args.allowed_runtime_parent,
                json_mode=args.json,
            )
        if args.skill_trust_command == "transition":
            return run_skill_trust_transition(
                registry=args.registry,
                canonical_skill_id=args.canonical_skill_id,
                target_state=args.target_state,
                reason_code=args.reason_code,
                expected_registry_snapshot_id=args.expected_registry_snapshot_id,
                idempotency_key=args.idempotency_key,
                operator_id_hash=args.operator_id_hash,
                override_id=args.override_id,
                override_indefinite_reason=args.override_indefinite_reason,
                expires_at=args.expires_at,
                disabled_until=args.disabled_until,
                json_mode=args.json,
            )
        lifecycle_shortcuts = {
            "allowlist": ("allowlist", "operator_allowlist"),
            "greylist": ("greylist", "operator_greylist"),
            "blacklist": ("blacklist", "operator_blacklist"),
            "revoke": ("revoked", "operator_revoke"),
            "disable": ("disabled", "operator_disable"),
            "restore": ("restore", "operator_restore"),
            "override": ("allowlist", "operator_override"),
        }
        if args.skill_trust_command in lifecycle_shortcuts:
            target_state, reason_code = lifecycle_shortcuts[args.skill_trust_command]
            return run_skill_trust_transition(
                registry=args.registry,
                canonical_skill_id=args.canonical_skill_id,
                target_state=target_state,
                reason_code=reason_code,
                expected_registry_snapshot_id=args.expected_registry_snapshot_id,
                idempotency_key=args.idempotency_key,
                operator_id_hash=args.operator_id_hash,
                override_id=(
                    args.override_id
                    or (
                        args.idempotency_key
                        if args.skill_trust_command == "override"
                        else None
                    )
                ),
                override_indefinite_reason=args.override_indefinite_reason,
                expires_at=getattr(args, "expires_at", None),
                disabled_until=getattr(args, "disabled_until", None),
                restore_target_state=getattr(args, "restore_target_state", None),
                json_mode=args.json,
            )
    except Exception as exc:
        print(f"clawsentry skill-trust: {exc}", file=sys.stderr)
        return 2
    print(
        "Usage: clawsentry skill-trust {scan,register,register-dir,transition,allowlist,greylist,blacklist,revoke,disable,restore,override}",
        file=sys.stderr,
    )
    return 2
