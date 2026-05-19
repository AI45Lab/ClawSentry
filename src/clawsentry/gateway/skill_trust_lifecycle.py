"""Skill Trust lifecycle transition helpers."""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Iterable

from .models import SkillRegistryRecord, SkillTrustTransitionEvent
from .skill_trust import apply_trust_list_state, transition_trust_list_state


def _parse_datetime(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _snapshot_for_record(record: SkillRegistryRecord) -> str:
    import hashlib
    import json

    payload = json.dumps(record.model_dump(mode="json"), sort_keys=True).encode("utf-8")
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _record_content_hashes(record: SkillRegistryRecord) -> set[str]:
    return {
        str(value).strip()
        for value in (record.content_hashes or {}).values()
        if str(value).strip()
    }


def _valid_operator_id_hash(value: str | None) -> bool:
    return bool(value and re.fullmatch(r"sha256:[0-9a-fA-F]{64}", value))


def apply_lifecycle_transition(
    record: SkillRegistryRecord,
    *,
    target_state: str,
    reason_code: str,
    actor_type: str,
    operator_id_hash: str | None = None,
    override_id: str | None = None,
    override_indefinite_reason: str | None = None,
    evidence_hashes: list[str] | None = None,
    evidence_refs: list[str] | None = None,
    expected_registry_snapshot_id: str | None,
    idempotency_key: str | None,
    policy_fingerprint: str = "sha256:skill-trust-lifecycle-v1",
    expires_at: str | None = None,
    disabled_until: str | None = None,
    restore_target_state: str | None = None,
) -> tuple[SkillRegistryRecord, SkillTrustTransitionEvent]:
    """Apply one validated lifecycle transition to a registry record."""

    if not expected_registry_snapshot_id:
        raise ValueError("expected_registry_snapshot_id is required")
    if not idempotency_key:
        raise ValueError("idempotency_key is required")
    hashes = list(evidence_hashes or [])
    refs = list(evidence_refs or [])
    if override_id:
        if actor_type not in {"operator", "manual_migration"}:
            raise ValueError("operator override requires operator or manual migration actor")
        if not _valid_operator_id_hash(operator_id_hash):
            raise ValueError("operator override requires operator_id_hash")
        if not expires_at and not str(override_indefinite_reason or "").strip():
            raise ValueError("operator override requires expires_at or override_indefinite_reason")
    if record.list_state in {"revoked", "blacklist"} and target_state == "allowlist":
        if reason_code != "trusted_migration" and not override_id:
            raise ValueError("revoked/blacklist allowlist transition requires trusted migration or operator override")
    if (
        record.list_state == "greylist"
        and target_state == "allowlist"
        and (
            reason_code in {"clean_admission_report", "trusted_migration"}
            or override_id
        )
    ):
        required_hashes = _record_content_hashes(record)
        if required_hashes and not required_hashes.issubset(set(hashes)):
            raise ValueError("greylist allowlist transition requires matching content integrity evidence")
    event = transition_trust_list_state(
        canonical_skill_id=record.canonical_skill_id,
        from_state=record.list_state,
        to_state=target_state,
        reason_code=(
            "operator_override"
            if override_id and target_state == "allowlist" and reason_code != "trusted_migration"
            else reason_code
        ),
        evidence_hashes=hashes,
        scope="workspace",
        actor_type=actor_type,
        policy_fingerprint=policy_fingerprint,
        operator_id_hash=operator_id_hash,
        override_id=override_id,
        override_indefinite_reason=override_indefinite_reason,
        expires_at=expires_at,
        disabled_until=disabled_until,
    )
    event = event.model_copy(update={
        "metadata_record_id": record.source.get("metadata_record_id"),
        "evidence_refs": refs,
        "restore_target_state": restore_target_state,
        "registry_snapshot_id": _snapshot_for_record(record),
        "idempotency_key": idempotency_key,
    })
    updated_source = dict(record.source or {})
    if target_state == "disabled":
        updated_source["previous_active_state"] = record.list_state
        if disabled_until:
            updated_source["disabled_until"] = disabled_until
    if restore_target_state:
        updated_source["restore_target_state"] = restore_target_state
    updated = apply_trust_list_state(record, target_state, reason_code=reason_code)
    updated = updated.model_copy(update={"source": updated_source})
    return updated, event


def apply_expired_lifecycle_windows(
    records: Iterable[SkillRegistryRecord],
    *,
    now: str,
    policy_fingerprint: str,
) -> tuple[list[SkillRegistryRecord], list[SkillTrustTransitionEvent]]:
    """Restore expired disabled windows with explicit system transition events."""

    now_dt = _parse_datetime(now) or datetime.now(timezone.utc)
    updated_records: list[SkillRegistryRecord] = []
    events: list[SkillTrustTransitionEvent] = []
    for record in records:
        disabled_until = _parse_datetime(str((record.source or {}).get("disabled_until") or ""))
        if record.list_state == "disabled" and disabled_until and disabled_until <= now_dt:
            target_state = str((record.source or {}).get("previous_active_state") or "unlisted")
            restored, event = apply_lifecycle_transition(
                record,
                target_state=target_state,
                reason_code="disabled_window_expired",
                actor_type="system",
                evidence_hashes=[],
                evidence_refs=[],
                expected_registry_snapshot_id=_snapshot_for_record(record),
                idempotency_key=f"expiry:{record.canonical_skill_id}:{disabled_until.isoformat()}",
                policy_fingerprint=policy_fingerprint,
            )
            updated_records.append(restored)
            events.append(event)
            continue
        updated_records.append(record)
    return updated_records, events
