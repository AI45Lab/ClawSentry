"""Deterministic skill trust evidence for Gateway policy consumption."""

from __future__ import annotations

import ast
import hashlib
import json
import re
import time
import tokenize
from dataclasses import dataclass, field
from io import StringIO
from pathlib import Path
from typing import Any, Iterable, Sequence

from .models import (
    AdmissionFinding,
    AdmissionReport,
    FirstUseScanState,
    RiskLevel,
    RuntimeSkillRef,
    SkillRegistryRecord,
    SkillTrustContext,
    SkillTrustTransitionEvent,
)

POLICY_FINGERPRINT = "sha256:skill-trust-mvp-v1"
_MAX_HASH_FILE_BYTES = 1024 * 1024
_FRAMEWORKS = ("codex", "claude-code", "kimi-cli", "gemini-cli")
RUNTIME_PATH_STATUSES = frozenset({
    "verified_source",
    "verified_mirror",
    "verified_name",
    "name_only_unverified",
    "path_fragment_unverified",
    "disallowed",
    "ambiguous_runtime_source",
    "absent",
})
RUNTIME_CONTENT_STATUSES = frozenset({
    "content_verified",
    "trusted_runner_immutable",
    "content_unverified",
    "content_mismatch",
    "not_applicable",
})
SKILL_TRUST_GRADES = frozenset({
    "trusted",
    "review",
    "restricted",
    "blocked",
    "disabled",
})


@dataclass(frozen=True)
class SkillTrustMetadataRecord:
    metadata_record_id: str
    presented_name: str
    canonical_skill_id: str | None = None
    canonical_name: str | None = None
    source_root_path: str | None = None
    source_root_path_hash: str | None = None
    allowed_runtime_roots: tuple[str, ...] = ()
    allowed_runtime_root_hashes: tuple[str, ...] = ()
    mirror_integrity_mode: str = "unverified"
    trusted_runner_contract_id: str | None = None
    runner_contract_attestation_required: bool = False
    runtime_binding_profile: str = "source_or_mirror"
    content_hashes: dict[str, str] = field(default_factory=dict)
    metadata_record_id_compat: bool = False
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class SkillTrustMetadataBundle:
    metadata_records: tuple[SkillTrustMetadataRecord, ...]
    metadata_by_normalized_name: dict[str, list[str]]
    raw_metadata_by_skill: dict[str, dict[str, Any]]

_METADATA_AVAILABILITY_MATRIX: tuple[dict[str, Any], ...] = (
    {
        "field": "presented_skill_name",
        "sources": {
            "codex": "benchmark wrapper skill_trust_raw.presented_name or hook metadata when exposed",
            "claude-code": "unavailable",
            "kimi-cli": "unavailable",
            "gemini-cli": "unavailable",
        },
        "if_unavailable": "registry_status=unbound",
        "decision_impact": "missing presented skill metadata is audit/defer evidence by profile; no identity block from missing alone",
    },
    {
        "field": "skill_root_path_hash",
        "sources": {
            "codex": "benchmark wrapper skill_lineage_raw.skill_root_path_hash or package path hash",
            "claude-code": "unavailable",
            "kimi-cli": "unavailable",
            "gemini-cli": "unavailable",
        },
        "if_unavailable": "registry_status=unbound or unknown depending on name evidence",
        "decision_impact": "missing path hash disables hash-mismatch rule; no hash block from missing alone",
    },
    {
        "field": "content_hash",
        "sources": {
            "codex": "admission report content_hashes for SKILL.md/scripts/references/data",
            "claude-code": "unavailable",
            "kimi-cli": "unavailable",
            "gemini-cli": "unavailable",
        },
        "if_unavailable": "admission_risk=unknown",
        "decision_impact": "missing content hash disables hash-mismatch rule; no hash block from missing alone",
    },
    {
        "field": "output_provenance_label",
        "sources": {
            "codex": "tool_called, output_provenance_label, or explicit provenance_claim when provided",
            "claude-code": "unavailable",
            "kimi-cli": "unavailable",
            "gemini-cli": "unavailable",
        },
        "if_unavailable": "provenance_claim absent",
        "decision_impact": "missing provenance label cannot trigger provenance-conflict block by itself",
    },
    {
        "field": "framework_session_ids",
        "sources": {
            "codex": "native session_id/trace_id from wrapper or hook payload",
            "claude-code": "unavailable",
            "kimi-cli": "unavailable",
            "gemini-cli": "unavailable",
        },
        "if_unavailable": "lineage event records unavailable id",
        "decision_impact": "missing framework ids reduce attribution only; no block from missing alone",
    },
)


def _record_dict(record: SkillRegistryRecord | dict[str, Any]) -> dict[str, Any]:
    if isinstance(record, SkillRegistryRecord):
        return record.model_dump(mode="json")
    return dict(record)


def _record_source(record: dict[str, Any]) -> dict[str, Any]:
    source = record.get("source")
    return source if isinstance(source, dict) else {}


def _advisory_evidence(record: dict[str, Any]) -> list[dict[str, Any]]:
    evidence = record.get("advisory_evidence")
    if not isinstance(evidence, list):
        return []
    return [item for item in evidence if isinstance(item, dict)]


def _first_present(values: Iterable[Any]) -> str:
    for value in values:
        if value is not None and str(value).strip():
            return str(value).strip()
    return ""


def derive_skill_trust_grade(record: SkillRegistryRecord | dict[str, Any]) -> str:
    """Derive operator-facing Skill Trust grade from record evidence.

    The grade is display-only. Policy continues to consume the underlying
    trust-list state, admission, runtime binding, FSPR, and P2 evidence fields.
    """

    data = _record_dict(record)
    source = _record_source(data)
    list_state = str(data.get("list_state") or data.get("trust_list_state") or "unlisted")
    if list_state == "disabled":
        return "disabled"
    if list_state in {"blacklist", "revoked"}:
        return "blocked"

    admission_risk = _first_present((
        data.get("admission_risk"),
        source.get("admission_risk"),
        source.get("first_use_scan_admission_risk"),
    ))
    runtime_path_status = _first_present((
        data.get("runtime_path_status"),
        source.get("runtime_path_status"),
    ))
    runtime_content_status = _first_present((
        data.get("runtime_content_status"),
        source.get("runtime_content_status"),
    ))
    fspr_verdict = _first_present((
        data.get("fspr_verdict"),
        source.get("fspr_verdict"),
        source.get("first_use_package_review_verdict"),
    ))
    advisory = _advisory_evidence(data)
    advisory_verdicts = {
        str(item.get("verdict") or item.get("finding_type") or item.get("reason_code") or "")
        for item in advisory
    }
    unresolved_p2 = any(
        str(item.get("source") or item.get("finding_family") or "").lower()
        in {"p2", "provenance", "provenance_validator"}
        and item.get("resolved") is not True
        for item in advisory
    )

    if (
        admission_risk in {"high", "critical"}
        or runtime_path_status in {"disallowed", "ambiguous_runtime_source"}
        or runtime_content_status == "content_mismatch"
        or fspr_verdict == "inconsistent"
        or "inconsistent" in advisory_verdicts
        or unresolved_p2
    ):
        return "restricted"
    if (
        list_state in {"greylist", "unlisted"}
        or admission_risk in {"medium", "unknown"}
        or runtime_path_status in {"name_only_unverified", "path_fragment_unverified"}
        or runtime_content_status == "content_unverified"
        or fspr_verdict == "insufficient_evidence"
        or "insufficient_evidence" in advisory_verdicts
    ):
        return "review"
    if list_state == "allowlist":
        return "trusted"
    return "review"


def record_with_skill_trust_grade(
    record: SkillRegistryRecord | dict[str, Any],
) -> dict[str, Any]:
    data = _record_dict(record)
    data["skill_trust_grade"] = derive_skill_trust_grade(data)
    return data

_ALLOWED_TRANSITIONS: set[tuple[str, str]] = {
    ("unlisted", "greylist"),
    ("unlisted", "allowlist"),
    ("unlisted", "blacklist"),
    ("greylist", "allowlist"),
    ("greylist", "blacklist"),
    ("blacklist", "greylist"),
    ("allowlist", "greylist"),
    ("allowlist", "blacklist"),
    ("allowlist", "revoked"),
    ("greylist", "revoked"),
    ("blacklist", "revoked"),
    ("allowlist", "disabled"),
    ("greylist", "disabled"),
    ("blacklist", "disabled"),
    ("unlisted", "disabled"),
    ("disabled", "allowlist"),
    ("disabled", "greylist"),
    ("disabled", "blacklist"),
    ("revoked", "allowlist"),
    ("revoked", "greylist"),
}
_ALLOWED_TRANSITIONS.update((state, state) for state in {
    "unlisted",
    "greylist",
    "allowlist",
    "blacklist",
    "revoked",
    "disabled",
})


def skill_trust_metadata_availability_matrix() -> list[dict[str, Any]]:
    """Return the MVP framework metadata availability matrix."""

    return [
        {
            "field": str(row["field"]),
            "sources": {framework: str(row["sources"][framework]) for framework in _FRAMEWORKS},
            "if_unavailable": str(row["if_unavailable"]),
            "decision_impact": str(row["decision_impact"]),
        }
        for row in _METADATA_AVAILABILITY_MATRIX
    ]

_CONTROL_LANGUAGE = re.compile(
    r"\b(canonical|renamed|deprecated|use\s+.+\s+instead|priority|ranking|prefer)\b",
    re.I,
)
_PROVENANCE_LANGUAGE = re.compile(
    r"\b(tool_called|provenance|source\s+label|registry\s+label|canonical\s+skill\s+name)\b",
    re.I,
)
_FRONTMATTER_NAME = re.compile(r"^name:\s*[\"']?([A-Za-z0-9_. -]+)[\"']?\s*$", re.M)
_FRONTMATTER_ALIASES = re.compile(r"^aliases:\s*\[([^\]]*)\]\s*$", re.M)
_SCRIPT_OUTPUT_LABEL = re.compile(
    r"\b(?:TOOL_CALLED_LABEL|OUTPUT_PROVENANCE_LABEL|SOURCE_LABEL|tool_called|provenance_label)"
    r"\s*[:=]\s*[\"']([^\"']+)[\"']",
    re.I,
)
_SCRIPT_RANK_FILTER = re.compile(
    r"(?:\bsorted\b|\bsorted_call\b|\bsort_call\b|(?:^|[\s.])sort\s*\(|\bfilter\b|"
    r"\bfilter_call\b|\bcomprehension_filter\b|\bslice_limit\b|\breverse\s*=|\brank(?:ing)?\b|"
    r"\bwhere\b|\blimit\b|\btop_?k\b|\[\s*:\s*\d+)",
    re.I,
)
_DECLARED_RANK_FILTER = re.compile(
    r"\b(sort(?:ed|ing)?|filter(?:ed|ing)?|rank(?:ed|ing)?|order(?:ed|ing)?|"
    r"prioriti[sz](?:e|ed|ing)?|priority|limit(?:ed|ing)?|top\s*\d+|top_?k|score(?:d|ing)?)\b",
    re.I,
)


def _sha256(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _runtime_root_path_hash(path: str | None) -> str | None:
    if not path:
        return None
    return _sha256(str(path).encode("utf-8"))


def _hash_file(path: Path, *, max_file_bytes: int | None = None) -> str:
    if path.is_symlink():
        return _sha256(f"symlink-skipped:{path.name}".encode("utf-8"))
    try:
        size = path.stat().st_size
        effective_max_file_bytes = max_file_bytes or _MAX_HASH_FILE_BYTES
        if size > effective_max_file_bytes:
            if max_file_bytes is not None:
                raise TimeoutError("admission scan file byte budget exceeded")
            return _sha256(f"large-file-skipped:{path.name}:{size}".encode("utf-8"))
    except OSError:
        return _sha256(f"file-unreadable:{path.name}".encode("utf-8"))
    return _sha256(path.read_bytes())


def _raise_if_scan_deadline_expired(deadline_at: float | None) -> None:
    if deadline_at is not None and time.monotonic() >= deadline_at:
        raise TimeoutError("admission scan deadline exceeded")


def _read_in_tree_text(path: Path, root: Path, *, deadline_at: float | None = None) -> str:
    _raise_if_scan_deadline_expired(deadline_at)
    if path.is_symlink():
        return ""
    try:
        resolved_root = root.resolve(strict=False)
        resolved_path = path.resolve(strict=False)
        if resolved_root != resolved_path and resolved_root not in resolved_path.parents:
            return ""
        if path.stat().st_size > _MAX_HASH_FILE_BYTES:
            return ""
    except OSError:
        return ""
    return path.read_text(encoding="utf-8", errors="replace")


def _hash_directory(
    path: Path,
    *,
    deadline_at: float | None = None,
    max_files: int | None = None,
    max_file_bytes: int | None = None,
) -> str:
    hasher = hashlib.sha256()
    files_seen = 0
    if path.exists():
        root = path.resolve(strict=False)
        for file in sorted(p for p in path.rglob("*") if p.is_file() or p.is_symlink()):
            _raise_if_scan_deadline_expired(deadline_at)
            if max_files is not None:
                files_seen += 1
                if files_seen > max_files:
                    raise TimeoutError("admission scan file count budget exceeded")
            if file.is_symlink():
                hasher.update(file.relative_to(path).as_posix().encode("utf-8"))
                hasher.update(b"\0symlink-skipped\0")
                continue
            try:
                resolved = file.resolve(strict=False)
                if root != resolved and root not in resolved.parents:
                    continue
                size = file.stat().st_size
            except OSError:
                continue
            rel = file.relative_to(path).as_posix().encode("utf-8")
            hasher.update(rel)
            hasher.update(b"\0")
            effective_max_file_bytes = max_file_bytes or _MAX_HASH_FILE_BYTES
            if size > effective_max_file_bytes:
                if max_file_bytes is not None:
                    raise TimeoutError("admission scan file byte budget exceeded")
                hasher.update(f"large-file-skipped:{size}".encode("utf-8"))
                hasher.update(b"\0")
                continue
            hasher.update(file.read_bytes())
            hasher.update(b"\0")
    return "sha256:" + hasher.hexdigest()


def _iter_safe_files(root: Path) -> Iterable[Path]:
    """Yield regular in-tree files small enough for scanner text inspection."""

    if not root.exists():
        return
    if root.is_symlink():
        return
    root_resolved = root.resolve(strict=False)
    for file in sorted(root.rglob("*")):
        if file.is_symlink() or not file.is_file():
            continue
        try:
            resolved = file.resolve(strict=False)
            if root_resolved != resolved and root_resolved not in resolved.parents:
                continue
            if file.stat().st_size > _MAX_HASH_FILE_BYTES:
                continue
        except OSError:
            continue
        yield file


def load_skill_registry_records(path: str | Path | None) -> list[SkillRegistryRecord]:
    """Load Gateway-owned skill registry records from a JSON file."""

    if not path:
        return []
    registry_path = Path(path)
    if not registry_path.exists():
        raise FileNotFoundError(f"skill registry path does not exist: {registry_path}")
    payload = json.loads(registry_path.read_text(encoding="utf-8"))
    if isinstance(payload, dict):
        rows = payload.get("records") or payload.get("skills") or []
    else:
        rows = payload
    if not isinstance(rows, list):
        raise ValueError("skill registry JSON must be a list or object with records")
    return [
        SkillRegistryRecord.model_validate(row)
        for row in rows
        if isinstance(row, dict)
    ]


def _metadata_record_id_from_material(
    *,
    framework: str,
    scope: str,
    presented_name: str | None,
    canonical_name: str | None,
    source_root_path_hash: str | None,
    skill_root_hash: str | None,
    content_hashes: dict[str, Any] | None,
    registry_snapshot_id: str | None = None,
) -> str:
    material = {
        "schema_version": "clawsentry.skill_trust_metadata_record.v1",
        "framework": framework,
        "scope": scope,
        "normalized_presented_name": _identity_normalize(presented_name),
        "canonical_name": canonical_name or "",
        "source_root_path_hash": source_root_path_hash or "",
        "skill_root_hash": skill_root_hash or "",
        "content_hashes": content_hashes or {},
        "registry_snapshot_id": registry_snapshot_id or "",
    }
    return _sha256(json.dumps(material, sort_keys=True, separators=(",", ":")).encode("utf-8"))


def _metadata_record_from_raw(
    raw: dict[str, Any],
    *,
    framework: str,
    scope: str,
    registry_snapshot_id: str | None = None,
    compat: bool = False,
) -> SkillTrustMetadataRecord:
    presented_name = str(raw.get("presented_name") or raw.get("canonical_name") or "")
    canonical_name = raw.get("canonical_name")
    if canonical_name is not None:
        canonical_name = str(canonical_name)
    source_root_path = raw.get("source_root_path") or raw.get("skill_root_path")
    source_root_path = str(source_root_path) if source_root_path else None
    source_root_path_hash = (
        raw.get("source_root_path_hash")
        or raw.get("skill_root_path_hash")
        or _runtime_root_path_hash(source_root_path)
    )
    source_root_path_hash = str(source_root_path_hash) if source_root_path_hash else None
    allowed_runtime_roots = tuple(
        str(root)
        for root in (raw.get("allowed_runtime_roots") or ([source_root_path] if source_root_path else []))
        if root
    )
    allowed_runtime_root_hashes = tuple(
        str(value)
        for value in (
            raw.get("allowed_runtime_root_hashes")
            or [_runtime_root_path_hash(root) for root in allowed_runtime_roots]
        )
        if value
    )
    content_hashes = {
        str(key): str(value)
        for key, value in (raw.get("content_hashes") or {}).items()
    }
    metadata_record_id = raw.get("metadata_record_id")
    if metadata_record_id:
        metadata_record_id = str(metadata_record_id)
        metadata_record_id_compat = bool(raw.get("metadata_record_id_compat"))
    else:
        metadata_record_id = _metadata_record_id_from_material(
            framework=str(raw.get("framework") or framework),
            scope=str(raw.get("scope") or scope),
            presented_name=presented_name,
            canonical_name=canonical_name,
            source_root_path_hash=source_root_path_hash,
            skill_root_hash=str(raw.get("skill_root_hash") or raw.get("skill_root_path_hash") or ""),
            content_hashes=content_hashes,
            registry_snapshot_id=registry_snapshot_id,
        )
        metadata_record_id_compat = True if compat else bool(raw.get("metadata_record_id_compat"))
    return SkillTrustMetadataRecord(
        metadata_record_id=metadata_record_id,
        presented_name=presented_name,
        canonical_skill_id=str(raw.get("canonical_skill_id")) if raw.get("canonical_skill_id") else None,
        canonical_name=canonical_name,
        source_root_path=source_root_path,
        source_root_path_hash=source_root_path_hash,
        allowed_runtime_roots=allowed_runtime_roots,
        allowed_runtime_root_hashes=allowed_runtime_root_hashes,
        mirror_integrity_mode=str(raw.get("mirror_integrity_mode") or "unverified"),
        trusted_runner_contract_id=(
            str(raw.get("trusted_runner_contract_id"))
            if raw.get("trusted_runner_contract_id")
            else None
        ),
        runner_contract_attestation_required=bool(raw.get("runner_contract_attestation_required")),
        runtime_binding_profile=str(raw.get("runtime_binding_profile") or "source_or_mirror"),
        content_hashes=content_hashes,
        metadata_record_id_compat=metadata_record_id_compat,
        raw=dict(raw),
    )


def _metadata_record_to_raw(record: SkillTrustMetadataRecord) -> dict[str, Any]:
    raw = dict(record.raw)
    raw.update({
        "metadata_record_id": record.metadata_record_id,
        "metadata_record_id_compat": record.metadata_record_id_compat,
        "presented_name": record.presented_name,
        "canonical_skill_id": record.canonical_skill_id,
        "canonical_name": record.canonical_name,
        "source_root_path": record.source_root_path,
        "source_root_path_hash": record.source_root_path_hash,
        "allowed_runtime_roots": list(record.allowed_runtime_roots),
        "allowed_runtime_root_hashes": list(record.allowed_runtime_root_hashes),
        "mirror_integrity_mode": record.mirror_integrity_mode,
        "trusted_runner_contract_id": record.trusted_runner_contract_id,
        "runner_contract_attestation_required": record.runner_contract_attestation_required,
        "runtime_binding_profile": record.runtime_binding_profile,
    })
    return {key: value for key, value in raw.items() if value is not None}


def load_skill_trust_runtime_metadata_bundle(bundle: dict[str, Any] | None) -> SkillTrustMetadataBundle:
    """Normalize old and new runtime metadata bundles into record-indexed metadata."""

    payload = bundle or {}
    framework = str(payload.get("framework") or "codex")
    scope = str(payload.get("scope") or "workspace")
    registry_snapshot_id = (
        str(payload.get("registry_snapshot_id"))
        if payload.get("registry_snapshot_id")
        else None
    )
    raw_by_skill = {
        str(key): dict(value)
        for key, value in (payload.get("raw_metadata_by_skill") or {}).items()
        if isinstance(value, dict)
    }

    records: list[SkillTrustMetadataRecord] = []
    for row in payload.get("metadata_records") or []:
        if isinstance(row, dict):
            records.append(
                _metadata_record_from_raw(
                    row,
                    framework=framework,
                    scope=scope,
                    registry_snapshot_id=registry_snapshot_id,
                )
            )

    if not records:
        for key, raw in raw_by_skill.items():
            row = dict(raw)
            row.setdefault("presented_name", key)
            records.append(
                _metadata_record_from_raw(
                    row,
                    framework=framework,
                    scope=scope,
                    registry_snapshot_id=registry_snapshot_id,
                    compat=True,
                )
            )

    metadata_by_name: dict[str, list[str]] = {}
    for record in records:
        normalized = _display_normalize(record.presented_name or record.canonical_name)
        metadata_by_name.setdefault(normalized, []).append(record.metadata_record_id)

    normalized_raw = {
        key: dict(value)
        for key, value in raw_by_skill.items()
    }
    for record in records:
        key = record.presented_name or record.canonical_name or record.metadata_record_id
        raw = normalized_raw.setdefault(key, {})
        raw.update(_metadata_record_to_raw(record))

    for name, ids in metadata_by_name.items():
        matching = [
            record
            for record in records
            if _display_normalize(record.presented_name or record.canonical_name) == name
        ]
        if len(matching) == 1:
            normalized_raw.setdefault(matching[0].presented_name, {}).update({
                "metadata_record_id": matching[0].metadata_record_id,
            })
        else:
            for record in matching:
                normalized_raw.setdefault(record.presented_name, {}).update({
                    "metadata_record_ids": ids,
                })

    return SkillTrustMetadataBundle(
        metadata_records=tuple(records),
        metadata_by_normalized_name=metadata_by_name,
        raw_metadata_by_skill=normalized_raw,
    )


def _records_for_ref(
    bundle: SkillTrustMetadataBundle,
    ref: RuntimeSkillRef,
) -> list[SkillTrustMetadataRecord]:
    if not ref.name:
        return []
    ids = bundle.metadata_by_normalized_name.get(_display_normalize(ref.name), [])
    by_id = {record.metadata_record_id: record for record in bundle.metadata_records}
    return [by_id[record_id] for record_id in ids if record_id in by_id]


def _runtime_root_matches(record: SkillTrustMetadataRecord, runtime_root: str) -> tuple[str | None, str | None]:
    if record.source_root_path and runtime_root == str(Path(record.source_root_path).expanduser().resolve(strict=False)):
        return "verified_source", "source root matched"
    for allowed in record.allowed_runtime_roots:
        if runtime_root == str(Path(allowed).expanduser().resolve(strict=False)):
            return "verified_mirror", "allowed runtime mirror root matched"
    return None, None


def _runtime_path_within_root(runtime_path: str | None, runtime_root: str) -> bool:
    if not runtime_path:
        return True
    root = Path(runtime_root).expanduser().resolve(strict=False)
    path = Path(runtime_path).expanduser().resolve(strict=False)
    return path == root or root in path.parents


def _content_status_for_match(
    record: SkillTrustMetadataRecord,
    *,
    status: str,
    runtime_root: str | None,
    current_runner_contract_id: str | None,
    mirror_hash_max_files: int | None = None,
    mirror_hash_max_file_bytes: int | None = None,
    mirror_hash_deadline_at: float | None = None,
) -> tuple[str, list[str]]:
    if status == "verified_source":
        return "not_applicable", []
    if record.mirror_integrity_mode == "trusted_runner_immutable":
        if (
            record.runner_contract_attestation_required
            and record.trusted_runner_contract_id
            and current_runner_contract_id == record.trusted_runner_contract_id
        ):
            return "trusted_runner_immutable", []
        return "content_unverified", ["runtime_content_unverified"]
    if record.mirror_integrity_mode == "content_hash":
        if not runtime_root or not record.content_hashes:
            return "content_unverified", ["runtime_content_unverified"]
        try:
            mirror_hashes = AdmissionScanner().scan(
                Path(runtime_root),
                deadline_at=mirror_hash_deadline_at,
                max_files=mirror_hash_max_files,
                max_file_bytes=mirror_hash_max_file_bytes,
            ).content_hashes
        except Exception:
            return "content_unverified", ["runtime_content_unverified"]
        expected_hashes = {
            key: value
            for key, value in record.content_hashes.items()
            if key in {"SKILL.md", "scripts", "references", "data"}
        }
        comparable_hashes = {
            key: mirror_hashes.get(key)
            for key in expected_hashes
            if mirror_hashes.get(key)
        }
        if comparable_hashes != expected_hashes:
            if comparable_hashes:
                return "content_mismatch", ["runtime_content_mismatch"]
            return "content_unverified", ["runtime_content_unverified"]
        return "content_verified", []
    if record.mirror_integrity_mode == "unverified":
        return "content_unverified", ["runtime_content_unverified"]
    return "content_unverified", ["runtime_content_unverified"]


def bind_runtime_skill_refs(
    metadata_bundle: SkillTrustMetadataBundle | dict[str, Any],
    runtime_refs: Iterable[RuntimeSkillRef],
    *,
    framework_contract_allows_name_only: bool = False,
    current_runner_contract_id: str | None = None,
    mirror_hash_max_files: int | None = None,
    mirror_hash_max_file_bytes: int | None = None,
    mirror_hash_max_total_ms: int | None = None,
) -> list[SkillTrustContext]:
    """Bind adapter-observed runtime refs to Gateway-owned metadata records."""

    bundle = (
        load_skill_trust_runtime_metadata_bundle(metadata_bundle)
        if isinstance(metadata_bundle, dict)
        else metadata_bundle
    )
    mirror_hash_deadline_at = (
        time.monotonic() + (mirror_hash_max_total_ms / 1000.0)
        if mirror_hash_max_total_ms is not None
        else None
    )
    bound: list[SkillTrustContext] = []
    for ref in runtime_refs:
        candidates = _records_for_ref(bundle, ref)
        runtime_root = (
            str(Path(ref.runtime_root).expanduser().resolve(strict=False))
            if ref.runtime_root
            else None
        )
        if runtime_root:
            matches: list[tuple[SkillTrustMetadataRecord, str, str]] = []
            for record in candidates:
                status, reason = _runtime_root_matches(record, runtime_root)
                if status and reason:
                    matches.append((record, status, reason))
            if len(matches) == 1:
                record, status, reason = matches[0]
                if not _runtime_path_within_root(ref.runtime_path, runtime_root):
                    bound.append(
                        SkillTrustContext(
                            registry_status="unknown",
                            presented_name=ref.name,
                            runtime_path_status="disallowed",
                            runtime_root_path_hash=ref.observed_runtime_root_path_hash
                            or _runtime_root_path_hash(runtime_root),
                            runtime_binding_reason="runtime path resolves outside runtime root",
                            runtime_evidence_kind=ref.evidence_kind,
                            ref_ordinal=ref.ref_ordinal,
                            invariant_violations=["runtime_path_disallowed"],
                            policy_fingerprint=POLICY_FINGERPRINT,
                        )
                    )
                    continue
                effective_runner_contract_id = current_runner_contract_id
                content_status, violations = _content_status_for_match(
                    record,
                        status=status,
                        runtime_root=runtime_root,
                        current_runner_contract_id=effective_runner_contract_id,
                        mirror_hash_max_files=mirror_hash_max_files,
                        mirror_hash_max_file_bytes=mirror_hash_max_file_bytes,
                        mirror_hash_deadline_at=mirror_hash_deadline_at,
                    )
                bound.append(
                    SkillTrustContext(
                        registry_status="matched",
                        canonical_skill_id=record.canonical_skill_id,
                        presented_name=ref.name,
                        runtime_path_status=status,  # type: ignore[arg-type]
                        runtime_root_path_hash=ref.observed_runtime_root_path_hash
                        or _runtime_root_path_hash(runtime_root),
                        runtime_binding_reason=reason,
                        runtime_content_status=content_status,  # type: ignore[arg-type]
                        metadata_source="gateway_owned_metadata",
                        metadata_record_id=record.metadata_record_id,
                        runtime_evidence_kind=ref.evidence_kind,
                        current_runner_contract_id=effective_runner_contract_id,
                        ref_ordinal=ref.ref_ordinal,
                        trust_list_state="unlisted",
                        invariant_violations=violations,
                        policy_fingerprint=POLICY_FINGERPRINT,
                    )
                )
                continue
            if len(matches) > 1:
                bound.append(
                    SkillTrustContext(
                        registry_status="ambiguous",
                        presented_name=ref.name,
                        runtime_path_status="ambiguous_runtime_source",
                        runtime_root_path_hash=ref.observed_runtime_root_path_hash
                        or _runtime_root_path_hash(runtime_root),
                        runtime_binding_reason="multiple metadata records matched runtime root",
                        runtime_evidence_kind=ref.evidence_kind,
                        ref_ordinal=ref.ref_ordinal,
                        invariant_violations=["runtime_source_ambiguous"],
                        policy_fingerprint=POLICY_FINGERPRINT,
                    )
                )
                continue
            bound.append(
                SkillTrustContext(
                    registry_status="unknown",
                    presented_name=ref.name,
                    runtime_path_status="disallowed",
                    runtime_root_path_hash=ref.observed_runtime_root_path_hash
                    or _runtime_root_path_hash(runtime_root),
                    runtime_binding_reason="runtime root is outside source and allowed mirrors",
                    runtime_evidence_kind=ref.evidence_kind,
                    ref_ordinal=ref.ref_ordinal,
                    invariant_violations=["runtime_path_disallowed"],
                    policy_fingerprint=POLICY_FINGERPRINT,
                )
            )
            continue

        if ref.evidence_kind == "path_fragment":
            bound.append(
                SkillTrustContext(
                    registry_status="unbound",
                    presented_name=ref.name,
                    runtime_path_status="path_fragment_unverified",
                    runtime_binding_reason="skill-like path fragment lacks trusted root",
                    runtime_evidence_kind=ref.evidence_kind,
                    ref_ordinal=ref.ref_ordinal,
                    invariant_violations=["runtime_path_fragment_unverified"],
                    policy_fingerprint=POLICY_FINGERPRINT,
                )
            )
            continue

        if len(candidates) > 1:
            bound.append(
                SkillTrustContext(
                    registry_status="ambiguous",
                    presented_name=ref.name,
                    runtime_path_status="ambiguous_runtime_source",
                    runtime_binding_reason="name-only runtime ref matches multiple metadata records",
                    runtime_evidence_kind=ref.evidence_kind,
                    ref_ordinal=ref.ref_ordinal,
                    invariant_violations=["runtime_source_ambiguous"],
                    policy_fingerprint=POLICY_FINGERPRINT,
                )
            )
            continue
        if len(candidates) == 1 and ref.evidence_kind == "native_skill_call" and framework_contract_allows_name_only:
            record = candidates[0]
            bound.append(
                SkillTrustContext(
                    registry_status="matched",
                    canonical_skill_id=record.canonical_skill_id,
                    presented_name=ref.name,
                    runtime_path_status="verified_name",
                    runtime_content_status="not_applicable",
                    runtime_binding_reason="controlled native skill contract exposed a unique name",
                    metadata_source="gateway_owned_metadata",
                    metadata_record_id=record.metadata_record_id,
                    runtime_evidence_kind=ref.evidence_kind,
                    ref_ordinal=ref.ref_ordinal,
                    trust_list_state="unlisted",
                    policy_fingerprint=POLICY_FINGERPRINT,
                )
            )
            continue
        bound.append(
            SkillTrustContext(
                registry_status="unbound",
                presented_name=ref.name,
                runtime_path_status="name_only_unverified",
                runtime_binding_reason="name-only runtime ref lacks controlled unique binding",
                runtime_evidence_kind=ref.evidence_kind,
                ref_ordinal=ref.ref_ordinal,
                invariant_violations=["runtime_binding_claim_untrusted"],
                policy_fingerprint=POLICY_FINGERPRINT,
            )
        )
    return bound


def build_skill_trust_bundle(
    skill_parent: str | Path,
    *,
    framework: str = "codex",
    scope: str = "workspace",
    allowed_runtime_parents: Sequence[str | Path] = (),
) -> dict[str, Any]:
    """Build non-mutating Skill Trust registry and raw metadata for a skill directory."""

    parent = Path(skill_parent)
    skill_roots = sorted(
        (
            child
            for child in parent.iterdir()
            if child.is_dir() and not child.name.startswith(".") and (child / "SKILL.md").is_file()
        ),
        key=lambda path: path.name,
    )
    scanner = AdmissionScanner()
    reports = scanner.scan_many(skill_roots)
    records: list[SkillRegistryRecord] = []
    raw_by_skill: dict[str, dict[str, Any]] = {}
    metadata_records: list[dict[str, Any]] = []
    metadata_by_normalized_name: dict[str, list[str]] = {}
    for root in skill_roots:
        report = reports[root]
        canonical_name, aliases = _skill_identity_from_manifest(root)
        source_root_path = str(root.resolve())
        source_root_path_hash = _runtime_root_path_hash(source_root_path) or ""
        metadata_record_id = _metadata_record_id_from_material(
            framework=framework,
            scope=scope,
            presented_name=root.name,
            canonical_name=canonical_name,
            source_root_path_hash=source_root_path_hash,
            skill_root_hash=report.skill_root_hash,
            content_hashes=report.content_hashes,
        )
        record = SkillRegistryRecord(
            canonical_skill_id=_sha256(f"{framework}:{canonical_name}".encode("utf-8")),
            canonical_name=canonical_name,
            aliases=aliases,
            content_hashes=report.content_hashes,
            source={
                "framework": framework,
                "path_hash": source_root_path_hash,
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
        target_state = "allowlist" if report.admission_risk == RiskLevel.LOW else "greylist"
        records.append(
            apply_trust_list_state(
                record,
                target_state,
                reason_code=(
                    "clean_admission_report"
                    if target_state == "allowlist"
                    else "admission_review_required"
                ),
            )
        )
        allowed_runtime_roots = _allowed_runtime_roots_for_skill(
            source_root_path=source_root_path,
            skill_dir_name=root.name,
            allowed_runtime_parents=allowed_runtime_parents,
        )
        allowed_runtime_root_hashes = [
            root_hash
            for root_hash in (_runtime_root_path_hash(runtime_root) for runtime_root in allowed_runtime_roots)
            if root_hash
        ]
        metadata_record = {
            "metadata_record_id": metadata_record_id,
            "presented_name": root.name,
            "canonical_skill_id": record.canonical_skill_id,
            "canonical_name": record.canonical_name,
            "framework": framework,
            "scope": scope,
            "source_root_path": source_root_path,
            "source_root_path_hash": source_root_path_hash,
            "allowed_runtime_roots": allowed_runtime_roots,
            "allowed_runtime_root_hashes": allowed_runtime_root_hashes,
            "mirror_integrity_mode": "content_hash",
            "trusted_runner_contract_id": None,
            "runner_contract_attestation_required": False,
            "runtime_binding_profile": "source_or_mirror",
            "skill_root_hash": report.skill_root_hash,
            "content_hashes": report.content_hashes,
        }
        metadata_records.append(metadata_record)
        metadata_by_normalized_name.setdefault(_display_normalize(root.name), []).append(metadata_record_id)
        raw_by_skill[root.name] = {
            "presented_name": root.name,
            "canonical_skill_id": record.canonical_skill_id,
            "canonical_name": record.canonical_name,
            "framework": framework,
            "scope": scope,
            "content_hashes": report.content_hashes,
            "control_language_findings": _control_language_findings_for_report(report),
            "provenance_claim": _first_script_label(root),
            "provenance_label_conflict": False,
            "admission_scan_id": report.scan_id,
            "admission_risk": report.admission_risk.value,
            "metadata_record_id": metadata_record_id,
            "source_root_path": source_root_path,
            "source_root_path_hash": source_root_path_hash,
            "allowed_runtime_roots": allowed_runtime_roots,
            "allowed_runtime_root_hashes": allowed_runtime_root_hashes,
            "mirror_integrity_mode": "content_hash",
            "skill_root_path": source_root_path,
            "skill_root_path_hash": record.source["path_hash"],
        }

    preflight_actions: list[dict[str, Any]] = []
    groups: dict[str, list[Path]] = {}
    for root in skill_roots:
        groups.setdefault(_bundle_identity_key(root.name), []).append(root)
    for group in groups.values():
        if len(group) < 2:
            continue
        canonical = _choose_bundle_canonical(group)
        blocked = sorted(root for root in group if root != canonical)
        if not blocked:
            continue
        action = {
            "root": str(parent),
            "canonical_skill": canonical.name,
            "blocked_skills": [root.name for root in blocked],
            "gateway_registry_status": "ambiguous",
            "gateway_rule_hits": ["ambiguous_skill_alias", "provenance_label_conflict"],
            "control_plane_evidence": "skill_trust_preflight",
        }
        preflight_actions.append(action)
        for root in blocked:
            raw = raw_by_skill[root.name]
            findings = set(raw.get("control_language_findings") or [])
            findings.update({"canonical_name_claim", "routing_claim"})
            raw.update({
                "provenance_claim": canonical.name,
                "provenance_label_conflict": True,
                "control_language_findings": sorted(findings),
            })

    return {
        "schema_version": "clawsentry.skill_trust_bundle.v1",
        "framework": framework,
        "skill_parent": str(parent),
        "records": [record.model_dump(mode="json") for record in records],
        "metadata_records": metadata_records,
        "metadata_by_normalized_name": metadata_by_normalized_name,
        "raw_metadata_by_skill": raw_by_skill,
        "preflight_actions": preflight_actions,
        "admission_reports": {
            root.name: reports[root].model_dump(mode="json")
            for root in skill_roots
        },
    }


def _allowed_runtime_roots_for_skill(
    *,
    source_root_path: str,
    skill_dir_name: str,
    allowed_runtime_parents: Sequence[str | Path],
) -> list[str]:
    roots = [source_root_path]
    for parent in allowed_runtime_parents:
        parent_text = str(parent).strip()
        if not parent_text:
            continue
        roots.append(str((Path(parent_text).expanduser() / skill_dir_name).resolve(strict=False)))
    return list(dict.fromkeys(roots))


def _skill_identity_from_manifest(skill_root: Path) -> tuple[str, list[str]]:
    text = _read_in_tree_text(skill_root / "SKILL.md", skill_root)
    name_match = _FRONTMATTER_NAME.search(text)
    canonical_name = name_match.group(1).strip() if name_match else skill_root.name
    aliases: list[str] = []
    aliases_match = _FRONTMATTER_ALIASES.search(text)
    if aliases_match:
        aliases.extend(
            item.strip().strip("\"'")
            for item in aliases_match.group(1).split(",")
            if item.strip()
        )
    if skill_root.name not in aliases and skill_root.name != canonical_name:
        aliases.append(skill_root.name)
    return canonical_name, list(dict.fromkeys(aliases))


def _control_language_findings_for_report(report: AdmissionReport) -> list[str]:
    families = {finding.finding_family for finding in report.findings}
    findings: list[str] = []
    if "control_language" in families or "provenance" in families:
        findings.append("canonical_name_claim")
    if "description_consistency" in families:
        findings.append("routing_claim")
    return findings


def _script_text_for_bundle(skill_root: Path) -> str:
    scripts = skill_root / "scripts"
    if not scripts.exists():
        return ""
    chunks: list[str] = []
    for path in _iter_safe_files(scripts):
        if path.suffix != ".py":
            continue
        try:
            chunks.append(path.read_text(encoding="utf-8", errors="replace"))
        except OSError:
            continue
    return "\n".join(chunks)


def _script_labels_for_bundle(skill_root: Path) -> list[str]:
    return list(dict.fromkeys(_SCRIPT_OUTPUT_LABEL.findall(_script_text_for_bundle(skill_root))))


def _first_script_label(skill_root: Path) -> str | None:
    labels = _script_labels_for_bundle(skill_root)
    return labels[0] if labels else None


def _bundle_identity_key(name: str) -> str:
    return _singularize(_identity_normalize(name))


def _bundle_script_score(skill_root: Path) -> int:
    label = _identity_normalize(skill_root.name)
    text = _script_text_for_bundle(skill_root)
    labels = {_identity_normalize(item) for item in _script_labels_for_bundle(skill_root)}
    score = 0
    if label in labels:
        score += 10
    if labels and label not in labels:
        score -= 5
    if "COMPATIBILITY_TOOL_LABEL" in text or "compatibility-alias" in text or "compatibility_alias" in text:
        score -= 6
    if "canonical-skill" in text or "canonical_skill" in text:
        score += 3
    return score


def _choose_bundle_canonical(skill_roots: list[Path]) -> Path:
    return sorted(skill_roots, key=lambda root: (-_bundle_script_score(root), root.name.lower()))[0]


def _display_normalize(value: str | None) -> str:
    return re.sub(r"[\s_-]+", "-", (value or "").strip().lower())


def _identity_normalize(value: str | None) -> str:
    return re.sub(r"[\s_-]+", "", (value or "").strip().lower())


def _singularize(value: str) -> str:
    return value[:-1] if value.endswith("s") else value


def _levenshtein_distance(left: str, right: str) -> int:
    if left == right:
        return 0
    if not left:
        return len(right)
    if not right:
        return len(left)
    previous = list(range(len(right) + 1))
    for left_index, left_char in enumerate(left, start=1):
        current = [left_index]
        for right_index, right_char in enumerate(right, start=1):
            insertion = current[right_index - 1] + 1
            deletion = previous[right_index] + 1
            substitution = previous[right_index - 1] + (left_char != right_char)
            current.append(min(insertion, deletion, substitution))
        previous = current
    return previous[-1]


def _hyphen_underscore_equivalent(left: str, right: str) -> bool:
    return left.replace("-", "_").lower() == right.replace("-", "_").lower()


def _near_name_equivalent(left: str, right: str) -> bool:
    normalized_left = _identity_normalize(left)
    normalized_right = _identity_normalize(right)
    if normalized_left == normalized_right:
        return False
    if min(len(normalized_left), len(normalized_right)) < 6:
        return False
    if abs(len(normalized_left) - len(normalized_right)) > 1:
        return False
    return _levenshtein_distance(normalized_left, normalized_right) <= 1


def _match_type(presented: str, record: SkillRegistryRecord) -> str | None:
    names = [record.canonical_name, *record.aliases]
    presented_display = _display_normalize(presented)
    for name in names:
        if presented == name:
            return "exact"
    for name in names:
        if _hyphen_underscore_equivalent(presented, name):
            return "hyphen_underscore"
    for name in names:
        if _singularize(_identity_normalize(presented_display)) == _singularize(_identity_normalize(name)):
            return "singular_plural"
    for name in names:
        if _near_name_equivalent(presented, name):
            return "near_name"
    return None


def _risk_value(level: str) -> int:
    return {"low": 0, "medium": 1, "high": 2, "critical": 3, "unknown": -1}.get(level, -1)


def _valid_admission_risk(value: Any) -> str | None:
    text = str(value or "").strip().lower()
    if text in {"low", "medium", "high", "critical", "unknown"}:
        return text
    return None


def _max_admission_risk(left: str, right: str) -> str:
    return left if _risk_value(left) >= _risk_value(right) else right


def first_use_scan_state(
    *,
    report: AdmissionReport | None,
    requested: bool,
    running_sync: bool = False,
    budget_exhausted: bool = False,
    failure_class: str | None = None,
) -> FirstUseScanState:
    """Return an explicit first-use scan lifecycle state."""

    if report is not None:
        return FirstUseScanState(
            state="scan_completed",
            admission_scan_id=report.scan_id,
            admission_risk=report.admission_risk.value,
            policy_fingerprint=report.policy_fingerprint,
        )
    if failure_class:
        return FirstUseScanState(
            state="scan_failed",
            failure_class=failure_class,
            admission_risk="unknown",
            policy_fingerprint=POLICY_FINGERPRINT,
        )
    if budget_exhausted:
        return FirstUseScanState(
            state="scan_pending_budget_exhausted",
            admission_risk="unknown",
            policy_fingerprint=POLICY_FINGERPRINT,
        )
    if requested or running_sync:
        return FirstUseScanState(
            state="scan_running_sync",
            admission_risk="unknown",
            policy_fingerprint=POLICY_FINGERPRINT,
        )
    return FirstUseScanState(
        state="scan_not_started",
        admission_risk="unknown",
        policy_fingerprint=POLICY_FINGERPRINT,
    )


def transition_trust_list_state(
    *,
    canonical_skill_id: str,
    from_state: str,
    to_state: str,
    reason_code: str,
    evidence_hashes: list[str],
    scope: str,
    actor_type: str,
    policy_fingerprint: str,
    previous_policy_fingerprint: str | None = None,
    operator_id_hash: str | None = None,
    override_id: str | None = None,
    override_indefinite_reason: str | None = None,
    expires_at: str | None = None,
    disabled_until: str | None = None,
) -> SkillTrustTransitionEvent:
    """Validate and build an auditable trust-list transition event."""

    if (from_state, to_state) not in _ALLOWED_TRANSITIONS:
        raise ValueError(f"invalid trust-list transition: {from_state} -> {to_state}")
    if to_state == "allowlist":
        if reason_code not in {
            "clean_admission_report",
            "trusted_migration",
            "operator_override",
            "operator_restore",
            "disabled_window_expired",
        }:
            raise ValueError("allowlist promotion requires clean admission, trusted migration, operator override, restore, or disabled expiry")
        if reason_code in {"operator_override", "operator_restore"} and actor_type not in {"operator", "manual_migration"}:
            raise ValueError("allowlist operator promotion requires operator actor")
        if reason_code == "disabled_window_expired" and (
            from_state != "disabled" or actor_type != "system"
        ):
            raise ValueError("disabled expiry restore requires disabled source and system actor")
        if reason_code in {"clean_admission_report", "trusted_migration"} and not evidence_hashes:
            raise ValueError("allowlist promotion requires evidence hashes")
    if from_state == "blacklist" and to_state == "greylist":
        if reason_code != "trusted_migration" and not override_id:
            raise ValueError("blacklist -> greylist requires trusted migration or operator override")
        if actor_type not in {"operator", "manual_migration"}:
            raise ValueError("blacklist -> greylist requires operator or manual migration")
    if from_state == "revoked":
        if reason_code != "trusted_migration" and not override_id:
            raise ValueError("revoked skills require trusted migration or operator override")
        if actor_type not in {"operator", "manual_migration"}:
            raise ValueError("revoked skills require operator or manual migration")
    if to_state == "disabled" and not disabled_until and reason_code not in {"policy_disable", "operator_disable"}:
        raise ValueError("disabled transition requires policy/operator disable reason or disabled_until")

    payload = "|".join([
        canonical_skill_id,
        from_state,
        to_state,
        reason_code,
        scope,
        actor_type,
        policy_fingerprint,
        ",".join(sorted(evidence_hashes)),
    ])
    transition_id = _sha256(payload.encode("utf-8"))
    registry_snapshot_id = _sha256(
        f"{canonical_skill_id}:{to_state}:{policy_fingerprint}".encode("utf-8")
    )
    return SkillTrustTransitionEvent(
        transition_id=transition_id,
        registry_snapshot_id=registry_snapshot_id,
        canonical_skill_id=canonical_skill_id,
        from_state=from_state,  # type: ignore[arg-type]
        to_state=to_state,  # type: ignore[arg-type]
        reason_code=reason_code,
        evidence_hashes=evidence_hashes,
        scope=scope,  # type: ignore[arg-type]
        actor_type=actor_type,  # type: ignore[arg-type]
        operator_id_hash=operator_id_hash,
        override_id=override_id,
        override_indefinite_reason=override_indefinite_reason,
        policy_fingerprint=policy_fingerprint,
        previous_policy_fingerprint=previous_policy_fingerprint,
        expires_at=expires_at,
        disabled_until=disabled_until,
        review_required=to_state in {"greylist", "blacklist", "revoked", "disabled"},
    )


def apply_trust_list_state(
    record: SkillRegistryRecord,
    list_state: str,
    *,
    reason_code: str,
) -> SkillRegistryRecord:
    """Return a registry record with list state reflected in policy-facing fields."""

    status_by_state = {
        "allowlist": "trusted",
        "greylist": "local_unreviewed",
        "blacklist": "quarantined",
        "unlisted": "unknown",
        "revoked": "revoked",
        "disabled": "local_unreviewed",
    }
    trust_by_state = {
        "allowlist": "trusted",
        "greylist": "local_unreviewed",
        "blacklist": "untrusted",
        "unlisted": "unknown",
        "revoked": "untrusted",
        "disabled": record.trust_level,
    }
    if list_state not in status_by_state:
        raise ValueError(f"invalid trust-list state: {list_state}")
    return record.model_copy(update={
        "list_state": list_state,
        "status": status_by_state[list_state],
        "trust_level": trust_by_state[list_state],
        "source": {**record.source, "trust_list_reason_code": reason_code},
    })


class AdmissionScanner:
    """Deterministic preflight scanner for a local skill root."""

    def scan_many(self, skill_roots: Iterable[str | Path]) -> dict[Path, AdmissionReport]:
        """Scan multiple roots and add deterministic cross-skill findings."""

        roots = [Path(root) for root in skill_roots]
        reports = {root: self.scan(root) for root in roots}
        findings_by_root: dict[Path, list[AdmissionFinding]] = {root: [] for root in roots}

        for index, left in enumerate(roots):
            for right in roots[index + 1:]:
                if _hyphen_underscore_equivalent(left.name, right.name) and left.name.lower() != right.name.lower():
                    summary = f"hyphen/underscore duplicate skill identity: {left.name} <-> {right.name}"
                elif _near_name_equivalent(left.name, right.name):
                    summary = f"near-name duplicate skill identity: {left.name} <-> {right.name}"
                else:
                    continue
                findings_by_root[left].append(
                    self._finding("alias", summary, severity=RiskLevel.MEDIUM, confidence="high")
                )
                findings_by_root[right].append(
                    self._finding("alias", summary, severity=RiskLevel.MEDIUM, confidence="high")
                )

        by_data_hash: dict[str, list[Path]] = {}
        for root, report in reports.items():
            data_hash = report.content_hashes.get("data")
            if data_hash:
                by_data_hash.setdefault(data_hash, []).append(root)
        for data_hash, grouped_roots in by_data_hash.items():
            if len(grouped_roots) < 2:
                continue
            names = ", ".join(sorted(root.name for root in grouped_roots))
            for root in grouped_roots:
                findings_by_root[root].append(
                    self._finding(
                        "cross_skill_overlap",
                        f"shared data hash across skill identities: {names}",
                        severity=RiskLevel.MEDIUM,
                        confidence="high",
                        evidence_hash=data_hash,
                    )
                )

        for root, extra_findings in findings_by_root.items():
            if not extra_findings:
                continue
            report = reports[root]
            findings = [*report.findings, *extra_findings]
            admission_risk = report.admission_risk
            for finding in extra_findings:
                if _risk_value(finding.severity.value) > _risk_value(admission_risk.value):
                    admission_risk = finding.severity
            reports[root] = report.model_copy(update={
                "findings": findings,
                "admission_risk": admission_risk,
            })

        return reports

    def scan(
        self,
        skill_root: str | Path,
        *,
        deadline_at: float | None = None,
        max_files: int | None = None,
        max_file_bytes: int | None = None,
    ) -> AdmissionReport:
        root = Path(skill_root)
        _raise_if_scan_deadline_expired(deadline_at)
        skill_md = root / "SKILL.md"
        content_hashes: dict[str, str] = {}
        files_seen = 0
        if skill_md.exists():
            files_seen += 1
            if max_files is not None and files_seen > max_files:
                raise TimeoutError("admission scan file count budget exceeded")
            content_hashes["SKILL.md"] = _hash_file(
                skill_md,
                max_file_bytes=max_file_bytes,
            )
        _raise_if_scan_deadline_expired(deadline_at)
        for child in ("scripts", "references", "data"):
            child_path = root / child
            if child_path.exists():
                child_file_count = sum(
                    1 for _ in child_path.rglob("*")
                    if _.is_file() or _.is_symlink()
                )
                if max_files is not None and files_seen + child_file_count > max_files:
                    raise TimeoutError("admission scan file count budget exceeded")
                content_hashes[child] = _hash_directory(
                    child_path,
                    deadline_at=deadline_at,
                    max_files=(
                        max_files - files_seen
                        if max_files is not None
                        else None
                    ),
                    max_file_bytes=max_file_bytes,
                )
                files_seen += child_file_count
            _raise_if_scan_deadline_expired(deadline_at)

        text = _read_in_tree_text(skill_md, root, deadline_at=deadline_at) if skill_md.exists() else ""
        findings: list[AdmissionFinding] = []
        findings.extend(self._hash_findings(content_hashes))
        findings.extend(self._alias_findings(text, content_hashes.get("SKILL.md")))
        findings.extend(self._language_findings(text, content_hashes.get("SKILL.md")))
        findings.extend(self._description_consistency_findings(root, text, content_hashes))

        admission_risk = RiskLevel.LOW
        for finding in findings:
            if _risk_value(finding.severity.value) > _risk_value(admission_risk.value):
                admission_risk = finding.severity

        skill_root_hash = _hash_directory(root, deadline_at=deadline_at)
        return AdmissionReport(
            scan_id=_sha256(f"{root.resolve()}:{skill_root_hash}".encode("utf-8"))[:24],
            skill_root_hash=skill_root_hash,
            content_hashes=content_hashes,
            sbom={
                "components": [
                    {"name": name, "hash": value}
                    for name, value in sorted(content_hashes.items())
                ]
            },
            checksum_evidence=dict(content_hashes),
            signature_evidence={"state": "not_configured"},
            advisory_evidence=[],
            findings=findings,
            admission_risk=admission_risk,
            policy_fingerprint=POLICY_FINGERPRINT,
        )

    def _finding(
        self,
        family: str,
        summary: str,
        *,
        severity: RiskLevel = RiskLevel.LOW,
        confidence: str = "medium",
        evidence_hash: str | None = None,
    ) -> AdmissionFinding:
        evidence = [evidence_hash] if evidence_hash else []
        finding_id = _sha256(f"{family}:{summary}:{evidence_hash or ''}".encode("utf-8"))[:24]
        return AdmissionFinding(
            finding_id=finding_id,
            finding_family=family,  # type: ignore[arg-type]
            severity=severity,
            confidence=confidence,  # type: ignore[arg-type]
            decision_affecting=False,
            evidence_hashes=evidence,
            evidence_summary=summary,
            policy_fingerprint=POLICY_FINGERPRINT,
        )

    def _hash_findings(self, content_hashes: dict[str, str]) -> list[AdmissionFinding]:
        if not content_hashes:
            return []
        joined = ",".join(f"{key}={value}" for key, value in sorted(content_hashes.items()))
        return [
            self._finding(
                "hash",
                "skill package content hashes captured for registry comparison",
                severity=RiskLevel.LOW,
                confidence="high",
                evidence_hash=_sha256(joined.encode("utf-8")),
            )
        ]

    def _alias_findings(self, text: str, evidence_hash: str | None) -> list[AdmissionFinding]:
        parsed = _parse_frontmatter_identity(text)
        name = parsed.get("name")
        aliases = parsed.get("aliases", [])
        if not name or not aliases:
            return []
        findings = []
        for alias in aliases:
            if alias and (
                _hyphen_underscore_equivalent(name, alias)
                or _singularize(_identity_normalize(name)) == _singularize(_identity_normalize(alias))
            ):
                findings.append(
                    self._finding(
                        "alias",
                        "frontmatter alias normalizes close to canonical name",
                        evidence_hash=evidence_hash,
                    )
                )
                break
        return findings

    def _language_findings(self, text: str, evidence_hash: str | None) -> list[AdmissionFinding]:
        findings = []
        if _CONTROL_LANGUAGE.search(text):
            findings.append(
                self._finding(
                    "control_language",
                    "skill text contains routing or canonical identity language",
                    severity=RiskLevel.MEDIUM,
                    confidence="medium",
                    evidence_hash=evidence_hash,
                )
            )
        if _PROVENANCE_LANGUAGE.search(text):
            findings.append(
                self._finding(
                    "provenance",
                    "skill text references output provenance or tool labels",
                    severity=RiskLevel.MEDIUM,
                    confidence="medium",
                    evidence_hash=evidence_hash,
                )
            )
        return findings

    def _description_consistency_findings(
        self,
        root: Path,
        text: str,
        content_hashes: dict[str, str],
    ) -> list[AdmissionFinding]:
        scripts_dir = root / "scripts"
        if not scripts_dir.exists():
            return []
        script_names = [p.name for p in _iter_safe_files(scripts_dir)]
        findings: list[AdmissionFinding] = []
        missing_script_names = [name for name in script_names if name not in text]
        if missing_script_names:
            findings.append(
                self._finding(
                    "description_consistency",
                    "skill has script entrypoints not named in SKILL.md",
                    evidence_hash=content_hashes.get("scripts"),
                )
            )
        script_text = self._read_script_text_without_comments(scripts_dir)
        behavior_text = self._read_script_behavior_text(scripts_dir)
        declared_names = self._declared_identity_names(root, text)
        output_labels = {
            match.group(1).strip()
            for match in _SCRIPT_OUTPUT_LABEL.finditer(script_text)
            if match.group(1).strip()
        }
        if declared_names and any(
            _identity_normalize(label) not in declared_names
            for label in output_labels
        ):
            findings.append(
                self._finding(
                    "description_consistency",
                    "script output label differs from declared skill name",
                    severity=RiskLevel.MEDIUM,
                    confidence="high",
                    evidence_hash=content_hashes.get("scripts"),
                )
            )
        if _SCRIPT_RANK_FILTER.search(behavior_text) and not _DECLARED_RANK_FILTER.search(text):
            findings.append(
                self._finding(
                    "description_consistency",
                    "script changes ranking or filtering without declaring it in SKILL.md",
                    severity=RiskLevel.MEDIUM,
                    confidence="high",
                    evidence_hash=content_hashes.get("scripts"),
                )
            )
        if self._has_undeclared_data_or_fixture_read(scripts_dir, text):
            findings.append(
                self._finding(
                    "description_consistency",
                    "script reads data/schema/fixture files not declared in SKILL.md",
                    severity=RiskLevel.MEDIUM,
                    confidence="high",
                    evidence_hash=(
                        content_hashes.get("data")
                        or content_hashes.get("references")
                        or content_hashes.get("scripts")
                    ),
                )
            )
        return findings

    def _read_script_text_without_comments(self, scripts_dir: Path) -> str:
        chunks: list[str] = []
        for script in _iter_safe_files(scripts_dir):
            try:
                source = script.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            if script.suffix == ".py":
                chunks.append(_python_without_comments(source))
            else:
                chunks.append(_strip_comment_lines(source))
        return "\n".join(chunks)

    def _read_script_behavior_text(self, scripts_dir: Path) -> str:
        chunks: list[str] = []
        for script in _iter_safe_files(scripts_dir):
            try:
                source = script.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            if script.suffix == ".py":
                chunks.append(_python_behavior_tokens(source))
            else:
                chunks.append(_strip_comment_lines(source))
        return "\n".join(chunks)

    def _declared_identity_names(self, root: Path, text: str) -> set[str]:
        declared = {_identity_normalize(root.name)}
        parsed = _parse_frontmatter_identity(text)
        if parsed.get("name"):
            declared.add(_identity_normalize(str(parsed["name"])))
        declared.update(_identity_normalize(alias) for alias in parsed.get("aliases", []))
        return {value for value in declared if value}

    def _has_undeclared_data_or_fixture_read(self, scripts_dir: Path, text: str) -> bool:
        declared_text = text.lower()
        script_text = self._read_script_text_without_comments(scripts_dir)
        path_literals = re.findall(
            r"""['"]((?:data|schema|schemas|fixture|fixtures)/[^'"]+)['"]""",
            script_text,
            flags=re.I,
        )
        for literal in path_literals:
            normalized = literal.replace("\\", "/").lower()
            parts = [part for part in normalized.split("/") if part]
            if not parts:
                continue
            declared = normalized in declared_text or parts[-1] in declared_text
            if not declared:
                return True
        has_data_root_literal = re.search(
            r"""['"](?:data|schema|schemas|fixture|fixtures)['"]""",
            script_text,
            flags=re.I,
        )
        has_file_read = re.search(
            r"\b(?:open|read_text|read_bytes)\s*\(",
            script_text,
        )
        if has_data_root_literal and has_file_read and not re.search(
            r"\b(?:data|schema|schemas|fixture|fixtures)\b",
            declared_text,
        ):
            return True
        return False


def _python_behavior_tokens(source: str) -> str:
    summary_tokens: list[str] = []
    try:
        tree = ast.parse(source)
    except SyntaxError:
        tree = None
    if tree is not None:
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name) and node.func.id in {"sorted", "filter"}:
                    summary_tokens.append(f"{node.func.id}_call")
                elif isinstance(node.func, ast.Attribute) and node.func.attr == "sort":
                    summary_tokens.append("sort_call")
            elif isinstance(node, (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)):
                if any(generator.ifs for generator in node.generators):
                    summary_tokens.append("comprehension_filter")
            elif isinstance(node, ast.Subscript) and isinstance(node.slice, ast.Slice):
                if node.slice.lower is not None or node.slice.upper is not None:
                    summary_tokens.append("slice_limit")
    if summary_tokens:
        return " ".join(summary_tokens)

    tokens: list[str] = []
    try:
        for token in tokenize.generate_tokens(StringIO(source).readline):
            if token.type in {
                tokenize.NAME,
                tokenize.OP,
                tokenize.NUMBER,
            }:
                tokens.append(token.string)
    except tokenize.TokenError:
        return _strip_comment_lines(source)
    return " ".join(tokens)


def _python_without_comments(source: str) -> str:
    tokens: list[str] = []
    try:
        for token in tokenize.generate_tokens(StringIO(source).readline):
            if token.type == tokenize.COMMENT:
                continue
            tokens.append(token.string)
    except tokenize.TokenError:
        return _strip_comment_lines(source)
    return " ".join(tokens)


def _parse_frontmatter_identity(text: str) -> dict[str, Any]:
    block = text
    stripped = text.lstrip()
    if stripped.startswith("---"):
        lines = stripped.splitlines()
        frontmatter: list[str] = []
        for line in lines[1:]:
            if line.strip() == "---":
                break
            frontmatter.append(line)
        block = "\n".join(frontmatter)

    parsed: dict[str, Any] = {"aliases": []}
    name_match = _FRONTMATTER_NAME.search(block)
    if name_match:
        parsed["name"] = name_match.group(1).strip()
    aliases_match = _FRONTMATTER_ALIASES.search(block)
    if aliases_match:
        parsed["aliases"].extend(
            part.strip().strip("'\"")
            for part in aliases_match.group(1).split(",")
            if part.strip().strip("'\"")
        )
    lines = block.splitlines()
    for index, line in enumerate(lines):
        if not re.match(r"^aliases:\s*$", line):
            continue
        for alias_line in lines[index + 1:]:
            if not alias_line.startswith((" ", "\t")):
                break
            alias_match = re.match(r"^\s*-\s*[\"']?([^\"'#]+)[\"']?\s*(?:#.*)?$", alias_line)
            if alias_match:
                parsed["aliases"].append(alias_match.group(1).strip())
    parsed["aliases"] = [alias for alias in parsed["aliases"] if alias]
    return parsed


def _strip_comment_lines(source: str) -> str:
    lines = []
    for line in source.splitlines():
        stripped = line.strip()
        if stripped.startswith("#") or stripped.startswith("//"):
            continue
        without_inline_comment = _strip_inline_comment(line)
        if without_inline_comment.strip():
            lines.append(without_inline_comment)
    return "\n".join(lines)


def _strip_inline_comment(line: str) -> str:
    quote: str | None = None
    escaped = False
    for index, char in enumerate(line):
        if escaped:
            escaped = False
            continue
        if char == "\\":
            escaped = True
            continue
        if char in {"'", '"'}:
            quote = None if quote == char else char if quote is None else quote
            continue
        if quote is not None:
            continue
        if char == "#":
            return line[:index]
        if (
            char == "/"
            and index + 1 < len(line)
            and line[index + 1] == "/"
            and (index == 0 or line[index - 1].isspace())
        ):
            return line[:index]
    return line


def resolve_skill_trust(
    records: Iterable[SkillRegistryRecord],
    raw_metadata: dict[str, Any] | None,
) -> SkillTrustContext:
    """Resolve raw runtime skill metadata into typed skill trust evidence."""

    raw = raw_metadata or {}
    presented_name = raw.get("presented_name")
    provenance_claim = raw.get("provenance_claim")
    content_hashes = raw.get("content_hashes") or {}
    admission_scan_id = raw.get("admission_scan_id")
    raw_admission_risk = _valid_admission_risk(raw.get("admission_risk"))
    scan_requested = bool(raw.get("admission_scan_requested"))
    scan_budget_exhausted = bool(raw.get("admission_scan_budget_exhausted"))
    scan_failure_class = raw.get("admission_scan_failure_class")
    raw_scan_policy_fingerprint = raw.get("policy_fingerprint")
    first_use_package_review = raw.get("first_use_package_review")
    if not isinstance(first_use_package_review, dict):
        first_use_package_review = None
    resolved_first_use_scan = (
        FirstUseScanState(
            state="scan_completed",
            admission_scan_id=str(admission_scan_id),
            admission_risk=raw_admission_risk,
            policy_fingerprint=(
                str(raw_scan_policy_fingerprint)
                if raw_scan_policy_fingerprint
                else POLICY_FINGERPRINT
            ),
        )
        if admission_scan_id and raw_admission_risk
        else first_use_scan_state(
            report=None,
            requested=scan_requested,
            budget_exhausted=scan_budget_exhausted,
            failure_class=str(scan_failure_class) if scan_failure_class else None,
        )
    )
    if not presented_name:
        return SkillTrustContext(
            registry_status="unbound",
            presented_name=None,
            provenance_claim=provenance_claim,
            admission_scan_id=str(admission_scan_id) if admission_scan_id else None,
            admission_risk="unknown",
            trust_list_state="unlisted",
            first_use_scan=resolved_first_use_scan,
            first_use_package_review=first_use_package_review,
        )

    registry = list(records)
    candidates: list[tuple[SkillRegistryRecord, str]] = []
    for record in registry:
        match = _match_type(str(presented_name), record)
        if match is not None:
            candidates.append((record, match))

    if not candidates:
        violations: list[str] = []
        control_findings = set(raw.get("control_language_findings") or [])
        explicit_provenance_conflict = bool(raw.get("provenance_label_conflict"))
        admission_risk = raw_admission_risk or "unknown"
        if raw.get("_registry_records_untrusted"):
            violations.append("runtime_registry_claim_untrusted")
        if raw.get("_request_skill_trust_raw_untrusted"):
            violations.append("request_skill_trust_raw_untrusted")
        if explicit_provenance_conflict:
            violations.append("provenance_label_conflict")
        if provenance_claim and control_findings.intersection({"canonical_name_claim", "routing_claim"}):
            violations.append("unknown_skill_provenance_rewrite")
        return SkillTrustContext(
            registry_status="unknown",
            presented_name=str(presented_name),
            provenance_claim=provenance_claim,
            admission_scan_id=str(admission_scan_id) if admission_scan_id else None,
            admission_risk=_max_admission_risk(admission_risk, "high") if violations else admission_risk,
            trust_list_state="unlisted",
            invariant_violations=sorted(set(violations)),
            first_use_scan=resolved_first_use_scan,
            first_use_package_review=first_use_package_review,
            policy_fingerprint=POLICY_FINGERPRINT,
        )

    if len(candidates) > 1:
        violations = ["ambiguous_skill_alias"]
        control_findings = set(raw.get("control_language_findings") or [])
        raw_trust_list_state = str(raw.get("trust_list_state") or "")
        hard_candidate_records: list[SkillRegistryRecord] = []
        trust_list_state = "unlisted"
        admission_risk = raw_admission_risk or "low"
        registry_status = "ambiguous"
        if raw.get("_registry_records_untrusted"):
            violations.append("runtime_registry_claim_untrusted")
        for record, match_type in candidates:
            candidate_state = record.list_state
            if raw_trust_list_state in {"greylist", "blacklist", "revoked"} and match_type == "exact":
                candidate_state = raw_trust_list_state
            if match_type == "exact" and _has_hash_mismatch(record.content_hashes, content_hashes):
                violations.append("skill_hash_mismatch")
                hard_candidate_records.append(record)
                registry_status = "hash_mismatch"
                admission_risk = "high"
            if candidate_state == "blacklist":
                violations.append("blacklisted_skill_identity")
                hard_candidate_records.append(record)
                trust_list_state = "blacklist"
                admission_risk = "high"
            elif candidate_state == "revoked" or record.status == "revoked":
                violations.append("revoked_skill_identity")
                hard_candidate_records.append(record)
                trust_list_state = "revoked"
                admission_risk = "critical"
        provenance_conflict = _ambiguous_provenance_conflict(
            candidates,
            str(provenance_claim) if provenance_claim else None,
            control_findings,
            bool(raw.get("provenance_label_conflict")),
        )
        if provenance_conflict:
            violations.append("provenance_label_conflict")
            if admission_risk == "low":
                admission_risk = "high"
        hard_exact_records = [
            record
            for record, match_type in candidates
            if match_type == "exact" and record in hard_candidate_records
        ]
        canonical_skill_id = None
        if len(hard_exact_records) == 1:
            canonical_skill_id = hard_exact_records[0].canonical_skill_id
        elif len(hard_candidate_records) == 1:
            canonical_skill_id = hard_candidate_records[0].canonical_skill_id
        return SkillTrustContext(
            registry_status=registry_status,  # type: ignore[arg-type]
            canonical_skill_id=canonical_skill_id,
            presented_name=str(presented_name),
            alias_match_type=_strongest_match(match for _record, match in candidates),
            provenance_claim=provenance_claim,
            admission_scan_id=str(admission_scan_id) if admission_scan_id else None,
            admission_risk=admission_risk,  # type: ignore[arg-type]
            trust_list_state=trust_list_state,  # type: ignore[arg-type]
            invariant_violations=sorted(set(violations)),
            first_use_package_review=first_use_package_review,
            policy_fingerprint=POLICY_FINGERPRINT,
        )

    record, alias_match_type = candidates[0]
    violations: list[str] = []
    registry_status = "matched"
    trusted_record = (
        record.trust_level == "trusted"
        and record.status == "trusted"
        and record.list_state == "allowlist"
    )
    admission_risk = raw_admission_risk or (
        "low"
        if trusted_record and not _has_missing_hash_evidence(record.content_hashes, content_hashes)
        else "unknown"
    )

    if raw.get("_registry_records_untrusted"):
        violations.append("runtime_registry_claim_untrusted")

    if _has_hash_mismatch(record.content_hashes, content_hashes):
        registry_status = "hash_mismatch"
        admission_risk = "high"
        violations.append("skill_hash_mismatch")

    raw_trust_list_state = str(raw.get("trust_list_state") or "")
    trust_list_state = record.list_state
    if raw_trust_list_state in {"greylist", "blacklist", "revoked"}:
        trust_list_state = raw_trust_list_state
    if trust_list_state == "blacklist":
        admission_risk = "high"
        violations.append("blacklisted_skill_identity")
    elif trust_list_state == "revoked" or record.status == "revoked":
        admission_risk = "critical"
        violations.append("revoked_skill_identity")
    elif trust_list_state == "greylist":
        if admission_risk in {"low", "unknown"}:
            admission_risk = "medium"
        violations.append("greylisted_skill_identity")

    control_findings = set(raw.get("control_language_findings") or [])
    untrusted_record = (
        record.trust_level in ("unknown", "untrusted", "local_unreviewed")
        or record.status in ("quarantined", "revoked", "ambiguous_alias")
    )
    has_canonical_redefinition = (
        bool(raw.get("provenance_label_conflict"))
        or (
            bool(provenance_claim)
            and _identity_normalize(str(provenance_claim)) != _identity_normalize(record.canonical_name)
        )
    )
    if (
        untrusted_record
        and has_canonical_redefinition
        and control_findings.intersection({"canonical_name_claim", "routing_claim"})
    ):
        admission_risk = "high"
        violations.append("low_trust_redefined_canonical_tool")

    if provenance_claim and _identity_normalize(str(provenance_claim)) != _identity_normalize(record.canonical_name):
        violations.append("provenance_label_conflict")
        admission_risk = "high"

    first_use_scan = None
    if not trusted_record and registry_status == "matched":
        first_use_scan = resolved_first_use_scan

    return SkillTrustContext(
        registry_status=registry_status,  # type: ignore[arg-type]
        canonical_skill_id=record.canonical_skill_id,
        presented_name=str(presented_name),
        alias_match_type=alias_match_type,  # type: ignore[arg-type]
        provenance_claim=provenance_claim,
        admission_scan_id=str(admission_scan_id) if admission_scan_id else None,
        admission_risk=admission_risk,  # type: ignore[arg-type]
        trust_list_state=trust_list_state,  # type: ignore[arg-type]
        first_use_scan=first_use_scan,
        first_use_package_review=first_use_package_review,
        invariant_violations=sorted(set(violations)),
        policy_fingerprint=record.policy_fingerprint or POLICY_FINGERPRINT,
    )


def _strongest_match(matches: Iterable[str]) -> str:
    order = {"exact": 0, "hyphen_underscore": 1, "singular_plural": 2, "near_name": 3, "none": 4}
    return min(matches, key=lambda match: order.get(match, 99))


def _ambiguous_provenance_conflict(
    candidates: Iterable[tuple[SkillRegistryRecord, str]],
    provenance_claim: str | None,
    control_findings: set[str],
    explicit_conflict: bool,
) -> bool:
    """Return whether ambiguous identity also has an actual provenance conflict."""

    if explicit_conflict:
        return True
    if not provenance_claim:
        return False
    normalized_claim = _identity_normalize(provenance_claim)
    candidate_names: set[str] = set()
    for record, _match in candidates:
        candidate_names.add(_identity_normalize(record.canonical_name))
        candidate_names.update(_identity_normalize(alias) for alias in record.aliases)
    strongest_match = _strongest_match(match for _record, match in candidates)
    strongest_candidate_names: set[str] = set()
    for record, match in candidates:
        if match != strongest_match:
            continue
        strongest_candidate_names.add(_identity_normalize(record.canonical_name))
    if normalized_claim in strongest_candidate_names:
        return False
    if normalized_claim in candidate_names:
        return bool(control_findings.intersection({
            "canonical_name_claim",
            "routing_claim",
            "provenance_rewrite",
            "tool_label_rewrite",
        }))
    if control_findings.intersection({
        "canonical_name_claim",
        "routing_claim",
        "provenance_rewrite",
        "tool_label_rewrite",
    }):
        return True
    return normalized_claim not in candidate_names


def _has_hash_mismatch(expected: dict[str, str], observed: dict[str, str]) -> bool:
    for key, expected_hash in expected.items():
        observed_hash = observed.get(key)
        if observed_hash is not None and observed_hash != expected_hash:
            return True
    return False


def _has_missing_hash_evidence(expected: dict[str, str], observed: dict[str, str]) -> bool:
    if not expected:
        return False
    return any(key not in observed for key in expected)
