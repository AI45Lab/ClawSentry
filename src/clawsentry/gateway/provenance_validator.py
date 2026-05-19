"""Generic artifact provenance validation against the runtime skill-use ledger."""

from __future__ import annotations

import fnmatch
import hashlib
import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from pathlib import PurePosixPath
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator


def _identity_normalize(value: str | None) -> str:
    return re.sub(r"[\s_-]+", "", (value or "").strip().lower())


def _singularize_identity(value: str) -> str:
    return value[:-1] if value.endswith("s") else value


def _identity_candidates(value: str | None) -> set[str]:
    normalized = _identity_normalize(value)
    if not normalized:
        return set()
    return {normalized, _singularize_identity(normalized)}


class ProvenancePolicy(BaseModel):
    """Configured artifact fields whose labels should reconcile with the ledger."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    policy_schema: str = Field(default="clawsentry.provenance_policy.v1", alias="schema")
    artifact_paths: list[str] = Field(default_factory=list)
    field_paths: list[str] = Field(default_factory=list)
    label_normalization: str = "skill_identity"
    on_unobserved_claim: str = "finding"
    on_blocked_claim: str = "finding_high"
    on_conflicting_claim: str = "finding_high"
    on_parse_error: str = "finding_audit"
    on_empty_ledger: str = "coverage_gap"

    @field_validator("artifact_paths")
    @classmethod
    def validate_artifact_paths(cls, value: list[str]) -> list[str]:
        for pattern in value:
            path = PurePosixPath(pattern)
            if path.is_absolute() or ".." in path.parts:
                raise ValueError(f"unsafe artifact glob: {pattern}")
        return value

    @field_validator("field_paths")
    @classmethod
    def validate_field_paths(cls, value: list[str]) -> list[str]:
        for path in value:
            if not path or path.startswith(".") or ".." in path.split("."):
                raise ValueError(f"unsafe field path: {path}")
        return value


@dataclass(frozen=True)
class ProvenanceFinding:
    finding_type: str
    finding_id: str | None = None
    declared_label: str | None = None
    normalized_identity: str | None = None
    matched_ledger_entry_ids: list[str] = field(default_factory=list)
    severity: str = "medium"
    confidence: str = "high"
    handling: str = "finding"
    artifact_path: str | None = None
    artifact_path_hash: str | None = None
    field_path: str | None = None

    def __post_init__(self) -> None:
        if self.artifact_path and not self.artifact_path_hash:
            digest = hashlib.sha256(self.artifact_path.encode("utf-8")).hexdigest()
            object.__setattr__(self, "artifact_path_hash", f"sha256:{digest}")
        if not self.finding_id:
            material = {
                "finding_type": self.finding_type,
                "declared_label": self.declared_label,
                "normalized_identity": self.normalized_identity,
                "matched_ledger_entry_ids": self.matched_ledger_entry_ids,
                "artifact_path_hash": self.artifact_path_hash,
                "field_path": self.field_path,
                "handling": self.handling,
            }
            digest = hashlib.sha256(
                json.dumps(material, sort_keys=True, separators=(",", ":")).encode("utf-8")
            ).hexdigest()
            object.__setattr__(self, "finding_id", f"prov-{digest[:16]}")


def load_provenance_policy_from_env() -> tuple[ProvenancePolicy | None, list[ProvenanceFinding]]:
    """Load explicit env JSON first, then explicit env file path."""

    raw_json = os.environ.get("CS_SKILL_TRUST_PROVENANCE_POLICY_JSON")
    raw_path = os.environ.get("CS_SKILL_TRUST_PROVENANCE_POLICY_PATH")
    if raw_json:
        try:
            return ProvenancePolicy.model_validate(json.loads(raw_json)), []
        except Exception:
            return None, [
                ProvenanceFinding(
                    finding_type="policy_not_applicable",
                    severity="low",
                    confidence="high",
                    handling="config_error",
                )
            ]
    if raw_path:
        try:
            with open(raw_path, "r", encoding="utf-8") as handle:
                return ProvenancePolicy.model_validate(json.load(handle)), []
        except Exception:
            return None, [
                ProvenanceFinding(
                    finding_type="policy_not_applicable",
                    severity="low",
                    confidence="high",
                    handling="config_error",
                )
            ]
    return None, []


def load_provenance_policy_from_config(config: Any) -> tuple[ProvenancePolicy | None, list[ProvenanceFinding]]:
    """Load provenance policy from DetectionConfig-like values."""

    if not bool(getattr(config, "skill_trust_provenance_enabled", False)):
        return None, []
    raw_json = getattr(config, "skill_trust_provenance_policy_json", None)
    raw_path = getattr(config, "skill_trust_provenance_policy_path", None)
    if raw_json:
        try:
            return ProvenancePolicy.model_validate(json.loads(str(raw_json))), []
        except Exception:
            return None, [
                ProvenanceFinding(
                    finding_type="policy_not_applicable",
                    severity="low",
                    confidence="high",
                    handling="config_error",
                )
            ]
    if raw_path:
        try:
            with open(str(raw_path), "r", encoding="utf-8") as handle:
                return ProvenancePolicy.model_validate(json.load(handle)), []
        except Exception:
            return None, [
                ProvenanceFinding(
                    finding_type="policy_not_applicable",
                    severity="low",
                    confidence="high",
                    handling="config_error",
                )
            ]
    return None, [
        ProvenanceFinding(
            finding_type="policy_not_applicable",
            severity="low",
            confidence="high",
            handling="missing_policy",
        )
    ]


def _extract_field_values(document: Any, field_path: str) -> list[str]:
    found, current = _lookup_field_value(document, field_path)
    if not found:
        return []
    if isinstance(current, str):
        return [current]
    if isinstance(current, list):
        return [item for item in current if isinstance(item, str)]
    return []


def _lookup_field_value(document: Any, field_path: str) -> tuple[bool, Any]:
    current = document
    for part in field_path.split("."):
        if isinstance(current, dict) and part in current:
            current = current[part]
        else:
            return False, None
    return True, current


def _artifact_selected(policy: ProvenancePolicy, artifact_path: str) -> bool:
    return any(fnmatch.fnmatch(artifact_path, pattern) for pattern in policy.artifact_paths)


def collect_policy_artifacts(
    policy: ProvenancePolicy,
    *,
    workspace_root: str | Path,
    max_artifact_bytes: int,
) -> tuple[dict[str, str], list[ProvenanceFinding]]:
    """Read configured artifact files under a workspace root with containment checks."""

    root = Path(workspace_root).resolve(strict=False)
    artifacts: dict[str, str] = {}
    findings: list[ProvenanceFinding] = []
    for pattern in policy.artifact_paths:
        for candidate in sorted(root.glob(pattern)):
            if not candidate.is_file():
                continue
            try:
                resolved = candidate.resolve(strict=True)
            except OSError:
                findings.append(
                    ProvenanceFinding(
                        finding_type="policy_not_applicable",
                        severity="low",
                        confidence="high",
                        handling="unsafe_artifact_path",
                        artifact_path=candidate.relative_to(root).as_posix(),
                    )
                )
                continue
            rel_path = candidate.relative_to(root).as_posix()
            if resolved != root and root not in resolved.parents:
                findings.append(
                    ProvenanceFinding(
                        finding_type="policy_not_applicable",
                        severity="low",
                        confidence="high",
                        handling="unsafe_artifact_path",
                        artifact_path=rel_path,
                    )
                )
                continue
            try:
                data = resolved.read_bytes()
            except OSError:
                findings.append(
                    ProvenanceFinding(
                        finding_type="policy_not_applicable",
                        severity="low",
                        confidence="high",
                        handling="artifact_read_error",
                        artifact_path=rel_path,
                    )
                )
                continue
            if len(data) > max_artifact_bytes:
                findings.append(
                    ProvenanceFinding(
                        finding_type="policy_not_applicable",
                        severity="low",
                        confidence="high",
                        handling="artifact_too_large",
                        artifact_path=rel_path,
                    )
                )
            artifacts[rel_path] = data[:max_artifact_bytes].decode("utf-8", errors="replace")
    return artifacts, findings


def _ledger_identity_labels(
    entry: dict[str, Any],
    approved_aliases: dict[str, list[str]],
) -> set[str]:
    labels = {
        _identity_normalize(str(entry.get("metadata_record_id") or "")),
        _identity_normalize(str(entry.get("canonical_skill_id") or "")),
    }
    labels.update(_identity_candidates(str(entry.get("observed_name") or "")))
    labels.update(_identity_candidates(str(entry.get("canonical_name") or "")))
    canonical_id = str(entry.get("canonical_skill_id") or "")
    for alias in approved_aliases.get(canonical_id, []):
        labels.update(_identity_candidates(alias))
    return {label for label in labels if label}


def _canonical_identity_label(entry: dict[str, Any]) -> str | None:
    canonical_name = str(entry.get("canonical_name") or "").strip()
    if canonical_name:
        return canonical_name
    canonical_id = str(entry.get("canonical_skill_id") or "").strip()
    if canonical_id.startswith("skill:"):
        return canonical_id.removeprefix("skill:")
    return canonical_id or None


def _is_approved_alias(
    declared: str,
    entry: dict[str, Any],
    approved_aliases: dict[str, list[str]],
) -> bool:
    canonical_id = str(entry.get("canonical_skill_id") or "")
    normalized = _identity_normalize(declared)
    return normalized in {
        _identity_normalize(alias)
        for alias in approved_aliases.get(canonical_id, [])
    }


def validate_provenance_claims(
    policy: ProvenancePolicy,
    *,
    artifacts: dict[str, str],
    ledger_entries: list[dict[str, Any]],
    approved_aliases: dict[str, list[str]] | None = None,
) -> list[ProvenanceFinding]:
    """Compare configured JSON artifact labels to observed runtime ledger entries."""

    aliases = approved_aliases or {}
    findings: list[ProvenanceFinding] = []
    selected_entries = [
        entry
        for entry in ledger_entries
        if isinstance(entry, dict)
    ]

    for artifact_path, content in artifacts.items():
        if not _artifact_selected(policy, artifact_path):
            continue
        try:
            document = json.loads(content)
        except Exception:
            findings.append(
                ProvenanceFinding(
                    finding_type="artifact_parse_error",
                    severity="low",
                    handling=policy.on_parse_error,
                    artifact_path=artifact_path,
                )
            )
            continue
        for field_path in policy.field_paths:
            found, raw_value = _lookup_field_value(document, field_path)
            if not found:
                findings.append(
                    ProvenanceFinding(
                        finding_type="policy_not_applicable",
                        severity="low",
                        confidence="high",
                        handling="missing_field",
                        artifact_path=artifact_path,
                        field_path=field_path,
                    )
                )
                continue
            field_values = _extract_field_values(document, field_path)
            if not field_values:
                findings.append(
                    ProvenanceFinding(
                        finding_type="policy_not_applicable",
                        severity="low",
                        confidence="high",
                        handling="non_string_label",
                        artifact_path=artifact_path,
                        field_path=field_path,
                    )
                )
                continue
            for declared in field_values:
                normalized = _identity_normalize(declared)
                normalized_candidates = _identity_candidates(declared)
                matches = [
                    entry
                    for entry in selected_entries
                    if normalized_candidates.intersection(_ledger_identity_labels(entry, aliases))
                ]
                if not selected_entries and not any(
                    finding.finding_type == "coverage_gap" for finding in findings
                ):
                    findings.append(
                        ProvenanceFinding(
                            finding_type="coverage_gap",
                            declared_label=None,
                            severity="low",
                            confidence="high",
                            handling=policy.on_empty_ledger,
                            artifact_path=artifact_path,
                            field_path=field_path,
                        )
                    )
                if not matches:
                    findings.append(
                        ProvenanceFinding(
                            finding_type="unobserved_claim",
                            declared_label=declared,
                            normalized_identity=normalized,
                            matched_ledger_entry_ids=[],
                            severity="medium",
                            handling=policy.on_unobserved_claim,
                            artifact_path=artifact_path,
                            field_path=field_path,
                        )
                    )
                    continue
                if len(matches) > 1:
                    findings.append(
                        ProvenanceFinding(
                            finding_type="ambiguous_claim",
                            declared_label=declared,
                            normalized_identity=normalized,
                            matched_ledger_entry_ids=[
                                str(entry.get("event_id") or entry.get("dedupe_key") or "")
                                for entry in matches
                            ],
                            severity="medium",
                            handling=policy.on_conflicting_claim,
                            artifact_path=artifact_path,
                            field_path=field_path,
                        )
                    )
                    continue
                blocked = [
                    entry
                    for entry in matches
                    if str(entry.get("decision") or "").lower() in {"block", "defer"}
                ]
                if blocked:
                    findings.append(
                        ProvenanceFinding(
                            finding_type=(
                                "blocked_skill_claim"
                                if str(blocked[0].get("decision") or "").lower() == "block"
                                else "deferred_skill_claim"
                            ),
                            declared_label=declared,
                            normalized_identity=normalized,
                            matched_ledger_entry_ids=[
                                str(entry.get("event_id") or entry.get("dedupe_key") or "")
                                for entry in blocked
                            ],
                            severity="high",
                            handling=policy.on_blocked_claim,
                            artifact_path=artifact_path,
                            field_path=field_path,
                        )
                    )
                    continue
                canonical_label = _canonical_identity_label(matches[0])
                if (
                    canonical_label
                    and normalized != _identity_normalize(canonical_label)
                    and not _is_approved_alias(declared, matches[0], aliases)
                ):
                    findings.append(
                        ProvenanceFinding(
                            finding_type="canonical_label_conflict",
                            declared_label=declared,
                            normalized_identity=normalized,
                            matched_ledger_entry_ids=[
                                str(matches[0].get("event_id") or matches[0].get("dedupe_key") or "")
                            ],
                            severity="high",
                            handling=policy.on_conflicting_claim,
                            artifact_path=artifact_path,
                            field_path=field_path,
                        )
                    )
    return findings
