from __future__ import annotations

import copy
import hashlib
import json
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from .models import CanonicalEvent
from .pattern_matcher import AttackPattern, PatternMatcher, _parse_evolved_pattern, _parse_pattern
from .review_skills import ReviewSkill, _validate_manifest_v1_fields

_REPORT_SCHEMA_VERSION = "cs-01.rule-governance.v1"
_DEFAULT_PATTERNS_PATH = Path(__file__).parent / "attack_patterns.yaml"
_DEFAULT_SKILLS_DIR = Path(__file__).parent / "skills"
_VALID_SEVERITIES = {"low", "medium", "high", "critical"}


@dataclass(frozen=True)
class GovernanceFinding:
    kind: str
    message: str
    severity: str = "error"
    source_kind: str | None = None
    item_id: str | None = None


@dataclass(frozen=True)
class RuleSourceSummary:
    source_kind: str
    source_name: str
    version: str
    item_count: int


@dataclass(frozen=True)
class RuleGovernanceVersionSummary:
    report_schema_version: str
    attack_patterns_version: str
    evolved_patterns_version: str
    review_skills_version: str
    attack_patterns_count: int
    inactive_evolved_patterns_count: int
    review_skills_count: int


@dataclass(frozen=True)
class RuleGovernanceReport:
    attack_patterns: tuple[AttackPattern, ...]
    review_skills: tuple[ReviewSkill, ...]
    source_summaries: tuple[RuleSourceSummary, ...]
    findings: tuple[GovernanceFinding, ...]
    version_summary: RuleGovernanceVersionSummary
    fingerprint: str


@dataclass(frozen=True)
class RuleDryRunEvent:
    event_id: str
    matched_pattern_ids: tuple[str, ...]
    selected_skill: str | None


@dataclass(frozen=True)
class RuleDryRunReport:
    fingerprint: str
    events: tuple[RuleDryRunEvent, ...]
    findings: tuple[GovernanceFinding, ...]


def load_rule_governance(
    patterns_path: str | Path | None = None,
    *,
    evolved_patterns_path: str | Path | None = None,
    skills_dir: str | Path | None = None,
) -> RuleGovernanceReport:
    attack_path = Path(patterns_path) if patterns_path else _DEFAULT_PATTERNS_PATH
    skill_path = Path(skills_dir) if skills_dir else _DEFAULT_SKILLS_DIR
    evolved_path = Path(evolved_patterns_path) if evolved_patterns_path else None

    findings: list[GovernanceFinding] = []

    attack_doc = _load_yaml_document(attack_path, "attack_patterns", findings)
    evolved_doc = (
        _load_yaml_document(evolved_path, "evolved_patterns", findings)
        if evolved_path is not None
        else {}
    )
    builtin_skill_docs = _load_skill_documents(_DEFAULT_SKILLS_DIR, findings)
    custom_skill_docs: list[dict[str, Any]] = []
    if skill_path != _DEFAULT_SKILLS_DIR:
        custom_skill_docs = _load_skill_documents(skill_path, findings)

    attack_patterns_list, inactive_evolved_count, active_evolved_count = _build_attack_patterns(
        attack_doc,
        evolved_doc,
        findings,
    )
    skill_docs = builtin_skill_docs + custom_skill_docs
    review_skills = tuple(_build_review_skills(skill_docs, findings))
    attack_patterns = tuple(attack_patterns_list)
    findings.extend(_review_skill_findings(skill_docs))

    attack_version = str(attack_doc.get("version") or "unknown")
    evolved_version = str(evolved_doc.get("version") or "none")
    review_version = _digest_text(
        json.dumps(
            [_canonicalize(doc["data"]) for doc in skill_docs],
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        )
    )[:12]

    source_summaries = (
        RuleSourceSummary(
            source_kind="attack_patterns",
            source_name=str(attack_path),
            version=attack_version,
            item_count=len(attack_patterns),
        ),
        RuleSourceSummary(
            source_kind="review_skills",
            source_name=str(_DEFAULT_SKILLS_DIR),
            version=f"skills@{review_version}",
            item_count=len(builtin_skill_docs),
        ),
    )
    extra_summaries: list[RuleSourceSummary] = []
    if evolved_path is not None:
        extra_summaries.append(
            RuleSourceSummary(
                source_kind="evolved_patterns",
                source_name=str(evolved_path),
                version=evolved_version,
                item_count=active_evolved_count,
            )
        )
    if custom_skill_docs:
        extra_summaries.append(
            RuleSourceSummary(
                source_kind="custom_review_skills",
                source_name=str(skill_path),
                version=f"skills@{review_version}",
                item_count=len(custom_skill_docs),
            )
        )
    source_summaries = source_summaries + tuple(extra_summaries)
    version_summary = RuleGovernanceVersionSummary(
        report_schema_version=_REPORT_SCHEMA_VERSION,
        attack_patterns_version=attack_version,
        evolved_patterns_version=evolved_version,
        review_skills_version=f"skills@{review_version}",
        attack_patterns_count=len(attack_patterns),
        inactive_evolved_patterns_count=inactive_evolved_count,
        review_skills_count=len(review_skills),
    )
    fingerprint = _build_fingerprint(
        attack_doc=attack_doc,
        evolved_doc=evolved_doc,
        skill_docs=skill_docs,
        version_summary=version_summary,
    )
    findings_tuple = tuple(sorted(findings, key=lambda item: (item.kind, item.item_id or "", item.message)))
    return RuleGovernanceReport(
        attack_patterns=attack_patterns,
        review_skills=review_skills,
        source_summaries=source_summaries,
        findings=findings_tuple,
        version_summary=version_summary,
        fingerprint=fingerprint,
    )


def dry_run_rule_governance(
    events_path: str | Path,
    *,
    patterns_path: str | Path | None = None,
    evolved_patterns_path: str | Path | None = None,
    skills_dir: str | Path | None = None,
) -> RuleDryRunReport:
    report = load_rule_governance(
        patterns_path=patterns_path,
        evolved_patterns_path=evolved_patterns_path,
        skills_dir=skills_dir,
    )
    findings = list(report.findings)
    matcher = PatternMatcher()
    matcher.patterns = [copy.deepcopy(pattern) for pattern in report.attack_patterns]
    events: list[RuleDryRunEvent] = []
    for event_label, raw, parse_error in _load_dry_run_events(Path(events_path)):
        if parse_error is not None:
            findings.append(
                GovernanceFinding(
                    kind="invalid_dry_run_event",
                    message=f"{event_label}: {parse_error}",
                    severity="error",
                )
            )
            continue
        try:
            event = CanonicalEvent.model_validate(raw)
        except Exception as exc:
            findings.append(
                GovernanceFinding(
                    kind="invalid_dry_run_event",
                    message=f"{event_label}: {exc}",
                    severity="error",
                )
            )
            continue
        payload_text = json.dumps(event.payload, sort_keys=True, ensure_ascii=False)
        matches = matcher.match(
            tool_name=str(event.tool_name or ""),
            payload=event.payload,
            content=payload_text,
        )
        events.append(
            RuleDryRunEvent(
                event_id=event.event_id,
                matched_pattern_ids=tuple(sorted(match.id for match in matches)),
                selected_skill=_select_review_skill(report.review_skills, event),
            )
        )
    findings_tuple = tuple(sorted(findings, key=lambda item: (item.kind, item.item_id or "", item.message)))
    return RuleDryRunReport(
        fingerprint=report.fingerprint,
        events=tuple(events),
        findings=findings_tuple,
    )


def _load_yaml_document(
    path: Path,
    source_kind: str,
    findings: list[GovernanceFinding],
) -> dict[str, Any]:
    if not path.exists():
        findings.append(
            GovernanceFinding(
                kind=f"missing_{source_kind}_source",
                message=f"{source_kind} source not found: {path}",
                source_kind=source_kind,
            )
        )
        return {}
    try:
        with open(path, encoding="utf-8") as handle:
            data = yaml.safe_load(handle) or {}
    except Exception as exc:
        findings.append(
            GovernanceFinding(
                kind=f"invalid_{source_kind}_yaml",
                message=f"{source_kind} YAML could not be parsed: {exc}",
                source_kind=source_kind,
            )
        )
        return {}
    if not isinstance(data, dict):
        findings.append(
            GovernanceFinding(
                kind=f"invalid_{source_kind}_shape",
                message=f"{source_kind} document must be a mapping",
                source_kind=source_kind,
            )
        )
        return {}
    return data


def _load_skill_documents(
    skills_dir: Path,
    findings: list[GovernanceFinding],
) -> list[dict[str, Any]]:
    if not skills_dir.exists() or not skills_dir.is_dir():
        findings.append(
            GovernanceFinding(
                kind="missing_review_skills_source",
                message=f"review_skills source not found: {skills_dir}",
                source_kind="review_skills",
            )
        )
        return []

    documents: list[dict[str, Any]] = []
    for path in sorted(skills_dir.glob("*.yaml")):
        try:
            with open(path, encoding="utf-8") as handle:
                data = yaml.safe_load(handle) or {}
        except Exception as exc:
            findings.append(
                GovernanceFinding(
                    kind="invalid_review_skill_yaml",
                    message=f"review skill YAML could not be parsed: {path}: {exc}",
                    source_kind="review_skills",
                )
            )
            continue
        if not isinstance(data, dict):
            findings.append(
                GovernanceFinding(
                    kind="invalid_review_skill_shape",
                    message=f"review skill document must be a mapping: {path}",
                    source_kind="review_skills",
                )
            )
            continue
        documents.append({"path": path, "data": data})
    return documents


def _build_attack_patterns(
    attack_doc: dict[str, Any],
    evolved_doc: dict[str, Any],
    findings: list[GovernanceFinding],
) -> tuple[list[AttackPattern], int, int]:
    core_patterns = _load_attack_patterns_from_document(
        attack_doc,
        source_kind="attack_patterns",
        findings=findings,
        parse_item=_parse_pattern,
    )
    core_ids = {pattern.id for pattern in core_patterns}

    inactive_evolved_count = 0
    evolved_patterns: list[AttackPattern] = []
    for pattern in _load_attack_patterns_from_document(
        evolved_doc,
        source_kind="evolved_patterns",
        findings=findings,
        parse_item=_parse_evolved_pattern,
    ):
        if pattern.id in core_ids:
            findings.append(
                GovernanceFinding(
                    kind="duplicate_attack_pattern_id",
                    message=f"duplicate attack pattern id across core and evolved sources: {pattern.id}",
                    source_kind="evolved_patterns",
                    item_id=pattern.id,
                )
            )
            continue
        if not getattr(pattern, "is_active", True):
            inactive_evolved_count += 1
            continue
        evolved_patterns.append(pattern)
    return core_patterns + evolved_patterns, inactive_evolved_count, len(evolved_patterns)


def _load_attack_patterns_from_document(
    document: dict[str, Any],
    *,
    source_kind: str,
    findings: list[GovernanceFinding],
    parse_item: Any,
) -> list[AttackPattern]:
    if not document:
        return []

    patterns = document.get("patterns")
    if patterns is None:
        return []
    if not isinstance(patterns, list):
        findings.append(
            GovernanceFinding(
                kind="invalid_attack_patterns_shape",
                message=f"{source_kind} patterns must be a list",
                source_kind=source_kind,
            )
        )
        return []

    loaded: list[AttackPattern] = []
    seen_ids: set[str] = set()
    for index, raw in enumerate(patterns, start=1):
        if not isinstance(raw, dict):
            findings.append(
                GovernanceFinding(
                    kind="invalid_attack_pattern_schema",
                    message=f"{source_kind}[{index}] must be a mapping",
                    source_kind=source_kind,
                    item_id=f"{source_kind}[{index}]",
                )
            )
            continue
        try:
            pattern = parse_item(copy.deepcopy(raw))
        except Exception as exc:
            item_id = str(raw.get("id") or f"{source_kind}[{index}]")
            findings.append(
                GovernanceFinding(
                    kind="invalid_attack_pattern_schema",
                    message=f"{source_kind}[{index}] invalid: {exc}",
                    source_kind=source_kind,
                    item_id=item_id,
                )
            )
            continue
        if pattern.id in seen_ids:
            findings.append(
                GovernanceFinding(
                    kind="duplicate_attack_pattern_id",
                    message=f"duplicate attack pattern id: {pattern.id}",
                    source_kind=source_kind,
                    item_id=pattern.id,
                )
            )
            continue
        seen_ids.add(pattern.id)
        loaded.append(pattern)
    return loaded


def _review_skill_findings(skill_docs: list[dict[str, Any]]) -> list[GovernanceFinding]:
    findings: list[GovernanceFinding] = []
    name_counts = Counter()
    signature_to_names: dict[str, set[str]] = defaultdict(set)

    for item in skill_docs:
        data = item["data"]
        name = str(data.get("name") or "").strip()
        if name:
            name_counts[name] += 1
        signature = _review_skill_signature(data)
        if signature is not None and name:
            signature_to_names[signature].add(name)

    for name, count in sorted(name_counts.items()):
        if count > 1:
            findings.append(
                GovernanceFinding(
                    kind="duplicate_review_skill_name",
                    message=f"duplicate review skill name: {name}",
                    source_kind="review_skills",
                    item_id=name,
                )
            )

    for signature, names in sorted(signature_to_names.items()):
        if len(names) > 1:
            findings.append(
                GovernanceFinding(
                    kind="review_skill_signature_conflict",
                    message=f"multiple review skills share the same trigger signature: {', '.join(sorted(names))}",
                    source_kind="review_skills",
                    item_id=signature,
                )
            )
    return findings


def _build_review_skills(
    skill_docs: list[dict[str, Any]],
    findings: list[GovernanceFinding],
) -> list[ReviewSkill]:
    skills: list[ReviewSkill] = []
    seen_names: set[str] = set()
    for item in skill_docs:
        path = item["path"]
        data = item["data"]
        try:
            skill = _validate_review_skill(data, path)
        except ValueError as exc:
            findings.append(
                GovernanceFinding(
                    kind="invalid_review_skill_schema",
                    message=str(exc),
                    source_kind="review_skills",
                    item_id=str(path),
                )
            )
            continue
        if skill.name in seen_names:
            continue
        seen_names.add(skill.name)
        skills.append(skill)
    return skills


def _validate_review_skill(data: dict[str, Any], path: Path) -> ReviewSkill:
    name = str(data.get("name") or "").strip()
    description = str(data.get("description") or "").strip()
    system_prompt = str(data.get("system_prompt") or "").strip()
    triggers = data.get("triggers") or {}
    evaluation_criteria = data.get("evaluation_criteria") or []

    if not name:
        raise ValueError(f"skill missing name: {path}")
    if not description:
        raise ValueError(f"skill missing description: {path}")
    if not system_prompt:
        raise ValueError(f"skill missing system_prompt: {path}")
    if not isinstance(triggers, dict):
        raise ValueError(f"skill triggers must be a dict: {path}")
    if not isinstance(evaluation_criteria, list):
        raise ValueError(f"skill evaluation_criteria must be a list: {path}")

    normalized_triggers = {
        "risk_hints": sorted(str(v).lower() for v in triggers.get("risk_hints", [])),
        "tool_names": sorted(str(v).lower() for v in triggers.get("tool_names", [])),
        "payload_patterns": sorted(str(v).lower() for v in triggers.get("payload_patterns", [])),
    }
    normalized_criteria: list[dict[str, str]] = []
    for idx, item in enumerate(evaluation_criteria):
        if not isinstance(item, dict):
            raise ValueError(f"skill evaluation_criteria[{idx}] must be a dict: {path}")
        crit_name = str(item.get("name") or "").strip()
        severity = str(item.get("severity") or "").strip().lower()
        description_text = str(item.get("description") or "").strip()
        if not crit_name or not description_text or severity not in _VALID_SEVERITIES:
            raise ValueError(f"invalid evaluation_criteria[{idx}] in {path}")
        normalized_criteria.append(
            {"name": crit_name, "severity": severity, "description": description_text}
        )
    enabled = data.get("enabled", True)
    if not isinstance(enabled, bool):
        enabled = True
    priority = data.get("priority", 0)
    if not isinstance(priority, int):
        priority = 0
    manifest = _validate_manifest_v1_fields(data, path)
    return ReviewSkill(
        name=name,
        description=description,
        triggers=normalized_triggers,
        system_prompt=system_prompt,
        evaluation_criteria=normalized_criteria,
        enabled=enabled,
        priority=priority,
        **manifest,
    )


def _review_skill_signature(data: dict[str, Any]) -> str | None:
    triggers = data.get("triggers") or {}
    if not isinstance(triggers, dict):
        return None
    normalized = {
        "risk_hints": sorted(str(v).lower() for v in triggers.get("risk_hints", [])),
        "tool_names": sorted(str(v).lower() for v in triggers.get("tool_names", [])),
        "payload_patterns": sorted(str(v).lower() for v in triggers.get("payload_patterns", [])),
    }
    if not any(normalized.values()):
        return None
    return json.dumps(normalized, sort_keys=True, separators=(",", ":"))


def _build_fingerprint(
    *,
    attack_doc: dict[str, Any],
    evolved_doc: dict[str, Any],
    skill_docs: list[dict[str, Any]],
    version_summary: RuleGovernanceVersionSummary,
) -> str:
    payload = {
        "version_summary": _canonicalize(version_summary.__dict__),
        "attack_patterns": sorted(
            (_canonicalize(item) for item in attack_doc.get("patterns", []) if isinstance(item, dict)),
            key=lambda item: json.dumps(item, sort_keys=True, separators=(",", ":")),
        ),
        "evolved_patterns": sorted(
            (_canonicalize(item) for item in evolved_doc.get("patterns", []) if isinstance(item, dict)),
            key=lambda item: json.dumps(item, sort_keys=True, separators=(",", ":")),
        ),
        "review_skills": sorted(
            (_canonicalize(item["data"]) for item in skill_docs),
            key=lambda item: json.dumps(item, sort_keys=True, separators=(",", ":")),
        ),
    }
    serialized = json.dumps(payload, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
    return _digest_text(serialized)


def _canonicalize(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: _canonicalize(value[key])
            for key in sorted(value)
            if not str(key).startswith("_")
        }
    if isinstance(value, list):
        items = [_canonicalize(item) for item in value]
        if all(not isinstance(item, (dict, list)) for item in items):
            return sorted(items)
        return sorted(items, key=lambda item: json.dumps(item, sort_keys=True, separators=(",", ":")))
    return value


def _digest_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _load_dry_run_events(path: Path) -> list[tuple[str, Any | None, str | None]]:
    content = path.read_text(encoding="utf-8")
    stripped = content.strip()
    if not stripped:
        return []
    try:
        payload = json.loads(stripped)
    except json.JSONDecodeError:
        events: list[tuple[str, Any | None, str | None]] = []
        for line_number, line in enumerate(content.splitlines(), start=1):
            line = line.strip()
            if not line:
                continue
            try:
                events.append((f"line {line_number}", json.loads(line), None))
            except json.JSONDecodeError as exc:
                events.append((f"line {line_number}", None, str(exc)))
        return events

    if isinstance(payload, list):
        return [(f"item {index}", item, None) for index, item in enumerate(payload, start=1)]
    return [("item 1", payload, None)]


def _select_review_skill(skills: tuple[ReviewSkill, ...], event: CanonicalEvent) -> str | None:
    general_name = None
    best_name = None
    best_score = -1
    best_priority = -1
    event_tool = str(event.tool_name or "").lower()
    payload_text = str(event.payload or {}).lower()
    normalized_hints = {str(hint).lower() for hint in (event.risk_hints or [])}

    for skill in skills:
        if skill.name == "general-review":
            general_name = skill.name
        if not skill.enabled or skill.name == "general-review":
            continue
        score = 0
        score += len(normalized_hints.intersection(skill.triggers.get("risk_hints", []))) * 10
        if event_tool and event_tool in skill.triggers.get("tool_names", []):
            score += 5
        score += sum(
            1
            for pattern in skill.triggers.get("payload_patterns", [])
            if pattern and pattern in payload_text
        )
        if score > best_score or (score == best_score and skill.priority > best_priority):
            best_score = score
            best_priority = skill.priority
            best_name = skill.name
    if best_score <= 0:
        return general_name
    return best_name
