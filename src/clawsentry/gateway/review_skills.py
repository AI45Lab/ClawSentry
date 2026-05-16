"""YAML-backed review skills for Phase 5.2 L3 Agent."""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from .models import CanonicalEvent

logger = logging.getLogger("ahp.review-skills")


_VALID_SEVERITIES = {"low", "medium", "high", "critical"}
SKILL_SCHEMA_VERSION = "clawsentry.l3_skill.v1"
VALID_L3_TOOLS = frozenset({
    "read_trajectory",
    "read_trajectory_page",
    "read_file",
    "read_file_range",
    "read_transcript",
    "read_session_risk",
    "read_l3_trace",
    "search_codebase",
    "query_git_diff",
    "query_git_status",
    "query_git_show",
    "list_changed_files",
    "list_directory",
    "read_package_manifest",
})
_VALID_REQUIRED_EVIDENCE = frozenset({
    "current_event",
    "trigger",
    "trajectory_summary",
    "session_risk",
    "workspace_context",
    "l1_snapshot",
    "prior_analysis",
    "skill_trust",
})
_VALID_FIELD_NOTES = frozenset({
    "event",
    "trigger",
    "local_evidence",
    "rule_hits",
    "effect_summary",
    "taint_flow_summary",
    "skill_trust_findings",
    "session_scope_summary",
    "mcp_summary",
    "tool_evidence",
    "prior_analysis",
})
_OUTPUT_TAG_RE = re.compile(r"^[a-z][a-z0-9_]{1,63}$")
_REAL_PATH_RE = re.compile(r"(/home/|/Users/|[A-Za-z]:\\\\|/etc/|/root/)")
_SECRET_TEXT_RE = re.compile(r"(AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{20,}|sk-[A-Za-z0-9]{20,}|SECRET|TOKEN|PASSWORD|PRIVATE KEY)", re.IGNORECASE)


@dataclass(frozen=True)
class ReviewSkill:
    name: str
    description: str
    triggers: dict[str, list[str]]
    system_prompt: str
    evaluation_criteria: list[dict[str, str]]
    enabled: bool = True
    priority: int = 0
    schema_version: str = "legacy"
    allowed_tools: tuple[str, ...] = tuple(sorted(VALID_L3_TOOLS))
    required_evidence: tuple[str, ...] = ()
    recommended_tools: tuple[dict[str, str], ...] = ()
    severity_rubric: dict[str, list[str]] | None = None
    benign_exceptions: tuple[str, ...] = ()
    output_tags: tuple[str, ...] = ()
    field_notes: dict[str, str] | None = None
    example_policy: dict[str, Any] | None = None
    example_cases: tuple[dict[str, Any], ...] = ()
    max_tool_calls: int | None = None


class SkillRegistry:
    """Load review skills from YAML files and select the best deterministic match."""

    def __init__(self, skills_dir: Path) -> None:
        self._skills: dict[str, ReviewSkill] = {}
        self._load_directory(skills_dir)
        if "general-review" not in self._skills:
            raise ValueError("general-review skill is required")

    @property
    def skills(self) -> dict[str, ReviewSkill]:
        return dict(self._skills)

    def _load_directory(self, skills_dir: Path) -> None:
        if not skills_dir.exists() or not skills_dir.is_dir():
            raise ValueError(f"skills_dir does not exist or is not a directory: {skills_dir}")
        for path in sorted(skills_dir.glob("*.yaml")):
            skill = self._load_skill(path)
            if skill.name in self._skills:
                raise ValueError(f"duplicate skill name: {skill.name}")
            self._skills[skill.name] = skill

    def load_additional(self, skills_dir: Path) -> int:
        """Load additional skills from an external directory. Returns count loaded."""
        count = 0
        for path in sorted(skills_dir.glob("*.yaml")):
            skill = self._load_skill(path)
            if skill.name in self._skills:
                logger.warning("Skipping duplicate skill: %s (from %s)", skill.name, path)
                continue
            self._skills[skill.name] = skill
            count += 1
        return count

    def _load_skill(self, path: Path) -> ReviewSkill:
        with open(path, "r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh) or {}
        return self._validate_skill(data, path)

    def _validate_skill(self, data: dict[str, Any], path: Path) -> ReviewSkill:
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
            "risk_hints": [str(v).lower() for v in triggers.get("risk_hints", [])],
            "tool_names": [str(v).lower() for v in triggers.get("tool_names", [])],
            "payload_patterns": [str(v).lower() for v in triggers.get("payload_patterns", [])],
        }

        normalized_criteria: list[dict[str, str]] = []
        for idx, item in enumerate(evaluation_criteria):
            if not isinstance(item, dict):
                raise ValueError(f"skill evaluation_criteria[{idx}] must be a dict: {path}")
            crit_name = str(item.get("name") or "").strip()
            severity = str(item.get("severity") or "").strip().lower()
            description = str(item.get("description") or "").strip()
            if not crit_name or not description or severity not in _VALID_SEVERITIES:
                raise ValueError(f"invalid evaluation_criteria[{idx}] in {path}")
            normalized_criteria.append(
                {"name": crit_name, "severity": severity, "description": description}
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

    def select_skill(self, event: CanonicalEvent, risk_hints: list[str]) -> ReviewSkill:
        ranked = self._ranked_skills(event, risk_hints)
        return ranked[0][1] if ranked else self._skills["general-review"]

    def secondary_criteria(
        self,
        event: CanonicalEvent,
        risk_hints: list[str],
        *,
        primary_name: str,
        limit: int = 2,
    ) -> list[dict[str, Any]]:
        """Return close-match criteria from distinct skills for cross-domain review."""
        secondary: list[dict[str, Any]] = []
        for _score, skill in self._ranked_skills(event, risk_hints):
            if skill.name in {primary_name, "general-review"}:
                continue
            secondary.append({
                "skill": skill.name,
                "description": skill.description,
                "evaluation_criteria": skill.evaluation_criteria,
                "output_tags": list(skill.output_tags),
            })
            if len(secondary) >= limit:
                break
        return secondary

    def _ranked_skills(
        self,
        event: CanonicalEvent,
        risk_hints: list[str],
    ) -> list[tuple[tuple[int, int, int], ReviewSkill]]:
        event_tool = str(event.tool_name or "").lower()
        payload_text = str(event.payload or {}).lower()
        normalized_hints = {str(h).lower() for h in (risk_hints or [])}

        ranked: list[tuple[tuple[int, int, int], ReviewSkill]] = []
        for order, (name, skill) in enumerate(self._skills.items()):
            if name == "general-review":
                continue
            if not skill.enabled:
                continue
            score = 0
            score += len(normalized_hints.intersection(skill.triggers.get("risk_hints", []))) * 10
            if event_tool and event_tool in skill.triggers.get("tool_names", []):
                score += 5
            score += sum(
                1 for pattern in skill.triggers.get("payload_patterns", [])
                if pattern and pattern in payload_text
            )
            if score > 0:
                ranked.append(((score, skill.priority, -order), skill))

        ranked.sort(key=lambda item: item[0], reverse=True)
        if not ranked:
            return [((0, self._skills["general-review"].priority, 0), self._skills["general-review"])]
        return ranked


def _as_str_list(value: Any, *, field_name: str, path: Path) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise ValueError(f"skill {field_name} must be a list: {path}")
    return [str(item).strip() for item in value if str(item).strip()]


def _validate_manifest_v1_fields(data: dict[str, Any], path: Path) -> dict[str, Any]:
    schema_version = str(data.get("schema_version") or "legacy").strip() or "legacy"
    allowed_tools_raw = _as_str_list(data.get("allowed_tools"), field_name="allowed_tools", path=path)
    allowed_tools = tuple(sorted(allowed_tools_raw or VALID_L3_TOOLS))
    illegal_tools = [tool for tool in allowed_tools if tool not in VALID_L3_TOOLS]
    if illegal_tools:
        raise ValueError(f"skill allowed_tools contain non-whitelisted tools {illegal_tools}: {path}")

    max_tool_calls = data.get("max_tool_calls")
    if max_tool_calls is not None:
        try:
            max_tool_calls = max(1, min(int(max_tool_calls), 20))
        except (TypeError, ValueError) as exc:
            raise ValueError(f"skill max_tool_calls must be an integer: {path}") from exc

    required_evidence = tuple(_as_str_list(data.get("required_evidence"), field_name="required_evidence", path=path))
    unknown_required = [item for item in required_evidence if item not in _VALID_REQUIRED_EVIDENCE]
    if unknown_required:
        raise ValueError(f"skill required_evidence contains unknown values {unknown_required}: {path}")

    recommended_raw = data.get("recommended_tools") or []
    if not isinstance(recommended_raw, list):
        raise ValueError(f"skill recommended_tools must be a list: {path}")
    recommended_tools: list[dict[str, str]] = []
    for idx, item in enumerate(recommended_raw):
        if not isinstance(item, dict):
            raise ValueError(f"skill recommended_tools[{idx}] must be a dict: {path}")
        name = str(item.get("name") or "").strip()
        if name and name not in VALID_L3_TOOLS:
            raise ValueError(f"skill recommended_tools[{idx}] references unknown tool {name}: {path}")
        recommended_tools.append({str(k): str(v) for k, v in item.items()})

    severity_rubric = data.get("severity_rubric")
    if severity_rubric is not None:
        if not isinstance(severity_rubric, dict):
            raise ValueError(f"skill severity_rubric must be a dict: {path}")
        normalized_rubric: dict[str, list[str]] = {}
        for severity, bullets in severity_rubric.items():
            sev = str(severity).lower()
            if sev not in _VALID_SEVERITIES:
                raise ValueError(f"skill severity_rubric has invalid severity {severity}: {path}")
            normalized_rubric[sev] = _as_str_list(bullets, field_name=f"severity_rubric.{sev}", path=path)
        severity_rubric = normalized_rubric

    output_tags = tuple(_as_str_list(data.get("output_tags"), field_name="output_tags", path=path))
    if len(set(output_tags)) != len(output_tags):
        raise ValueError(f"skill output_tags must not contain duplicates: {path}")
    invalid_tags = [tag for tag in output_tags if not _OUTPUT_TAG_RE.match(tag)]
    if invalid_tags:
        raise ValueError(f"skill output_tags contain invalid tags {invalid_tags}: {path}")

    field_notes = data.get("field_notes")
    if field_notes is not None:
        if not isinstance(field_notes, dict):
            raise ValueError(f"skill field_notes must be a dict: {path}")
        unknown_fields = [str(key) for key in field_notes if str(key) not in _VALID_FIELD_NOTES]
        if unknown_fields:
            raise ValueError(f"skill field_notes references unknown fields {unknown_fields}: {path}")
        field_notes = {str(key): str(value) for key, value in field_notes.items()}

    example_policy = data.get("example_policy")
    if example_policy is not None and not isinstance(example_policy, dict):
        raise ValueError(f"skill example_policy must be a dict: {path}")
    example_policy = dict(example_policy or {})
    max_examples = int(example_policy.get("max_examples", 0) or 0)
    max_chars = int(example_policy.get("max_chars_per_example", 900) or 900)

    example_cases_raw = data.get("example_cases") or []
    if not isinstance(example_cases_raw, list):
        raise ValueError(f"skill example_cases must be a list: {path}")
    if max_examples and len(example_cases_raw) > max_examples:
        raise ValueError(f"skill example_cases exceed example_policy.max_examples: {path}")
    example_cases: list[dict[str, Any]] = []
    for idx, item in enumerate(example_cases_raw):
        if not isinstance(item, dict):
            raise ValueError(f"skill example_cases[{idx}] must be a dict: {path}")
        serialized = yaml.safe_dump(item, allow_unicode=True, sort_keys=True)
        if len(serialized) > max_chars:
            raise ValueError(f"skill example_cases[{idx}] exceeds max_chars_per_example: {path}")
        if item.get("synthetic") is not True or item.get("not_current_case") is not True:
            raise ValueError(f"skill example_cases[{idx}] must be synthetic and not_current_case: {path}")
        if _REAL_PATH_RE.search(serialized) or _SECRET_TEXT_RE.search(serialized):
            raise ValueError(f"skill example_cases[{idx}] contains real path or secret-like text: {path}")
        example_cases.append(dict(item))

    if schema_version == SKILL_SCHEMA_VERSION:
        if not required_evidence:
            raise ValueError(f"skill required_evidence is required for {SKILL_SCHEMA_VERSION}: {path}")
        if not severity_rubric or not (set(severity_rubric) & {"high", "critical"}):
            raise ValueError(f"skill severity_rubric must cover high or critical: {path}")
        if not output_tags:
            raise ValueError(f"skill output_tags is required for {SKILL_SCHEMA_VERSION}: {path}")
    elif schema_version != "legacy":
        raise ValueError(f"unsupported skill schema_version {schema_version}: {path}")

    return {
        "schema_version": schema_version,
        "allowed_tools": allowed_tools,
        "required_evidence": required_evidence,
        "recommended_tools": tuple(recommended_tools),
        "severity_rubric": severity_rubric,
        "benign_exceptions": tuple(_as_str_list(data.get("benign_exceptions"), field_name="benign_exceptions", path=path)),
        "output_tags": output_tags,
        "field_notes": field_notes,
        "example_policy": example_policy or None,
        "example_cases": tuple(example_cases),
        "max_tool_calls": max_tool_calls,
    }
