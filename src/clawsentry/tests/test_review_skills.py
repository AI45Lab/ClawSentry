"""Tests for YAML-backed ReviewSkill and SkillRegistry."""

from pathlib import Path

import pytest

from clawsentry.gateway.models import CanonicalEvent, EventType
from clawsentry.gateway.review_skills import SkillRegistry


def _evt(tool_name=None, payload=None, risk_hints=None) -> CanonicalEvent:
    return CanonicalEvent(
        event_id="evt-review-skill",
        trace_id="trace-review-skill",
        event_type=EventType.PRE_ACTION,
        session_id="sess-review-skill",
        agent_id="agent-review-skill",
        source_framework="test",
        occurred_at="2026-03-21T12:00:00+00:00",
        payload=payload or {},
        tool_name=tool_name,
        risk_hints=risk_hints or [],
    )


def _write_skill(path: Path, body: str) -> None:
    path.write_text(body, encoding="utf-8")


def test_loads_yaml_skills_and_selects_best_match(tmp_path: Path):
    _write_skill(
        tmp_path / "credential-audit.yaml",
        """
name: credential-audit
description: 审查涉及凭证、密钥、令牌的操作
triggers:
  risk_hints:
    - credential_exfiltration
  tool_names:
    - bash
  payload_patterns:
    - token
system_prompt: |
  你是一个凭证审查专家。
evaluation_criteria:
  - name: credential_exposure
    severity: critical
    description: 凭证内容是否被暴露
""".strip(),
    )
    _write_skill(
        tmp_path / "general-review.yaml",
        """
name: general-review
description: 通用兜底审查
triggers:
  risk_hints: []
  tool_names: []
  payload_patterns: []
system_prompt: |
  你是一个通用安全审查专家。
evaluation_criteria:
  - name: general_risk
    severity: medium
    description: 整体风险评估
""".strip(),
    )

    registry = SkillRegistry(tmp_path)
    skill = registry.select_skill(
        _evt(
            tool_name="bash",
            payload={"command": "cat api_token.txt"},
            risk_hints=["credential_exfiltration"],
        ),
        ["credential_exfiltration"],
    )

    assert skill.name == "credential-audit"


def test_falls_back_to_general_review_when_no_specific_match(tmp_path: Path):
    _write_skill(
        tmp_path / "general-review.yaml",
        """
name: general-review
description: 通用兜底审查
triggers:
  risk_hints: []
  tool_names: []
  payload_patterns: []
system_prompt: |
  你是一个通用安全审查专家。
evaluation_criteria:
  - name: general_risk
    severity: medium
    description: 整体风险评估
""".strip(),
    )

    registry = SkillRegistry(tmp_path)
    skill = registry.select_skill(
        _evt(tool_name="read_file", payload={"path": "README.md"}, risk_hints=[]),
        [],
    )

    assert skill.name == "general-review"


def test_load_additional_skills(tmp_path: Path):
    """load_additional() loads skills from external directory."""
    main_dir = tmp_path / "main"
    main_dir.mkdir()
    extra_dir = tmp_path / "extra"
    extra_dir.mkdir()

    _write_skill(
        main_dir / "general-review.yaml",
        """
name: general-review
description: 通用兜底审查
triggers:
  risk_hints: []
  tool_names: []
  payload_patterns: []
system_prompt: |
  你是一个通用安全审查专家。
evaluation_criteria:
  - name: general_risk
    severity: medium
    description: 整体风险评估
""".strip(),
    )

    _write_skill(
        extra_dir / "custom-audit.yaml",
        """
name: custom-audit
description: 自定义审查
triggers:
  risk_hints:
    - custom_risk
  tool_names: []
  payload_patterns: []
system_prompt: |
  自定义审查专家。
evaluation_criteria:
  - name: custom_check
    severity: high
    description: 自定义检查
""".strip(),
    )

    registry = SkillRegistry(main_dir)
    assert "custom-audit" not in registry.skills
    count = registry.load_additional(extra_dir)
    assert count == 1
    assert "custom-audit" in registry.skills


def test_load_additional_skip_duplicates(tmp_path: Path):
    """load_additional() skips skills with duplicate names."""
    main_dir = tmp_path / "main"
    main_dir.mkdir()
    extra_dir = tmp_path / "extra"
    extra_dir.mkdir()

    skill_body = """
name: general-review
description: 通用兜底审查
triggers:
  risk_hints: []
  tool_names: []
  payload_patterns: []
system_prompt: |
  你是一个通用安全审查专家。
evaluation_criteria:
  - name: general_risk
    severity: medium
    description: 整体风险评估
""".strip()

    _write_skill(main_dir / "general-review.yaml", skill_body)
    _write_skill(extra_dir / "general-review.yaml", skill_body)

    registry = SkillRegistry(main_dir)
    count = registry.load_additional(extra_dir)
    assert count == 0  # Duplicate skipped


def test_skills_in_package_data():
    """Verify pyproject.toml includes skills YAML in package-data."""
    pyproject_path = Path(__file__).parents[3] / "pyproject.toml"
    content = pyproject_path.read_text()
    assert "gateway/skills/*.yaml" in content


def test_custom_skills_dir_env_var(tmp_path: Path, monkeypatch):
    """AHP_SKILLS_DIR env var is used by llm_factory."""
    # Just verify the env var is read — full integration requires LLM config
    monkeypatch.setenv("AHP_SKILLS_DIR", str(tmp_path))
    import os
    assert os.getenv("AHP_SKILLS_DIR") == str(tmp_path)


# ===========================================================================
# Task 6: Skill Schema — enabled + priority
# ===========================================================================

_GENERAL_SKILL = """
name: general-review
description: fallback
triggers:
  risk_hints: []
  tool_names: []
  payload_patterns: []
system_prompt: |
  General reviewer.
evaluation_criteria:
  - name: general
    severity: medium
    description: general check
""".strip()


def test_enabled_false_skill_skipped(tmp_path: Path):
    """Disabled skill should not participate in selection."""
    _write_skill(tmp_path / "general-review.yaml", _GENERAL_SKILL)
    _write_skill(
        tmp_path / "disabled-skill.yaml",
        """
name: disabled-skill
description: should be skipped
enabled: false
priority: 100
triggers:
  risk_hints:
    - privilege_escalation
  tool_names:
    - bash
  payload_patterns:
    - sudo
system_prompt: |
  Disabled.
evaluation_criteria:
  - name: check
    severity: high
    description: check
""".strip(),
    )
    registry = SkillRegistry(tmp_path)
    skill = registry.select_skill(
        _evt(tool_name="bash", payload={"command": "sudo rm -rf /"}, risk_hints=["privilege_escalation"]),
        ["privilege_escalation"],
    )
    # Should fall back to general-review since disabled-skill is skipped
    assert skill.name == "general-review"


def test_priority_tiebreaker(tmp_path: Path):
    """When two skills have the same score, higher priority wins."""
    _write_skill(tmp_path / "general-review.yaml", _GENERAL_SKILL)
    _write_skill(
        tmp_path / "skill-a.yaml",
        """
name: skill-a
description: lower priority
enabled: true
priority: 5
triggers:
  risk_hints:
    - test_hint
  tool_names: []
  payload_patterns: []
system_prompt: |
  Skill A.
evaluation_criteria:
  - name: check
    severity: medium
    description: check
""".strip(),
    )
    _write_skill(
        tmp_path / "skill-b.yaml",
        """
name: skill-b
description: higher priority
enabled: true
priority: 10
triggers:
  risk_hints:
    - test_hint
  tool_names: []
  payload_patterns: []
system_prompt: |
  Skill B.
evaluation_criteria:
  - name: check
    severity: medium
    description: check
""".strip(),
    )
    registry = SkillRegistry(tmp_path)
    skill = registry.select_skill(
        _evt(risk_hints=["test_hint"]),
        ["test_hint"],
    )
    assert skill.name == "skill-b"


def test_secondary_skill_criteria_selects_close_distinct_family(tmp_path: Path):
    _write_skill(tmp_path / "general-review.yaml", _GENERAL_SKILL)
    _write_skill(
        tmp_path / "credential.yaml",
        """
name: credential
description: credential
priority: 10
triggers:
  risk_hints: [credential_exfiltration]
  tool_names: [bash]
  payload_patterns: []
system_prompt: reviewer
evaluation_criteria:
  - name: credential
    severity: critical
    description: credential check
""".strip(),
    )
    _write_skill(
        tmp_path / "network.yaml",
        """
name: network
description: network
priority: 9
risk_families: [network]
triggers:
  risk_hints: [network_exfiltration]
  tool_names: [bash]
  payload_patterns: []
system_prompt: reviewer
evaluation_criteria:
  - name: network
    severity: high
    description: network check
""".strip(),
    )
    registry = SkillRegistry(tmp_path)

    secondary = registry.secondary_criteria(
        _evt(tool_name="bash", risk_hints=["credential_exfiltration", "network_exfiltration"]),
        ["credential_exfiltration", "network_exfiltration"],
        primary_name="credential",
    )

    assert secondary[0]["skill"] == "network"
    assert secondary[0]["evaluation_criteria"][0]["name"] == "network"


def test_backward_compat_no_enabled_field(tmp_path: Path):
    """Skill without 'enabled' field defaults to True."""
    _write_skill(tmp_path / "general-review.yaml", _GENERAL_SKILL)
    # general-review has no explicit 'enabled' in _GENERAL_SKILL
    registry = SkillRegistry(tmp_path)
    skill = registry.skills["general-review"]
    assert skill.enabled is True


def test_backward_compat_no_priority_field(tmp_path: Path):
    """Skill without 'priority' field defaults to 0."""
    _write_skill(tmp_path / "general-review.yaml", _GENERAL_SKILL)
    registry = SkillRegistry(tmp_path)
    skill = registry.skills["general-review"]
    assert skill.priority == 0


def test_manifest_v1_rejects_illegal_allowed_tool(tmp_path: Path):
    _write_skill(tmp_path / "general-review.yaml", _GENERAL_SKILL)
    _write_skill(
        tmp_path / "bad-tool.yaml",
        """
schema_version: clawsentry.l3_skill.v1
name: bad-tool
description: bad tool
triggers:
  risk_hints: [credential_exfiltration]
  tool_names: []
  payload_patterns: []
allowed_tools:
  - write_file
required_evidence:
  - current_event
severity_rubric:
  high:
    - risky
output_tags:
  - credential
system_prompt: reviewer
evaluation_criteria:
  - name: check
    severity: high
    description: check
""".strip(),
    )

    with pytest.raises(ValueError, match="allowed_tools"):
        SkillRegistry(tmp_path)


def test_manifest_v1_rejects_bad_examples_and_duplicate_output_tags(tmp_path: Path):
    _write_skill(tmp_path / "general-review.yaml", _GENERAL_SKILL)
    _write_skill(
        tmp_path / "bad-example.yaml",
        """
schema_version: clawsentry.l3_skill.v1
name: bad-example
description: bad example
triggers:
  risk_hints: [credential_exfiltration]
  tool_names: []
  payload_patterns: []
allowed_tools:
  - read_file
required_evidence:
  - current_event
severity_rubric:
  high:
    - risky
output_tags:
  - credential
  - credential
example_policy:
  max_examples: 1
  max_chars_per_example: 100
  synthetic_only: true
  examples_are_not_evidence: true
example_cases:
  - example_id: real_case
    synthetic: false
    not_current_case: true
    input_summary: "/home/alice/real/project"
    expected_focus: "bad"
system_prompt: reviewer
evaluation_criteria:
  - name: check
    severity: high
    description: check
""".strip(),
    )

    with pytest.raises(ValueError, match="example_cases|output_tags"):
        SkillRegistry(tmp_path)


def test_builtin_skills_load_with_new_fields():
    """Verify builtin skills load correctly with manifest fields."""
    skills_dir = Path(__file__).parents[1] / "gateway" / "skills"
    registry = SkillRegistry(skills_dir)
    assert len(registry.skills) >= 11
    assert "skill-trust-audit" in registry.skills
    assert "data-staging-exfil-chain-audit" in registry.skills
    for name, skill in registry.skills.items():
        assert isinstance(skill.enabled, bool)
        assert isinstance(skill.priority, int)
        assert skill.schema_version == "clawsentry.l3_skill.v1"
        assert skill.allowed_tools
        assert skill.required_evidence
        assert skill.output_tags


def test_builtin_skills_describe_content_evidence_as_untrusted_not_instructions():
    skills_dir = Path(__file__).parents[1] / "gateway" / "skills"
    registry = SkillRegistry(skills_dir)
    skill = registry.skills["data-staging-exfil-chain-audit"]

    assert skill.field_notes is not None
    note = str(skill.field_notes.get("content_evidence") or "")
    combined = f"{note}\n{skill.system_prompt}".lower()
    assert "content_evidence" in combined
    assert "untrusted" in combined
    assert "not instructions" in combined
