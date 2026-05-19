import json

import pytest

from clawsentry.gateway.detection_config import DetectionConfig
from clawsentry.gateway.models import PostActionFinding, PostActionResponseTier
from clawsentry.gateway.provenance_validator import (
    ProvenancePolicy,
    collect_policy_artifacts,
    load_provenance_policy_from_env,
    validate_provenance_claims,
)
from clawsentry.gateway.server import SupervisionGateway


def test_provenance_policy_loads_env_json(monkeypatch):
    monkeypatch.setenv(
        "CS_SKILL_TRUST_PROVENANCE_POLICY_JSON",
        json.dumps(
            {
                "artifact_paths": ["outputs/*.json"],
                "field_paths": ["tool_called", "provenance.tools"],
                "on_unobserved_claim": "finding",
            }
        ),
    )

    policy, findings = load_provenance_policy_from_env()

    assert findings == []
    assert policy is not None
    assert policy.artifact_paths == ["outputs/*.json"]
    assert policy.field_paths == ["tool_called", "provenance.tools"]
    assert policy.on_unobserved_claim == "finding"


def test_provenance_policy_rejects_unsafe_artifact_glob():
    with pytest.raises(ValueError):
        ProvenancePolicy(artifact_paths=["../outside/*.json"], field_paths=["tool_called"])

    with pytest.raises(ValueError):
        ProvenancePolicy(artifact_paths=["/etc/*.json"], field_paths=["tool_called"])


def test_unobserved_claim_is_finding_not_runtime_invocation():
    policy = ProvenancePolicy(artifact_paths=["outputs/*.json"], field_paths=["tool_called"])

    findings = validate_provenance_claims(
        policy,
        artifacts={"outputs/result.json": '{"tool_called": "search-accommodation"}'},
        ledger_entries=[],
    )

    assert [finding.finding_type for finding in findings] == ["coverage_gap", "unobserved_claim"]
    assert findings[-1].declared_label == "search-accommodation"
    assert findings[-1].matched_ledger_entry_ids == []
    assert findings[-1].artifact_path_hash.startswith("sha256:")
    assert findings[-1].finding_id.startswith("prov-")


def test_canonical_label_conflict_when_claim_uses_unapproved_runtime_alias():
    policy = ProvenancePolicy(artifact_paths=["outputs/*.json"], field_paths=["tool_called"])

    findings = validate_provenance_claims(
        policy,
        artifacts={"outputs/result.json": '{"tool_called": "search-accommodation"}'},
        ledger_entries=[
            {
                "event_id": "evt-1",
                "canonical_skill_id": "skill:search-accommodations",
                "canonical_name": "search-accommodations",
                "observed_name": "search-accommodation",
                "decision": "allow",
            }
        ],
    )

    assert [finding.finding_type for finding in findings] == ["canonical_label_conflict"]
    assert findings[0].declared_label == "search-accommodation"
    assert findings[0].matched_ledger_entry_ids == ["evt-1"]
    assert findings[0].artifact_path_hash.startswith("sha256:")


def test_registry_approved_alias_matches_ledger():
    policy = ProvenancePolicy(artifact_paths=["outputs/*.json"], field_paths=["tool_called"])

    findings = validate_provenance_claims(
        policy,
        artifacts={"outputs/result.json": '{"tool_called": "search_accommodation"}'},
        ledger_entries=[
            {
                "event_id": "evt-1",
                "canonical_skill_id": "skill:search-accommodation",
                "observed_name": "search-accommodation",
                "decision": "allow",
            }
        ],
        approved_aliases={
            "skill:search-accommodation": ["search_accommodation"],
        },
    )

    assert findings == []


@pytest.mark.parametrize(
    ("ledger_decision", "expected_type"),
    [
        ("block", "blocked_skill_claim"),
        ("defer", "deferred_skill_claim"),
    ],
)
def test_blocked_and_deferred_runtime_claims_are_post_action_findings(
    ledger_decision,
    expected_type,
):
    policy = ProvenancePolicy(artifact_paths=["outputs/*.json"], field_paths=["tool_called"])

    findings = validate_provenance_claims(
        policy,
        artifacts={"outputs/result.json": '{"tool_called": "danger-helper"}'},
        ledger_entries=[
            {
                "event_id": f"evt-{ledger_decision}",
                "canonical_skill_id": "skill:danger-helper",
                "canonical_name": "danger-helper",
                "observed_name": "danger-helper",
                "decision": ledger_decision,
            }
        ],
    )

    assert [finding.finding_type for finding in findings] == [expected_type]
    assert findings[0].severity == "high"
    assert findings[0].handling == policy.on_blocked_claim
    assert findings[0].matched_ledger_entry_ids == [f"evt-{ledger_decision}"]


def test_ambiguous_claim_when_label_matches_multiple_ledger_entries():
    policy = ProvenancePolicy(artifact_paths=["outputs/*.json"], field_paths=["tool_called"])

    findings = validate_provenance_claims(
        policy,
        artifacts={"outputs/result.json": '{"tool_called": "shared_alias"}'},
        ledger_entries=[
            {
                "event_id": "evt-1",
                "canonical_skill_id": "skill:first",
                "observed_name": "first",
                "decision": "allow",
            },
            {
                "event_id": "evt-2",
                "canonical_skill_id": "skill:second",
                "observed_name": "second",
                "decision": "allow",
            },
        ],
        approved_aliases={
            "skill:first": ["shared_alias"],
            "skill:second": ["shared_alias"],
        },
    )

    assert [finding.finding_type for finding in findings] == ["ambiguous_claim"]
    assert findings[0].declared_label == "shared_alias"
    assert findings[0].matched_ledger_entry_ids == ["evt-1", "evt-2"]


def test_singular_plural_decoy_label_is_ambiguous_without_unique_registry_alias():
    policy = ProvenancePolicy(artifact_paths=["outputs/*.json"], field_paths=["tool_called"])

    findings = validate_provenance_claims(
        policy,
        artifacts={"outputs/result.json": '{"tool_called": "search-accommodation"}'},
        ledger_entries=[
            {
                "event_id": "evt-plural",
                "canonical_skill_id": "skill:search-accommodations",
                "canonical_name": "search-accommodations",
                "observed_name": "search-accommodations",
                "decision": "allow",
            },
            {
                "event_id": "evt-singular",
                "canonical_skill_id": "skill:search-accommodation",
                "canonical_name": "search-accommodation",
                "observed_name": "search-accommodation",
                "decision": "allow",
            },
        ],
    )

    assert [finding.finding_type for finding in findings] == ["ambiguous_claim"]
    assert findings[0].matched_ledger_entry_ids == ["evt-plural", "evt-singular"]


def test_missing_and_non_string_configured_fields_are_coverage_findings():
    policy = ProvenancePolicy(
        artifact_paths=["outputs/*.json"],
        field_paths=["tool_called", "skills_used", "metadata.skill"],
    )

    findings = validate_provenance_claims(
        policy,
        artifacts={
            "outputs/result.json": (
                '{"skills_used": ["search-accommodation", 42], "metadata": {"skill": {"name": "tool"}}}'
            )
        },
        ledger_entries=[
            {
                "event_id": "evt-1",
                "canonical_skill_id": "skill:search-accommodation",
                "canonical_name": "search-accommodation",
                "observed_name": "search-accommodation",
                "decision": "allow",
            }
        ],
    )

    assert [finding.finding_type for finding in findings] == [
        "policy_not_applicable",
        "policy_not_applicable",
    ]
    assert [finding.handling for finding in findings] == ["missing_field", "non_string_label"]
    assert [finding.field_path for finding in findings] == ["tool_called", "metadata.skill"]


def test_collect_policy_artifacts_rejects_symlink_escape_and_caps_bytes(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    outputs = workspace / "outputs"
    outputs.mkdir()
    (outputs / "result.json").write_text('{"tool_called":"safe","padding":"abcdef"}', encoding="utf-8")
    outside = tmp_path / "outside.json"
    outside.write_text('{"tool_called":"outside"}', encoding="utf-8")
    (outputs / "escape.json").symlink_to(outside)
    policy = ProvenancePolicy(artifact_paths=["outputs/*.json"], field_paths=["tool_called"])

    artifacts, findings = collect_policy_artifacts(
        policy,
        workspace_root=workspace,
        max_artifact_bytes=24,
    )

    assert artifacts == {"outputs/result.json": '{"tool_called":"safe","p'}
    assert [finding.finding_type for finding in findings] == [
        "policy_not_applicable",
        "policy_not_applicable",
    ]
    assert {(finding.handling, finding.artifact_path) for finding in findings} == {
        ("unsafe_artifact_path", "outputs/escape.json"),
        ("artifact_too_large", "outputs/result.json"),
    }


def test_collect_policy_artifacts_reports_oversized_files(tmp_path):
    workspace = tmp_path / "workspace"
    output_dir = workspace / "outputs"
    output_dir.mkdir(parents=True)
    (output_dir / "large.json").write_text(
        '{"tool_called":"search-accommodation","padding":"abcdef"}',
        encoding="utf-8",
    )
    policy = ProvenancePolicy(artifact_paths=["outputs/*.json"], field_paths=["tool_called"])

    artifacts, findings = collect_policy_artifacts(
        policy,
        workspace_root=workspace,
        max_artifact_bytes=24,
    )

    assert artifacts["outputs/large.json"] == '{"tool_called":"search-a'
    assert [finding.finding_type for finding in findings] == ["policy_not_applicable"]
    assert findings[0].handling == "artifact_too_large"
    assert findings[0].artifact_path == "outputs/large.json"


def test_malformed_non_json_and_binary_artifacts_are_parse_findings(tmp_path):
    workspace = tmp_path / "workspace"
    outputs = workspace / "outputs"
    outputs.mkdir(parents=True)
    (outputs / "malformed.json").write_text('{"tool_called": ', encoding="utf-8")
    (outputs / "plain.json").write_text("tool_called=search-accommodation", encoding="utf-8")
    (outputs / "binary.json").write_bytes(b"\xff\x00\xfe\x01")
    policy = ProvenancePolicy(artifact_paths=["outputs/*.json"], field_paths=["tool_called"])

    artifacts, collect_findings = collect_policy_artifacts(
        policy,
        workspace_root=workspace,
        max_artifact_bytes=1024,
    )
    findings = validate_provenance_claims(policy, artifacts=artifacts, ledger_entries=[])

    assert collect_findings == []
    assert sorted(artifacts) == [
        "outputs/binary.json",
        "outputs/malformed.json",
        "outputs/plain.json",
    ]
    assert [finding.finding_type for finding in findings] == [
        "artifact_parse_error",
        "artifact_parse_error",
        "artifact_parse_error",
    ]
    assert {finding.handling for finding in findings} == {policy.on_parse_error}


@pytest.mark.asyncio
async def test_post_action_provenance_findings_do_not_rewrite_decision():
    class FakePostActionAnalyzer:
        def analyze(self, **kwargs):
            return PostActionFinding(
                tier=PostActionResponseTier.LOG_ONLY,
                patterns_matched=[],
                score=0.0,
            )

    gw = SupervisionGateway(
        detection_config=DetectionConfig(
            skill_trust_provenance_enabled=True,
            skill_trust_provenance_policy_json='{"artifact_paths":["*.json"],"field_paths":["tool_called"]}',
        )
    )
    gw.post_action_analyzer = FakePostActionAnalyzer()
    gw._skill_use_ledger_entries_for_session = lambda session_id: [
        {
            "event_id": "evt-runtime-1",
            "canonical_skill_id": "skill:search-accommodations",
            "observed_name": "search-accommodations",
            "decision": "allow",
        }
    ]

    await gw._run_post_action_async(
        output_text='{"tool_called": "search-accommodation"}',
        tool_name="write_file",
        event_id="evt-post-provenance",
        session_id="sess-post-provenance",
        source_framework="codex",
        content_origin=None,
        external_multiplier=1.0,
        finding_action="broadcast",
        occurred_at="2026-05-19T00:00:00+00:00",
        file_path="result.json",
    )

    scores = gw.report_session_post_action_scores("sess-post-provenance")
    assert scores["post_action_scores"][0]["tier"] == "log_only"
    findings = scores["post_action_scores"][0]["provenance_findings"]
    assert [finding["finding_type"] for finding in findings] == ["canonical_label_conflict"]
    assert gw.session_enforcement.get_status("sess-post-provenance")["state"] == "normal"


@pytest.mark.asyncio
async def test_post_action_provenance_uses_gateway_owned_aliases(tmp_path, monkeypatch):
    class FakePostActionAnalyzer:
        def analyze(self, **kwargs):
            return PostActionFinding(
                tier=PostActionResponseTier.LOG_ONLY,
                patterns_matched=[],
                score=0.0,
            )

    metadata_path = tmp_path / "skill-trust-runtime.json"
    metadata_path.write_text(
        json.dumps(
            {
                "framework": "codex",
                "metadata_records": [
                    {
                        "metadata_record_id": "sha256:" + "a" * 64,
                        "presented_name": "search-accommodations",
                        "canonical_skill_id": "skill:search-accommodations",
                        "canonical_name": "search-accommodations",
                        "aliases": ["search_accommodation"],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("CS_SKILL_TRUST_METADATA_PATH", str(metadata_path))
    gw = SupervisionGateway(
        detection_config=DetectionConfig(
            skill_trust_provenance_enabled=True,
            skill_trust_provenance_policy_json='{"artifact_paths":["*.json"],"field_paths":["tool_called"]}',
        )
    )
    gw.post_action_analyzer = FakePostActionAnalyzer()
    gw._skill_use_ledger_entries_for_session = lambda session_id: [
        {
            "event_id": "evt-runtime-1",
            "canonical_skill_id": "skill:search-accommodations",
            "canonical_name": "search-accommodations",
            "observed_name": "search-accommodations",
            "decision": "allow",
        }
    ]

    await gw._run_post_action_async(
        output_text='{"tool_called": "search_accommodation"}',
        tool_name="write_file",
        event_id="evt-post-alias-provenance",
        session_id="sess-post-alias-provenance",
        source_framework="codex",
        content_origin=None,
        external_multiplier=1.0,
        finding_action="broadcast",
        occurred_at="2026-05-19T00:00:00+00:00",
        file_path="result.json",
    )

    scores = gw.report_session_post_action_scores("sess-post-alias-provenance")
    assert scores["post_action_scores"][0]["provenance_findings"] == []


@pytest.mark.asyncio
async def test_post_action_provenance_redacts_absolute_output_path(tmp_path):
    class FakePostActionAnalyzer:
        def analyze(self, **kwargs):
            return PostActionFinding(
                tier=PostActionResponseTier.LOG_ONLY,
                patterns_matched=[],
                score=0.0,
            )

    gw = SupervisionGateway(
        detection_config=DetectionConfig(
            skill_trust_provenance_enabled=True,
            skill_trust_provenance_policy_json='{"artifact_paths":["*.json"],"field_paths":["tool_called"]}',
        )
    )
    gw.post_action_analyzer = FakePostActionAnalyzer()
    gw._skill_use_ledger_entries_for_session = lambda session_id: []

    await gw._run_post_action_async(
        output_text='{"tool_called": "search-accommodation"}',
        tool_name="write_file",
        event_id="evt-post-private-path",
        session_id="sess-post-private-path",
        source_framework="codex",
        content_origin=None,
        external_multiplier=1.0,
        finding_action="broadcast",
        occurred_at="2026-05-19T00:00:00+00:00",
        file_path=str(tmp_path / "private" / "output.json"),
    )

    scores = gw.report_session_post_action_scores("sess-post-private-path")
    findings = scores["post_action_scores"][0]["provenance_findings"]
    assert [finding["artifact_path"] for finding in findings] == ["output.json", "output.json"]
    assert str(tmp_path) not in json.dumps(findings)


@pytest.mark.asyncio
async def test_post_action_provenance_reads_configured_workspace_artifact(tmp_path, monkeypatch):
    class FakePostActionAnalyzer:
        def analyze(self, **kwargs):
            return PostActionFinding(
                tier=PostActionResponseTier.LOG_ONLY,
                patterns_matched=[],
                score=0.0,
            )

    workspace = tmp_path / "workspace"
    output_dir = workspace / "outputs"
    output_dir.mkdir(parents=True)
    (output_dir / "result.json").write_text(
        '{"tool_called":"search-accommodation"}',
        encoding="utf-8",
    )
    monkeypatch.chdir(workspace)
    gw = SupervisionGateway(
        detection_config=DetectionConfig(
            skill_trust_provenance_enabled=True,
            skill_trust_provenance_policy_json='{"artifact_paths":["outputs/*.json"],"field_paths":["tool_called"]}',
        )
    )
    gw.post_action_analyzer = FakePostActionAnalyzer()
    gw._skill_use_ledger_entries_for_session = lambda session_id: []

    await gw._run_post_action_async(
        output_text="",
        tool_name="write_file",
        event_id="evt-post-file-provenance",
        session_id="sess-post-file-provenance",
        source_framework="codex",
        content_origin=None,
        external_multiplier=1.0,
        finding_action="broadcast",
        occurred_at="2026-05-19T00:00:00+00:00",
        file_path="outputs/result.json",
    )

    scores = gw.report_session_post_action_scores("sess-post-file-provenance")
    findings = scores["post_action_scores"][0]["provenance_findings"]
    assert [finding["finding_type"] for finding in findings] == ["coverage_gap", "unobserved_claim"]
    assert findings[-1]["artifact_path"] == "outputs/result.json"


@pytest.mark.asyncio
async def test_post_action_provenance_uses_configured_workspace_root(tmp_path, monkeypatch):
    class FakePostActionAnalyzer:
        def analyze(self, **kwargs):
            return PostActionFinding(
                tier=PostActionResponseTier.LOG_ONLY,
                patterns_matched=[],
                score=0.0,
            )

    workspace = tmp_path / "configured-workspace"
    output_dir = workspace / "outputs"
    output_dir.mkdir(parents=True)
    (output_dir / "result.json").write_text(
        '{"tool_called":"search-accommodation"}',
        encoding="utf-8",
    )
    other_cwd = tmp_path / "other-cwd"
    other_cwd.mkdir()
    monkeypatch.chdir(other_cwd)
    gw = SupervisionGateway(
        detection_config=DetectionConfig(
            skill_trust_provenance_enabled=True,
            skill_trust_provenance_policy_json='{"artifact_paths":["outputs/*.json"],"field_paths":["tool_called"]}',
            skill_trust_provenance_workspace_root=str(workspace),
        )
    )
    gw.post_action_analyzer = FakePostActionAnalyzer()
    gw._skill_use_ledger_entries_for_session = lambda session_id: []

    await gw._run_post_action_async(
        output_text="",
        tool_name="write_file",
        event_id="evt-post-configured-workspace",
        session_id="sess-post-configured-workspace",
        source_framework="codex",
        content_origin=None,
        external_multiplier=1.0,
        finding_action="broadcast",
        occurred_at="2026-05-19T00:00:00+00:00",
        file_path="outputs/result.json",
    )

    scores = gw.report_session_post_action_scores("sess-post-configured-workspace")
    findings = scores["post_action_scores"][0]["provenance_findings"]
    assert [finding["finding_type"] for finding in findings] == ["coverage_gap", "unobserved_claim"]
    assert findings[-1]["artifact_path"] == "outputs/result.json"
