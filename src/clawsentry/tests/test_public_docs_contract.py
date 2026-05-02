"""Contract tests for public docs and release guardrails."""

from __future__ import annotations

import json
import re
from pathlib import Path



REPO_ROOT = Path(__file__).resolve().parents[3]
ROOT_README = REPO_ROOT / "README.md"
PROJECT_STATUS = REPO_ROOT / "docs" / "PROJECT_STATUS.md"
PYPROJECT = REPO_ROOT / "pyproject.toml"
PACKAGE_INIT = REPO_ROOT / "src" / "clawsentry" / "__init__.py"
ENV_VARS_DOC = REPO_ROOT / "site-docs" / "configuration" / "env-vars.md"
RELEASE_CHECKLIST = REPO_ROOT / "docs" / "management" / "RELEASE_CHECKLIST.md"
RULES_CI_EXAMPLE = REPO_ROOT / "examples" / "ci" / "rules-governance.yml"
PACKAGE_README = REPO_ROOT / "src" / "clawsentry" / "README.md"
PUBLIC_README = REPO_ROOT / "README_PUBLIC.md"
METRIC_DICTIONARY = REPO_ROOT / "site-docs" / "api" / "metric-dictionary.md"
OPENAPI_JSON = REPO_ROOT / "site-docs" / "api" / "openapi.json"


def _extract(pattern: str, source: str) -> str:
    match = re.search(pattern, source, flags=re.MULTILINE)
    assert match is not None
    return match.group(1)


def _read_doc(relative_path: str) -> str:
    return (REPO_ROOT / relative_path).read_text(encoding="utf-8")


def _openapi_operation(path: str, method: str) -> dict:
    openapi = json.loads(OPENAPI_JSON.read_text(encoding="utf-8"))
    return openapi["paths"][path][method.lower()]


def test_workspace_readme_status_and_package_versions_stay_aligned() -> None:
    pyproject = PYPROJECT.read_text(encoding="utf-8")
    package_init = PACKAGE_INIT.read_text(encoding="utf-8")
    readme = ROOT_README.read_text(encoding="utf-8")
    project_status = (
        PROJECT_STATUS.read_text(encoding="utf-8") if PROJECT_STATUS.exists() else ""
    )

    package_version = _extract(r'^version = "([^"]+)"$', pyproject)
    init_version = _extract(r'^__version__ = "([^"]+)"$', package_init)

    assert init_version == package_version
    if project_status:
        assert f"workspace baseline: v{package_version}" in readme
        if "local prep" in readme:
            assert "latest public PyPI/docs live for v" in readme
            assert f"**Next local version**: `v{package_version}`" in project_status
        else:
            assert f"public PyPI/docs live for v{package_version}" in readme
            assert f"**Released baseline**: `v{package_version}`" in project_status
    else:
        assert f"What's New in v{package_version}" in readme


def test_env_vars_doc_mentions_public_l3_trigger_controls() -> None:
    source = ENV_VARS_DOC.read_text(encoding="utf-8")

    assert "CS_L3_ROUTING_MODE" in source
    assert "CS_L3_TRIGGER_PROFILE" in source
    assert "CS_L3_BUDGET_TUNING_ENABLED" in source


def test_release_checklist_requires_public_surface_verification() -> None:
    if not RELEASE_CHECKLIST.exists():
        assert not (REPO_ROOT / "docs" / "management").exists()
        return

    source = RELEASE_CHECKLIST.read_text(encoding="utf-8")

    assert "pypi.org/project/clawsentry/" in source
    assert "elroyper.github.io/ClawSentry/" in source
    assert "configuration/env-vars/" in source


def test_rules_governance_ci_example_publishes_report_artifact() -> None:
    source = RULES_CI_EXAMPLE.read_text(encoding="utf-8")

    assert "python -m clawsentry rules lint --json" in source
    assert "python -m clawsentry rules dry-run --events examples/sample-events.jsonl --json" in source
    assert (
        "python -m clawsentry rules report --output artifacts/rules-report.json "
        "--events examples/sample-events.jsonl "
        "--summary-markdown artifacts/rules-dashboard.md --json"
    ) in source
    assert "actions/upload-artifact" in source
    assert "artifacts/rules-report.json" in source
    assert "artifacts/rules-dashboard.md" in source
    assert "retention-days: 30" in source


def test_sample_events_cover_representative_rule_governance_cases() -> None:
    sample_events = [
        json.loads(line)
        for line in (REPO_ROOT / "examples" / "sample-events.jsonl")
        .read_text(encoding="utf-8")
        .splitlines()
        if line.strip()
    ]

    assert [event["event_id"] for event in sample_events] == [
        "sample-safe-read",
        "sample-credential-upload",
        "sample-download-execute",
    ]
    assert sample_events[0]["tool_name"] == "list_directory"
    assert sample_events[0]["risk_hints"] == []
    assert "curl -F file=@" in sample_events[1]["payload"]["command"]
    assert "| bash" in sample_events[2]["payload"]["command"]


def test_codex_docs_describe_optional_native_hook_setup() -> None:
    codex_doc = (REPO_ROOT / "site-docs" / "integration" / "codex.md").read_text(
        encoding="utf-8"
    )
    cli_doc = (REPO_ROOT / "site-docs" / "cli" / "index.md").read_text(
        encoding="utf-8"
    )

    assert "clawsentry init codex --setup" in codex_doc
    assert ".codex/hooks.json" in codex_doc
    assert "PreToolUse(Bash)" in codex_doc
    assert "permissionDecision: \"deny\"" in codex_doc
    assert "--codex-home PATH" in cli_doc


def test_web_ui_auth_docs_align_token_source_proxy_and_paths() -> None:
    quickstart = (REPO_ROOT / "site-docs" / "getting-started" / "quickstart.md").read_text(
        encoding="utf-8"
    )
    dashboard = (REPO_ROOT / "site-docs" / "dashboard" / "index.md").read_text(
        encoding="utf-8"
    )
    cli_doc = (REPO_ROOT / "site-docs" / "cli" / "index.md").read_text(
        encoding="utf-8"
    )
    installation = (
        REPO_ROOT / "site-docs" / "getting-started" / "installation.md"
    ).read_text(encoding="utf-8")
    troubleshooting = (
        REPO_ROOT / "site-docs" / "operations" / "troubleshooting.md"
    ).read_text(encoding="utf-8")

    combined = "\n".join([quickstart, dashboard, cli_doc, installation, troubleshooting])
    assert "clawsentry start" in combined
    assert "CS_AUTH_TOKEN" in combined
    assert "?token=" in combined
    assert "sessionStorage" in combined
    assert "401" in combined
    assert "Gateway" in combined and "unavailable" in combined
    assert "NO_PROXY=localhost,127.0.0.1,::1" in combined
    assert "Vite" in combined and "/ui/" in combined
    assert "https://elroyper.github.io/ClawSentry/" in combined
    assert "mkdocs serve" in combined
    assert "stale global" in combined
    assert "pip install -e" in combined


def test_public_docs_explain_high_friction_terms_and_low_risk_smoke_path() -> None:
    concepts = (REPO_ROOT / "site-docs" / "getting-started" / "concepts.md").read_text(
        encoding="utf-8"
    )
    dashboard = (REPO_ROOT / "site-docs" / "dashboard" / "index.md").read_text(
        encoding="utf-8"
    )
    browser_validation_path = (
        REPO_ROOT / "docs" / "operations" / "2026-04-10-clawsentry-p2-browser-validation.md"
    )
    browser_validation = (
        browser_validation_path.read_text(encoding="utf-8")
        if browser_validation_path.exists()
        else ""
    )

    for term in [
        "DEFER",
        "L3 advisory",
        "advisory-only",
        "toolkit evidence budget",
        "framework",
        "workspace",
        "session",
    ]:
        assert term in concepts

    assert "Cumulative trajectory records" in dashboard
    assert "Live Events" not in dashboard
    assert "remote Google Fonts" in dashboard
    assert "system-font fallback" in dashboard
    if browser_validation_path.exists():
        assert "no new dependency" in browser_validation
        assert "ui_validation_fixture" in browser_validation
    else:
        assert not (REPO_ROOT / "docs" / "operations").exists()


def test_public_readmes_share_web_ui_auth_story() -> None:
    root_public = (PUBLIC_README if PUBLIC_README.exists() else ROOT_README).read_text(encoding="utf-8")
    package_readme = PACKAGE_README.read_text(encoding="utf-8")

    for source in [root_public, package_readme]:
        assert "Web UI" in source
        assert "?token=" in source
        assert "CS_AUTH_TOKEN" in source
        assert "invalid token" in source.lower()
        assert "Gateway unavailable" in source
        assert "NO_PROXY=localhost,127.0.0.1,::1" in source


def test_recent_user_facing_features_have_online_docs_journey_anchors() -> None:
    """Recent release features should stay discoverable as user journeys."""

    docs = {
        "l3": _read_doc("site-docs/decision-layers/l3-advisory.md"),
        "api_decisions": _read_doc("site-docs/api/decisions.md"),
        "api_reporting": _read_doc("site-docs/api/reporting.md"),
        "quickstart": _read_doc("site-docs/getting-started/quickstart.md"),
        "installation": _read_doc("site-docs/getting-started/installation.md"),
        "rules": _read_doc("site-docs/advanced/rule-governance.md"),
        "codex": _read_doc("site-docs/integration/codex.md"),
        "api_overview": _read_doc("site-docs/api/overview.md"),
    }

    l3_required = [
        "heartbeat_aggregate",
        "clawsentry l3 jobs list",
        "clawsentry l3 jobs run-next",
        "clawsentry l3 jobs drain",
        "advisory_only=true",
        "canonical_decision_mutated=false",
        "l3_advisory_provider_smoke",
        "--require-completed",
    ]
    for term in l3_required:
        assert term in docs["l3"]

    decision_effect_terms = [
        "decision_effects",
        "adapter_effect_result",
        "modified_payload",
        "rewrite_effect",
        "mark_blocked",
        "GET /report/session/{session_id}/quarantine",
        "POST /ahp/adapter-effect-result",
        "degrade_reason",
    ]
    combined_decision_docs = docs["api_decisions"] + "\n" + docs["api_reporting"]
    for term in decision_effect_terms:
        assert term in combined_decision_docs

    first_run_docs = docs["quickstart"] + "\n" + docs["installation"]
    for term in ["invalid token", "Gateway unavailable", "NO_PROXY", "stale global"]:
        assert term in first_run_docs

    rules_terms = [
        "clawsentry rules report",
        "--summary-markdown",
        "artifacts/rules-dashboard.md",
        "examples/sample-events.jsonl",
        "Policy-change review checklist",
    ]
    for term in rules_terms:
        assert term in docs["rules"]

    codex_terms = [
        "clawsentry init codex --setup",
        "PreToolUse(Bash)",
        "PostToolUse(Bash): async",
        "Gateway 不可达",
        "clawsentry doctor",
    ]
    for term in codex_terms:
        assert term in docs["codex"]

    api_validity_terms = [
        "api-validity.json",
        "validity-report.md",
        "python scripts/docs_api_inventory.py validate",
    ]
    for term in api_validity_terms:
        assert term in docs["api_overview"]


def test_metric_dictionary_has_single_clear_canonical_section() -> None:
    source = METRIC_DICTIONARY.read_text(encoding="utf-8")

    assert source.count("## 核心字段解释") == 1
    assert source.count("## D1-D6 风险维度") == 1
    assert source.count("## `window_risk_summary` 最低字段集") == 1
    assert "## 核心指标解释" not in source
    assert "composite_score_sum" not in source
    assert "high_risk_event_count" not in source

    for field in [
        "latest_composite_score",
        "session_risk_sum",
        "session_risk_ewma",
        "post_action_score_ewma",
        "latest_post_action_score",
        "risk_points_sum",
        "risk_velocity",
        "window_risk_summary",
        "post_action_score_summary",
        "score_semantics",
        "system_security_posture",
    ]:
        assert field in source

    reporting_source = (REPO_ROOT / "site-docs" / "api" / "reporting.md").read_text(encoding="utf-8")
    assert "GET /report/session/{id}/post-action" in reporting_source
    assert "post_action_score_ewma" in reporting_source
    assert "no_data_not_confirmed_low_risk" in reporting_source


def test_report_openapi_examples_match_current_runtime_payloads() -> None:
    risk_example = _openapi_operation(
        "/report/session/{session_id}/risk", "GET"
    )["responses"]["200"]["content"]["application/json"]["example"]
    post_action_example = _openapi_operation(
        "/report/session/{session_id}/post-action", "GET"
    )["responses"]["200"]["content"]["application/json"]["example"]
    sessions_example = _openapi_operation(
        "/report/sessions", "GET"
    )["responses"]["200"]["content"]["application/json"]["example"]

    assert "session_risk_ewma" in risk_example
    assert "window_risk_summary" in risk_example
    assert "critical_event_count" not in risk_example["window_risk_summary"]
    assert "decision_path_io" in risk_example

    assert "post_action_score_summary" in post_action_example
    assert "decision_path_io" in post_action_example
    assert post_action_example["score_range"] == [0.0, 3.0]

    assert "total_active" in sessions_example
    assert "total" not in sessions_example
    assert sessions_example["sessions"][0]["score_range"] == [0.0, 3.0]
    assert "score_semantics" in sessions_example["sessions"][0]


def test_report_openapi_query_params_match_source_routes() -> None:
    def param_names(path: str) -> set[str]:
        return {
            param["name"]
            for param in _openapi_operation(path, "GET").get("parameters", [])
            if param.get("in") == "query"
        }

    assert param_names("/report/sessions") == {
        "status",
        "sort",
        "limit",
        "min_risk",
        "window_seconds",
    }
    assert param_names("/report/session/{session_id}/risk") == {
        "limit",
        "window_seconds",
    }
    assert param_names("/report/session/{session_id}/post-action") == {
        "limit",
        "window_seconds",
    }
    assert param_names("/report/stream") == {
        "session_id",
        "min_risk",
        "types",
        "token",
    }


def test_enterprise_sessions_openapi_documents_5000_limit() -> None:
    operation = _openapi_operation("/enterprise/report/sessions", "GET")
    limit_param = next(
        param for param in operation["parameters"]
        if param.get("in") == "query" and param["name"] == "limit"
    )

    assert limit_param["schema"]["maximum"] == 5000


def test_report_docs_do_not_publish_stale_window_or_score_contracts() -> None:
    reporting = _read_doc("site-docs/api/reporting.md")
    metric_dictionary = _read_doc("site-docs/api/metric-dictionary.md")
    openapi_text = OPENAPI_JSON.read_text(encoding="utf-8")

    assert "critical_event_count" not in reporting
    assert "critical_event_count" not in metric_dictionary
    assert "critical_event_count" not in openapi_text
    assert "检测评分（0.0-3.0）" in reporting
    assert "检测评分（0.0-1.0）" not in reporting
    post_action_section = reporting.split(
        "## GET /report/session/{id}/post-action", 1
    )[1].split("## GET /report/session/{id}/enforcement", 1)[0]
    assert "decision_path_io" in post_action_section

def test_clawsentry_config_docs_use_dotenv_templates_not_section_configs() -> None:
    """User-facing ClawSentry config docs must match the env-file parser."""

    docs = [
        REPO_ROOT / "site-docs" / "configuration" / "configuration-overview.md",
        REPO_ROOT / "site-docs" / "configuration" / "templates.md",
        REPO_ROOT / "site-docs" / "configuration" / "detection-config.md",
        REPO_ROOT / "site-docs" / "configuration" / "env-vars.md",
        REPO_ROOT / "site-docs" / "getting-started" / "quickstart.md",
        REPO_ROOT / "site-docs" / "cli" / "index.md",
        REPO_ROOT / "site-docs" / "integration" / "claude-code.md",
        REPO_ROOT / "site-docs" / "integration" / "openclaw.md",
    ]
    combined = "\n".join(path.read_text(encoding="utf-8") for path in docs)

    stale_terms = [
        "```env-template",
        ".clawsentry.env.example [frameworks]",
        "唯一会自动发现",
        "唯一自动发现",
        "自动发现的项目配置",
        "读取或生成 `.clawsentry.env.example`",
        "生成/合并 **`.clawsentry.env.example`**",
        "只会生成或合并项目 `.clawsentry.env.example`",
        "--include-secret-sources",
        "ProjectConfig dataclass + .clawsentry.env.example 加载",
        "pyproject.env-template",
        "config.env-template",
        "env-templatelib",
    ]
    for term in stale_terms:
        assert term not in combined

    # The copy-paste template page should be dotenv, with reusable feature blocks.
    templates = (REPO_ROOT / "site-docs" / "configuration" / "templates.md").read_text(
        encoding="utf-8"
    )
    for term in [
        "CS_ANTI_BYPASS_GUARD_ENABLED=true",
        "CS_ANTI_BYPASS_EXACT_REPEAT_ACTION=block",
        "CS_DEFER_BRIDGE_ENABLED=true",
        "CS_POST_ACTION_FINDING_ACTION=broadcast",
        "CS_MODE=benchmark",
    ]:
        assert term in templates

    overview = (
        REPO_ROOT / "site-docs" / "configuration" / "configuration-overview.md"
    ).read_text(encoding="utf-8")
    assert ".clawsentry.env.example` 是可提交的 dotenv 模板，正常启动不会读取它" in overview
    assert "cp .clawsentry.env.example .clawsentry.env.local" in overview


def test_release_docs_use_real_toml_paths_and_current_public_status() -> None:
    pyproject = PYPROJECT.read_text(encoding="utf-8")
    package_version = _extract(r'^version = "([^"]+)"$', pyproject)
    release_doc_paths = [
        REPO_ROOT / "README.md",
        REPO_ROOT / "CHANGELOG.md",
        REPO_ROOT / "docs" / "validation" / "v0.6.4-env-file-hints-release-2026-04-30.md",
        REPO_ROOT / "docs" / "validation" / "v0.6.3-env-first-config-docs-release-2026-04-30.md",
        REPO_ROOT / "docs" / "management" / "RELEASE_CHECKLIST.md",
        REPO_ROOT / "docs" / "management" / "REPO_WORKFLOW.md",
    ]
    release_docs = "\n".join(
        path.read_text(encoding="utf-8") for path in release_doc_paths if path.exists()
    )

    if (REPO_ROOT / "docs" / "management").exists():
        assert (
            f"workspace baseline: v{package_version} released" in release_docs
            or f"workspace baseline: v{package_version} local prep" in release_docs
        )
    else:
        assert f"What's New in v{package_version}" in release_docs
    assert package_version in release_docs
    assert f"https://github.com/Elroyper/ClawSentry/releases/tag/v{package_version}" in release_docs
    assert "https://pypi.org/project/clawsentry/" in release_docs
    assert "pyproject.env-template" not in release_docs
    assert "config.env-template" not in release_docs
    assert "pyproject.toml" in release_docs
