"""Contract tests for the public docs API reference artifacts."""
from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
COVERAGE_FILE = REPO_ROOT / "site-docs" / "api" / "api-coverage.json"
OPENAPI_FILE = REPO_ROOT / "site-docs" / "api" / "openapi.json"
VALIDITY_JSON_FILE = REPO_ROOT / "site-docs" / "api" / "api-validity.json"
VALIDITY_REPORT_PAGE = REPO_ROOT / "site-docs" / "api" / "validity-report.md"
REFERENCE_PAGE = REPO_ROOT / "site-docs" / "api" / "reference.md"
INVENTORY_SCRIPT = REPO_ROOT / "scripts" / "docs_api_inventory.py"


def _coverage() -> list[dict]:
    return json.loads(COVERAGE_FILE.read_text(encoding="utf-8"))


def test_docs_api_inventory_script_validates_generated_artifacts() -> None:
    result = subprocess.run(
        [sys.executable, str(INVENTORY_SCRIPT), "validate"],
        cwd=REPO_ROOT,
        text=True,
        capture_output=True,
        check=True,
    )
    assert "valid" in result.stdout


def test_api_validity_report_command_generates_traceable_outputs(tmp_path: Path) -> None:
    output_dir = tmp_path / "reports"
    docs_output = tmp_path / "api"
    result = subprocess.run(
        [
            sys.executable,
            str(INVENTORY_SCRIPT),
            "report",
            "--output-dir",
            str(output_dir),
            "--docs-output",
            str(docs_output),
            "--timestamp",
            "pytest",
        ],
        cwd=REPO_ROOT,
        text=True,
        capture_output=True,
        check=True,
    )
    assert "API validity report is valid" in result.stdout

    json_report = output_dir / "clawsentry-api-validity-pytest.json"
    md_report = output_dir / "clawsentry-api-validity-pytest.md"
    docs_json = docs_output / "api-validity.json"
    docs_md = docs_output / "validity-report.md"
    for path in [json_report, md_report, docs_json, docs_md]:
        assert path.exists(), path

    report = json.loads(docs_json.read_text(encoding="utf-8"))
    assert report["schema_version"] == "clawsentry-api-validity.v1"
    assert report["summary"]["valid"] is True
    assert report["summary"]["total_coverage_entries"] == 54
    assert report["summary"]["openapi_operations"] == 51
    assert report["summary"]["docs_endpoint_mentions_unmatched"] == 0
    assert report["docs_reverse_validation"]["rules"]
    assert not report["validation_errors"]

    for endpoint in report["endpoints"]:
        assert endpoint["source_line_valid"], endpoint
        assert endpoint["source_route_present"], endpoint
        assert endpoint["markdown_anchor_present"], endpoint
        assert endpoint["runtime_check_result"] in {"contract-verified", "excluded-from-reference"}
    assert any(
        mention["rule"] == "group-alias:/report/*"
        for mention in report["docs_reverse_validation"]["matched"]
    )
    assert any(
        mention["rule"] == "endpoint-alias"
        for mention in report["docs_reverse_validation"]["matched"]
    )


def test_deployable_api_validity_report_is_current_and_traceable() -> None:
    assert VALIDITY_JSON_FILE.exists()
    assert VALIDITY_REPORT_PAGE.exists()
    report = json.loads(VALIDITY_JSON_FILE.read_text(encoding="utf-8"))
    assert report["summary"]["valid"] is True
    assert report["source_artifacts"]["coverage"] == "site-docs/api/api-coverage.json"
    assert report["summary"]["status_counts"] == {"enterprise": 10, "excluded": 3, "public": 41}
    report_page = VALIDITY_REPORT_PAGE.read_text(encoding="utf-8")
    assert "API 维护说明" in report_page
    assert "python scripts/docs_api_inventory.py validate" in report_page
    assert "src/clawsentry/gateway/server.py:" not in report_page


def test_api_coverage_matrix_has_semantic_fields_and_unique_routes() -> None:
    assert COVERAGE_FILE.exists()
    coverage = _coverage()
    assert coverage

    keys = [(entry["service"], entry["method"], entry["path"]) for entry in coverage]
    assert len(keys) == len(set(keys))

    required_fields = {
        "service",
        "method",
        "path",
        "source",
        "group",
        "audience",
        "public_status",
        "auth",
        "auth_note",
        "request_example",
        "response_example",
        "errors",
        "openapi_ref",
        "markdown_ref",
        "exclusion_reason",
    }
    allowed_status = {"public", "enterprise", "conditional", "internal", "excluded"}
    allowed_methods = {"GET", "POST", "PATCH", "PUT", "DELETE"}

    for entry in coverage:
        assert required_fields <= entry.keys(), entry
        assert entry["method"] in allowed_methods
        assert entry["path"].startswith("/")
        assert entry["public_status"] in allowed_status
        assert entry["source"].startswith("src/clawsentry/")
        assert entry["auth_note"]
        if entry["public_status"] in {"public", "enterprise", "conditional"}:
            assert entry["group"]
            assert any(part in {"user", "developer", "operator"} for part in entry["audience"].split("|"))
            assert entry["response_example"]
            assert "see Markdown page for full payload" not in json.dumps(entry.get("request_example"), ensure_ascii=False)
            assert "see Markdown page for full payload" not in json.dumps(entry.get("response_example"), ensure_ascii=False)
            assert isinstance(entry["errors"], list) and entry["errors"]
            assert all(re.fullmatch(r"[1-5][0-9][0-9]", str(code)) for code in entry["errors"])
            assert str(entry["openapi_ref"]).startswith("#/paths/")
            assert entry["markdown_ref"].startswith("api/") or entry["markdown_ref"].startswith("dashboard/")
        else:
            assert entry["exclusion_reason"]


def test_api_coverage_covers_gateway_stack_and_webhook_surfaces() -> None:
    by_key = {(entry["service"], entry["method"], entry["path"]): entry for entry in _coverage()}

    required = {
        ("gateway", "POST", "/ahp"),
        ("gateway", "POST", "/ahp/a3s"),
        ("gateway", "POST", "/ahp/codex"),
        ("stack", "POST", "/ahp/resolve"),
        ("gateway", "GET", "/health"),
        ("gateway", "GET", "/metrics"),
        ("gateway", "GET", "/report/summary"),
        ("gateway", "GET", "/report/stream"),
        ("gateway", "GET", "/report/sessions"),
        ("gateway", "GET", "/report/session/{session_id}"),
        ("gateway", "GET", "/report/session/{session_id}/page"),
        ("gateway", "GET", "/report/session/{session_id}/risk"),
        ("gateway", "POST", "/report/session/{session_id}/l3-advisory/snapshots"),
        ("gateway", "GET", "/report/session/{session_id}/l3-advisory/snapshots"),
        ("gateway", "GET", "/report/l3-advisory/snapshot/{snapshot_id}"),
        ("gateway", "POST", "/report/l3-advisory/snapshot/{snapshot_id}/jobs"),
        ("gateway", "POST", "/report/l3-advisory/reviews"),
        ("gateway", "PATCH", "/report/l3-advisory/review/{review_id}"),
        ("gateway", "POST", "/report/l3-advisory/snapshot/{snapshot_id}/run-local-review"),
        ("gateway", "POST", "/report/l3-advisory/job/{job_id}/run-local"),
        ("gateway", "POST", "/report/l3-advisory/job/{job_id}/run-worker"),
        ("gateway", "POST", "/report/session/{session_id}/l3-advisory/full-review"),
        ("gateway", "GET", "/report/alerts"),
        ("gateway", "POST", "/report/alerts/{alert_id}/acknowledge"),
        ("gateway", "GET", "/report/session/{session_id}/enforcement"),
        ("gateway", "POST", "/report/session/{session_id}/enforcement"),
        ("gateway", "GET", "/ahp/patterns"),
        ("gateway", "POST", "/ahp/patterns/confirm"),
        ("gateway-enterprise", "GET", "/enterprise/health"),
        ("gateway-ui", "GET", "/ui"),
        ("gateway-ui", "GET", "/ui/{path:path}"),
        ("openclaw-webhook", "POST", "/webhook/openclaw"),
        ("openclaw-webhook", "GET", "/health"),
    }
    assert required <= set(by_key)

    assert by_key[("gateway", "GET", "/health")]["auth"] == "none"
    assert by_key[("gateway", "GET", "/metrics")]["auth"] == "metrics-conditional"
    assert by_key[("stack", "POST", "/ahp/resolve")]["auth"] == "bearer-disabled-when-empty-token"
    assert "CS_AUTH_TOKEN" in by_key[("gateway", "POST", "/ahp")]["auth_note"]

    webhook = by_key[("openclaw-webhook", "POST", "/webhook/openclaw")]
    assert "webhook" in webhook["auth"]
    assert "hmac" in webhook["auth_note"].lower()
    assert "timestamp" in webhook["auth_note"].lower()
    assert "idempot" in webhook["auth_note"].lower()
    assert set(webhook["errors"]) >= {"400", "401", "403", "409", "413", "415", "422", "500"}
    assert webhook["request_example"].get("idempotencyKey")
    assert webhook["request_example"].get("type") != "see Markdown page for full payload"

    assert by_key[("gateway-enterprise", "GET", "/enterprise/health")]["public_status"] == "enterprise"
    assert by_key[("gateway-ui", "GET", "/ui")]["public_status"] == "excluded"


def test_api_coverage_markdown_references_exist() -> None:
    for entry in _coverage():
        markdown_ref = entry["markdown_ref"]
        page, _, anchor = markdown_ref.partition("#")
        page_path = REPO_ROOT / "site-docs" / page
        assert page_path.exists(), entry
        if anchor and page_path.suffix == ".md":
            text = page_path.read_text(encoding="utf-8")
            assert f"{{#{anchor}}}" in text, entry


def test_openapi_artifact_matches_public_coverage_entries() -> None:
    assert OPENAPI_FILE.exists()
    spec = json.loads(OPENAPI_FILE.read_text(encoding="utf-8"))
    assert spec["openapi"].startswith("3.")
    assert spec["info"]["title"]
    assert spec["paths"]

    for entry in _coverage():
        if entry["public_status"] == "excluded":
            continue
        operation = spec["paths"].get(entry["path"], {}).get(entry["method"].lower())
        assert operation is not None, entry
        assert operation.get("tags")
        assert operation.get("responses")
        assert any(code in operation["responses"] for code in entry["errors"]), entry
        if entry["service"] == "openclaw-webhook" and entry["path"] == "/webhook/openclaw":
            assert set(entry["errors"]) <= set(operation["responses"])
            headers = {param["name"] for param in operation.get("parameters", []) if param.get("in") == "header"}
            assert {"Authorization", "X-AHP-Signature", "X-AHP-Timestamp", "Content-Type"} <= headers
            body = operation.get("requestBody", {}).get("content", {}).get("application/json", {}).get("example", {})
            assert body.get("idempotencyKey")
            assert operation.get("requestBody", {}).get("required") is True
            assert operation.get("security") == [{"BearerAuth": []}]


def test_codex_public_docs_use_http_event_type_contract() -> None:
    spec = json.loads(OPENAPI_FILE.read_text(encoding="utf-8"))
    operation = spec["paths"]["/ahp/codex"]["post"]
    body = operation["requestBody"]["content"]["application/json"]["example"]

    assert body["event_type"] == "function_call"
    assert "hook_type" not in body
    assert "hook_event_name" not in body
    assert isinstance(body["payload"], dict)
    response = operation["responses"]["200"]["content"]["application/json"]["example"]
    assert response["result"]["action"] in {"allow", "block", "continue", "defer"}
    assert "permissionDecision" not in response

    coverage = {
        (entry["service"], entry["method"], entry["path"]): entry
        for entry in _coverage()
    }
    coverage_body = coverage[("gateway", "POST", "/ahp/codex")]["request_example"]
    assert coverage_body == body
    coverage_response = coverage[("gateway", "POST", "/ahp/codex")]["response_example"]
    assert coverage_response == response

    decisions = (REPO_ROOT / "site-docs" / "api" / "decisions.md").read_text(encoding="utf-8")
    section = decisions.split("## POST /ahp/codex", 1)[1].split("\n---", 1)[0]
    assert '"event_type": "function_call"' in section
    assert '"result": {' in section
    assert '"hook_type": "function_call"' not in section
    assert '"hook_event_name": "PreToolUse"' not in section


def test_openapi_info_version_matches_package_version() -> None:
    spec = json.loads(OPENAPI_FILE.read_text(encoding="utf-8"))
    pyproject = (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    expected = re.search(r'^version = "([^"]+)"$', pyproject, re.MULTILINE)
    assert expected is not None
    assert spec["info"]["version"] == expected.group(1)


def test_report_session_risk_ewma_is_declared_in_openapi_response_schemas() -> None:
    spec = json.loads(OPENAPI_FILE.read_text(encoding="utf-8"))

    def response_schema(path: str) -> dict:
        content = (
            spec["paths"][path]["get"]["responses"]["200"]["content"]["application/json"]
        )
        assert "example" in content, path
        assert "schema" in content, path
        return content["schema"]

    sessions_paths = [
        "/report/sessions",
        "/enterprise/report/sessions",
    ]
    risk_paths = [
        "/report/session/{session_id}/risk",
        "/enterprise/report/session/{session_id}/risk",
    ]

    for path in sessions_paths:
        session_schema = response_schema(path)["properties"]["sessions"]["items"]
        field = session_schema["properties"]["session_risk_ewma"]
        assert field["type"] == "number"
        assert field["minimum"] == 0.0
        assert field["maximum"] == 3.0
        assert "alpha=0.3" in field["description"]
        assert "no_data_not_confirmed_low_risk" in field["description"]
        assert "decision-affecting" in field["description"]

    for path in risk_paths:
        field = response_schema(path)["properties"]["session_risk_ewma"]
        assert field["type"] == "number"
        assert field["minimum"] == 0.0
        assert field["maximum"] == 3.0
        assert "alpha=0.3" in field["description"]
        assert "no_data_not_confirmed_low_risk" in field["description"]
        assert "decision-affecting" in field["description"]

    public_window = (
        response_schema("/report/session/{session_id}/risk")["properties"]["window_risk_summary"]
        ["properties"]
    )
    assert "session_risk_ewma" in public_window
    assert "high_or_critical_count" in public_window
    assert "high_risk_event_count" not in public_window


def test_api_reference_page_is_in_nav_and_has_raw_openapi_fallback() -> None:
    reference_text = REFERENCE_PAGE.read_text(encoding="utf-8")
    mkdocs_text = (REPO_ROOT / "mkdocs.yml").read_text(encoding="utf-8")

    assert "api/reference.md" in mkdocs_text
    assert "交互式 API Reference" in mkdocs_text
    assert "api/validity-report.md" not in mkdocs_text
    assert "API 有效性报告" not in mkdocs_text
    assert "openapi.json" in reference_text
    assert "Scalar" in reference_text or "scalar" in reference_text
    assert "原始 OpenAPI JSON" in reference_text
    assert "api-validity.json" not in reference_text
    assert "validity-report.md" not in reference_text
    assert 'href="../openapi.json"' in reference_text
    assert "🧭" not in reference_text
    if "cdn.jsdelivr" in reference_text or "unpkg.com" in reference_text:
        assert "权衡" in reference_text
        assert "openapi.json" in reference_text
        assert "@latest" not in reference_text


def test_primary_docs_use_external_reader_voice_and_keep_scope() -> None:
    pages = [
        REPO_ROOT / "site-docs" / "index.md",
        REPO_ROOT / "site-docs" / "getting-started" / "quickstart.md",
        REPO_ROOT / "site-docs" / "getting-started" / "concepts.md",
        REPO_ROOT / "site-docs" / "api" / "overview.md",
        REPO_ROOT / "site-docs" / "api" / "reference.md",
        REPO_ROOT / "site-docs" / "api" / "webhooks.md",
    ]
    banned = ["internal validation", "research note", "handoff", "todo", "tbd"]
    for path in pages:
        text = path.read_text(encoding="utf-8").lower()
        for term in banned:
            assert term not in text, f"{path} contains internal wording: {term}"

    home = (REPO_ROOT / "site-docs" / "index.md").read_text(encoding="utf-8")
    quickstart = (REPO_ROOT / "site-docs" / "getting-started" / "quickstart.md").read_text(encoding="utf-8")
    assert "API Reference" in home
    assert "快速开始" in home
    assert "pip install" in quickstart
    assert "CS_AUTH_TOKEN" in quickstart
    assert "http://127.0.0.1" in quickstart
    assert not (REPO_ROOT / "site-docs" / "en").exists()
    assert not (REPO_ROOT / "site-docs" / "english").exists()


def test_public_docs_avoid_internal_readiness_jargon() -> None:
    pages = [
        REPO_ROOT / "site-docs" / "configuration" / "env-vars.md",
        REPO_ROOT / "site-docs" / "decision-layers" / "l3-agent.md",
        REPO_ROOT / "site-docs" / "integration" / "codex.md",
        REPO_ROOT / "site-docs" / "advanced" / "rule-governance.md",
    ]
    banned_phrases = [
        "手动 smoke",
        "manual smoke",
        "provider smoke",
        "real-provider smoke",
        "smoke 工具",
        "真实网络 smoke",
        "发布前至少保留三条 smoke",
    ]
    for path in pages:
        text = path.read_text(encoding="utf-8")
        for phrase in banned_phrases:
            assert phrase not in text, f"{path} contains internal readiness jargon: {phrase}"
