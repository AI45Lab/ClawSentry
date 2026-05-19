from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[3]
UI_ROOT = REPO_ROOT / "src" / "clawsentry" / "ui" / "src"


def _read_ui_file(relative_path: str) -> str:
    return (UI_ROOT / relative_path).read_text(encoding="utf-8")


def test_dashboard_feed_subscribes_to_runtime_activity_events() -> None:
    source = _read_ui_file("components/RuntimeFeed.tsx")
    locales = _read_ui_file("lib/locales.ts")

    assert "runtime.title" in source
    assert "Live Activity Feed" in locales
    assert "trajectory_alert" in source
    assert "post_action_finding" in source
    assert "pattern_candidate" in source
    assert "pattern_evolved" in source
    assert "defer_pending" in source
    assert "defer_resolved" in source
    assert "session_enforcement_change" in source
    assert "alert" in source


def test_dashboard_highlights_framework_workspace_monitoring() -> None:
    source = _read_ui_file("pages/Dashboard.tsx")
    locales = _read_ui_file("lib/locales.ts")

    assert "dashboard.frameworkCoverage" in source
    assert "Framework coverage" in locales
    assert "dashboard.workspaceRiskBoard" in source
    assert "Workspace risk board" in locales


def test_health_response_exposes_budget_snapshot_for_operator_surfaces() -> None:
    source = _read_ui_file("api/types.ts")

    assert "export interface HealthBudgetSnapshot" in source
    assert "budget: HealthBudgetSnapshot" in source
    assert "limit_tokens" in source
    assert "used_input_tokens" in source
    assert "used_output_tokens" in source
    assert "used_total_tokens" in source
    assert "remaining_tokens" in source
    assert "exhausted" in source


def test_status_bar_surfaces_budget_snapshot_copy() -> None:
    source = _read_ui_file("components/StatusBar.tsx")

    assert "formatTokenBudgetSnapshot" in source
    assert "health.budget.exhausted" in source


def test_dashboard_surfaces_budget_snapshot_in_current_posture() -> None:
    source = _read_ui_file("pages/Dashboard.tsx")
    locales = _read_ui_file("lib/locales.ts")

    assert "dashboard.panel.dailyBudget" in source
    assert "Token limit" in locales
    assert "formatTokenBudgetSnapshot" in source
    assert "limit_tokens" in source


def test_ui_types_model_llm_usage_snapshot_for_operator_surfaces() -> None:
    source = _read_ui_file("api/types.ts")

    assert "export interface LLMUsageBucket" in source
    assert "export interface LLMUsageSnapshot" in source
    assert "total_calls" in source
    assert "total_input_tokens" in source
    assert "total_output_tokens" in source
    assert "total_cost_usd" in source
    assert "by_provider: Record<string, LLMUsageBucket>" in source
    assert "by_tier: Record<string, LLMUsageBucket>" in source
    assert "by_status: Record<string, LLMUsageBucket>" in source
    assert "llm_usage_snapshot?: LLMUsageSnapshot | null" in source


def test_status_bar_surfaces_llm_usage_snapshot_summary_for_operators() -> None:
    source = _read_ui_file("components/StatusBar.tsx")

    assert "health?.llm_usage_snapshot" in source
    assert "formatLlmUsageSummary" in source
    assert "formatLlmUsageSummary" in source


def test_dashboard_surfaces_llm_usage_snapshot_summary_for_operators() -> None:
    source = _read_ui_file("pages/Dashboard.tsx")

    assert "summary?.llm_usage_snapshot" in source
    assert "formatLlmUsageSummary" in source
    assert "total_calls" in source


def test_defer_panel_uses_explicit_defer_lifecycle_events() -> None:
    source = _read_ui_file("pages/DeferPanel.tsx")

    assert "connectSSE(['defer_pending', 'defer_resolved'])" in source


def test_alerts_page_uses_backend_aligned_severity_taxonomy() -> None:
    source = _read_ui_file("pages/Alerts.tsx")
    styles = (REPO_ROOT / "src" / "clawsentry" / "ui" / "src" / "styles.css").read_text(encoding="utf-8")

    assert '<option value="low">Low</option>' in source
    assert '<option value="medium">Medium</option>' in source
    assert '<option value="high">High</option>' in source
    assert '<option value="critical">Critical</option>' in source
    assert '<option value="warning">' not in source
    assert '<option value="info">' not in source
    assert "alert-severity-text-high" in styles
    assert "color: var(--color-block)" in styles


def test_alert_types_bind_severity_to_risk_levels() -> None:
    source = _read_ui_file("api/types.ts")

    assert "export type AlertSeverity = RiskLevel" in source
    assert "severity: AlertSeverity" in source


def test_ui_types_expose_l3_reason_code_for_operator_surfaces() -> None:
    source = _read_ui_file("api/types.ts")

    assert "l3_reason_code?: string" in source


def test_ui_types_expose_l3_advisory_surfaces() -> None:
    source = _read_ui_file("api/types.ts")
    feed_source = _read_ui_file("components/RuntimeFeed.tsx")

    assert "export interface L3EvidenceSnapshot" in source
    assert "export interface L3AdvisoryReview" in source
    assert "export interface L3AdvisoryJob" in source
    assert "l3_advisory?: L3AdvisoryPayload" in source
    assert "l3_advisory_latest?: L3AdvisoryReview | null" in source
    assert "'l3_advisory_snapshot'" in source
    assert "'l3_advisory_review'" in source
    assert "'l3_advisory_job'" in source
    assert "l3_state: string" in source
    assert "L3 snapshot" in feed_source
    assert "L3 advisory" in feed_source
    assert "L3 job" in feed_source


def test_session_summary_types_expose_l3_metadata_and_evidence_for_lists() -> None:
    source = _read_ui_file("api/types.ts")

    assert "export interface SessionSummary" in source
    assert "l3_state?: string" in source
    assert "l3_reason?: string" in source
    assert "l3_reason_code?: string" in source
    assert "evidence_summary?: L3EvidenceSummary | null" in source


def test_ui_types_expose_compact_toolkit_budget_fields_in_l3_evidence_summary() -> None:
    source = _read_ui_file("api/types.ts")

    assert "export interface L3EvidenceSummary" in source
    assert "toolkit_budget_mode?: string" in source
    assert "toolkit_budget_cap?: number" in source
    assert "toolkit_calls_remaining?: number" in source
    assert "toolkit_budget_exhausted?: boolean" in source


def test_ui_types_expose_l3_availability_and_request_state() -> None:
    source = _read_ui_file("api/types.ts")

    assert "l3_available?: boolean" in source
    assert "l3_requested?: boolean" in source


def test_ui_types_expose_l3_state_and_reason_for_operator_surfaces() -> None:
    source = _read_ui_file("api/types.ts")

    assert "l3_state?: string" in source
    assert "l3_reason?: string" in source


def test_ui_types_expose_l3_as_a_first_class_decision_tier() -> None:
    source = _read_ui_file("api/types.ts")

    assert "export type DecisionTier = 'L1' | 'L2' | 'L3'" in source
    assert "actual_tier: DecisionTier" in source
    assert "trigger_detail?: string" in source


def test_runtime_feed_surfaces_trigger_detail_for_decision_events() -> None:
    source = _read_ui_file("components/RuntimeFeed.tsx")

    assert "event.trigger_detail" in source
    assert "Trigger pattern" in source


def test_runtime_feed_surfaces_l3_reason_code_for_decision_events() -> None:
    source = _read_ui_file("components/RuntimeFeed.tsx")

    assert "event.l3_reason_code" in source
    assert "L3 reason code" in source


def test_runtime_feed_surfaces_l3_availability_and_request_state_for_decision_events() -> None:
    source = _read_ui_file("components/RuntimeFeed.tsx")

    assert "event.l3_available" in source
    assert "event.l3_requested" in source
    assert "L3 available" in source
    assert "L3 requested" in source


def test_runtime_feed_surfaces_l3_state_and_reason_for_decision_events() -> None:
    source = _read_ui_file("components/RuntimeFeed.tsx")

    assert "event.l3_state" in source
    assert "event.l3_reason" in source


def test_ui_types_model_budget_exhausted_runtime_events() -> None:
    source = _read_ui_file("api/types.ts")

    assert "export interface SSEBudgetExhaustedEvent" in source
    assert "type: 'budget_exhausted'" in source
    assert "provider: string" in source
    assert "tier: string" in source
    assert "cost_usd: number" in source
    assert "budget: HealthBudgetSnapshot" in source
    assert "budget_exhausted" in source


def test_ui_types_model_budget_exhaustion_event_response_payloads() -> None:
    source = _read_ui_file("api/types.ts")

    assert "budget_exhaustion_event?: SSEBudgetExhaustedEvent | null" in source
    assert "budget_exhaustion_event" in source


def test_runtime_feed_surfaces_budget_exhausted_operator_copy() -> None:
    source = _read_ui_file("components/RuntimeFeed.tsx")

    assert "budget_exhausted" in source
    assert "Token exhausted" in source
    assert "Provider" in source
    assert "Tier" in source
    assert "formatTokenBudgetSnapshot" in source


def test_status_bar_emphasizes_budget_exhaustion_for_operators() -> None:
    source = _read_ui_file("components/StatusBar.tsx")

    assert "budget_exhaustion_event" in source
    assert "TOKEN EXHAUSTED" in source
    assert "Operator action required" in source


def test_dashboard_emphasizes_budget_exhaustion_for_operators() -> None:
    source = _read_ui_file("pages/Dashboard.tsx")
    locales = _read_ui_file("lib/locales.ts")

    assert "budget_exhaustion_event" in source
    assert "dashboard.panel.budgetAlert" in source
    assert "Token alert" in locales


def test_ui_types_model_reporting_envelope_for_session_detail_surfaces() -> None:
    source = _read_ui_file("api/types.ts")

    assert "export interface ReportingEnvelope" in source
    assert "budget: HealthBudgetSnapshot" in source
    assert "export interface SessionRiskResponse" in source
    assert "export interface SessionReplayResponse" in source
    assert "budget_exhaustion_event?: SSEBudgetExhaustedEvent | null" in source
    assert "llm_usage_snapshot?: LLMUsageSnapshot | null" in source


def test_api_client_preserves_session_detail_reporting_envelope() -> None:
    source = _read_ui_file("api/client.ts")

    assert "SessionRiskResponse" in source
    assert "SessionReplayResponse" in source
    assert "SessionReplayPageResponse" in source
    assert "sessionRisk: (id: string, params?: { windowSeconds?: number | null }) =>" in source
    assert "apiFetch<SessionRiskResponse>" in source
    assert "sessionReplay: (id: string, limit?: number): Promise<SessionReplayResponse> =>" in source
    assert "apiFetch<SessionReplayResponse>" in source
    assert "sessionReplayPage: (" in source
    assert "params?: { limit?: number; cursor?: number; windowSeconds?: number | null }" in source
    assert "): Promise<SessionReplayPageResponse> =>" in source
    assert "new URLSearchParams()" in source
    assert "qs.set('cursor', String(params.cursor))" in source
    assert "qs.set('limit', String(params.limit))" in source
    assert "qs.set('window_seconds', String(params.windowSeconds))" in source
    assert "apiFetch<SessionReplayPageResponse>" in source
    assert "/report/session/${id}/page" in source
    assert "return result.records ?? []" not in source


def test_session_detail_replay_surfaces_l3_trigger_detail() -> None:
    source = _read_ui_file("pages/SessionDetail.tsx")

    assert "record.l3_trace?.trigger_detail" in source
    assert "Trigger detail" in source


def test_session_detail_replay_surfaces_l3_reason_code() -> None:
    source = _read_ui_file("pages/SessionDetail.tsx")

    assert "record.meta.l3_reason_code" in source
    assert "L3 reason code" in source


def test_session_detail_replay_surfaces_l3_availability_and_request_state() -> None:
    source = _read_ui_file("pages/SessionDetail.tsx")

    assert "record.meta.l3_available" in source
    assert "record.meta.l3_requested" in source
    assert "L3 available" in source
    assert "L3 requested" in source


def test_session_detail_replay_surfaces_l3_state_and_reason() -> None:
    source = _read_ui_file("pages/SessionDetail.tsx")

    assert "record.meta.l3_state" in source
    assert "record.meta.l3_reason" in source


def test_session_detail_replay_surfaces_skill_trust_grade() -> None:
    source = _read_ui_file("pages/SessionDetail.tsx")

    assert "skill_trust_grade" in source


def test_session_detail_replay_surfaces_compact_evidence_summary() -> None:
    source = _read_ui_file("pages/SessionDetail.tsx")

    assert "record.l3_trace?.evidence_summary" in source
    assert "Evidence" in source


def test_shared_evidence_summary_helper_marks_toolkit_exhaustion() -> None:
    source = _read_ui_file("lib/l3EvidenceSummary.ts")

    assert "toolkit_budget_exhausted" in source
    assert "(exhausted)" in source


def test_session_detail_replay_reuses_shared_l3_evidence_summary_helper() -> None:
    session_detail_source = _read_ui_file("pages/SessionDetail.tsx")
    helper_source = _read_ui_file("lib/l3EvidenceSummary.ts")
    types_source = _read_ui_file("api/types.ts")

    assert "formatL3EvidenceSummary" in session_detail_source
    assert "formatL3EvidenceSummary" in helper_source
    assert "retained_sources" in helper_source
    assert "tool_calls_count" in helper_source
    assert "toolkit_budget_mode" in types_source
    assert "toolkit_budget_cap" in helper_source
    assert "toolkit_calls_remaining" in helper_source
    assert "parts.join(' · ')" in helper_source


def test_dashboard_priority_sessions_surface_l3_reason_code_and_evidence_summary() -> None:
    source = _read_ui_file("pages/Dashboard.tsx")
    helper_source = _read_ui_file("lib/sessionL3Annotations.ts")

    assert "formatSessionL3Annotation" in source
    assert "toolkit_budget_exhausted" in source
    assert "dashboard.evidenceHotspots" in source
    assert "session.l3_reason_code" in helper_source
    assert "session.evidence_summary" in helper_source
    assert "formatL3EvidenceSummary" in helper_source


def test_dashboard_surfaces_toolkit_evidence_budget_hotspot_metric() -> None:
    source = _read_ui_file("pages/Dashboard.tsx")
    locales = _read_ui_file("lib/locales.ts")

    assert "dashboard.metric.evidenceBudget" in source
    assert "Toolkit Evidence Quota" in locales
    assert "dashboard.noEvidenceHotspots" in source
    assert "No sessions are currently hitting toolkit evidence quota." in locales


def test_sessions_inventory_surface_l3_reason_code_and_evidence_summary() -> None:
    source = _read_ui_file("pages/Sessions.tsx")
    helper_source = _read_ui_file("lib/sessionL3Annotations.ts")
    locales = _read_ui_file("lib/locales.ts")

    assert "formatSessionL3Annotation" in source
    assert "session.l3_reason_code" in helper_source
    assert "session.evidence_summary" in helper_source
    assert "formatL3EvidenceSummary" in helper_source
    assert "session.evidence_summary?.toolkit_budget_exhausted" in source
    assert "sessions.budgetOnly" in source
    assert "Evidence quota exhausted only" in locales
    assert "aria-pressed" in source


def test_session_detail_surfaces_budget_snapshot_and_current_exhaustion_state() -> None:
    source = _read_ui_file("pages/SessionDetail.tsx")

    assert "budget_exhaustion_event" in source
    assert "formatTokenBudgetSnapshot" in source
    assert "session.tokenGovernance" in source
    assert "session.tokenExhaustionEvent" in source


def test_ui_types_model_session_replay_page_cursor_contract() -> None:
    source = _read_ui_file("api/types.ts")

    assert "export interface SessionReplayPageResponse" in source
    assert "extends ReportingEnvelope" in source
    assert "session_id: string" in source
    assert "record_count: number" in source
    assert "records: TrajectoryRecord[]" in source
    assert "next_cursor: number | null" in source
    assert "window_seconds: number | null" in source


def test_session_detail_uses_paged_replay_with_load_more() -> None:
    source = _read_ui_file("pages/SessionDetail.tsx")

    assert "api.sessionReplayPage(sessionId, { windowSeconds: sessionWindowSeconds })" in source
    assert "cursor: replayNextCursor" in source
    assert "windowSeconds: sessionWindowSeconds" in source
    assert "session.loadOlder" in source
    assert "nextCursor" in source


def test_session_risk_timeline_exposes_tier_fields_without_trace_parsing() -> None:
    source = _read_ui_file("api/types.ts")
    timeline_section = source.split("risk_timeline: Array<{", 1)[1].split("}>", 1)[0]

    assert "actual_tier: DecisionTier" in timeline_section
    assert "classified_by: DecisionTier" in timeline_section


def test_alerts_page_gates_sse_insertions_by_active_filters() -> None:
    source = _read_ui_file("pages/Alerts.tsx")

    assert "const matchesAlertFilters" in source
    assert "matchesAlertFilters(newAlert, severity, showAcknowledged)" in source
