export type RiskLevel = 'low' | 'medium' | 'high' | 'critical'
export type DecisionVerdict = 'allow' | 'block' | 'defer' | 'modify'
export type DecisionTier = 'L1' | 'L2' | 'L3'
export type AlertSeverity = RiskLevel

export interface LLMUsageBucket {
  calls: number
  input_tokens: number
  output_tokens: number
  cost_usd: number
}

export interface LLMUsageSnapshot {
  total_calls: number
  total_input_tokens: number
  total_output_tokens: number
  total_cost_usd: number
  by_provider: Record<string, LLMUsageBucket>
  by_tier: Record<string, LLMUsageBucket>
  by_status: Record<string, LLMUsageBucket>
}

export interface ReportingEnvelope {
  budget: HealthBudgetSnapshot
  budget_exhaustion_event?: SSEBudgetExhaustedEvent | null
  llm_usage_snapshot?: LLMUsageSnapshot | null
}

export interface HealthBudgetSnapshot {
  enabled?: boolean
  limit_tokens?: number
  scope?: 'total' | 'input' | 'output' | string
  used_input_tokens?: number
  used_output_tokens?: number
  used_total_tokens?: number
  remaining_tokens?: number | null
  exhausted: boolean
  daily_budget_usd?: number
  daily_spend_usd?: number
  remaining_usd?: number | null
}

export interface HealthResponse extends ReportingEnvelope {
  status: string
  uptime_seconds: number
  cache_size: number
  trajectory_count: number
  policy_engine: string
  auth_enabled: boolean
}

export interface SummaryResponse extends ReportingEnvelope {
  total_records: number
  by_source_framework: Record<string, number>
  by_event_type: Record<string, number>
  by_decision: Record<string, number>
  by_risk_level: Record<string, number>
  by_actual_tier: Partial<Record<DecisionTier, number>>
  by_caller_adapter: Record<string, number>
  generated_at: string
  window_seconds: number | null
  system_security_posture?: SystemSecurityPosture | null
}

export interface RiskDimensions {
  d1: number
  d2: number
  d3: number
  d4: number
  d5: number
  d6?: number
}

export type RiskVelocity = 'up' | 'down' | 'flat' | 'unknown' | number

export interface ScoreSemantics {
  range?: [number, number]
  zero_with_no_events?: string
  decision_affecting?: boolean
  aggregation?: string
}

export interface WindowRiskSummary {
  window_seconds?: number | null
  event_count?: number
  high_risk_event_count?: number
  high_or_critical_count?: number
  max_composite_score?: number
  mean_composite_score?: number
  latest_composite_score?: number
  composite_score_sum?: number
  session_risk_sum?: number
  session_risk_ewma?: number
  risk_points_sum?: number
  risk_density?: number
  risk_velocity?: RiskVelocity
  score_range?: [number, number]
  score_semantics?: ScoreSemantics
  decision_affecting?: boolean
}

export interface PostActionScoreSummary {
  window_seconds?: number | null
  generated_at?: string
  event_count?: number
  latest_post_action_score?: number
  post_action_score_sum?: number
  post_action_score_avg?: number
  post_action_score_ewma?: number
  score_range?: [number, number]
  score_semantics?: ScoreSemantics
  decision_affecting?: boolean
}

export interface PostActionScorePoint {
  event_id: string
  occurred_at: string
  tool_name?: string | null
  source_framework?: string | null
  tier?: string | null
  patterns_matched?: string[]
  score: number
  handling?: string | null
}

export interface ControlHealthSnapshot {
  enforced_sessions?: number
  released_sessions?: number
  l3_required_sessions?: number
  budget_exhausted_sessions?: number
  high_risk_session_count?: number
}

export interface SystemSecurityPosture {
  posture_score?: number
  score_0_100?: number
  risk_level?: RiskLevel
  level?: string
  latest_composite_score?: number
  session_risk_ewma?: number
  risk_velocity?: RiskVelocity
  drivers?: Array<Record<string, unknown>>
  window_seconds?: number | null
  generated_at?: string
  decision_affecting?: boolean
  control_health?: ControlHealthSnapshot | null
  window_risk_summary?: WindowRiskSummary | null
}

export interface PolicyDriftBucket {
  record_count: number
  decision_distribution: Record<string, number>
  risk_distribution: Record<string, number>
  rule_hits: Record<string, number>
  block_rate: number
  high_or_critical_rate: number
}

export interface PolicyDriftCell {
  cell_id: string
  workspace_root: string
  source_framework: string
  session_id: string
  rule_family: string
  current: PolicyDriftBucket
  previous: PolicyDriftBucket
  delta: {
    record_count: number
    block_rate: number
    high_or_critical_rate: number
  }
  traceability: {
    request_ids: string[]
    record_ids: string[]
    event_ids: string[]
    registry_states: string[]
    rule_evidence: string[]
    fallback_paths: string[]
    adapter_effect_result_ids: string[]
  }
  traceability_applicability: Record<string, boolean>
}

export interface MetricCellTraceability {
  passed: boolean
  coverage: number
  total_cells: number
  cell_count?: number
  complete_cell_count?: number
  required_fields: string[]
  conditional_fields: string[]
  incomplete_cells: Array<{
    workspace_root: string
    source_framework: string
    session_id: string
    rule_family: string
    missing_fields: string[]
  }>
}

export interface PolicyDriftResponse {
  generated_at: string
  window_seconds: number | null
  comparison_window_seconds?: number | null
  grouping_dimensions: string[]
  total_cells: number
  cells: PolicyDriftCell[]
  metric_cell_traceability: MetricCellTraceability
}

export interface EnterpriseLiveRiskOverview {
  generated_at?: string
  active_sessions: number
  high_risk_sessions: number
  mapped_active_sessions: number
  by_risk_level?: Record<string, number>
  by_trinityguard_tier?: Record<string, number>
  by_trinityguard_subtype?: Record<string, number>
}

export interface EnterpriseRuntimeTelemetry {
  live_risk_overview?: EnterpriseLiveRiskOverview
  trinityguard_classification?: Record<string, unknown>
}

export interface SessionSummary {
  session_id: string
  agent_id: string
  source_framework: string
  caller_adapter: string
  workspace_root: string
  transcript_path: string
  current_risk_level: RiskLevel
  cumulative_score: number
  event_count: number
  high_risk_event_count: number
  decision_distribution: Record<string, number>
  first_event_at: string
  last_event_at: string
  l3_state?: string
  l3_reason?: string
  l3_reason_code?: string
  evidence_summary?: L3EvidenceSummary | null
  l3_advisory_latest?: L3AdvisoryReview | null
  l3_advisory_latest_action?: L3AdvisoryAction | null
  latest_composite_score?: number
  session_risk_sum?: number
  session_risk_ewma?: number
  latest_post_action_score?: number
  post_action_score_sum?: number
  post_action_score_avg?: number
  post_action_score_ewma?: number
  post_action_event_count?: number
  post_action_score_summary?: PostActionScoreSummary | null
  risk_points_sum?: number
  risk_velocity?: RiskVelocity
  window_risk_summary?: WindowRiskSummary | null
  score_range?: [number, number]
  score_semantics?: ScoreSemantics
}

export interface SessionRisk {
  session_id: string
  agent_id: string
  source_framework: string
  caller_adapter: string
  workspace_root: string
  transcript_path: string
  current_risk_level: RiskLevel
  cumulative_score: number
  latest_composite_score?: number
  session_risk_sum?: number
  session_risk_ewma?: number
  latest_post_action_score?: number
  post_action_score_sum?: number
  post_action_score_avg?: number
  post_action_score_ewma?: number
  post_action_event_count?: number
  post_action_score_summary?: PostActionScoreSummary | null
  risk_points_sum?: number
  risk_velocity?: RiskVelocity
  window_risk_summary?: WindowRiskSummary | null
  score_range?: [number, number]
  score_semantics?: ScoreSemantics
  dimensions_latest: RiskDimensions
  event_count: number
  high_risk_event_count: number
  first_event_at: string
  last_event_at: string
  l3_state?: string
  l3_reason?: string
  l3_reason_code?: string
  evidence_summary?: L3EvidenceSummary | null
  risk_timeline: Array<{
    event_id: string
    occurred_at: string
    risk_level: RiskLevel
    composite_score: number
    risk_velocity?: RiskVelocity
    tool_name: string
    decision: DecisionVerdict
    actual_tier: DecisionTier
    classified_by: DecisionTier
    l3_reason_code?: string
    evidence_summary?: L3EvidenceSummary | null
  }>
  post_action_scores?: PostActionScorePoint[]
  risk_hints_seen: string[]
  tools_used: string[]
  actual_tier_distribution: Partial<Record<DecisionTier, number>>
  l3_advisory?: L3AdvisoryPayload
}

export interface SessionPostActionScores {
  session_id: string
  latest_post_action_score: number
  post_action_score_sum: number
  post_action_score_avg: number
  post_action_score_ewma: number
  post_action_event_count: number
  post_action_score_summary: PostActionScoreSummary
  post_action_scores: PostActionScorePoint[]
  score_range: [number, number]
  score_semantics?: ScoreSemantics
  generated_at: string
  window_seconds: number | null
  decision_affecting: boolean
}

export interface L3EvidenceSummary {
  retained_sources?: string[]
  tool_calls_count?: number
  toolkit_budget_mode?: string
  toolkit_budget_cap?: number
  toolkit_calls_remaining?: number
  toolkit_budget_exhausted?: boolean
}

export interface L3EvidenceSnapshot {
  snapshot_id: string
  session_id: string
  created_at: string
  trigger_event_id: string
  trigger_reason: string
  trigger_detail?: string | null
  event_range: {
    from_record_id: number
    to_record_id: number
  }
  record_count: number
  trajectory_fingerprint: string
  risk_summary: {
    current_risk_level: RiskLevel
    high_risk_event_count: number
    decision_distribution: Record<string, number>
  }
  evidence_budget: {
    max_records: number
    max_tool_calls: number
  }
  advisory_only: true
}

export interface L3AdvisoryReview {
  review_id: string
  type: 'l3_advisory_review'
  snapshot_id: string
  session_id: string
  risk_level: RiskLevel
  findings: string[]
  confidence?: number | null
  advisory_only: true
  recommended_operator_action: 'inspect' | 'pause' | 'escalate' | 'none' | string
  l3_state: string
  l3_reason_code?: string | null
  created_at: string
  completed_at?: string | null
  evidence_record_count?: number
  evidence_event_ids?: string[]
  source_record_range?: {
    from_record_id: number
    to_record_id: number
  }
  review_runner?: string
  worker_backend?: string
  analysis_summary?: string
  analysis_points?: string[]
  operator_next_steps?: string[]
}

export interface L3AdvisoryPayload {
  snapshots: L3EvidenceSnapshot[]
  reviews: L3AdvisoryReview[]
  jobs: L3AdvisoryJob[]
  latest_review: L3AdvisoryReview | null
  latest_job: L3AdvisoryJob | null
  latest_action?: L3AdvisoryAction | null
}

export interface L3AdvisoryAction {
  type: 'l3_advisory_action'
  action_id: string
  session_id: string
  snapshot_id: string
  job_id?: string | null
  review_id: string
  risk_level: RiskLevel
  recommended_operator_action: string
  l3_state: string
  l3_reason_code?: string | null
  source_record_range?: {
    from_record_id: number
    to_record_id: number
  } | null
  summary: string
  analysis_summary?: string
  analysis_points?: string[]
  operator_next_steps?: string[]
  advisory_only: true
  canonical_decision_mutated: false
  created_at?: string | null
}

export interface L3AdvisoryJob {
  job_id: string
  snapshot_id: string
  session_id: string
  review_id?: string | null
  job_state: 'queued' | 'running' | 'completed' | 'failed' | string
  runner: string
  created_at: string
  updated_at: string
  completed_at?: string | null
  error?: string
}

export interface L3FullReviewResponse {
  snapshot: L3EvidenceSnapshot | { snapshot_id: string }
  job: L3AdvisoryJob | { job_id: string; job_state: string; runner?: string }
  review: L3AdvisoryReview | null
  advisory_only: true
  canonical_decision_mutated: false
}

export interface TrajectoryRecord {
  event: Record<string, unknown>
  decision: {
    decision: DecisionVerdict
    reason: string
    risk_level: RiskLevel
    decision_latency_ms: number
  }
  risk_snapshot: {
    risk_level: RiskLevel
    composite_score: number
    dimensions: RiskDimensions
    rule_hits?: string[]
    skill_trust_findings?: Record<string, unknown>[]
  }
  meta: {
    actual_tier: DecisionTier
    caller_adapter: string
    request_id?: string
    skill_lineage?: Record<string, unknown>
    skill_trust_raw?: Record<string, unknown>
    l3_available?: boolean
    l3_requested?: boolean
    l3_reason_code?: string
    l3_state?: string
    l3_reason?: string
  }
  adapter_effect_results?: Record<string, unknown>[]
  record_id?: number
  l3_trace?: {
    trigger_reason?: string
    trigger_detail?: string
    evidence_summary?: L3EvidenceSummary | null
  } | null
  recorded_at: string
}

export interface Alert {
  alert_id: string
  severity: AlertSeverity
  metric: string
  session_id: string
  message: string
  details: Record<string, unknown>
  triggered_at: string
  acknowledged: boolean
  acknowledged_by: string | null
  acknowledged_at: string | null
}

export interface SessionRiskResponse extends ReportingEnvelope, SessionRisk {
  generated_at: string
  window_seconds: number | null
}

export interface SessionReplayResponse extends ReportingEnvelope {
  session_id: string
  record_count: number
  records: TrajectoryRecord[]
  generated_at: string
  window_seconds: number | null
}

export interface SessionReplayPageResponse extends ReportingEnvelope {
  session_id: string
  record_count: number
  records: TrajectoryRecord[]
  next_cursor: number | null
  generated_at: string
  window_seconds: number | null
}

export interface SSEDecisionEvent {
  session_id: string
  event_id: string
  risk_level: RiskLevel
  decision: DecisionVerdict
  tool_name: string
  actual_tier: DecisionTier
  timestamp: string
  reason: string
  command: string
  l3_available?: boolean
  l3_requested?: boolean
  trigger_detail?: string
  l3_reason_code?: string
  l3_state?: string
  l3_reason?: string
  evidence_summary?: L3EvidenceSummary | null
  approval_id?: string
  expires_at?: number
}

export interface SSEAlertEvent {
  alert_id: string
  severity: AlertSeverity
  metric: string
  session_id: string
  current_risk: string
  message: string
  timestamp: string
}

export interface SSEBudgetExhaustedEvent {
  type: 'budget_exhausted'
  timestamp: string
  provider: string
  tier: string
  status: string
  cost_usd?: number
  budget: HealthBudgetSnapshot
}

export type SSEPostActionFindingEvent = {
  event_id: string
  session_id: string
  source_framework: string
  tier: 'warn' | 'escalate' | 'emergency'
  patterns_matched: string[]
  score: number
  handling: 'broadcast' | 'defer' | 'block'
  timestamp: string
}

export type SSETrajectoryAlertEvent = {
  session_id: string
  sequence_id: string
  risk_level: RiskLevel
  matched_event_ids: string[]
  reason: string
  handling: 'broadcast' | 'defer' | 'block'
  timestamp: string
}

export type SSEPatternCandidateEvent = {
  pattern_id: string
  session_id: string
  source_framework: string
  status: 'candidate'
  timestamp: string
}

export type SSEPatternEvolvedEvent = {
  pattern_id: string
  action: string
  result: string
  timestamp: string
}

export type SSEDeferPendingEvent = {
  session_id: string
  approval_id: string
  tool_name: string
  command: string
  reason: string
  timeout_s: number
  timestamp: string
  approval_prompt?: {
    affected_target?: string
    operation?: string
    consequence?: string
    dry_run_or_narrower_scope_suggestion?: string
    rollback_hint?: string
    field_sources?: Record<
      string,
      'generated' | 'adapter_provided' | 'unavailable' | string
    >
  }
}

export type SSEDeferResolvedEvent = {
  session_id: string
  approval_id: string
  resolved_decision: 'allow' | 'allow-once' | 'block'
  resolved_reason: string
  timestamp: string
}

export type SSESessionEnforcementChangeEvent = {
  session_id: string
  state: 'enforced' | 'released'
  action: 'defer' | 'block' | 'l3_require' | null
  high_risk_count?: number
  reason?: string
  timestamp: string
}

export type SSEL3AdvisorySnapshotEvent = {
  session_id: string
  snapshot_id: string
  trigger_event_id: string
  trigger_reason: string
  trigger_detail?: string | null
  event_range: {
    from_record_id: number
    to_record_id: number
  }
  advisory_only: true
  canonical_decision_mutated?: false
  timestamp: string
}

export type SSEL3AdvisoryReviewEvent = {
  session_id: string
  snapshot_id: string
  review_id: string
  risk_level: RiskLevel
  recommended_operator_action: string
  l3_state: string
  l3_reason_code?: string | null
  analysis_summary?: string
  analysis_points?: string[]
  operator_next_steps?: string[]
  advisory_only: true
  canonical_decision_mutated?: false
  timestamp: string
}

export type SSEL3AdvisoryJobEvent = {
  session_id: string
  snapshot_id: string
  job_id: string
  job_state: string
  runner: string
  review_id?: string | null
  advisory_only?: true
  canonical_decision_mutated?: false
  timestamp: string
}

export type SSEL3AdvisoryActionEvent = L3AdvisoryAction & {
  timestamp: string
}

export type RuntimeEventType =
  | 'decision'
  | 'alert'
  | 'trajectory_alert'
  | 'post_action_finding'
  | 'pattern_candidate'
  | 'pattern_evolved'
  | 'defer_pending'
  | 'defer_resolved'
  | 'budget_exhausted'
  | 'session_enforcement_change'
  | 'l3_advisory_snapshot'
  | 'l3_advisory_review'
  | 'l3_advisory_job'
  | 'l3_advisory_action'

export type SSERuntimeEvent = (
  (SSEDecisionEvent & { type: 'decision' })
  | (SSEAlertEvent & { type: 'alert' })
  | (SSEPostActionFindingEvent & { type: 'post_action_finding' })
  | (SSETrajectoryAlertEvent & { type: 'trajectory_alert' })
  | (SSEPatternCandidateEvent & { type: 'pattern_candidate' })
  | (SSEPatternEvolvedEvent & { type: 'pattern_evolved' })
  | (SSEDeferPendingEvent & { type: 'defer_pending' })
  | (SSEDeferResolvedEvent & { type: 'defer_resolved' })
  | SSEBudgetExhaustedEvent
  | (SSESessionEnforcementChangeEvent & { type: 'session_enforcement_change' })
  | (SSEL3AdvisorySnapshotEvent & { type: 'l3_advisory_snapshot' })
  | (SSEL3AdvisoryReviewEvent & { type: 'l3_advisory_review' })
  | (SSEL3AdvisoryJobEvent & { type: 'l3_advisory_job' })
  | (SSEL3AdvisoryActionEvent & { type: 'l3_advisory_action' })
) & EnterpriseRuntimeTelemetry
