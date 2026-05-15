import { useEffect, useState } from 'react'
import { Link, useParams, useSearchParams } from 'react-router-dom'
import { ArrowLeft, FolderTree, ScrollText, ShieldAlert } from 'lucide-react'
import { api } from '../api/client'
import { DecisionBadge, RiskBadge } from '../components/badges'
import SkeletonCard from '../components/SkeletonCard'
import type {
  HealthBudgetSnapshot,
  SSEBudgetExhaustedEvent,
  SessionReplayPageResponse,
  SessionRisk,
  SessionRiskResponse,
  RiskVelocity,
  WindowRiskSummary,
  TrajectoryRecord,
} from '../api/types'
import {
  Area,
  AreaChart,
  CartesianGrid,
  PolarAngleAxis,
  PolarGrid,
  PolarRadiusAxis,
  Radar,
  RadarChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts'
import { formatRelativeTime, workspaceDisplayLabel, workspaceTechnicalDetail } from '../lib/sessionGroups'
import { formatL3EvidenceSummary } from '../lib/l3EvidenceSummary'
import { DEMO_FALLBACK_ENABLED, DEMO_REPLAY_PAGE, DEMO_SESSION_RISK } from '../lib/demoData'
import { usePreferences } from '../lib/preferences'
import {
  appendReadableLabel,
  formatOperatorAction,
  formatOperatorLabel,
  formatRunnerLabel,
} from '../lib/operatorLabels'
import { formatTokenBudgetSnapshot } from '../lib/tokenBudget'

type ReportingEnvelope = {
  budget?: HealthBudgetSnapshot | null
  budget_exhaustion_event?: SSEBudgetExhaustedEvent | null
}

const DIMENSION_LABELS: Record<string, Record<'en' | 'zh', string>> = {
  d1: { en: 'Tool risk', zh: '工具风险' },
  d2: { en: 'Target sensitivity', zh: '目标敏感度' },
  d3: { en: 'Data flow', zh: '数据流' },
  d4: { en: 'Frequency', zh: '频率' },
  d5: { en: 'Context', zh: '上下文' },
  d6: { en: 'Injection', zh: '注入' },
}

const RISK_SCORE_MAX = 3

const DIMENSION_MAX: Record<string, number> = {
  d1: 3,
  d2: 3,
  d3: 3,
  d4: 2,
  d5: 2,
  d6: 3,
}

const TOOLTIP_STYLE = {
  background: 'rgba(255, 255, 255, 0.96)',
  border: '1px solid rgba(148, 163, 184, 0.18)',
  borderRadius: 16,
  fontSize: 12,
  color: '#142133',
  boxShadow: '0 18px 40px rgba(15, 23, 42, 0.12)',
}

const RECENT_WINDOW_SECONDS = 60 * 60
const WINDOW_OPTIONS: Array<{ label: string; value: number | null }> = [
  { label: 'All', value: null },
  { label: 'Recent 1h', value: RECENT_WINDOW_SECONDS },
]
const FULL_REVIEW_RUNNERS = ['llm_provider', 'deterministic_local'] as const
type FullReviewRunner = typeof FULL_REVIEW_RUNNERS[number]

function parseWindowSeconds(value: string | null): number | null {
  if (!value || value === 'all') return null
  if (value === 'recent-1h') return RECENT_WINDOW_SECONDS
  const parsed = Number(value)
  return Number.isFinite(parsed) && parsed > 0 ? parsed : null
}

function classifyHint(hint: string): string {
  const normalized = hint.toLowerCase()
  if (normalized.includes('shell') || normalized.includes('command')) return 'shell'
  if (normalized.includes('file') || normalized.includes('path')) return 'file'
  if (normalized.includes('network') || normalized.includes('url')) return 'network'
  if (normalized.includes('secret') || normalized.includes('credential') || normalized.includes('data')) return 'data'
  return 'default'
}

function HintTag({ hint }: { hint: string }) {
  return <span className={`hint-tag hint-tag-${classifyHint(hint)}`}>{hint}</span>
}

function formatMetricScore(value?: number | null): string {
  return typeof value === 'number' && Number.isFinite(value) ? value.toFixed(2) : '—'
}

function formatSignedMetric(value?: number | null): string {
  if (typeof value !== 'number' || !Number.isFinite(value)) return '—'
  return `${value >= 0 ? '+' : ''}${value.toFixed(2)}`
}

function formatRiskVelocityValue(value?: RiskVelocity | null): string {
  if (typeof value === 'number') return formatSignedMetric(value)
  if (value === 'up') return 'up'
  if (value === 'down') return 'down'
  if (value === 'flat') return 'flat'
  return '—'
}

function windowHighRiskCount(summary?: WindowRiskSummary | null): number {
  return summary?.high_or_critical_count ?? summary?.high_risk_event_count ?? 0
}

function windowRiskDensity(summary?: WindowRiskSummary | null): number | null {
  if (!summary) return null
  if (typeof summary.risk_density === 'number' && Number.isFinite(summary.risk_density)) {
    return summary.risk_density
  }
  const eventCount = summary.event_count ?? 0
  return eventCount > 0 ? windowHighRiskCount(summary) / eventCount : null
}

function formatWindowRiskSummary(risk: SessionRisk | null): string {
  const summary = risk?.window_risk_summary
  if (!summary) return 'Window metrics unavailable'
  return [
    `${summary.event_count ?? 0} events`,
    `${windowHighRiskCount(summary)} high-risk`,
    `density ${formatMetricScore(windowRiskDensity(summary))}`,
  ].join(' · ')
}

function TierBadge({ tier }: { tier: string }) {
  const normalized = tier.toUpperCase()
  const className = normalized === 'L3' ? 'badge-tier-l3' : normalized === 'L2' ? 'badge-tier-l2' : 'badge-tier-l1'
  return <span className={`badge ${className}`}>{normalized}</span>
}

function TimelineLatency({ ms }: { ms: number }) {
  const className = ms < 100 ? 'latency-fast' : ms < 3000 ? 'latency-medium' : 'latency-slow'
  return <span className={`latency-badge ${className}`}>{ms}ms</span>
}

function compactEventSubtypeLabel(value?: unknown): string {
  const normalized = String(value || '').trim().toLowerCase()
  if (!normalized) return ''
  if (normalized.includes('preprompt') || normalized === 'pre_prompt') return 'Prompt'
  if (normalized.includes('postresponse') || normalized === 'post_response') return 'Response'
  if (normalized.includes('pretooluse') || normalized === 'pre_action') return 'Tool request'
  if (normalized.includes('posttooluse') || normalized === 'post_action') return 'Tool result'
  return String(value)
    .replace(/_/g, ' ')
    .replace(/([a-z])([A-Z])/g, '$1 $2')
    .replace(/\b\w/g, char => char.toUpperCase())
}

function replayEventLabel(record: TrajectoryRecord): string {
  const directTool = String(record.event?.tool_name || '').trim()
  if (directTool) return directTool
  return compactEventSubtypeLabel(record.event?.event_subtype)
    || compactEventSubtypeLabel(record.event?.event_type)
    || 'Event'
}

function replayEventPreview(record: TrajectoryRecord): string {
  if (typeof record.event?.input === 'string' && record.event.input.trim()) {
    return record.event.input.trim()
  }
  const payload = record.event?.payload
  if (!payload || typeof payload !== 'object') return ''
  const payloadRecord = payload as Record<string, unknown>
  const argumentsValue = payloadRecord.arguments
  if (typeof payloadRecord.command === 'string' && payloadRecord.command.trim()) return payloadRecord.command.trim()
  if (typeof payloadRecord.prompt === 'string' && payloadRecord.prompt.trim()) return payloadRecord.prompt.trim()
  if (typeof payloadRecord.response_text === 'string' && payloadRecord.response_text.trim()) {
    return payloadRecord.response_text.trim()
  }
  if (typeof payloadRecord.file_path === 'string' && payloadRecord.file_path.trim()) return payloadRecord.file_path.trim()
  if (typeof payloadRecord.path === 'string' && payloadRecord.path.trim()) return payloadRecord.path.trim()
  if (argumentsValue && typeof argumentsValue === 'object') {
    const args = argumentsValue as Record<string, unknown>
    for (const key of ['command', 'file_path', 'path']) {
      if (typeof args[key] === 'string' && args[key].trim()) return args[key].trim()
    }
  }
  return ''
}

function hasActionableL3Meta(meta: TrajectoryRecord['meta']): boolean {
  const state = String(meta.l3_state || '').trim().toLowerCase()
  return Boolean(
    meta.l3_requested
    || meta.l3_reason_code
    || meta.l3_reason
    || (state && state !== 'enabled' && state !== 'completed'),
  )
}

function compactRecordValue(value: unknown): string {
  if (value === null || value === undefined) return ''
  if (Array.isArray(value)) {
    return value.map(item => compactRecordValue(item)).filter(Boolean).join(', ')
  }
  if (typeof value === 'object') {
    return Object.entries(value as Record<string, unknown>)
      .filter(([, nested]) => nested !== null && nested !== undefined && nested !== '')
      .slice(0, 5)
      .map(([key, nested]) => `${key}=${compactRecordValue(nested)}`)
      .join(', ')
  }
  return String(value)
}

function lineageDrilldownLines(record: TrajectoryRecord): string[] {
  const lines: string[] = []
  const lineage = record.meta.skill_lineage
  if (lineage && typeof lineage === 'object') {
    const summary = ['presented_skill_name', 'canonical_skill_id', 'content_hash', 'skill_root_path_hash', 'output_provenance_label']
      .map(key => {
        const value = lineage[key]
        return value ? `${key}=${compactRecordValue(value)}` : ''
      })
      .filter(Boolean)
      .join(', ')
    lines.push(summary || 'redacted lineage metadata available')
  }
  const trustRaw = record.meta.skill_trust_raw
  if (trustRaw && typeof trustRaw === 'object') {
    const trustSummary = ['presented_name', 'provenance_claim', 'trust_level', 'status', 'list_state', 'registry_record_count']
      .map(key => {
        const value = trustRaw[key]
        return value !== undefined && value !== null && value !== '' ? `${key}=${compactRecordValue(value)}` : ''
      })
      .filter(Boolean)
      .join(', ')
    if (trustSummary) lines.push(`registry ${trustSummary}`)
  }
  const ruleHits = record.risk_snapshot.rule_hits || []
  if (ruleHits.length) lines.push(`rules ${ruleHits.join(', ')}`)
  if (record.adapter_effect_results?.length) {
    const effects = record.adapter_effect_results
      .map(effect => compactRecordValue({
        effect_id: effect.effect_id,
        result_kind: effect.result_kind,
        adapter: effect.adapter,
      }))
      .filter(Boolean)
      .join(' | ')
    if (effects) lines.push(`adapter effects ${effects}`)
  }
  if (record.meta.request_id || record.record_id) {
    lines.push(`trace request=${record.meta.request_id || 'unknown'}, record=${record.record_id || 'unknown'}`)
  }
  return lines
}

function normalizeSessionRisk(result: SessionRisk | SessionRiskResponse): {
  risk: SessionRisk
  reporting: ReportingEnvelope
} {
  const response = result as SessionRiskResponse
  return {
    risk: response,
    reporting: {
      budget: response.budget ?? null,
      budget_exhaustion_event: response.budget_exhaustion_event ?? null,
    },
  }
}

function normalizeSessionReplayPage(result: SessionReplayPageResponse): {
  records: TrajectoryRecord[]
  nextCursor: number | null
  reporting: ReportingEnvelope
} {
  return {
    records: Array.isArray(result.records) ? result.records : [],
    nextCursor: result.next_cursor ?? null,
    reporting: {
      budget: result.budget ?? null,
      budget_exhaustion_event: result.budget_exhaustion_event ?? null,
    },
  }
}

function formatAdvisoryRecordRange(review: NonNullable<SessionRisk['l3_advisory']>['latest_review']): string {
  const range = review?.source_record_range
  if (!range) return 'Frozen boundary unavailable'
  const count = review.evidence_record_count ?? review.evidence_event_ids?.length ?? 0
  return `Records ${range.from_record_id}–${range.to_record_id} · ${count} event(s)`
}

function getOperatorRecommendation(
  risk: SessionRisk | null,
  showBudgetWarning: boolean,
  latestAdvisoryReview: NonNullable<SessionRisk['l3_advisory']>['latest_review'] | null,
) {
  if (latestAdvisoryReview?.recommended_operator_action) {
    return {
      label: latestAdvisoryReview.recommended_operator_action,
      detail: 'Follow the advisory-only recommendation while keeping the canonical decision unchanged.',
    }
  }

  if (showBudgetWarning) {
    return {
      label: 'review budget evidence',
      detail: 'Confirm LLM budget exhaustion before requesting additional L3 work.',
    }
  }

  if (risk?.current_risk_level === 'critical') {
    return {
      label: 'escalate immediately',
      detail: 'Critical posture detected; inspect replay evidence before releasing activity.',
    }
  }

  if (risk?.current_risk_level === 'high') {
    return {
      label: 'inspect replay',
      detail: 'High-risk activity is present; review recent decisions and L3 readiness.',
    }
  }

  return {
    label: 'monitor session',
    detail: 'No urgent advisory action is attached; keep observing trajectory changes.',
  }
}

function shouldUseSessionDetailDemoFallback(sessionId?: string): boolean {
  return DEMO_FALLBACK_ENABLED && Boolean(sessionId?.startsWith('demo-'))
}

function trajectorySortValue(record: TrajectoryRecord): number {
  const recordId = (record as TrajectoryRecord & { record_id?: number }).record_id
  if (typeof recordId === 'number' && Number.isFinite(recordId)) return recordId
  const ts = new Date(record.recorded_at).getTime()
  return Number.isFinite(ts) ? ts : 0
}

export default function SessionDetail() {
  const { t, language } = usePreferences()
  const { sessionId } = useParams<{ sessionId: string }>()
  const [searchParams, setSearchParams] = useSearchParams()
  const [risk, setRisk] = useState<SessionRisk | null>(null)
  const [trajectory, setTrajectory] = useState<TrajectoryRecord[]>([])
  const [replayNextCursor, setReplayNextCursor] = useState<number | null>(null)
  const [replayLoadingMore, setReplayLoadingMore] = useState(false)
  const [replayLoadMoreError, setReplayLoadMoreError] = useState<string | null>(null)
  const [budget, setBudget] = useState<HealthBudgetSnapshot | null>(null)
  const [budgetExhaustionEvent, setBudgetExhaustionEvent] = useState<SSEBudgetExhaustedEvent | null>(null)
  const [initialLoadError, setInitialLoadError] = useState<string | null>(null)
  const [reloadNonce, setReloadNonce] = useState(0)
  const [sessionWindowSeconds, setSessionWindowSeconds] = useState<number | null>(
    () => parseWindowSeconds(searchParams.get('windowSeconds') || searchParams.get('window')),
  )
  const [loading, setLoading] = useState(true)
  const [demoMode, setDemoMode] = useState(false)
  const [fullReviewStatus, setFullReviewStatus] = useState<string | null>(null)
  const [fullReviewError, setFullReviewError] = useState<string | null>(null)
  const [fullReviewRunning, setFullReviewRunning] = useState(false)
  const [fullReviewRunner, setFullReviewRunner] = useState<FullReviewRunner>('llm_provider')
  const [fullReviewQueueOnly, setFullReviewQueueOnly] = useState(false)

  useEffect(() => {
    if (!sessionId) return
    setLoading(true)
    setInitialLoadError(null)
    setRisk(null)
    setTrajectory([])
    setReplayNextCursor(null)
    setReplayLoadMoreError(null)
    setBudget(null)
    setBudgetExhaustionEvent(null)
    Promise.all([
      api.sessionRisk(sessionId, { windowSeconds: sessionWindowSeconds }),
      api.sessionReplayPage(sessionId, { windowSeconds: sessionWindowSeconds }),
    ])
      .then(([riskResult, trajectoryResult]) => {
        const normalizedRisk = normalizeSessionRisk(riskResult)
        const normalizedReplay = normalizeSessionReplayPage(trajectoryResult)

        setRisk(normalizedRisk.risk)
        setTrajectory(normalizedReplay.records)
        setReplayNextCursor(normalizedReplay.nextCursor)
        setBudget(normalizedRisk.reporting.budget ?? normalizedReplay.reporting.budget ?? null)
        setBudgetExhaustionEvent(
          normalizedRisk.reporting.budget_exhaustion_event
          ?? normalizedReplay.reporting.budget_exhaustion_event
          ?? null,
        )
        setDemoMode(false)
      })
      .catch(() => {
        if (!shouldUseSessionDetailDemoFallback(sessionId)) {
          setInitialLoadError('Could not load session detail. Try again.')
          return
        }
        const normalizedRisk = normalizeSessionRisk({
          ...DEMO_SESSION_RISK,
          session_id: sessionId,
        })
        const normalizedReplay = normalizeSessionReplayPage({
          ...DEMO_REPLAY_PAGE,
          session_id: sessionId,
        })
        setRisk(normalizedRisk.risk)
        setTrajectory(normalizedReplay.records)
        setReplayNextCursor(normalizedReplay.nextCursor)
        setBudget(normalizedRisk.reporting.budget ?? normalizedReplay.reporting.budget ?? null)
        setBudgetExhaustionEvent(
          normalizedRisk.reporting.budget_exhaustion_event
          ?? normalizedReplay.reporting.budget_exhaustion_event
          ?? null,
        )
        setDemoMode(true)
      })
      .finally(() => setLoading(false))
  }, [reloadNonce, sessionId, sessionWindowSeconds])

  async function loadMoreReplayRecords() {
    if (!sessionId || replayLoadingMore || replayNextCursor === null) return

    setReplayLoadingMore(true)
    setReplayLoadMoreError(null)
    try {
      const replayResult = await api.sessionReplayPage(sessionId, {
        cursor: replayNextCursor,
        windowSeconds: sessionWindowSeconds,
      })
      const normalizedReplay = normalizeSessionReplayPage(replayResult)
      setTrajectory(prev => [...prev, ...normalizedReplay.records])
      setReplayNextCursor(normalizedReplay.nextCursor)
      setBudget(prev => prev ?? normalizedReplay.reporting.budget ?? null)
      setBudgetExhaustionEvent(prev => prev ?? normalizedReplay.reporting.budget_exhaustion_event ?? null)
    } catch {
      setReplayLoadMoreError('Could not load older replay records. Try again.')
    } finally {
      setReplayLoadingMore(false)
    }
  }

  async function requestFullReview() {
    if (!sessionId || fullReviewRunning) return
    setFullReviewRunning(true)
    setFullReviewError(null)
    setFullReviewStatus(null)
    try {
      const result = await api.requestL3FullReview(sessionId, {
        runner: fullReviewRunner,
        run: !fullReviewQueueOnly,
      })
      const responseRunner = result.review?.review_runner
        || result.review?.worker_backend
        || ('runner' in result.job ? result.job.runner : null)
        || fullReviewRunner
      const runnerLabel = formatRunnerLabel(responseRunner, language)
      const reviewId = result.review?.review_id
      const state = result.review?.l3_state || result.job?.job_state || 'queued'
      const degradedDetail = result.review?.l3_state === 'degraded' && result.review?.l3_reason_code
        ? ` Provider/config issue: ${formatOperatorLabel('l3ReasonCode', result.review.l3_reason_code, language)}.`
        : ''
      if (fullReviewQueueOnly) {
        setFullReviewStatus(
          `Full review queued (${runnerLabel}): ${result.job?.job_id || 'job pending'}. Canonical decision unchanged.`,
        )
      } else {
        setFullReviewStatus(
          reviewId
            ? `Full review ${state} (${runnerLabel}): ${reviewId}. Canonical decision unchanged.${degradedDetail}`
            : `Full review queued (${runnerLabel}): ${result.job?.job_id || 'job pending'}. Canonical decision unchanged.`,
        )
      }
      setReloadNonce(value => value + 1)
    } catch {
      setFullReviewError('Could not request L3 full review. Try again.')
    } finally {
      setFullReviewRunning(false)
    }
  }

  if (loading) {
    return (
      <div>
        <div className="session-skeleton-spacer" />
        <div className="session-detail-grid">
          {[0, 1, 2].map(index => <SkeletonCard key={index} rows={4} height={220} />)}
        </div>
        <SkeletonCard rows={8} height={320} />
      </div>
    )
  }

  if (initialLoadError) {
    return (
      <div className="session-detail-shell">
        <Link to="/sessions" className="back-link">
          <ArrowLeft size={13} />
          Back to session inventory
        </Link>
        <section className="card section-card session-error-card" role="alert">
          <div className="section-card-header">
            <div>
              <p className="section-kicker">Session detail</p>
              <h2>Unable to load session data</h2>
            </div>
          </div>
          <p className="priority-session-meta session-error-copy">
            {initialLoadError}
          </p>
          <button
            type="button"
            className="secondary-button"
            onClick={() => setReloadNonce(value => value + 1)}
          >
            Retry
          </button>
        </section>
      </div>
    )
  }

  const radarData = risk
    ? Object.entries(risk.dimensions_latest).map(([key, value]) => {
        const max = DIMENSION_MAX[key] ?? 1
        const normalizedValue = Math.max(0, Math.min(value / max, 1))
        return {
        dimension: DIMENSION_LABELS[key]?.[language] || key,
        key,
        value,
          normalizedValue,
          max,
          fullMark: 1,
        }
      })
    : []

  const timelineData = risk?.risk_timeline.map(item => ({
    time: new Date(item.occurred_at).toLocaleTimeString(),
    score: Number(item.composite_score.toFixed(3)),
  })) ?? []
  const showBudgetWarning = Boolean(budget?.exhausted || budgetExhaustionEvent)
  const workspaceName = risk
    ? workspaceDisplayLabel(risk, language)
    : (language === 'zh' ? '未绑定工作区' : 'Unbound workspace')
  const latestAdvisoryReview = risk?.l3_advisory?.latest_review ?? null
  const latestAdvisoryJob = risk?.l3_advisory?.latest_job ?? null
  const latestAdvisoryAction = risk?.l3_advisory?.latest_action ?? null
  const displayTrajectory = [...trajectory].sort((a, b) => trajectorySortValue(b) - trajectorySortValue(a))
  const latestRecord = displayTrajectory[0] ?? null
  const latestToolName = latestRecord ? replayEventLabel(latestRecord) : 'No tool observed'
  const latestDecisionLabel = latestRecord ? String(latestRecord.decision.decision).toUpperCase() : 'NO REPLAY'
  const workbenchWindowLabel = sessionWindowSeconds === null ? 'All recorded evidence' : 'Recent 1h replay scope'
  const operatorRecommendation = getOperatorRecommendation(risk, showBudgetWarning, latestAdvisoryReview)
  const evidenceBoundaryLabel = latestAdvisoryReview ? latestAdvisoryReview.snapshot_id : 'No frozen snapshot'
  const evidenceBoundaryDetail = latestAdvisoryReview
    ? formatAdvisoryRecordRange(latestAdvisoryReview)
    : 'Request full review to freeze a bounded advisory snapshot.'
  const capturedSummary = risk
    ? `${formatRelativeTime(risk.first_event_at)} · ${risk.source_framework}`
    : 'Waiting for session telemetry.'
  const latestCompositeScore = risk?.latest_composite_score ?? risk?.cumulative_score ?? null
  const classifiedSummary = risk
    ? `${risk.current_risk_level} posture · score ${formatMetricScore(latestCompositeScore)}`
    : 'Risk posture unavailable.'
  const replayEvidenceSummary = trajectory.length > 0
    ? `${trajectory.length} decision event(s) loaded for operator review.`
    : 'No replay records loaded yet.'
  const advisoryActionSummary = latestAdvisoryReview
    ? `L3 ${formatOperatorLabel('l3State', latestAdvisoryReview.l3_state, language)} · ${formatOperatorAction(latestAdvisoryAction?.recommended_operator_action || latestAdvisoryReview.recommended_operator_action || 'inspect', language)}.`
    : 'No advisory review attached yet.'
  const latestAdvisoryRunner = latestAdvisoryReview?.review_runner
    || latestAdvisoryReview?.worker_backend
    || latestAdvisoryJob?.runner
    || null

  function updateSessionWindow(value: number | null) {
    setSessionWindowSeconds(value)
    const next = new URLSearchParams(searchParams)
    if (value === null) {
      next.delete('windowSeconds')
      next.delete('window')
    } else {
      next.set('windowSeconds', String(value))
      next.delete('window')
    }
    setSearchParams(next, { replace: true })
  }

  return (
    <div className="session-detail-shell">
      <Link to="/sessions" className="back-link">
        <ArrowLeft size={13} />
        {t('session.back')}
      </Link>

      <section className="session-hero">
        <div className="session-overview-copy">
          <p className="section-kicker">{t('session.detail')}</p>
          {demoMode && <span className="showcase-pill">Showcase mode · demo replay</span>}
          <h1>{workspaceName}</h1>
          <p className="hero-copy">
            {risk?.source_framework || 'unknown'} · {risk?.caller_adapter || 'unknown adapter'} ·
            last seen {risk ? formatRelativeTime(risk.last_event_at) : 'recently'}
          </p>
        </div>
        <div className="hero-chip-row session-overview-chips">
          {risk && <RiskBadge level={risk.current_risk_level} />}
          {risk && <span className="framework-chip"><span>Agent</span><strong>{risk.agent_id}</strong></span>}
          {risk && <span className="framework-chip"><span>Events</span><strong>{risk.event_count}</strong></span>}
        </div>
      </section>

      <section className="session-surface session-analysis-surface" aria-labelledby="session-analysis-heading">
        <div className="section-card-header session-surface-header">
          <div>
            <p className="section-kicker">{t('session.analysis')}</p>
            <h2 id="session-analysis-heading">{t('session.analysisTitle')}</h2>
          </div>
          <div className="session-surface-actions">
            <span className="section-meta">{t('session.analysisMeta')}</span>
            <div className="full-review-controls">
              <label className="full-review-runner-select">
                <span>{t('session.fullReviewRunner')}</span>
                <select
                  aria-label={t('session.fullReviewRunner')}
                  value={fullReviewRunner}
                  onChange={event => setFullReviewRunner(event.target.value as FullReviewRunner)}
                  disabled={fullReviewRunning}
                >
                  {FULL_REVIEW_RUNNERS.map(runner => (
                    <option key={runner} value={runner}>
                      {formatRunnerLabel(runner, language)}
                    </option>
                  ))}
                </select>
              </label>
              <label className="full-review-queue-toggle">
                <input
                  type="checkbox"
                  checked={fullReviewQueueOnly}
                  onChange={event => setFullReviewQueueOnly(event.target.checked)}
                  disabled={fullReviewRunning}
                />
                <span>{t('session.fullReviewQueueOnly')}</span>
              </label>
            </div>
            <button
              type="button"
              className="secondary-button"
              onClick={requestFullReview}
              disabled={fullReviewRunning || !sessionId}
            >
              {fullReviewRunning ? t('session.requestingReview') : t('session.requestReview')}
            </button>
          </div>
        </div>
        {(fullReviewStatus || fullReviewError) && (
          <p
            role={fullReviewError ? 'alert' : 'status'}
            className="priority-session-meta"
            data-tone={fullReviewError ? 'warning' : 'muted'}
          >
            {fullReviewError || fullReviewStatus}
          </p>
        )}
        <div className="session-analysis-grid">
          <section className="card section-card session-analysis-card-wide investigation-brief-card">
            <div className="section-card-header">
              <div>
                <p className="section-kicker">{t('session.workbench')}</p>
                <h3>{t('session.storyline')}</h3>
              </div>
              <span className="section-meta">{workbenchWindowLabel}</span>
            </div>
            <p className="investigation-lede">
              {workspaceName} is being reconstructed from {trajectory.length} replay event(s),{' '}
              {risk?.event_count ?? 0} tracked event(s), and {risk?.high_risk_event_count ?? 0} high-risk signal(s).
              The workbench keeps the advisory path visible without changing canonical safety decisions.
            </p>
            <div className="investigation-brief-grid">
              <div className="investigation-focus-card investigation-focus-card-primary">
                <span className="workbench-summary-label">{t('session.operatorRecommendation')}</span>
                <strong>{operatorRecommendation.label}</strong>
                <p>{operatorRecommendation.detail}</p>
              </div>
              <div className="investigation-focus-card">
                <span className="workbench-summary-label">{t('session.latestDecision')}</span>
                <strong>{latestDecisionLabel}</strong>
                <p>{latestToolName}</p>
              </div>
              <div className="investigation-focus-card">
                <span className="workbench-summary-label">{t('session.evidenceBoundary')}</span>
                <strong>{evidenceBoundaryLabel}</strong>
                <p>{evidenceBoundaryDetail}</p>
              </div>
            </div>
            <ol className="investigation-flow" aria-label="Investigation sequence">
              <li>
                <span>1</span>
                <div>
                  <strong>Session captured</strong>
                  <p>{capturedSummary}</p>
                </div>
              </li>
              <li>
                <span>2</span>
                <div>
                  <strong>Risk classified</strong>
                  <p>{classifiedSummary}</p>
                </div>
              </li>
              <li>
                <span>3</span>
                <div>
                  <strong>Replay evidence assembled</strong>
                  <p>{replayEvidenceSummary}</p>
                </div>
              </li>
              <li>
                <span>4</span>
                <div>
                  <strong>Advisory action</strong>
                  <p>{advisoryActionSummary}</p>
                </div>
              </li>
            </ol>
          </section>

          <section className="card section-card session-analysis-card-wide session-analysis-summary-card">
            <div className="section-card-header">
              <div>
                <p className="section-kicker">{t('session.priorityView')}</p>
                <h3>{t('session.currentPosture')}</h3>
              </div>
              <div className="hero-panel-header">
                <ShieldAlert size={14} />
                {t('session.analysisSummary')}
              </div>
            </div>
            <div className="session-analysis-summary-grid">
              <div className="session-analysis-stat">
                <span>{t('session.currentRisk')}</span>
                <div className="session-analysis-stat-value">
                  {risk ? <RiskBadge level={risk.current_risk_level} /> : t('common.unavailable')}
                </div>
              </div>
              <div className="session-analysis-stat">
                <span>{t('session.latestComposite')}</span>
                <strong className="mono">{formatMetricScore(latestCompositeScore)}</strong>
              </div>
              <div className="session-analysis-stat">
                <span>{t('session.cumulativeScore')}</span>
                <strong className="mono">{formatMetricScore(risk?.cumulative_score)}</strong>
              </div>
              <div className="session-analysis-stat">
                <span>{t('session.sessionRiskEwma')}</span>
                <strong className="mono">{formatMetricScore(risk?.session_risk_ewma)}</strong>
              </div>
              <div className="session-analysis-stat">
                <span>{t('session.riskVelocity')}</span>
                <strong className="mono">{formatRiskVelocityValue(risk?.risk_velocity ?? risk?.window_risk_summary?.risk_velocity)}</strong>
              </div>
              <div className="session-analysis-stat">
                <span>{t('session.windowRiskSummary')}</span>
                <strong className="mono">{formatWindowRiskSummary(risk)}</strong>
              </div>
              <div className="session-analysis-stat">
                <span>{t('session.highRiskEvents')}</span>
                <strong className="mono">{risk?.high_risk_event_count ?? 0}</strong>
              </div>
              <div className="session-analysis-stat">
                <span>{t('session.trackedEvents')}</span>
                <strong className="mono">{risk?.event_count ?? 0}</strong>
              </div>
              <div className="session-analysis-stat">
                <span>{t('session.firstEvent')}</span>
                <strong className="mono">{risk ? formatRelativeTime(risk.first_event_at) : '—'}</strong>
              </div>
              <div className="session-analysis-stat">
                <span>{t('session.lastEvent')}</span>
                <strong className="mono">{risk ? formatRelativeTime(risk.last_event_at) : '—'}</strong>
              </div>
            </div>
          </section>

          <section className="card section-card session-analysis-card-wide advisory-review-card">
            <div className="section-card-header">
              <div>
                <p className="section-kicker">{t('session.advisoryOnly')}</p>
                <h3>{t('session.l3Review')}</h3>
              </div>
              <span className="section-meta">{t('session.l3ReviewMeta')}</span>
            </div>
            {latestAdvisoryReview ? (
              <>
                <div className="advisory-review-grid">
                  <div className="session-analysis-stat">
                    <span>{t('session.reviewState')}</span>
                    <strong className="mono">{formatOperatorLabel('l3State', latestAdvisoryReview.l3_state, language)}</strong>
                  </div>
                  <div className="session-analysis-stat">
                    <span>{t('session.reviewId')}</span>
                    <strong className="mono">{latestAdvisoryReview.review_id}</strong>
                  </div>
                  <div className="session-analysis-stat">
                    <span>{t('session.snapshotId')}</span>
                    <strong className="mono">{latestAdvisoryReview.snapshot_id}</strong>
                  </div>
                  <div className="session-analysis-stat">
                    <span>{t('session.jobId')}</span>
                    <strong className="mono">{latestAdvisoryJob?.job_id || t('common.unavailable')}</strong>
                  </div>
                  <div className="session-analysis-stat">
                    <span>{t('session.advisoryRisk')}</span>
                    <div className="session-analysis-stat-value">
                      <RiskBadge level={latestAdvisoryReview.risk_level} />
                    </div>
                  </div>
                  <div className="session-analysis-stat">
                    <span>{t('session.operatorAction')}</span>
                    <strong className="mono">{formatOperatorAction(latestAdvisoryReview.recommended_operator_action || 'inspect', language)}</strong>
                  </div>
                  <div className="session-analysis-stat">
                    <span>{t('session.reviewRunner')}</span>
                    <strong className="mono">{formatRunnerLabel(latestAdvisoryRunner, language)}</strong>
                  </div>
                </div>
                <p className="priority-session-meta advisory-review-boundary">
                  {formatAdvisoryRecordRange(latestAdvisoryReview)}
                </p>
                {latestAdvisoryReview.findings?.length > 0 && (
                  <p className="priority-session-meta">
                    Finding: <span className="mono">{latestAdvisoryReview.findings[0]}</span>
                  </p>
                )}
                {latestAdvisoryReview.analysis_summary && (
                  <div className="advisory-narrative-panel">
                    <strong>{t('session.narrativeAnalysis')}</strong>
                    <p>{latestAdvisoryReview.analysis_summary}</p>
                  </div>
                )}
                {latestAdvisoryReview.analysis_points?.length ? (
                  <div className="advisory-narrative-panel">
                    <strong>{t('session.analysisPoints')}</strong>
                    <ul>
                      {latestAdvisoryReview.analysis_points.map(point => <li key={point}>{point}</li>)}
                    </ul>
                  </div>
                ) : null}
                {latestAdvisoryReview.operator_next_steps?.length ? (
                  <div className="advisory-narrative-panel">
                    <strong>{t('session.nextSteps')}</strong>
                    <ol>
                      {latestAdvisoryReview.operator_next_steps.map(step => <li key={step}>{step}</li>)}
                    </ol>
                  </div>
                ) : null}
                <p className="priority-session-meta">
                  {t('session.canonicalUnchanged')}
                </p>
                {latestAdvisoryAction && (
                  <p className="priority-session-meta">
                    L3 advisory action: <span className="mono">{formatOperatorAction(latestAdvisoryAction.recommended_operator_action, language)}</span>
                    {' '}· advisory-only / canonical unchanged
                    {latestAdvisoryAction.source_record_range
                      ? ` · records ${latestAdvisoryAction.source_record_range.from_record_id}–${latestAdvisoryAction.source_record_range.to_record_id}`
                      : ''}
                  </p>
                )}
              </>
            ) : (
              <p className="empty-inline">
                {t('session.noL3Review')}
              </p>
            )}
          </section>

          <section className="card section-card chart-card">
            <div className="section-card-header">
              <div>
                <p className="section-kicker">{t('session.dimensions')}</p>
                <h3>{t('session.riskComposition')}</h3>
              </div>
            </div>
            <div className="chart-card-body chart-card-radar">
              {radarData.length > 0 ? (
                <>
                  <ResponsiveContainer width="100%" height={260}>
                    <RadarChart data={radarData}>
                      <defs>
                        <radialGradient id="riskRadarFill" cx="50%" cy="50%" r="62%">
                          <stop offset="0%" stopColor="#22d3ee" stopOpacity={0.42} />
                          <stop offset="68%" stopColor="#5ea5ff" stopOpacity={0.24} />
                          <stop offset="100%" stopColor="#a78bfa" stopOpacity={0.16} />
                        </radialGradient>
                      </defs>
                      <PolarGrid stroke="rgba(120, 196, 255, 0.16)" radialLines={false} />
                      <PolarAngleAxis dataKey="dimension" tick={{ fill: '#b8c7dd', fontSize: 11, fontWeight: 600 }} />
                      <PolarRadiusAxis angle={90} domain={[0, RISK_SCORE_MAX]} tick={false} axisLine={false} />
                      <Radar dataKey="value" stroke="#67e8f9" fill="url(#riskRadarFill)" fillOpacity={0.88} strokeWidth={2.5} />
                      <Tooltip contentStyle={TOOLTIP_STYLE} formatter={(_, __, item) => {
                        const payload = item?.payload as { value?: number; max?: number } | undefined
                        return [payload ? `${formatMetricScore(payload.value)} / ${payload.max}` : '—', 'score']
                      }} />
                    </RadarChart>
                  </ResponsiveContainer>
                  <div className="risk-dimension-bars">
                    {[...radarData].sort((a, b) => b.value - a.value).map(item => (
                      <div key={item.dimension} className="risk-dimension-row">
                        <div>
                          <strong>{item.dimension}</strong>
                          <span className="mono">{formatMetricScore(item.value)}</span>
                        </div>
                        <div className="risk-dimension-track" aria-hidden="true">
                          <span style={{ width: `${item.normalizedValue * 100}%` }} />
                        </div>
                      </div>
                    ))}
                  </div>
                </>
              ) : (
                <p className="empty-inline">{t('session.noDimensionData')}</p>
              )}
            </div>
          </section>

          <section className="card section-card chart-card">
            <div className="section-card-header">
              <div>
                <p className="section-kicker">{t('session.timeline')}</p>
                <h3>{t('session.riskTimeline')}</h3>
              </div>
            </div>
            <div className="chart-card-body chart-card-area">
              {timelineData.length > 0 ? (
                <ResponsiveContainer width="100%" height={220}>
                  <AreaChart data={timelineData} margin={{ top: 8, right: 8, bottom: 0, left: -12 }}>
                    <defs>
                      <linearGradient id="riskGradient" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%" stopColor="#5ea5ff" stopOpacity={0.34} />
                        <stop offset="95%" stopColor="#5ea5ff" stopOpacity={0} />
                      </linearGradient>
                    </defs>
                    <CartesianGrid strokeDasharray="3 3" stroke="rgba(120, 196, 255, 0.08)" />
                    <XAxis dataKey="time" tick={{ fill: '#89a4bd', fontSize: 10 }} axisLine={false} tickLine={false} />
                    <YAxis tick={{ fill: '#89a4bd', fontSize: 10 }} axisLine={false} tickLine={false} domain={[0, RISK_SCORE_MAX]} />
                    <Tooltip contentStyle={TOOLTIP_STYLE} />
                    <Area
                      type="monotone"
                      dataKey="score"
                      stroke="#5ea5ff"
                      strokeWidth={2}
                      fill="url(#riskGradient)"
                      dot={{ fill: '#5ea5ff', r: 3, strokeWidth: 0 }}
                      activeDot={{ r: 5, fill: '#5ea5ff' }}
                    />
                  </AreaChart>
                </ResponsiveContainer>
              ) : (
                <p className="empty-inline">{t('session.noTimelineData')}</p>
              )}
            </div>
          </section>

          <section className="card section-card session-analysis-card-wide">
            <div className="section-card-header">
              <div>
                <p className="section-kicker">{t('session.replay')}</p>
                <h3>{t('session.decisionTimeline')}</h3>
                <p className="toolbar-subtitle">{t('session.newestFirst')}</p>
              </div>
              <div
                role="group"
                aria-label="Session time window"
                className="session-window-controls"
              >
                {WINDOW_OPTIONS.map(option => {
                  const isSelected = sessionWindowSeconds === option.value
                  return (
                    <button
                      key={option.label}
                      type="button"
                      className="secondary-button"
                      aria-pressed={isSelected}
                      onClick={() => updateSessionWindow(option.value)}
                      data-selected={isSelected ? 'true' : 'false'}
                    >
                      {option.label}
                    </button>
                  )
                })}
              </div>
              <span className="section-meta">{trajectory.length} events</span>
            </div>
            <div className="decision-timeline" aria-label="Scrollable replay window">
              {displayTrajectory.map((record, index) => {
                const input = replayEventPreview(record)
                const evidenceSummary = formatL3EvidenceSummary(record.l3_trace?.evidence_summary)
                const actionableL3Meta = hasActionableL3Meta(record.meta)
                const lineageLines = lineageDrilldownLines(record)
                return (
                  <div key={`${record.recorded_at}-${index}`} className="decision-timeline-row">
                    <span className="mono decision-timeline-time">
                      {new Date(record.recorded_at).toLocaleTimeString()}
                    </span>
                    <div className="decision-timeline-main">
                      <div className="decision-timeline-badges">
                        <DecisionBadge decision={record.decision.decision} />
                        <RiskBadge level={record.risk_snapshot.risk_level} />
                        <TierBadge tier={record.meta.actual_tier} />
                        <span className="cmd-snippet">{replayEventLabel(record)}</span>
                        <TimelineLatency ms={record.decision.decision_latency_ms} />
                      </div>
                      {input && (
                        <div className="cmd-snippet decision-command">
                          {input.slice(0, 180)}
                        </div>
                      )}
                      {record.decision.reason && (
                        <p className="priority-session-meta">{String(record.decision.reason)}</p>
                      )}
                      {record.l3_trace?.trigger_detail && (
                        <p className="priority-session-meta">
                          Trigger detail: <span className="mono">{record.l3_trace?.trigger_detail}</span>
                        </p>
                      )}
                      {actionableL3Meta && record.meta.l3_requested !== undefined && (
                        <p className="priority-session-meta">
                          L3 requested: <span className="mono">{record.meta.l3_requested ? 'yes' : 'no'}</span>
                        </p>
                      )}
                      {actionableL3Meta && record.meta.l3_available !== undefined && (
                        <p className="priority-session-meta">
                          L3 available: <span className="mono">{record.meta.l3_available ? 'yes' : 'no'}</span>
                        </p>
                      )}
                      {record.meta.l3_reason_code && (
                        <p className="priority-session-meta">
                          L3 reason code: <span className="mono">{appendReadableLabel('l3ReasonCode', record.meta.l3_reason_code, language)}</span>
                        </p>
                      )}
                      {actionableL3Meta && record.meta.l3_state && record.meta.l3_state !== 'completed' && record.meta.l3_state !== 'enabled' && (
                        <p className="priority-session-meta">
                          L3 state: <span className="mono">{appendReadableLabel('l3State', record.meta.l3_state, language)}</span>
                        </p>
                      )}
                      {record.meta.l3_reason && record.meta.l3_state && record.meta.l3_state !== 'completed' && (
                        <p className="priority-session-meta">
                          L3 reason: <span className="mono">{record.meta.l3_reason}</span>
                        </p>
                      )}
                      {evidenceSummary && (
                        <p className="priority-session-meta">
                          Evidence: <span className="mono">{evidenceSummary}</span>
                        </p>
                      )}
                      {lineageLines.length > 0 && (
                        <div className="priority-session-meta">
                          <span>Lineage drilldown:</span>
                          {lineageLines.map(line => (
                            <p key={line} className="priority-session-meta mono">
                              {line}
                            </p>
                          ))}
                        </div>
                      )}
                    </div>
                  </div>
                )
              })}
              {trajectory.length === 0 && (
                <div className="empty-inline">{t('session.noTrajectory')}</div>
              )}
            </div>
            {replayLoadMoreError && (
              <p
                className="priority-session-meta replay-load-more-error"
                role="alert"
                data-tone="warning"
              >
                {replayLoadMoreError}
              </p>
            )}
            {replayNextCursor !== null && (
              <div className="replay-footer">
                <button
                  type="button"
                  className="secondary-button"
                  onClick={loadMoreReplayRecords}
                  disabled={replayLoadingMore}
                >
                  {replayLoadingMore ? t('session.loadingOlder') : t('session.loadOlder')}
                </button>
              </div>
            )}
          </section>

          <section className="card section-card">
            <div className="section-card-header">
              <div>
                <p className="section-kicker">Signals</p>
                <h3>Observed indicators</h3>
              </div>
            </div>
            <div className="detail-pill-row tier-distribution-row">
              {Object.entries(risk?.actual_tier_distribution || {}).map(([tier, count]) => (
                <span key={tier}>
                  <TierBadge tier={tier} /> <span className="mono">{count}</span>
                </span>
              ))}
            </div>
            <div className="detail-list-block">
              <span className="detail-list-label">Tools used</span>
              <div className="detail-pill-row">
                {risk?.tools_used.length
                  ? risk.tools_used.map(tool => <span key={tool} className="cmd-snippet">{tool}</span>)
                  : <span className="empty-inline">No tool usage recorded.</span>}
              </div>
            </div>
            <div className="detail-list-block">
              <span className="detail-list-label">Risk hints</span>
              <div className="detail-pill-row">
                {risk?.risk_hints_seen.length
                  ? risk.risk_hints_seen.map(hint => <HintTag key={hint} hint={hint} />)
                  : <span className="empty-inline">No risk hints recorded.</span>}
              </div>
            </div>
          </section>

          {budget && (
            <section className="card section-card">
              <div className="section-card-header">
                <div>
                  <p className="section-kicker">LLM</p>
                  <h3>{t('session.tokenGovernance')}</h3>
                </div>
              </div>
              <div className="detail-meta-list">
                <div className="detail-meta-item">
                  <div>
                    <span>{t('session.tokenUsage')}</span>
                    <strong className="mono">{formatTokenBudgetSnapshot(budget, language)}</strong>
                  </div>
                </div>
                <div className="detail-meta-item">
                  <div>
                    <span>{t('session.currentPosture')}</span>
                    <strong className="mono">
                      {budget.exhausted ? (language === 'zh' ? '已耗尽' : 'exhausted') : (language === 'zh' ? '可用' : 'active')}
                    </strong>
                  </div>
                </div>
                {showBudgetWarning && (
                  <div className="mono budget-warning-panel">
                    <strong className="budget-warning-title">{t('session.tokenExhaustionEvent')}</strong>
                    <span> · {language === 'zh' ? '需要操作员关注' : 'Operator attention required'}</span>
                    {budgetExhaustionEvent && (
                      <div className="budget-warning-detail">
                        {budgetExhaustionEvent.provider || 'unknown'} · {budgetExhaustionEvent.tier || 'unknown'}
                      </div>
                    )}
                  </div>
                )}
              </div>
            </section>
          )}
        </div>
      </section>

      <section className="session-surface session-context-surface" aria-labelledby="session-context-heading">
        <div className="section-card-header session-surface-header">
          <div>
            <p className="section-kicker">{t('session.context')}</p>
            <h2 id="session-context-heading">{t('session.contextTitle')}</h2>
          </div>
          <span className="section-meta">{t('session.identityMeta')}</span>
        </div>
        <div className="session-context-grid">
          <section className="card section-card session-context-card">
            <div className="section-card-header">
              <div>
                <p className="section-kicker">{t('session.identity')}</p>
                <h3>{t('session.workspaceContext')}</h3>
              </div>
            </div>
            <div className="detail-meta-list">
              <div className="detail-meta-item">
                <FolderTree size={15} />
                <div>
                  <span>{t('session.workspaceRoot')}</span>
                  <strong className="mono">{workspaceTechnicalDetail(risk?.workspace_root, language)}</strong>
                </div>
              </div>
              <div className="detail-meta-item">
                <ScrollText size={15} />
                <div>
                  <span>{t('session.transcriptPath')}</span>
                  <strong className="mono">{risk?.transcript_path || t('common.unavailable')}</strong>
                </div>
              </div>
            </div>
          </section>

          <section className="card section-card session-context-card">
            <div className="section-card-header">
              <div>
                <p className="section-kicker">{t('session.metadata')}</p>
                <h3>{t('session.provenance')}</h3>
              </div>
            </div>
            <div className="detail-meta-list">
              <div className="detail-pill-row">
                <span className="framework-chip"><span>Framework</span><strong>{risk?.source_framework || 'unknown'}</strong></span>
                <span className="framework-chip"><span>Adapter</span><strong>{risk?.caller_adapter || 'unknown'}</strong></span>
              </div>
              <div className="detail-meta-item">
                <div>
                  <span>Session ID</span>
                  <strong className="mono">{risk?.session_id || sessionId || t('common.unavailable')}</strong>
                </div>
              </div>
              <div className="detail-meta-item">
                <div>
                  <span>Agent ID</span>
                  <strong className="mono">{risk?.agent_id || t('common.unavailable')}</strong>
                </div>
              </div>
            </div>
          </section>
        </div>
      </section>
    </div>
  )
}
