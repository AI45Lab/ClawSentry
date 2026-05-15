import { fireEvent, render, screen, within } from '@testing-library/react'
import { Children, isValidElement } from 'react'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import SessionDetail from './SessionDetail'
import { api } from '../api/client'

vi.mock('../api/client', () => ({
  api: {
    sessionRisk: vi.fn(),
    sessionReplay: vi.fn(),
    sessionReplayPage: vi.fn(),
    requestL3FullReview: vi.fn(),
  },
}))

vi.mock('recharts', () => {
  const Stub = ({ children }: { children?: React.ReactNode }) => <div>{children}</div>
  const ChartStub = ({ children }: { children?: React.ReactNode }) => (
    <div>
      {Children.toArray(children).filter(child => isValidElement(child) && child.type !== 'defs')}
    </div>
  )
  const ResponsiveContainerStub = ({
    children,
    width,
    height,
    className,
  }: {
    children?: React.ReactNode
    width?: string | number
    height?: string | number
    className?: string
  }) => (
    <div
      data-testid="responsive-container"
      data-width={String(width ?? '')}
      data-height={String(height ?? '')}
      className={className}
    >
      {children}
    </div>
  )
  return {
    ResponsiveContainer: ResponsiveContainerStub,
    AreaChart: ChartStub,
    CartesianGrid: () => null,
    PolarAngleAxis: () => null,
    PolarGrid: () => null,
    PolarRadiusAxis: ({ domain }: { domain?: unknown }) => (
      <div data-testid="risk-radar-radius-axis" data-domain={JSON.stringify(domain ?? null)} />
    ),
    Radar: () => null,
    RadarChart: ChartStub,
    Tooltip: () => null,
    XAxis: () => null,
    YAxis: ({ domain }: { domain?: unknown }) => (
      <div data-testid="risk-timeline-y-axis" data-domain={JSON.stringify(domain ?? null)} />
    ),
    Area: () => null,
  }
})

function makeRiskResponse(overrides: Record<string, unknown> = {}) {
  return {
    session_id: 'sess-123',
    agent_id: 'agent-1',
    source_framework: 'codex',
    caller_adapter: 'codex-http',
    workspace_root: '/workspace/demo',
    transcript_path: '/workspace/demo/session.jsonl',
    current_risk_level: 'medium',
    cumulative_score: 0.62,
    latest_composite_score: 0.68,
    session_risk_ewma: 0.55,
    risk_velocity: 'down',
    window_risk_summary: {
      window_seconds: 3600,
      event_count: 9,
      high_risk_event_count: 2,
      risk_density: 0.22,
      max_composite_score: 0.71,
      mean_composite_score: 0.49,
    },
    dimensions_latest: { d1: 0.2, d2: 0.1, d3: 0.3, d4: 0.0, d5: 0.1, d6: 0.4 },
    event_count: 3,
    high_risk_event_count: 0,
    first_event_at: '2026-04-14T08:00:00Z',
    last_event_at: '2026-04-14T08:05:00Z',
    risk_timeline: [
      {
        event_id: 'evt-1',
        occurred_at: '2026-04-14T08:05:00Z',
        risk_level: 'medium',
        composite_score: 0.62,
        tool_name: 'bash',
        decision: 'allow',
        actual_tier: 'L2',
        classified_by: 'L2',
      },
    ],
    risk_hints_seen: ['shell command'],
    tools_used: ['bash'],
    actual_tier_distribution: { L2: 1 },
    budget: {
      daily_budget_usd: 10,
      daily_spend_usd: 3.25,
      remaining_usd: 6.75,
      exhausted: false,
    },
    budget_exhaustion_event: null,
    ...overrides,
  }
}

function makeReplayPageResponse(overrides: Record<string, unknown> = {}) {
  return {
    session_id: 'sess-123',
    record_count: 1,
    records: [
      {
        event: { tool_name: 'bash', input: 'ls -la' },
        decision: {
          decision: 'allow',
          reason: 'Safe read-only command',
          risk_level: 'low',
          decision_latency_ms: 42,
        },
        risk_snapshot: {
          risk_level: 'low',
          composite_score: 0.21,
          dimensions: { d1: 0.1, d2: 0.0, d3: 0.1, d4: 0.0, d5: 0.0, d6: 0.0 },
        },
        meta: {
          actual_tier: 'L1',
          caller_adapter: 'codex-http',
        },
        l3_trace: {
          evidence_summary: {
            retained_sources: ['trajectory', 'file'],
            tool_calls_count: 2,
            toolkit_budget_mode: 'multi_turn',
            toolkit_budget_cap: 5,
            toolkit_calls_remaining: 0,
            toolkit_budget_exhausted: true,
          },
        },
        recorded_at: '2026-04-14T08:05:10Z',
      },
    ],
    next_cursor: 2,
    generated_at: '2026-04-14T08:05:15Z',
    window_seconds: null,
    budget: {
      daily_budget_usd: 10,
      daily_spend_usd: 3.25,
      remaining_usd: 6.75,
      exhausted: false,
    },
    budget_exhaustion_event: null,
    ...overrides,
  }
}

const RECENT_WINDOW_SECONDS = 60 * 60

function renderSessionDetail(initialEntry = '/sessions/sess-123') {
  return render(
    <MemoryRouter
      initialEntries={[initialEntry]}
      future={{ v7_startTransition: true, v7_relativeSplatPath: true }}
    >
      <Routes>
        <Route path="/sessions/:sessionId" element={<SessionDetail />} />
      </Routes>
    </MemoryRouter>,
  )
}

describe('SessionDetail', () => {
  beforeEach(() => {
    vi.mocked(api.sessionRisk).mockResolvedValue(makeRiskResponse() as never)
    vi.mocked(api.sessionReplayPage).mockResolvedValue(makeReplayPageResponse() as never)
    vi.mocked(api.requestL3FullReview).mockResolvedValue({
      snapshot: { snapshot_id: 'snap-full-review' },
      job: { job_id: 'job-full-review', job_state: 'completed', runner: 'llm_provider' },
      review: {
        review_id: 'review-full-review',
        l3_state: 'completed',
        advisory_only: true,
        review_runner: 'llm_provider',
      },
      advisory_only: true,
      canonical_decision_mutated: false,
    } as never)
  })

  it('keeps analysis first while preserving supporting context and heading hierarchy', async () => {
    renderSessionDetail()

    const analysisRegion = await screen.findByRole('region', { name: 'Session analysis' })
    const contextRegion = screen.getByRole('region', { name: 'Session context' })

    expect(analysisRegion).toBeInTheDocument()
    expect(contextRegion).toBeInTheDocument()
    expect(analysisRegion.compareDocumentPosition(contextRegion) & Node.DOCUMENT_POSITION_FOLLOWING).not.toBe(0)

    expect(screen.getByRole('heading', { level: 2, name: 'Session analysis' })).toBeInTheDocument()
    expect(screen.getByRole('heading', { level: 2, name: 'Session context' })).toBeInTheDocument()
    expect(screen.getByRole('heading', { level: 3, name: 'Incident storyline' })).toBeInTheDocument()
    expect(screen.getByRole('heading', { level: 3, name: 'Risk composition' })).toBeInTheDocument()
    expect(screen.getByRole('heading', { level: 3, name: 'Risk score over time' })).toBeInTheDocument()
    expect(screen.getByRole('heading', { level: 3, name: 'Decision timeline' })).toBeInTheDocument()
    expect(screen.getByRole('heading', { level: 3, name: 'Workspace context' })).toBeInTheDocument()
    expect(screen.getByRole('heading', { level: 3, name: 'Session provenance' })).toBeInTheDocument()

    expect(within(contextRegion).getByText('Workspace root')).toBeInTheDocument()
    expect(within(contextRegion).getByText('/workspace/demo')).toBeInTheDocument()
    expect(within(contextRegion).getByText('Transcript path')).toBeInTheDocument()
    expect(within(contextRegion).getByText('/workspace/demo/session.jsonl')).toBeInTheDocument()
    expect(within(contextRegion).getByText('Framework')).toBeInTheDocument()
    expect(within(contextRegion).getByText('codex')).toBeInTheDocument()
    expect(within(contextRegion).getByText('Adapter')).toBeInTheDocument()
    expect(within(contextRegion).getByText('codex-http')).toBeInTheDocument()
    expect(within(contextRegion).getByText('Session ID')).toBeInTheDocument()
    expect(within(contextRegion).getByText('sess-123')).toBeInTheDocument()
    expect(within(contextRegion).getByText('Agent ID')).toBeInTheDocument()
    expect(within(contextRegion).getByText('agent-1')).toBeInTheDocument()
  })

  it('uses canonical 0-3 risk scale for charts instead of compressing high-risk values', async () => {
    vi.mocked(api.sessionRisk).mockResolvedValueOnce(makeRiskResponse({
      dimensions_latest: { d1: 2.5, d2: 2.0, d3: 1.5, d4: 1.0, d5: 0.5, d6: 2.8 },
      risk_timeline: [
        {
          event_id: 'evt-high-scale',
          occurred_at: '2026-04-15T07:05:00Z',
          composite_score: 2.4,
          risk_level: 'high',
          dimensions: { d1: 2.5, d2: 2.0, d3: 1.5, d4: 1.0, d5: 0.5, d6: 2.8 },
        },
      ],
    }) as never)

    renderSessionDetail()

    expect(await screen.findByRole('heading', { level: 3, name: 'Risk composition' })).toBeInTheDocument()
    expect(screen.getByTestId('risk-radar-radius-axis')).toHaveAttribute('data-domain', '[0,3]')
    expect(screen.getByTestId('risk-timeline-y-axis')).toHaveAttribute('data-domain', '[0,3]')
  })

  it('renders an investigation workbench brief before charts and replay controls', async () => {
    renderSessionDetail()

    const storylineHeading = await screen.findByRole('heading', { level: 3, name: 'Incident storyline' })
    const workbenchCard = storylineHeading.closest('section')

    expect(workbenchCard).not.toBeNull()
    expect(within(workbenchCard as HTMLElement).getByText('Operator recommendation')).toBeInTheDocument()
    expect(within(workbenchCard as HTMLElement).getByText('monitor session')).toBeInTheDocument()
    expect(within(workbenchCard as HTMLElement).getByText('Latest replay decision')).toBeInTheDocument()
    expect(within(workbenchCard as HTMLElement).getByText('ALLOW')).toBeInTheDocument()
    expect(within(workbenchCard as HTMLElement).getByText('bash')).toBeInTheDocument()
    expect(within(workbenchCard as HTMLElement).getByText('Evidence boundary')).toBeInTheDocument()
    expect(within(workbenchCard as HTMLElement).getByText('No frozen snapshot')).toBeInTheDocument()
    expect(within(workbenchCard as HTMLElement).getByText('Session captured')).toBeInTheDocument()
    expect(within(workbenchCard as HTMLElement).getByText('Advisory action')).toBeInTheDocument()
  })

  it('renders the current budget snapshot without an exhaustion warning when budget is active', async () => {
    renderSessionDetail()

    expect(await screen.findByText('Token governance')).toBeInTheDocument()
    expect(screen.getByText('Token usage')).toBeInTheDocument()
    expect(screen.getByText(/total tokens/i)).toBeInTheDocument()
    expect(screen.queryByText('Token exhaustion event')).not.toBeInTheDocument()
  })

  it('hydrates the replay time window from URL-backed state', async () => {
    renderSessionDetail('/sessions/sess-123?windowSeconds=3600')

    expect(await screen.findByRole('button', { name: 'Recent 1h' })).toHaveAttribute('aria-pressed', 'true')
    expect(api.sessionRisk).toHaveBeenCalledWith('sess-123', { windowSeconds: RECENT_WINDOW_SECONDS })
    expect(api.sessionReplayPage).toHaveBeenCalledWith('sess-123', { windowSeconds: RECENT_WINDOW_SECONDS })
  })

  it('renders toolkit budget telemetry inside the compact evidence summary', async () => {
    renderSessionDetail()

    expect(await screen.findByText('Evidence:')).toBeInTheDocument()
    expect(screen.getByText('trajectory, file · 2 tool call(s) · toolkit 0/5 (exhausted)')).toBeInTheDocument()
  })

  it('renders redacted lineage and traceability drilldown for replay records', async () => {
    vi.mocked(api.sessionReplayPage).mockResolvedValueOnce(makeReplayPageResponse({
      records: [
        {
          event: { tool_name: 'bash', payload: { command: 'cat /workspace/demo/README.md' } },
          decision: {
            decision: 'block',
            reason: 'Skill alias conflict',
            risk_level: 'high',
            decision_latency_ms: 33,
          },
          risk_snapshot: {
            risk_level: 'high',
            composite_score: 2.2,
            dimensions: { d1: 2.0, d2: 0.0, d3: 1.0, d4: 0.0, d5: 0.0, d6: 1.0 },
            rule_hits: ['ambiguous_skill_alias'],
            skill_trust_findings: [{ rule_id: 'ambiguous_skill_alias', registry_state: 'unlisted' }],
          },
          meta: {
            actual_tier: 'L1',
            caller_adapter: 'codex-http',
            request_id: 'req-lineage',
            skill_lineage: {
              presented_skill_name: 'search_accommodation',
              content_hash: 'sha256:content',
              skill_root_path_hash: 'sha256:path',
            },
            skill_trust_raw: {
              presented_name: 'search_accommodation',
              registry_record_count: 1,
              redaction_policy_version: 'cs.skill_trust_raw.redaction.v1',
            },
          },
          adapter_effect_results: [
            { effect_id: 'effect-lineage', result_kind: 'enforced', adapter: 'codex' },
          ],
          record_id: 7,
          l3_trace: null,
          recorded_at: '2026-04-14T08:05:10Z',
        },
      ],
      next_cursor: null,
    }) as never)

    renderSessionDetail()

    expect(await screen.findByText('Lineage drilldown:')).toBeInTheDocument()
    expect(screen.getByText(/presented_skill_name=search_accommodation/)).toBeInTheDocument()
    expect(screen.getByText(/content_hash=sha256:content/)).toBeInTheDocument()
    expect(screen.getByText(/registry presented_name=search_accommodation/)).toBeInTheDocument()
    expect(screen.getByText(/rules ambiguous_skill_alias/)).toBeInTheDocument()
    expect(screen.getByText(/adapter effects effect_id=effect-lineage/)).toBeInTheDocument()
    expect(screen.getByText(/trace request=req-lineage, record=7/)).toBeInTheDocument()
  })

  it('uses conversation event labels instead of unknown for prompt and response replay rows', async () => {
    vi.mocked(api.sessionReplayPage).mockResolvedValueOnce(makeReplayPageResponse({
      records: [
        {
          event: { event_type: 'pre_prompt', event_subtype: 'PrePrompt', payload: { prompt: '请删除临时目录' } },
          decision: {
            decision: 'allow',
            reason: 'Conversation marker',
            risk_level: 'low',
            decision_latency_ms: 12,
          },
          risk_snapshot: {
            risk_level: 'low',
            composite_score: 0.05,
            dimensions: { d1: 0.0, d2: 0.0, d3: 0.0, d4: 0.0, d5: 0.0, d6: 0.0 },
          },
          meta: { actual_tier: 'L1', caller_adapter: 'a3s-adapter.v1' },
          l3_trace: null,
          recorded_at: '2026-04-14T08:05:10Z',
        },
        {
          event: { event_type: 'post_response', event_subtype: 'PostResponse', payload: { response_text: '已停止执行危险操作' } },
          decision: {
            decision: 'allow',
            reason: 'Conversation marker',
            risk_level: 'low',
            decision_latency_ms: 14,
          },
          risk_snapshot: {
            risk_level: 'low',
            composite_score: 0.05,
            dimensions: { d1: 0.0, d2: 0.0, d3: 0.0, d4: 0.0, d5: 0.0, d6: 0.0 },
          },
          meta: { actual_tier: 'L1', caller_adapter: 'a3s-adapter.v1' },
          l3_trace: null,
          recorded_at: '2026-04-14T08:05:20Z',
        },
      ],
      next_cursor: null,
    }) as never)

    renderSessionDetail()

    expect(await screen.findByText('Prompt')).toBeInTheDocument()
    expect(screen.getAllByText('Response').length).toBeGreaterThan(0)
    expect(screen.queryByText('unknown')).not.toBeInTheDocument()
  })

  it('hides non-actionable L3 enabled metadata on replay rows', async () => {
    vi.mocked(api.sessionReplayPage).mockResolvedValueOnce(makeReplayPageResponse({
      records: [
        {
          event: { tool_name: 'bash', input: 'echo ok' },
          decision: {
            decision: 'allow',
            reason: 'Safe command',
            risk_level: 'low',
            decision_latency_ms: 20,
          },
          risk_snapshot: {
            risk_level: 'low',
            composite_score: 0.05,
            dimensions: { d1: 0.0, d2: 0.0, d3: 0.0, d4: 0.0, d5: 0.0, d6: 0.0 },
          },
          meta: {
            actual_tier: 'L1',
            caller_adapter: 'a3s-adapter.v1',
            l3_requested: false,
            l3_available: true,
            l3_state: 'enabled',
          },
          l3_trace: null,
          recorded_at: '2026-04-14T08:05:10Z',
        },
      ],
      next_cursor: null,
    }) as never)

    renderSessionDetail()

    expect(await screen.findByText('echo ok')).toBeInTheDocument()
    expect(screen.queryByText(/L3 requested:/i)).not.toBeInTheDocument()
    expect(screen.queryByText(/L3 available:/i)).not.toBeInTheDocument()
    expect(screen.queryByText(/L3 state:/i)).not.toBeInTheDocument()
  })

  it('renders latest/window risk metrics and the D6 injection dimension', async () => {
    renderSessionDetail()

    expect(await screen.findByText('Latest composite score')).toBeInTheDocument()
    expect(screen.getByText('0.68')).toBeInTheDocument()
    expect(screen.getByText('Session risk EWMA')).toBeInTheDocument()
    expect(screen.getByText('0.55')).toBeInTheDocument()
    expect(screen.getByText('Risk velocity')).toBeInTheDocument()
    expect(screen.getByText('down')).toBeInTheDocument()
    expect(screen.getByText('Window risk summary')).toBeInTheDocument()
    expect(screen.getByText('9 events · 2 high-risk · density 0.22')).toBeInTheDocument()
    expect(screen.getByText('Injection')).toBeInTheDocument()
  })

  it('gives risk charts explicit dimensions so Recharts can measure them', async () => {
    renderSessionDetail()

    const compositionCard = (await screen.findByRole('heading', { level: 3, name: 'Risk composition' })).closest('section')
    const timelineCard = screen.getByRole('heading', { level: 3, name: 'Risk score over time' }).closest('section')

    expect(compositionCard).not.toBeNull()
    expect(timelineCard).not.toBeNull()

    const compositionContainer = within(compositionCard as HTMLElement).getByTestId('responsive-container')
    const timelineContainer = within(timelineCard as HTMLElement).getByTestId('responsive-container')

    expect(compositionContainer).toHaveAttribute('data-width', '100%')
    expect(compositionContainer).toHaveAttribute('data-height', '260')
    expect(timelineContainer).toHaveAttribute('data-width', '100%')
    expect(timelineContainer).toHaveAttribute('data-height', '220')
  })

  it('lets operators request an LLM provider full review from session detail by default', async () => {
    renderSessionDetail()

    const runnerSelect = await screen.findByRole('combobox', { name: 'Full-review runner' })
    expect(runnerSelect).toHaveValue('llm_provider')
    expect(within(runnerSelect).queryByRole('option', { name: 'Fake LLM' })).not.toBeInTheDocument()

    const button = await screen.findByRole('button', { name: 'Request L3 full review' })
    fireEvent.click(button)

    expect(api.requestL3FullReview).toHaveBeenCalledWith('sess-123', {
      runner: 'llm_provider',
      run: true,
    })
    expect(await screen.findByRole('status')).toHaveTextContent('Full review completed (LLM provider): review-full-review')
    expect(screen.getByText(/canonical decision unchanged/i)).toBeInTheDocument()
  })

  it('supports queue-only full review requests with alternate runner selection', async () => {
    vi.mocked(api.requestL3FullReview).mockResolvedValueOnce({
      snapshot: { snapshot_id: 'snap-full-review' },
      job: { job_id: 'job-full-review', job_state: 'queued', runner: 'deterministic_local' },
      review: null,
      advisory_only: true,
      canonical_decision_mutated: false,
    } as never)
    renderSessionDetail()

    const runnerSelect = await screen.findByRole('combobox', { name: 'Full-review runner' })
    fireEvent.change(runnerSelect, { target: { value: 'deterministic_local' } })
    fireEvent.click(screen.getByRole('checkbox', { name: 'Queue only (do not run now)' }))
    fireEvent.click(screen.getByRole('button', { name: 'Request L3 full review' }))

    expect(api.requestL3FullReview).toHaveBeenCalledWith('sess-123', {
      runner: 'deterministic_local',
      run: false,
    })
    expect(await screen.findByRole('status')).toHaveTextContent('Full review queued (Deterministic local): job-full-review')
    expect(screen.getByText(/canonical decision unchanged/i)).toBeInTheDocument()
  })

  it('summarizes the latest advisory review IDs and frozen boundary from session risk', async () => {
    vi.mocked(api.sessionRisk).mockResolvedValueOnce(makeRiskResponse({
      l3_advisory: {
        snapshots: [],
        reviews: [],
        jobs: [],
        latest_job: {
          job_id: 'job-risk-1',
          snapshot_id: 'snap-risk-1',
          session_id: 'sess-123',
          review_id: 'review-risk-1',
          job_state: 'completed',
          runner: 'deterministic_local',
          created_at: '2026-04-21T08:00:00Z',
          updated_at: '2026-04-21T08:00:01Z',
          completed_at: '2026-04-21T08:00:01Z',
        },
        latest_review: {
          review_id: 'review-risk-1',
          type: 'l3_advisory_review',
          snapshot_id: 'snap-risk-1',
          session_id: 'sess-123',
          risk_level: 'high',
          findings: ['operator requested bounded replay inspection'],
          confidence: 0.72,
          advisory_only: true,
          recommended_operator_action: 'escalate',
          l3_state: 'completed',
          l3_reason_code: null,
          created_at: '2026-04-21T08:00:00Z',
          completed_at: '2026-04-21T08:00:01Z',
          evidence_record_count: 5,
          evidence_event_ids: ['evt-4', 'evt-8'],
          source_record_range: {
            from_record_id: 4,
            to_record_id: 8,
          },
          review_runner: 'deterministic_local',
          worker_backend: 'deterministic_local',
        },
        latest_action: {
          type: 'l3_advisory_action',
          action_id: 'action-risk-1',
          session_id: 'sess-123',
          snapshot_id: 'snap-risk-1',
          job_id: 'job-risk-1',
          review_id: 'review-risk-1',
          risk_level: 'high',
          recommended_operator_action: 'escalate',
          l3_state: 'completed',
          source_record_range: {
            from_record_id: 4,
            to_record_id: 8,
          },
          summary: 'L3 advisory high risk recommends escalate; advisory only, canonical unchanged.',
          advisory_only: true,
          canonical_decision_mutated: false,
          created_at: '2026-04-21T08:00:01Z',
        },
      },
    }) as never)

    renderSessionDetail()

    const advisory = await screen.findByRole('heading', { level: 3, name: 'L3 advisory review' })
    const advisoryCard = advisory.closest('section')
    expect(advisoryCard).not.toBeNull()
    expect(within(advisoryCard as HTMLElement).getByText('review-risk-1')).toBeInTheDocument()
    expect(within(advisoryCard as HTMLElement).getByText('snap-risk-1')).toBeInTheDocument()
    expect(within(advisoryCard as HTMLElement).getByText('job-risk-1')).toBeInTheDocument()
    expect(within(advisoryCard as HTMLElement).getByText('Completed')).toBeInTheDocument()
    expect(within(advisoryCard as HTMLElement).getAllByText('Escalate').length).toBeGreaterThan(0)
    expect(within(advisoryCard as HTMLElement).getByText('Deterministic local')).toBeInTheDocument()
    expect(within(advisoryCard as HTMLElement).getByText('Records 4–8 · 5 event(s)')).toBeInTheDocument()
    expect(within(advisoryCard as HTMLElement).getByText(/canonical decision unchanged/i)).toBeInTheDocument()
    expect(within(advisoryCard as HTMLElement).getByText(/L3 advisory action:/i)).toBeInTheDocument()
    expect(within(advisoryCard as HTMLElement).getByText(/advisory-only \/ canonical unchanged/i)).toBeInTheDocument()
  })

  it('switches the initial window and re-fetches the first replay page for the new scope', async () => {
    vi.mocked(api.sessionRisk).mockImplementation((_sessionId, params) =>
      Promise.resolve(makeRiskResponse({
        window_seconds: params?.windowSeconds ?? null,
      }) as never))
    vi.mocked(api.sessionReplayPage).mockImplementation((_sessionId, params) => {
      if (params?.cursor !== undefined) {
        return Promise.reject(new Error('older page unavailable') as never)
      }

      const isRecentWindow = params?.windowSeconds === RECENT_WINDOW_SECONDS
      return Promise.resolve(makeReplayPageResponse({
        records: [
          {
            event: { tool_name: 'bash', input: isRecentWindow ? 'recent ls -la' : 'ls -la' },
            decision: {
              decision: 'allow',
              reason: isRecentWindow ? 'Recent window record' : 'All window record',
              risk_level: 'low',
              decision_latency_ms: 42,
            },
            risk_snapshot: {
              risk_level: 'low',
              composite_score: 0.21,
              dimensions: { d1: 0.1, d2: 0.0, d3: 0.1, d4: 0.0, d5: 0.0 },
            },
            meta: {
              actual_tier: 'L1',
              caller_adapter: 'codex-http',
            },
            l3_trace: null,
            recorded_at: '2026-04-14T08:05:10Z',
          },
        ],
        next_cursor: isRecentWindow ? null : 9,
      }) as never)
    })

    renderSessionDetail()

    expect(await screen.findByText('ls -la')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Load older' })).toBeInTheDocument()

    fireEvent.click(screen.getByRole('button', { name: 'Load older' }))
    expect(await screen.findByRole('alert')).toHaveTextContent('Could not load older replay records. Try again.')

    fireEvent.click(screen.getByRole('button', { name: 'Recent 1h' }))

    expect(await screen.findByText('recent ls -la')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Load older' })).not.toBeInTheDocument()
    expect(screen.queryByText('Could not load older replay records. Try again.')).not.toBeInTheDocument()

    const riskWindowParams = vi.mocked(api.sessionRisk).mock.calls.map(call => call[1])
    expect(riskWindowParams).toContainEqual({ windowSeconds: null })
    expect(riskWindowParams).toContainEqual({ windowSeconds: RECENT_WINDOW_SECONDS })

    const replayWindowParams = vi.mocked(api.sessionReplayPage).mock.calls.map(call => call[1])
    expect(replayWindowParams).toContainEqual({ windowSeconds: null })
    expect(replayWindowParams).toContainEqual({ cursor: 9, windowSeconds: null })
    expect(replayWindowParams).toContainEqual({ windowSeconds: RECENT_WINDOW_SECONDS })
    expect(replayWindowParams[replayWindowParams.length - 1]).toEqual({ windowSeconds: RECENT_WINDOW_SECONDS })
  })

  it('shows a visible error state when the initial session risk load fails', async () => {
    vi.mocked(api.sessionRisk).mockRejectedValueOnce(new Error('risk unavailable') as never)

    renderSessionDetail()

    expect(await screen.findByRole('alert')).toHaveTextContent('Could not load session detail. Try again.')
    expect(screen.getByRole('button', { name: 'Retry' })).toBeInTheDocument()
    expect(screen.queryByText('Decision timeline')).not.toBeInTheDocument()
  })

  it('shows a visible error state when the first replay page load fails', async () => {
    vi.mocked(api.sessionReplayPage).mockRejectedValueOnce(new Error('replay unavailable') as never)

    renderSessionDetail()

    expect(await screen.findByRole('alert')).toHaveTextContent('Could not load session detail. Try again.')
    expect(screen.getByRole('button', { name: 'Retry' })).toBeInTheDocument()
    expect(screen.queryByText('Decision timeline')).not.toBeInTheDocument()
  })

  it('renders the first replay page and allows loading older records', async () => {
    vi.mocked(api.sessionReplayPage)
      .mockResolvedValueOnce(makeReplayPageResponse({
        records: [
          {
            event: { tool_name: 'bash', input: 'ls -la' },
            decision: {
              decision: 'allow',
              reason: 'Safe read-only command',
              risk_level: 'low',
              decision_latency_ms: 42,
            },
            risk_snapshot: {
              risk_level: 'low',
              composite_score: 0.21,
              dimensions: { d1: 0.1, d2: 0.0, d3: 0.1, d4: 0.0, d5: 0.0 },
            },
            meta: {
              actual_tier: 'L1',
              caller_adapter: 'codex-http',
            },
            l3_trace: null,
            recorded_at: '2026-04-14T08:05:10Z',
          },
          {
            event: { tool_name: 'python', input: 'print("new")' },
            decision: {
              decision: 'allow',
              reason: 'Safe transform',
              risk_level: 'low',
              decision_latency_ms: 28,
            },
            risk_snapshot: {
              risk_level: 'low',
              composite_score: 0.18,
              dimensions: { d1: 0.0, d2: 0.0, d3: 0.1, d4: 0.0, d5: 0.0 },
            },
            meta: {
              actual_tier: 'L1',
              caller_adapter: 'codex-http',
            },
            l3_trace: null,
            recorded_at: '2026-04-14T08:05:20Z',
          },
        ],
        next_cursor: 9,
      }) as never)
      .mockResolvedValueOnce(makeReplayPageResponse({
        records: [
          {
            event: { tool_name: 'cat', input: 'cat older.txt' },
            decision: {
              decision: 'allow',
              reason: 'Older record',
              risk_level: 'low',
              decision_latency_ms: 36,
            },
            risk_snapshot: {
              risk_level: 'low',
              composite_score: 0.12,
              dimensions: { d1: 0.0, d2: 0.0, d3: 0.0, d4: 0.0, d5: 0.0 },
            },
            meta: {
              actual_tier: 'L1',
              caller_adapter: 'codex-http',
            },
            l3_trace: null,
            recorded_at: '2026-04-14T08:04:10Z',
          },
        ],
        next_cursor: null,
      }) as never)

    const { container } = renderSessionDetail()

    expect(await screen.findByText('ls -la')).toBeInTheDocument()
    expect(screen.getByText('print("new")')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Load older' })).toBeInTheDocument()

    fireEvent.click(screen.getByRole('button', { name: 'Load older' }))

    expect(await screen.findByText('cat older.txt')).toBeInTheDocument()
    const rows = container.querySelectorAll('.decision-timeline-row')
    expect(rows).toHaveLength(3)
    expect(within(rows[2] as HTMLElement).getByText('cat older.txt')).toBeInTheDocument()
  })

  it('shows an error when loading older replay records fails and keeps the pagination button visible', async () => {
    vi.mocked(api.sessionReplayPage)
      .mockResolvedValueOnce(makeReplayPageResponse({
        records: [
          {
            event: { tool_name: 'bash', input: 'ls -la' },
            decision: {
              decision: 'allow',
              reason: 'Safe read-only command',
              risk_level: 'low',
              decision_latency_ms: 42,
            },
            risk_snapshot: {
              risk_level: 'low',
              composite_score: 0.21,
              dimensions: { d1: 0.1, d2: 0.0, d3: 0.1, d4: 0.0, d5: 0.0 },
            },
            meta: {
              actual_tier: 'L1',
              caller_adapter: 'codex-http',
            },
            l3_trace: null,
            recorded_at: '2026-04-14T08:05:10Z',
          },
        ],
        next_cursor: 9,
      }) as never)
      .mockRejectedValueOnce(new Error('network down') as never)

    renderSessionDetail()

    expect(await screen.findByText('ls -la')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Load older' }))

    expect(await screen.findByRole('alert')).toHaveTextContent('Could not load older replay records. Try again.')
    expect(screen.getByRole('button', { name: 'Load older' })).toBeInTheDocument()
  })

  it('renders an exhaustion warning when the current budget is exhausted', async () => {
    vi.mocked(api.sessionRisk).mockResolvedValue(makeRiskResponse({
      budget: {
        daily_budget_usd: 10,
        daily_spend_usd: 10,
        remaining_usd: 0,
        exhausted: true,
      },
      budget_exhaustion_event: {
        type: 'budget_exhausted',
        timestamp: '2026-04-14T08:05:00Z',
        provider: 'openai',
        tier: 'L2',
        status: 'ok',
        cost_usd: 1.25,
        budget: {
          daily_budget_usd: 10,
          daily_spend_usd: 10,
          remaining_usd: 0,
          exhausted: true,
        },
      },
    }) as never)

    renderSessionDetail()

    expect(await screen.findByText('Token exhaustion event')).toBeInTheDocument()
    expect(screen.getByText(/Operator attention required/i)).toBeInTheDocument()
    expect(screen.getByText(/openai · L2/i)).toBeInTheDocument()
  })

  it('hides the load more button when no older replay pages remain', async () => {
    vi.mocked(api.sessionReplayPage).mockResolvedValueOnce(makeReplayPageResponse({
      records: [
        {
          event: { tool_name: 'bash', input: 'ls -la' },
          decision: {
            decision: 'allow',
            reason: 'Safe read-only command',
            risk_level: 'low',
            decision_latency_ms: 42,
          },
          risk_snapshot: {
            risk_level: 'low',
            composite_score: 0.21,
            dimensions: { d1: 0.1, d2: 0.0, d3: 0.1, d4: 0.0, d5: 0.0 },
          },
          meta: {
            actual_tier: 'L1',
            caller_adapter: 'codex-http',
          },
          l3_trace: null,
          recorded_at: '2026-04-14T08:05:10Z',
        },
      ],
      next_cursor: null,
    }) as never)

    renderSessionDetail()

    expect(await screen.findByText('ls -la')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Load older' })).not.toBeInTheDocument()
  })

  it('does not render a stale exhaustion warning after reset when the current budget is no longer exhausted', async () => {
    vi.mocked(api.sessionRisk).mockResolvedValue(makeRiskResponse({
      risk_timeline: [
        {
          event_id: 'evt-reset-1',
          occurred_at: '2026-04-13T23:59:59Z',
          risk_level: 'medium',
          composite_score: 0.71,
          tool_name: 'bash',
          decision: 'defer',
          actual_tier: 'L1',
          classified_by: 'L2',
          l3_reason_code: 'budget_exhausted',
        },
      ],
      budget: {
        daily_budget_usd: 10,
        daily_spend_usd: 0,
        remaining_usd: 10,
        exhausted: false,
      },
      budget_exhaustion_event: null,
    }) as never)

    renderSessionDetail()

    expect(await screen.findByText('Token governance')).toBeInTheDocument()
    expect(screen.getByText(/token limit disabled \/ unlimited · active/i)).toBeInTheDocument()
    expect(screen.queryByText('Token exhaustion event')).not.toBeInTheDocument()
  })
})
