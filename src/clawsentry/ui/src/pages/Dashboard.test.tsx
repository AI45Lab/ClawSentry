import { render, screen, within } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import Dashboard from './Dashboard'
import { api } from '../api/client'

vi.mock('../api/client', () => ({
  api: {
    summary: vi.fn(),
    health: vi.fn(),
    sessions: vi.fn(),
    policyDrift: vi.fn(),
  },
}))

vi.mock('../components/RuntimeFeed', () => ({
  default: () => (
    <section aria-label="Live activity feed">
      <h2>Live Activity Feed</h2>
      <p data-testid="runtime-feed-stub">Streaming feed stub</p>
    </section>
  ),
}))

function makeSessionSummary(overrides: Record<string, unknown> = {}) {
  return {
    session_id: 'sess-123',
    agent_id: 'agent-1',
    source_framework: 'codex',
    caller_adapter: 'codex-http',
    workspace_root: '/workspace/demo',
    transcript_path: '/workspace/demo/session.jsonl',
    current_risk_level: 'medium',
    cumulative_score: 0.62,
    event_count: 12,
    high_risk_event_count: 2,
    decision_distribution: { allow: 10, block: 2 },
    first_event_at: '2026-04-15T07:00:00Z',
    last_event_at: '2026-04-15T07:15:00Z',
    l3_state: 'degraded',
    l3_reason_code: 'toolkit_budget_exhausted',
    evidence_summary: {
      retained_sources: ['trajectory', 'file'],
      tool_calls_count: 3,
      toolkit_budget_mode: 'multi_turn',
      toolkit_budget_cap: 5,
      toolkit_calls_remaining: 0,
      toolkit_budget_exhausted: true,
    },
    ...overrides,
  }
}

function makeSummaryResponse() {
  return {
    total_records: 12,
    by_source_framework: { codex: 1 },
    by_event_type: { decision: 12 },
    by_decision: { allow: 10, block: 2 },
    by_risk_level: { medium: 1 },
    by_actual_tier: { L2: 1 },
    by_caller_adapter: { 'codex-http': 1 },
    generated_at: '2026-04-15T07:15:00Z',
    window_seconds: null,
    system_security_posture: {
      posture_score: 0.82,
      risk_level: 'high',
      latest_composite_score: 0.91,
      session_risk_ewma: 0.74,
      risk_velocity: 'up',
      control_health: {
        enforced_sessions: 2,
        released_sessions: 4,
        l3_required_sessions: 1,
      },
      window_risk_summary: {
        window_seconds: 3600,
        event_count: 18,
        high_risk_event_count: 5,
        risk_density: 0.28,
      },
    },
    budget: {
      daily_budget_usd: 10,
      daily_spend_usd: 3.25,
      remaining_usd: 6.75,
      exhausted: false,
    },
    budget_exhaustion_event: null,
    llm_usage_snapshot: {
      total_calls: 4,
      total_input_tokens: 100,
      total_output_tokens: 50,
      total_cost_usd: 1.23,
      by_provider: {},
      by_tier: {},
      by_status: {},
    },
  }
}

function makeHealthResponse() {
  return {
    status: 'ok',
    uptime_seconds: 7200,
    cache_size: 3,
    trajectory_count: 12,
    policy_engine: 'default',
    auth_enabled: true,
    budget: {
      daily_budget_usd: 10,
      daily_spend_usd: 3.25,
      remaining_usd: 6.75,
      exhausted: false,
    },
    budget_exhaustion_event: null,
    llm_usage_snapshot: {
      total_calls: 4,
      total_input_tokens: 100,
      total_output_tokens: 50,
      total_cost_usd: 1.23,
      by_provider: {},
      by_tier: {},
      by_status: {},
    },
  }
}

function makePolicyDriftResponse() {
  return {
    generated_at: '2026-04-15T07:15:00Z',
    window_seconds: 300,
    comparison_window_seconds: 300,
    grouping_dimensions: ['workspace_root', 'source_framework', 'session_id', 'rule_family'],
    total_cells: 1,
    metric_cell_traceability: {
      passed: false,
      coverage: 0,
      total_cells: 1,
      cell_count: 1,
      complete_cell_count: 0,
      required_fields: ['request_ids', 'fallback_paths'],
      conditional_fields: ['rule_evidence', 'registry_states', 'adapter_effect_result_ids'],
      incomplete_cells: [
        {
          workspace_root: '/workspace/demo',
          source_framework: 'codex',
          session_id: 'sess-123',
          rule_family: 'skill_trust',
          missing_fields: ['fallback_paths'],
        },
      ],
    },
    cells: [
      {
        cell_id: '/workspace/demo|codex|sess-123|skill_trust',
        workspace_root: '/workspace/demo',
        source_framework: 'codex',
        session_id: 'sess-123',
        rule_family: 'skill_trust',
        current: {
          record_count: 2,
          decision_distribution: { block: 1, allow: 1 },
          risk_distribution: { high: 1, low: 1 },
          rule_hits: { ambiguous_skill_alias: 1 },
          block_rate: 0.5,
          high_or_critical_rate: 0.5,
        },
        previous: {
          record_count: 1,
          decision_distribution: { allow: 1 },
          risk_distribution: { low: 1 },
          rule_hits: {},
          block_rate: 0,
          high_or_critical_rate: 0,
        },
        delta: { record_count: 1, block_rate: 0.5, high_or_critical_rate: 0.5 },
        traceability: {
          request_ids: ['req-123'],
          record_ids: ['42'],
          event_ids: ['evt-123'],
          registry_states: ['unlisted'],
          rule_evidence: ['ambiguous_skill_alias'],
          fallback_paths: [],
          adapter_effect_result_ids: [],
        },
        traceability_applicability: {
          rule_evidence: true,
          registry_states: true,
          adapter_effect_result_ids: false,
        },
      },
    ],
  }
}

function renderDashboard() {
  return render(
    <MemoryRouter future={{ v7_startTransition: true, v7_relativeSplatPath: true }}>
      <Dashboard />
    </MemoryRouter>,
  )
}

describe('Dashboard', () => {
  beforeEach(() => {
    vi.mocked(api.summary).mockResolvedValue(makeSummaryResponse() as never)
    vi.mocked(api.health).mockResolvedValue(makeHealthResponse() as never)
    vi.mocked(api.sessions).mockResolvedValue([makeSessionSummary()] as never)
    vi.mocked(api.policyDrift).mockResolvedValue(makePolicyDriftResponse() as never)
  })

  it('composes the dashboard regions and key widgets', async () => {
    const { container } = renderDashboard()

    expect(await screen.findByRole('region', { name: /global posture/i })).toBeInTheDocument()
    expect(screen.getByRole('region', { name: /operational scan/i })).toBeInTheDocument()
    expect(screen.getByRole('region', { name: /deep inspection/i })).toBeInTheDocument()
    expect(screen.getByRole('region', { name: /llm usage drill-down/i })).toBeInTheDocument()
    expect(screen.getByRole('region', { name: /live activity feed/i })).toBeInTheDocument()
    expect(screen.getByText('Live Activity Feed')).toBeInTheDocument()
    expect(screen.getByRole('heading', { name: /what to inspect first/i })).toBeInTheDocument()
    expect(screen.getByText('1 · Start here')).toBeInTheDocument()
    expect(screen.getByText('2 · Evidence')).toBeInTheDocument()
    expect(screen.getByText('3 · Live stream')).toBeInTheDocument()
    expect(await screen.findByText('Toolkit evidence quota hotspots')).toBeInTheDocument()
    expect(screen.getByText('Toolkit Evidence Quota')).toBeInTheDocument()

    const metricCard = Array.from(container.querySelectorAll('.metric-card')).find(card =>
      card.textContent?.includes('Toolkit Evidence Quota'),
    )
    expect(metricCard).toBeTruthy()
    expect(within(metricCard as HTMLElement).getByText('1')).toBeInTheDocument()

    const hotspotSection = screen.getByText('Toolkit evidence quota hotspots').closest('section')
    expect(hotspotSection).not.toBeNull()
    expect(within(hotspotSection as HTMLElement).getByText('sess-123')).toBeInTheDocument()
    expect(screen.getByText('Toolkit evidence quota exhausted · codex · 12 events')).toBeInTheDocument()
    expect(await screen.findByText('Policy drift cells')).toBeInTheDocument()
    expect(screen.getByText('Traceability 0%')).toBeInTheDocument()
    expect(screen.getByText('skill_trust · codex')).toBeInTheDocument()
    expect(screen.getByText('missing fallback_paths')).toBeInTheDocument()
    expect(screen.getByRole('link', { name: /open session replay for skill_trust drift cell/i })).toHaveAttribute(
      'href',
      '/sessions/sess-123?event=evt-123&request=req-123',
    )
  })

  it('shows an empty hotspot state when no sessions hit toolkit evidence budget', async () => {
    vi.mocked(api.sessions).mockResolvedValue([
      makeSessionSummary({
        session_id: 'sess-clean',
        evidence_summary: {
          retained_sources: ['trajectory'],
          tool_calls_count: 1,
          toolkit_budget_mode: 'multi_turn',
          toolkit_budget_cap: 5,
          toolkit_calls_remaining: 2,
          toolkit_budget_exhausted: false,
        },
      }),
    ] as never)

    const { container } = renderDashboard()

    expect(await screen.findByRole('region', { name: /global posture/i })).toBeInTheDocument()
    expect(screen.getByRole('region', { name: /operational scan/i })).toBeInTheDocument()
    expect(screen.getByRole('region', { name: /deep inspection/i })).toBeInTheDocument()
    expect(await screen.findByText('Toolkit evidence quota hotspots')).toBeInTheDocument()
    const metricCard = Array.from(container.querySelectorAll('.metric-card')).find(card =>
      card.textContent?.includes('Toolkit Evidence Quota'),
    )
    expect(metricCard).toBeTruthy()
    expect(within(metricCard as HTMLElement).getByText('0')).toBeInTheDocument()
    expect(screen.getByText('No sessions are currently hitting toolkit evidence quota.')).toBeInTheDocument()
  })

  it('surfaces system security posture, control health, and risk velocity metrics', async () => {
    renderDashboard()

    expect((await screen.findAllByText('System security posture')).length).toBeGreaterThan(0)
    expect(screen.getByText('Posture score 0.82')).toBeInTheDocument()
    expect(screen.getByText('Control health: 2 enforced · 4 released · 1 L3 required')).toBeInTheDocument()
    expect(screen.getByText('Risk velocity up · density 0.28')).toBeInTheDocument()
  })
})
