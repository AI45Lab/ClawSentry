import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import DeferPanel from './DeferPanel'
import { ApiError, api } from '../api/client'
import { connectSSE } from '../api/sse'

vi.mock('../api/client', async () => {
  const actual = await vi.importActual<typeof import('../api/client')>('../api/client')
  return {
    ...actual,
    api: {
      ...actual.api,
      resolve: vi.fn(),
    },
  }
})

vi.mock('../api/sse', () => ({
  connectSSE: vi.fn(),
}))

vi.mock('../lib/demoData', async () => {
  const actual = await vi.importActual<typeof import('../lib/demoData')>('../lib/demoData')
  return {
    ...actual,
    DEMO_FALLBACK_ENABLED: false,
  }
})

vi.mock('../components/CountdownTimer', () => ({
  default: ({ expiresAt, onExpired }: { expiresAt: number, onExpired?: () => void }) => (
    <div>
      <span className="mono">Due at {new Date(expiresAt * 1000).toLocaleTimeString()}</span>
      {onExpired && (
        <button type="button" onClick={onExpired}>
          Mark expired
        </button>
      )}
    </div>
  ),
}))

class MockEventSource {
  private listeners = new Map<string, Array<(event: MessageEvent) => void>>()

  addEventListener(type: string, listener: (event: MessageEvent) => void) {
    const current = this.listeners.get(type) ?? []
    current.push(listener)
    this.listeners.set(type, current)
  }

  close = vi.fn()

  emit(type: string, payload: unknown) {
    const event = new MessageEvent(type, { data: JSON.stringify(payload) })
    for (const listener of this.listeners.get(type) ?? []) {
      listener(event)
    }
  }
}

function renderDeferPanel() {
  return render(<DeferPanel />)
}

describe('Defer approvals workbench', () => {
  let eventSource: MockEventSource

  beforeEach(() => {
    eventSource = new MockEventSource()
    vi.mocked(connectSSE).mockReturnValue(eventSource as unknown as EventSource)
    vi.mocked(api.resolve).mockResolvedValue({ status: 'ok', approval_id: 'approval-1' } as never)
  })

  afterEach(() => {
    vi.useRealTimers()
  })

  it('renders the approvals queue hierarchy and moves resolved work into history', async () => {
    renderDeferPanel()

    expect(screen.getByRole('heading', { level: 1, name: /defer approvals/i })).toBeInTheDocument()
    expect(screen.getByRole('region', { name: /defer approvals overview/i })).toBeInTheDocument()
    expect(screen.getByRole('region', { name: /pending approvals queue/i })).toBeInTheDocument()
    expect(screen.getByRole('region', { name: /approval outcomes history/i })).toBeInTheDocument()
    expect(screen.getByText('No pending DEFER decisions')).toBeInTheDocument()
    expect(screen.getByText('No approval outcomes yet')).toBeInTheDocument()

    eventSource.emit('defer_pending', {
      approval_id: 'approval-1',
      session_id: 'sess-123',
      tool_name: 'shell',
      command: 'npm publish',
      reason: 'Outbound package publication requested',
      timeout_s: 45,
      timestamp: '2026-04-15T09:00:00Z',
      approval_prompt: {
        affected_target: '/workspace/package',
        operation: 'shell',
        consequence: 'Approving publishes the package.',
        dry_run_or_narrower_scope_suggestion: 'Run npm publish --dry-run first.',
        rollback_hint: 'Use npm deprecate if the package is published incorrectly.',
        field_sources: {
          affected_target: 'adapter_provided',
          operation: 'adapter_provided',
          consequence: 'generated',
          dry_run_or_narrower_scope_suggestion: 'generated',
          rollback_hint: 'generated',
        },
      },
    })

    const pendingQueue = screen.getByRole('region', { name: /pending approvals queue/i })
    expect(await within(pendingQueue).findByRole('heading', { level: 3, name: 'shell' })).toBeInTheDocument()
    expect(within(pendingQueue).getByText('Outbound package publication requested')).toBeInTheDocument()
    expect(within(pendingQueue).getByText('Affected target')).toBeInTheDocument()
    expect(within(pendingQueue).getByText('/workspace/<redacted>')).toBeInTheDocument()
    expect(within(pendingQueue).getByText('Consequence')).toBeInTheDocument()
    expect(within(pendingQueue).getByText('Approving publishes the package.')).toBeInTheDocument()
    expect(within(pendingQueue).getByText('Safer option')).toBeInTheDocument()
    expect(within(pendingQueue).getByText('Run npm publish --dry-run first.')).toBeInTheDocument()
    expect(within(pendingQueue).getAllByText('Generated guidance')).toHaveLength(3)
    expect(within(pendingQueue).getAllByText('Adapter-provided')).toHaveLength(2)
    expect(within(pendingQueue).getByText('Rollback hint')).toBeInTheDocument()
    expect(within(pendingQueue).getByText('Use npm deprecate if the package is published incorrectly.')).toBeInTheDocument()
    expect(within(pendingQueue).getByText(/due at/i)).toBeInTheDocument()

    fireEvent.click(screen.getByRole('button', { name: /allow approval shell/i }))

    await waitFor(() => {
      expect(api.resolve).toHaveBeenCalledWith('approval-1', 'allow-once', '')
    })

    const resolvedQueue = await screen.findByRole('region', { name: /approval outcomes history/i })
    expect(within(resolvedQueue).getByText('allowed')).toBeInTheDocument()
    expect(within(resolvedQueue).getByText('npm publish')).toBeInTheDocument()
  })

  it('surfaces resolve availability failures and disables queue actions', async () => {
    vi.mocked(api.resolve).mockRejectedValue(new ApiError(503, 'offline'))

    renderDeferPanel()

    eventSource.emit('defer_pending', {
      approval_id: 'approval-2',
      session_id: 'sess-789',
      tool_name: 'network',
      command: 'curl https://example.com',
      reason: 'External network call requested',
      timeout_s: 15,
      timestamp: '2026-04-15T09:10:00Z',
    })

    expect(await screen.findByText('External network call requested')).toBeInTheDocument()

    fireEvent.click(screen.getByRole('button', { name: /deny approval network/i }))

    await screen.findByText(/resolve not available/i)
    expect(screen.getByRole('button', { name: /allow approval network/i })).toBeDisabled()
    expect(screen.getByRole('button', { name: /deny approval network/i })).toBeDisabled()
  })

  it('uses unique accessible action names when approvals share the same tool name and session id', async () => {
    renderDeferPanel()

    eventSource.emit('defer_pending', {
      approval_id: 'approval-a',
      session_id: 'sess-123',
      tool_name: 'shell',
      command: 'npm publish --tag next',
      reason: 'First shell request',
      timeout_s: 45,
      timestamp: '2026-04-15T09:00:00Z',
    })
    eventSource.emit('defer_pending', {
      approval_id: 'approval-b',
      session_id: 'sess-123',
      tool_name: 'shell',
      command: 'npm publish --otp 123456',
      reason: 'Second shell request',
      timeout_s: 45,
      timestamp: '2026-04-15T09:01:00Z',
    })

    expect(await screen.findByRole('button', { name: /allow approval shell for session sess-123 for command npm publish --tag next \(approval-a\)/i })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /allow approval shell for session sess-123 for command npm publish --otp 123456 \(approval-b\)/i })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /deny approval shell for session sess-123 for command npm publish --tag next \(approval-a\)/i })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /deny approval shell for session sess-123 for command npm publish --otp 123456 \(approval-b\)/i })).toBeInTheDocument()
  })

  it('keeps expired approvals out of the operator decision count and records the expiration timestamp in history', async () => {
    const requestTimestamp = '2026-04-15T09:10:00Z'
    const timeoutSeconds = 15
    const expiredAt = new Date(Date.parse(requestTimestamp) + timeoutSeconds * 1000)
    const callbackRanAt = new Date('2026-04-15T09:10:42Z')

    renderDeferPanel()

    eventSource.emit('defer_pending', {
      approval_id: 'approval-expired',
      session_id: 'sess-expired',
      tool_name: 'network',
      command: 'curl https://example.com',
      reason: 'External network call requested',
      timeout_s: timeoutSeconds,
      timestamp: requestTimestamp,
    })

    expect(await screen.findByText('External network call requested')).toBeInTheDocument()
    vi.useFakeTimers()
    vi.setSystemTime(callbackRanAt)

    fireEvent.click(screen.getByRole('button', { name: /mark expired/i }))

    const overview = screen.getByRole('region', { name: /defer approvals overview/i })
    expect(within(overview).getByText('0 operator decisions')).toBeInTheDocument()
    expect(within(overview).getByText('1 timed out')).toBeInTheDocument()

    const history = screen.getByRole('region', { name: /approval outcomes history/i })
    expect(within(history).getByRole('heading', { level: 2, name: /approval outcomes history/i })).toBeInTheDocument()
    expect(within(history).getByText('expired')).toBeInTheDocument()
    expect(within(history).getByText(/timed out without an operator decision/i)).toBeInTheDocument()
    expect(within(history).getByText(expiredAt.toLocaleTimeString())).toBeInTheDocument()
    expect(within(history).queryByText(callbackRanAt.toLocaleTimeString())).not.toBeInTheDocument()
  })
})
