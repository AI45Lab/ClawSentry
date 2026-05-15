import { useState, useEffect, useCallback } from 'react'
import { ShieldAlert, ShieldCheck, Clock } from 'lucide-react'
import { api, ApiError } from '../api/client'
import { connectSSE } from '../api/sse'
import CountdownTimer from '../components/CountdownTimer'
import EmptyState from '../components/EmptyState'
import type { SSEDeferPendingEvent, SSEDeferResolvedEvent } from '../api/types'
import { DEMO_FALLBACK_ENABLED, DEMO_RUNTIME_EVENTS } from '../lib/demoData'
import { usePreferences } from '../lib/preferences'

type DeferStatus = 'pending' | 'allowed' | 'denied' | 'expired'

interface DeferItem {
  approval_id: string
  session_id: string
  tool_name: string
  command: string
  reason: string
  timestamp: string
  approval_prompt?: SSEDeferPendingEvent['approval_prompt']
  expires_at?: number
  status: DeferStatus
}

function formatResolveActionLabel(
  action: 'Allow' | 'Deny',
  item: Pick<DeferItem, 'approval_id' | 'tool_name' | 'session_id' | 'command'>,
) {
  const command = item.command.trim()
  const commandLabel = command.length > 48 ? `${command.slice(0, 45)}...` : command
  const detail = commandLabel ? ` for command ${commandLabel}` : ''
  return `${action} approval ${item.tool_name} for session ${item.session_id}${detail} (${item.approval_id})`
}

function redactPromptContextValue(value?: string): string {
  return String(value || '')
    .replace(/\/workspace\/[^\s'"<>|)]+/g, '/workspace/<redacted>')
    .replace(/\/home\/[^\s'"<>|)]+/g, '/home/<redacted>')
    .replace(/~\/?[^\s'"<>|)]*/g, '~/<redacted>')
    .replace(/(token|password|secret|api_key)=([^\s&]+)/gi, '$1=<redacted>')
}

function promptFieldSourceLabel(
  item: DeferItem,
  field: string,
): string | null {
  const source = item.approval_prompt?.field_sources?.[field]
  if (!source) return null
  if (source === 'generated') return 'Generated guidance'
  if (source === 'adapter_provided') return 'Adapter-provided'
  if (source === 'unavailable') return 'Unavailable'
  return source
}

function PromptFieldSource({ item, field }: { item: DeferItem; field: string }) {
  const label = promptFieldSourceLabel(item, field)
  if (!label) return null
  return <span className="badge badge-neutral">{label}</span>
}

export default function DeferPanel() {
  const { t } = usePreferences()
  const [items, setItems] = useState<DeferItem[]>([])
  const [resolveAvailable, setResolveAvailable] = useState(true)
  const [demoMode, setDemoMode] = useState(false)

  useEffect(() => {
    const es = connectSSE(['defer_pending', 'defer_resolved'])
    es.addEventListener('defer_pending', (e: MessageEvent) => {
      try {
        const data: SSEDeferPendingEvent = JSON.parse(e.data)
        setItems(prev => {
          if (prev.some(item => item.approval_id === data.approval_id)) return prev
          const expiresAt = data.timeout_s > 0
            ? (Date.parse(data.timestamp) / 1000) + data.timeout_s
            : undefined
          return [{
            approval_id: data.approval_id,
            session_id: data.session_id,
            tool_name: data.tool_name,
            command: data.command,
            reason: data.reason,
            timestamp: data.timestamp,
            approval_prompt: data.approval_prompt,
            expires_at: expiresAt,
            status: 'pending',
          }, ...prev]
        })
      } catch { /* ignore */ }
    })
    es.addEventListener('defer_resolved', (e: MessageEvent) => {
      try {
        const data: SSEDeferResolvedEvent = JSON.parse(e.data)
        setItems(prev => prev.map(item =>
          item.approval_id === data.approval_id
            ? {
                ...item,
                status: data.resolved_decision === 'block' ? 'denied' : 'allowed',
                reason: data.resolved_reason || item.reason,
                timestamp: data.timestamp,
              }
            : item
        ))
      } catch { /* ignore */ }
    })
    return () => es.close()
  }, [])

  useEffect(() => {
    if (!DEMO_FALLBACK_ENABLED || items.length > 0) return undefined
    const timer = setTimeout(() => {
      const demoPending = DEMO_RUNTIME_EVENTS.find((event): event is SSEDeferPendingEvent & { type: 'defer_pending' } =>
        event.type === 'defer_pending',
      )
      if (!demoPending) return
      setItems([{
        approval_id: demoPending.approval_id,
        session_id: demoPending.session_id,
        tool_name: demoPending.tool_name,
        command: demoPending.command,
        reason: demoPending.reason,
        timestamp: demoPending.timestamp,
        expires_at: Date.now() / 1000 + demoPending.timeout_s,
        status: 'pending',
      }])
      setDemoMode(true)
    }, 800)
    return () => clearTimeout(timer)
  }, [items.length])

  const handleResolve = useCallback(async (approvalId: string, decision: 'allow-once' | 'deny') => {
    try {
      await api.resolve(approvalId, decision, decision === 'deny' ? 'operator denied via dashboard' : '')
      setItems(prev => prev.map(item =>
        item.approval_id === approvalId
          ? { ...item, status: decision === 'allow-once' ? 'allowed' : 'denied' }
          : item
      ))
    } catch (e) {
      if (e instanceof ApiError && e.status === 503) setResolveAvailable(false)
    }
  }, [])

  const handleExpired = useCallback((approvalId: string) => {
    setItems(prev => prev.map(item => {
      if (item.approval_id !== approvalId || item.status !== 'pending') return item

      const expiredAt = item.expires_at
        ? new Date(item.expires_at * 1000).toISOString()
        : new Date().toISOString()

      return { ...item, status: 'expired', timestamp: expiredAt }
    }))
  }, [])

  const pendingItems = items.filter(i => i.status === 'pending')
  const decisionItems = items.filter(i => i.status === 'allowed' || i.status === 'denied')
  const outcomeItems = items.filter(i => i.status !== 'pending')
  const expiredItems = items.filter(i => i.status === 'expired')

  return (
    <div className="workbench-shell">
      <section className="workbench-hero defer-hero" aria-labelledby="defer-approvals-title">
        <div className="workbench-hero-copy">
          <div className="eyebrow">{t('defer.hero.kicker')}</div>
          <h1 id="defer-approvals-title">
            <ShieldCheck size={20} className="workbench-title-icon" />
            {t('defer.hero.title')}
          </h1>
          {demoMode && <span className="showcase-pill">Showcase mode · demo approval</span>}
          <p className="workbench-hero-text">
            {t('defer.hero.copy')}
          </p>
        </div>
        <div className="workbench-hero-side">
          <span className={`badge ${pendingItems.length > 0 ? 'badge-defer' : 'badge-allow'}`}>
            {pendingItems.length} {t('defer.pending')}
          </span>
          <span className="workbench-hero-note">
            {resolveAvailable ? t('defer.resolveConnected') : t('defer.resolveUnavailable')}
          </span>
        </div>
      </section>

      <section className="workbench-section" aria-label="Defer approvals overview">
        <div className="section-card-header workbench-section-header">
          <div>
            <div className="section-kicker">{t('defer.overview')}</div>
            <h2>{t('defer.posture')}</h2>
          </div>
          <div className="section-meta">Pending decisions stream in over SSE and stay local to the operator view.</div>
        </div>
        <div className="workbench-summary-grid">
          <div className="workbench-summary-card">
            <span className="workbench-summary-label">Pending</span>
            <strong>{pendingItems.length} approvals waiting</strong>
            <p>Requests that still need an allow or deny decision.</p>
          </div>
          <div className="workbench-summary-card">
            <span className="workbench-summary-label">Operator decisions</span>
            <strong>{decisionItems.length} operator decisions</strong>
            <p>Approvals explicitly allowed or denied by an operator.</p>
          </div>
          <div className="workbench-summary-card">
            <span className="workbench-summary-label">Expired</span>
            <strong>{expiredItems.length} timed out</strong>
            <p>Pending requests that aged out before an operator decision.</p>
          </div>
          <div className="workbench-summary-card">
            <span className="workbench-summary-label">Operator channel</span>
            <strong>{resolveAvailable ? 'Interactive' : 'Read only'}</strong>
            <p>{resolveAvailable ? 'Actions are available for incoming approvals.' : 'Actions are disabled until enforcement reconnects.'}</p>
          </div>
        </div>
      </section>

      {!resolveAvailable && (
        <div className="card workbench-banner">
          <div className="workbench-banner-content">
            <ShieldAlert size={15} />
            Resolve not available — OpenClaw enforcement is not connected
          </div>
        </div>
      )}

      <section className="workbench-section" aria-label="Pending approvals queue">
        <div className="section-card-header workbench-section-header">
          <div>
            <div className="section-kicker">{t('defer.pendingQueue')}</div>
            <h2>{t('defer.pendingQueueTitle')}</h2>
          </div>
          <div className="section-meta">Due time, command scope, and operator actions are grouped per approval.</div>
        </div>
        {pendingItems.length === 0 ? (
          <div className="card workbench-empty-card">
            <EmptyState
              icon={<ShieldCheck size={20} />}
              title={t('defer.noPendingTitle')}
              subtitle={t('defer.noPendingSubtitle')}
            />
          </div>
        ) : (
          <div className="operator-list">
            {pendingItems.map(item => {
              const remaining = item.expires_at ? item.expires_at - Date.now() / 1000 : 999
              const isUrgent = remaining < 10
              return (
                <article
                  key={item.approval_id}
                  className={`operator-card defer-card ${isUrgent ? 'defer-card-critical' : 'defer-card-pending'}`}
                >
                  <div className="operator-card-main">
                    <div className="operator-card-topline">
                      <div className="operator-card-tags">
                        <span className="badge badge-defer">pending</span>
                        <span className="badge badge-neutral">{item.tool_name}</span>
                        {isUrgent && <span className="badge badge-block">due soon</span>}
                      </div>
                      <div className="operator-time">{new Date(item.timestamp).toLocaleTimeString()}</div>
                    </div>

                    <h3 className="operator-card-title">{item.tool_name}</h3>
                    <div className="cmd-snippet operator-command">{item.command || '—'}</div>
                    {item.reason && (
                      <p className="operator-card-description">{item.reason}</p>
                    )}
                    {item.approval_prompt && (
                      <div className="operator-card-meta approval-prompt-context">
                        {item.approval_prompt.affected_target && (
                          <div className="operator-meta-block">
                            <span className="operator-meta-label">Affected target</span>
                            <strong className="mono">{redactPromptContextValue(item.approval_prompt.affected_target)}</strong>
                            <PromptFieldSource item={item} field="affected_target" />
                          </div>
                        )}
                        {item.approval_prompt.operation && (
                          <div className="operator-meta-block">
                            <span className="operator-meta-label">Operation</span>
                            <strong>{item.approval_prompt.operation}</strong>
                            <PromptFieldSource item={item} field="operation" />
                          </div>
                        )}
                        {item.approval_prompt.consequence && (
                          <div className="operator-meta-block">
                            <span className="operator-meta-label">Consequence</span>
                            <strong>{redactPromptContextValue(item.approval_prompt.consequence)}</strong>
                            <PromptFieldSource item={item} field="consequence" />
                          </div>
                        )}
                        {item.approval_prompt.dry_run_or_narrower_scope_suggestion && (
                          <div className="operator-meta-block">
                            <span className="operator-meta-label">Safer option</span>
                            <strong>{item.approval_prompt.dry_run_or_narrower_scope_suggestion}</strong>
                            <PromptFieldSource item={item} field="dry_run_or_narrower_scope_suggestion" />
                          </div>
                        )}
                        {item.approval_prompt.rollback_hint && (
                          <div className="operator-meta-block">
                            <span className="operator-meta-label">Rollback hint</span>
                            <strong>{redactPromptContextValue(item.approval_prompt.rollback_hint)}</strong>
                            <PromptFieldSource item={item} field="rollback_hint" />
                          </div>
                        )}
                      </div>
                    )}

                    <div className="operator-card-meta">
                      <div className="operator-meta-block">
                        <span className="operator-meta-label">Session</span>
                        <strong className="mono">{item.session_id}</strong>
                      </div>
                      <div className="operator-meta-block">
                        <span className="operator-meta-label">Pending state</span>
                        <strong>{resolveAvailable ? 'Operator decision required' : 'Awaiting reconnection'}</strong>
                      </div>
                      <div className="operator-meta-block">
                        <span className="operator-meta-label">Command</span>
                        <strong className="mono">{item.command || '—'}</strong>
                      </div>
                    </div>
                  </div>

                  <div className="operator-card-side">
                    <div className="operator-side-panel">
                      <span className="operator-meta-label">Due time</span>
                      {item.expires_at ? (
                        <CountdownTimer
                          expiresAt={item.expires_at}
                          onExpired={() => handleExpired(item.approval_id)}
                        />
                      ) : (
                        <div className="operator-no-timeout">
                          <Clock size={13} className="text-muted" />
                          <span className="mono text-muted operator-no-timeout-copy">{t('defer.noTimeout')}</span>
                        </div>
                      )}
                    </div>

                    <div className="operator-action-group">
                      <button
                        className="btn btn-allow"
                        onClick={() => handleResolve(item.approval_id, 'allow-once')}
                        disabled={!resolveAvailable}
                        aria-label={formatResolveActionLabel('Allow', item)}
                      >
                        {t('defer.allow')}
                      </button>
                      <button
                        className="btn btn-deny"
                        onClick={() => handleResolve(item.approval_id, 'deny')}
                        disabled={!resolveAvailable}
                        aria-label={formatResolveActionLabel('Deny', item)}
                      >
                        {t('defer.deny')}
                      </button>
                    </div>
                  </div>
                </article>
              )
            })}
          </div>
        )}
      </section>

      <section className="workbench-section" aria-label="Approval outcomes history">
          <div className="section-card-header workbench-section-header">
            <div>
              <div className="section-kicker">{t('defer.history')}</div>
              <h2>{t('defer.historyTitle')}</h2>
            </div>
            <div className="section-meta">Operator decisions and timed-out requests stay visible for quick operator audit.</div>
          </div>
          {outcomeItems.length === 0 ? (
            <div className="card workbench-empty-card">
              <EmptyState
                icon={<ShieldCheck size={20} />}
                title={t('defer.noOutcomesTitle')}
                subtitle={t('defer.noOutcomesSubtitle')}
              />
            </div>
          ) : (
            <div className="operator-history-list">
              {outcomeItems.map(item => (
                <div key={item.approval_id} className="operator-history-card">
                  <span className={`badge ${item.status === 'allowed' ? 'badge-allow' : item.status === 'denied' ? 'badge-block' : 'badge-defer'}`}>
                    {item.status}
                  </span>
                  <span className="mono">{item.tool_name}</span>
                  <span className="cmd-snippet operator-history-command">{item.command || '—'}</span>
                  {item.status === 'expired' && (
                    <span className="text-muted">Timed out without an operator decision</span>
                  )}
                  <span className="text-muted mono operator-history-time">
                    {new Date(item.timestamp).toLocaleTimeString()}
                  </span>
                </div>
              ))}
            </div>
          )}
        </section>
    </div>
  )
}
