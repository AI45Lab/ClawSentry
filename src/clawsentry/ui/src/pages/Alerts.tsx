import { useState, useEffect, useCallback } from 'react'
import { Link } from 'react-router-dom'
import { CheckCircle, XCircle, RefreshCw } from 'lucide-react'
import { api } from '../api/client'
import { connectSSE } from '../api/sse'
import type { Alert, SSEAlertEvent } from '../api/types'

const SEVERITY_COLORS: Record<string, string> = {
  warning: 'var(--color-defer)',
  critical: 'var(--color-block)',
  info: 'var(--color-accent)',
}

export default function Alerts() {
  const [alerts, setAlerts] = useState<Alert[]>([])
  const [loading, setLoading] = useState(true)
  const [severity, setSeverity] = useState<string>('')
  const [showAcknowledged, setShowAcknowledged] = useState<boolean | undefined>(undefined)

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const data = await api.alerts({
        severity: severity || undefined,
        acknowledged: showAcknowledged,
        limit: 100,
      })
      setAlerts(data)
    } catch { /* ignore */ }
    setLoading(false)
  }, [severity, showAcknowledged])

  useEffect(() => { load() }, [load])

  useEffect(() => {
    const timer = setInterval(load, 30_000)
    return () => clearInterval(timer)
  }, [load])

  // SSE: auto-prepend new alerts
  useEffect(() => {
    const es = connectSSE(['alert'])
    es.addEventListener('alert', (e: MessageEvent) => {
      try {
        const data: SSEAlertEvent = JSON.parse(e.data)
        // Create an Alert-like object from the SSE event
        const newAlert: Alert = {
          alert_id: data.alert_id,
          severity: data.severity,
          metric: data.metric,
          session_id: data.session_id,
          message: data.message,
          details: {},
          triggered_at: data.timestamp,
          acknowledged: false,
          acknowledged_by: null,
          acknowledged_at: null,
        }
        setAlerts(prev => [newAlert, ...prev])
      } catch { /* ignore */ }
    })
    return () => es.close()
  }, [])

  const handleAcknowledge = async (alertId: string) => {
    try {
      await api.acknowledgeAlert(alertId)
      setAlerts(prev => prev.map(a =>
        a.alert_id === alertId
          ? { ...a, acknowledged: true, acknowledged_by: 'dashboard', acknowledged_at: new Date().toISOString() }
          : a
      ))
    } catch { /* ignore */ }
  }

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
        <h2 className="section-header" style={{ marginBottom: 0, borderBottom: 'none', paddingBottom: 0 }}>
          Alerts Workbench
        </h2>
        <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
          <select
            value={severity}
            onChange={e => setSeverity(e.target.value)}
            style={{
              background: 'var(--color-surface-raised)',
              color: 'var(--color-text)',
              border: '1px solid var(--color-border)',
              borderRadius: 'var(--radius)',
              padding: '6px 10px',
              fontFamily: 'var(--font-mono)',
              fontSize: '0.75rem',
            }}
          >
            <option value="">All Severities</option>
            <option value="info">Info</option>
            <option value="warning">Warning</option>
            <option value="critical">Critical</option>
          </select>
          <select
            value={showAcknowledged === undefined ? '' : String(showAcknowledged)}
            onChange={e => {
              const v = e.target.value
              setShowAcknowledged(v === '' ? undefined : v === 'true')
            }}
            style={{
              background: 'var(--color-surface-raised)',
              color: 'var(--color-text)',
              border: '1px solid var(--color-border)',
              borderRadius: 'var(--radius)',
              padding: '6px 10px',
              fontFamily: 'var(--font-mono)',
              fontSize: '0.75rem',
            }}
          >
            <option value="">All Status</option>
            <option value="false">Unacknowledged</option>
            <option value="true">Acknowledged</option>
          </select>
          <button className="btn" onClick={load} disabled={loading}>
            <RefreshCw size={14} style={loading ? { animation: 'spin 1s linear infinite' } : undefined} />
          </button>
        </div>
      </div>

      <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
        <table>
          <thead>
            <tr>
              <th>Severity</th>
              <th>Metric</th>
              <th>Session</th>
              <th>Message</th>
              <th>Triggered</th>
              <th>Status</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {alerts.map(alert => (
              <tr key={alert.alert_id} style={alert.acknowledged ? { opacity: 0.5 } : undefined}>
                <td>
                  <span className="mono" style={{
                    fontSize: '0.75rem',
                    fontWeight: 600,
                    color: SEVERITY_COLORS[alert.severity] || 'var(--color-text)',
                    textTransform: 'uppercase',
                  }}>
                    {alert.severity}
                  </span>
                </td>
                <td className="mono" style={{ fontSize: '0.8rem' }}>{alert.metric}</td>
                <td>
                  <Link
                    to={`/sessions/${alert.session_id}`}
                    style={{ color: 'var(--color-accent)', textDecoration: 'none', fontFamily: 'var(--font-mono)', fontSize: '0.75rem' }}
                  >
                    {(alert.session_id ?? '').length > 12
                      ? (alert.session_id ?? '').slice(0, 12) + '...'
                      : (alert.session_id ?? '—')}
                  </Link>
                </td>
                <td className="text-secondary" style={{ fontSize: '0.8rem', maxWidth: 300, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                  {alert.message}
                </td>
                <td className="mono text-muted" style={{ fontSize: '0.7rem' }}>
                  {new Date(alert.triggered_at).toLocaleString()}
                </td>
                <td>
                  {alert.acknowledged ? (
                    <span style={{ display: 'flex', alignItems: 'center', gap: 4, color: 'var(--color-allow)', fontSize: '0.75rem' }}>
                      <CheckCircle size={14} /> ACK
                    </span>
                  ) : (
                    <span style={{ display: 'flex', alignItems: 'center', gap: 4, color: 'var(--color-defer)', fontSize: '0.75rem' }}>
                      <XCircle size={14} /> OPEN
                    </span>
                  )}
                </td>
                <td>
                  {!alert.acknowledged && (
                    <button
                      className="btn btn-primary"
                      style={{ padding: '4px 10px', fontSize: '0.7rem' }}
                      onClick={() => handleAcknowledge(alert.alert_id)}
                    >
                      Acknowledge
                    </button>
                  )}
                </td>
              </tr>
            ))}
            {alerts.length === 0 && !loading && (
              <tr><td colSpan={7} className="text-muted" style={{ textAlign: 'center', padding: 24 }}>No alerts found</td></tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  )
}
