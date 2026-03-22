import type {
  HealthResponse,
  SummaryResponse,
  SessionSummary,
  SessionRisk,
  TrajectoryRecord,
  Alert,
} from './types'

let _token: string | null = null

export function setToken(token: string) {
  _token = token
  sessionStorage.setItem('ahp_token', token)
}

export function getToken(): string | null {
  if (!_token) {
    _token = sessionStorage.getItem('ahp_token')
  }
  return _token
}

export function clearToken() {
  _token = null
  sessionStorage.removeItem('ahp_token')
}

export class AuthError extends Error {
  name = 'AuthError' as const
}
export class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
  ) {
    super(message)
    this.name = 'ApiError'
  }
}

async function apiFetch<T>(path: string, init?: RequestInit): Promise<T> {
  const token = getToken()
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    ...((init?.headers as Record<string, string>) || {}),
  }
  if (token) {
    headers['Authorization'] = `Bearer ${token}`
  }
  const resp = await fetch(path, { ...init, headers })
  if (resp.status === 401) {
    clearToken()
    throw new AuthError('Unauthorized')
  }
  if (!resp.ok) {
    throw new ApiError(resp.status, await resp.text())
  }
  return resp.json()
}

export const api = {
  health: () => apiFetch<HealthResponse>('/health'),
  summary: (windowSeconds?: number) =>
    apiFetch<SummaryResponse>(
      `/report/summary${windowSeconds ? `?window_seconds=${windowSeconds}` : ''}`,
    ),
  sessions: async (params?: { sort?: string; limit?: number; min_risk?: string }) => {
    const qs = new URLSearchParams()
    if (params?.sort) qs.set('sort', params.sort)
    if (params?.limit) qs.set('limit', String(params.limit))
    if (params?.min_risk) qs.set('min_risk', params.min_risk)
    const result = await apiFetch<{ sessions: SessionSummary[] }>(`/report/sessions?${qs}`)
    return result.sessions ?? []
  },
  sessionRisk: (id: string) => apiFetch<SessionRisk>(`/report/session/${id}/risk`),
  sessionReplay: async (id: string, limit?: number) => {
    const result = await apiFetch<{ records: TrajectoryRecord[] }>(
      `/report/session/${id}${limit ? `?limit=${limit}` : ''}`,
    )
    return result.records ?? []
  },
  alerts: async (params?: { severity?: string; acknowledged?: boolean; limit?: number }) => {
    const qs = new URLSearchParams()
    if (params?.severity) qs.set('severity', params.severity)
    if (params?.acknowledged !== undefined)
      qs.set('acknowledged', String(params.acknowledged))
    if (params?.limit) qs.set('limit', String(params.limit))
    const result = await apiFetch<{ alerts: Alert[] }>(`/report/alerts?${qs}`)
    return result.alerts ?? []
  },
  acknowledgeAlert: (id: string) =>
    apiFetch<{ status: string }>(`/report/alerts/${id}/acknowledge`, {
      method: 'POST',
    }),
  resolve: (approvalId: string, decision: string, reason?: string) =>
    apiFetch<{ status: string; approval_id: string }>('/ahp/resolve', {
      method: 'POST',
      body: JSON.stringify({
        approval_id: approvalId,
        decision,
        reason: reason || '',
      }),
    }),
}
