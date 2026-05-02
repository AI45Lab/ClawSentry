import type {
  HealthResponse,
  SummaryResponse,
  SessionSummary,
  SessionRiskResponse,
  SessionPostActionScores,
  SessionReplayPageResponse,
  SessionReplayResponse,
  Alert,
  L3FullReviewResponse,
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

function withQuery(path: string, qs: URLSearchParams): string {
  const query = qs.toString()
  return query ? `${path}?${query}` : path
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
    const result = await apiFetch<{ sessions: SessionSummary[] }>(withQuery('/report/sessions', qs))
    return result.sessions ?? []
  },
  sessionRisk: (id: string, params?: { windowSeconds?: number | null }) => {
    const qs = new URLSearchParams()
    if (params?.windowSeconds !== undefined && params?.windowSeconds !== null) {
      qs.set('window_seconds', String(params.windowSeconds))
    }
    return apiFetch<SessionRiskResponse>(
      `/report/session/${id}/risk${qs.toString() ? `?${qs.toString()}` : ''}`,
    )
  },
  sessionPostActionScores: (
    id: string,
    params?: { limit?: number; windowSeconds?: number | null },
  ) => {
    const qs = new URLSearchParams()
    if (params?.limit) qs.set('limit', String(params.limit))
    if (params?.windowSeconds !== undefined && params?.windowSeconds !== null) {
      qs.set('window_seconds', String(params.windowSeconds))
    }
    return apiFetch<SessionPostActionScores>(
      `/report/session/${id}/post-action${qs.toString() ? `?${qs.toString()}` : ''}`,
    )
  },
  sessionReplay: (id: string, limit?: number): Promise<SessionReplayResponse> =>
    apiFetch<SessionReplayResponse>(`/report/session/${id}${limit ? `?limit=${limit}` : ''}`),
  sessionReplayPage: (
    id: string,
    params?: { limit?: number; cursor?: number; windowSeconds?: number | null },
  ): Promise<SessionReplayPageResponse> => {
    const qs = new URLSearchParams()
    if (params?.limit) qs.set('limit', String(params.limit))
    if (params?.cursor !== undefined) qs.set('cursor', String(params.cursor))
    if (params?.windowSeconds !== undefined && params?.windowSeconds !== null) {
      qs.set('window_seconds', String(params.windowSeconds))
    }
    return apiFetch<SessionReplayPageResponse>(
      `/report/session/${id}/page${qs.toString() ? `?${qs.toString()}` : ''}`,
    )
  },
  requestL3FullReview: (
    id: string,
    body?: {
      runner?: 'llm_provider' | 'deterministic_local' | string
      run?: boolean
      trigger_event_id?: string
      trigger_detail?: string
      from_record_id?: number
      to_record_id?: number
      max_records?: number
      max_tool_calls?: number
    },
  ): Promise<L3FullReviewResponse> =>
    apiFetch<L3FullReviewResponse>(`/report/session/${id}/l3-advisory/full-review`, {
      method: 'POST',
      body: JSON.stringify(body ?? {}),
    }),
  alerts: async (params?: { severity?: string; acknowledged?: boolean; limit?: number }) => {
    const qs = new URLSearchParams()
    if (params?.severity) qs.set('severity', params.severity)
    if (params?.acknowledged !== undefined)
      qs.set('acknowledged', String(params.acknowledged))
    if (params?.limit) qs.set('limit', String(params.limit))
    const result = await apiFetch<{ alerts: Alert[] }>(withQuery('/report/alerts', qs))
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
