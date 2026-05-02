import { useState, useCallback } from 'react'
import { getToken, setToken, clearToken, api, AuthError } from '../api/client'

export type AuthFailure = 'missing_token' | 'invalid_token' | 'gateway_unavailable' | null

function isGatewayUnavailable(error: unknown): boolean {
  if (error instanceof TypeError) return true
  if (!(error instanceof Error)) return false
  return /failed to fetch|networkerror|load failed|gateway unavailable/i.test(error.message)
}

export function useAuth() {
  const [authenticated, setAuthenticated] = useState<boolean | null>(null)
  const [checking, setChecking] = useState(false)
  const [authFailure, setAuthFailure] = useState<AuthFailure>(null)

  const check = useCallback(async () => {
    setChecking(true)
    setAuthFailure(null)
    const token = getToken()
    try {
      await api.summary()
      setAuthenticated(true)
      return true
    } catch (e) {
      if (e instanceof AuthError) {
        setAuthenticated(false)
        setAuthFailure(token ? 'invalid_token' : 'missing_token')
        return false
      } else if (isGatewayUnavailable(e)) {
        setAuthenticated(false)
        setAuthFailure('gateway_unavailable')
        return false
      } else {
        // API might be down but no auth error = auth disabled or OK
        setAuthenticated(true)
        return true
      }
    } finally {
      setChecking(false)
    }
  }, [])

  const login = useCallback(
    async (token: string) => {
      setToken(token)
      return await check()
    },
    [check],
  )

  const logout = useCallback(() => {
    clearToken()
    setAuthenticated(false)
    setAuthFailure(null)
  }, [])

  return { authenticated, checking, authFailure, check, login, logout, hasToken: !!getToken() }
}
