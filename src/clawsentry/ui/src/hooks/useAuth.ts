import { useState, useCallback } from 'react'
import { getToken, setToken, clearToken, api, AuthError } from '../api/client'

export function useAuth() {
  const [authenticated, setAuthenticated] = useState<boolean | null>(null)
  const [checking, setChecking] = useState(false)

  const check = useCallback(async () => {
    setChecking(true)
    try {
      await api.summary()
      setAuthenticated(true)
    } catch (e) {
      if (e instanceof AuthError) {
        setAuthenticated(false)
      } else {
        // API might be down but no auth error = auth disabled or OK
        setAuthenticated(true)
      }
    } finally {
      setChecking(false)
    }
  }, [])

  const login = useCallback(
    async (token: string) => {
      setToken(token)
      await check()
    },
    [check],
  )

  const logout = useCallback(() => {
    clearToken()
    setAuthenticated(false)
  }, [])

  return { authenticated, checking, check, login, logout, hasToken: !!getToken() }
}
