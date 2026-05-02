import { useState, FormEvent } from 'react'
import type { AuthFailure } from '../hooks/useAuth'

interface LoginFormProps {
  onLogin: (token: string) => void | Promise<boolean>
  authFailure?: AuthFailure
  checking?: boolean
}

function failureMessage(authFailure: AuthFailure): string | null {
  if (authFailure === 'missing_token') {
    return null
  }
  if (authFailure === 'invalid_token') {
    return 'Token was rejected (401). Paste the exact CS_AUTH_TOKEN value printed by clawsentry start, set in process env, or passed with --env-file.'
  }
  if (authFailure === 'gateway_unavailable') {
    return 'Gateway is unavailable. This is not a bad token; start the Gateway or check host/port/proxy settings, then retry.'
  }
  return null
}

export default function LoginForm({ onLogin, authFailure = null, checking = false }: LoginFormProps) {
  const [token, setToken] = useState('')
  const message = failureMessage(authFailure)

  const handleSubmit = (e: FormEvent) => {
    e.preventDefault()
    if (token.trim() && !checking) {
      void onLogin(token.trim())
    }
  }

  return (
    <div className="login-container">
      <div className="login-card">
        <p className="eyebrow">Secure access</p>
        <h2>CLAWSENTRY</h2>
        <div className="subtitle">Enter your AHP auth token to connect</div>
        <p className="login-help">
          Use the token printed by clawsentry start in the Web UI URL, or the
          <code> CS_AUTH_TOKEN</code> value in your process env or explicit <code>--env-file</code>.
        </p>
        {message && (
          <div className="login-alert" role="alert">
            {message}
          </div>
        )}
        <form className="login-form" onSubmit={handleSubmit}>
          <label className="login-label" htmlFor="auth-token">
            Auth token
          </label>
          <input
            id="auth-token"
            type="password"
            className="login-input"
            placeholder="CS_AUTH_TOKEN"
            value={token}
            onChange={e => setToken(e.target.value)}
            autoFocus
          />
          <button
            type="submit"
            className="btn btn-primary login-button"
            disabled={checking}
          >
            {checking ? 'Checking…' : 'Connect'}
          </button>
        </form>
      </div>
    </div>
  )
}
