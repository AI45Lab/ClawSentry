import { useState, FormEvent } from 'react'

interface LoginFormProps {
  onLogin: (token: string) => void
}

export default function LoginForm({ onLogin }: LoginFormProps) {
  const [token, setToken] = useState('')

  const handleSubmit = (e: FormEvent) => {
    e.preventDefault()
    if (token.trim()) {
      onLogin(token.trim())
    }
  }

  return (
    <div className="login-container">
      <div className="login-card">
        <h2>CLAWSENTRY</h2>
        <div className="subtitle">Enter your AHP auth token to connect</div>
        <form onSubmit={handleSubmit}>
          <input
            type="password"
            className="login-input"
            placeholder="CS_AUTH_TOKEN"
            value={token}
            onChange={e => setToken(e.target.value)}
            autoFocus
          />
          <button
            type="submit"
            className="btn btn-primary"
            style={{ width: '100%', marginTop: 16, padding: '10px 14px' }}
          >
            Connect
          </button>
        </form>
      </div>
    </div>
  )
}
