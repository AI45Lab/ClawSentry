import { fireEvent, render, screen } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'

import LoginForm from './LoginForm'

describe('LoginForm', () => {
  it('explains where the auth token comes from without rendering a token value', () => {
    render(<LoginForm onLogin={vi.fn()} />)

    expect(screen.getByText(/use the token printed by clawsentry start/i)).toBeInTheDocument()
    expect(screen.getByText(/CS_AUTH_TOKEN/i)).toBeInTheDocument()
    expect(screen.queryByText(/secret-token/i)).not.toBeInTheDocument()
  })

  it('distinguishes invalid tokens from gateway availability failures', () => {
    const { rerender } = render(<LoginForm onLogin={vi.fn()} authFailure="invalid_token" />)

    expect(screen.getByRole('alert')).toHaveTextContent(/token was rejected/i)
    expect(screen.getByRole('alert')).toHaveTextContent(/401/i)

    rerender(<LoginForm onLogin={vi.fn()} authFailure="gateway_unavailable" />)

    expect(screen.getByRole('alert')).toHaveTextContent(/gateway is unavailable/i)
    expect(screen.getByRole('alert')).toHaveTextContent(/not a bad token/i)
  })

  it('does not label a first-time missing token as a rejected token', () => {
    render(<LoginForm onLogin={vi.fn()} authFailure="missing_token" />)

    expect(screen.queryByRole('alert')).not.toBeInTheDocument()
    expect(screen.getByText(/enter your AHP auth token/i)).toBeInTheDocument()
  })

  it('submits the trimmed token and disables duplicate submits while checking', () => {
    const onLogin = vi.fn()

    const { rerender } = render(<LoginForm onLogin={onLogin} />)
    fireEvent.change(screen.getByLabelText(/auth token/i), {
      target: { value: '  token-123  ' },
    })
    fireEvent.click(screen.getByRole('button', { name: /connect/i }))

    expect(onLogin).toHaveBeenCalledWith('token-123')

    rerender(<LoginForm onLogin={onLogin} checking />)
    expect(screen.getByRole('button', { name: /checking/i })).toBeDisabled()
  })
})
