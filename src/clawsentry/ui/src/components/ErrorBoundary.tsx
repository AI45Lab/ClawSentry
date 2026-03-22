import { Component, ErrorInfo, ReactNode } from 'react'

interface Props {
  children: ReactNode
}

interface State {
  error: Error | null
}

export default class ErrorBoundary extends Component<Props, State> {
  state: State = { error: null }

  static getDerivedStateFromError(error: Error): State {
    return { error }
  }

  componentDidCatch(error: Error, info: ErrorInfo) {
    console.error('[ClawSentry UI]', error, info.componentStack)
  }

  render() {
    if (this.state.error) {
      return (
        <div style={{ padding: 40 }}>
          <h3 style={{ color: 'var(--color-block)', marginBottom: 12 }}>Page Error</h3>
          <pre style={{
            color: 'var(--color-text-muted)',
            fontSize: '0.75rem',
            background: 'var(--color-surface-raised)',
            padding: 16,
            borderRadius: 'var(--radius)',
            overflow: 'auto',
            marginBottom: 16,
          }}>
            {this.state.error.message}
          </pre>
          <button className="btn" onClick={() => this.setState({ error: null })}>
            Dismiss
          </button>
        </div>
      )
    }
    return this.props.children
  }
}
