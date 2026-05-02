import { render, screen } from '@testing-library/react'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { describe, expect, it, vi } from 'vitest'

import Layout from './Layout'

vi.mock('./StatusBar', () => ({
  default: () => <div data-testid="status-bar" />,
}))

describe('Layout', () => {
  it('exposes the shell landmarks and session page title', () => {
    render(
      <MemoryRouter initialEntries={['/sessions']} future={{ v7_startTransition: true, v7_relativeSplatPath: true }}>
        <Routes>
          <Route element={<Layout />}>
            <Route path="/sessions" element={<div>Sessions page</div>} />
          </Route>
        </Routes>
      </MemoryRouter>,
    )

    expect(screen.getByRole('complementary')).toBeInTheDocument()
    expect(screen.getByRole('navigation', { name: /primary/i })).toBeInTheDocument()
    expect(screen.getByRole('banner')).toBeInTheDocument()
    expect(screen.getByRole('main')).toBeInTheDocument()
    expect(screen.getByRole('link', { name: /skip to main content/i })).toHaveAttribute('href', '#main-content')
    expect(screen.getByText('Session Inventory')).toBeInTheDocument()
  })
})
