import { NavLink, Outlet } from 'react-router-dom'
import { LayoutDashboard, Users, AlertTriangle, ShieldCheck } from 'lucide-react'
import StatusBar from './StatusBar'
import ErrorBoundary from './ErrorBoundary'

const navItems = [
  { to: '/', icon: LayoutDashboard, label: 'Dashboard' },
  { to: '/sessions', icon: Users, label: 'Sessions' },
  { to: '/alerts', icon: AlertTriangle, label: 'Alerts' },
  { to: '/defer', icon: ShieldCheck, label: 'DEFER Panel' },
]

export default function Layout() {
  return (
    <div className="app-layout">
      <aside className="sidebar">
        <div className="sidebar-header">
          <h1>CLAWSENTRY</h1>
          <div className="subtitle">Security Dashboard</div>
        </div>
        <nav className="sidebar-nav">
          {navItems.map(({ to, icon: Icon, label }) => (
            <NavLink
              key={to}
              to={to}
              end={to === '/'}
              className={({ isActive }) => `nav-link${isActive ? ' active' : ''}`}
            >
              <Icon />
              {label}
            </NavLink>
          ))}
        </nav>
      </aside>
      <div className="main-content">
        <div className="topbar">
          <StatusBar />
        </div>
        <div className="page-content fade-in">
            <ErrorBoundary>
              <Outlet />
            </ErrorBoundary>
          </div>
      </div>
    </div>
  )
}
