import { NavLink, Outlet, useLocation } from 'react-router-dom'
import { LayoutDashboard, Users, AlertTriangle, ShieldCheck, Radio } from 'lucide-react'
import StatusBar from './StatusBar'
import ErrorBoundary from './ErrorBoundary'
import { usePreferences } from '../lib/preferences'

const navItems = [
  { to: '/', icon: LayoutDashboard, labelKey: 'nav.dashboard' },
  { to: '/sessions', icon: Users, labelKey: 'nav.sessions' },
  { to: '/alerts', icon: AlertTriangle, labelKey: 'nav.alerts' },
  { to: '/defer', icon: ShieldCheck, labelKey: 'nav.defer' },
]

const PAGE_TITLES: Record<string, string> = {
  '/': 'page.dashboard',
  '/sessions': 'page.sessions',
  '/alerts': 'page.alerts',
  '/defer': 'page.defer',
}

export default function Layout() {
  const location = useLocation()
  const { language, theme, toggleLanguage, toggleTheme, t } = usePreferences()
  const titleKey = Object.entries(PAGE_TITLES)
    .sort(([a], [b]) => b.length - a.length)
    .find(([path]) => location.pathname.startsWith(path))?.[1] ?? 'page.dashboard'
  const title = t(titleKey as Parameters<typeof t>[0])

  return (
    <div className="app-layout">
      <a className="skip-link" href="#main-content">
        Skip to main content
      </a>
      <aside className="sidebar">
        <div className="sidebar-header">
          <div className="sidebar-brand-row">
            <div className="sidebar-logo">ClawSentry</div>
            <span className="sidebar-signal" aria-hidden="true">
              <Radio size={15} />
            </span>
          </div>
          <div className="subtitle">{t('app.subtitle')}</div>
          <div className="sidebar-command-strip" aria-hidden="true">
            <span />
            <span />
            <span />
          </div>
        </div>
        <nav className="sidebar-nav" aria-label="Primary">
          <div className="sidebar-nav-label">Console</div>
          {navItems.map(({ to, icon: Icon, labelKey }) => (
            <NavLink
              key={to}
              to={to}
              end={to === '/'}
              className={({ isActive }) => `nav-link${isActive ? ' active' : ''}`}
            >
              <Icon />
              {t(labelKey as Parameters<typeof t>[0])}
            </NavLink>
          ))}
        </nav>
        <div className="sidebar-footer">
          <span className="sidebar-footer-label">{t('app.footer')}</span>
          <span className="sidebar-footer-state">HARDENED · LIVE</span>
        </div>
      </aside>
      <section className="main-content">
        <header className="topbar" role="banner">
          <div className="topbar-heading">
            <p className="topbar-kicker">{t('topbar.kicker')}</p>
            <span className="topbar-title">{title}</span>
          </div>
          <div className="preference-controls" aria-label="Display preferences">
            <button type="button" className="preference-toggle" onClick={toggleLanguage} aria-label={t('prefs.languageLabel')}>
              {t('prefs.language')}
            </button>
            <button type="button" className="preference-toggle" onClick={toggleTheme} aria-label={t('prefs.themeLabel')} aria-pressed={theme === 'dark'}>
              {theme === 'dark' ? t('prefs.theme.light') : t('prefs.theme.dark')}
            </button>
            <span className="preference-state mono">{language.toUpperCase()} · {theme.toUpperCase()}</span>
          </div>
          <StatusBar />
        </header>
        <main id="main-content" className="page-content fade-in" role="main" tabIndex={-1}>
          <ErrorBoundary>
            <Outlet />
          </ErrorBoundary>
        </main>
      </section>
    </div>
  )
}
