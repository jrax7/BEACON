import {
  useEffect,
  useRef,
  useState,
} from 'react'

import {
  NavLink,
  useLocation,
  useNavigate,
} from 'react-router'

import { useAuth } from '../auth/useAuth'
import BrandMark from './BrandMark'
import ApiProgressBeam from './system/ApiProgressBeam'
import BootSequence from './system/BootSequence'
import ConnectionStatus from './system/ConnectionStatus'
import DocumentTitle from './system/DocumentTitle'
import RouteViewport from './system/RouteViewport'
import ToastViewport from './system/ToastViewport'

function getNavClass({ isActive }) {
  return isActive
    ? 'nav-item active'
    : 'nav-item'
}

function NavIcon({ name }) {
  const paths = {
    dashboard: (
      <>
        <rect x="3" y="3" width="7" height="7" rx="1" />
        <rect x="14" y="3" width="7" height="7" rx="1" />
        <rect x="3" y="14" width="7" height="7" rx="1" />
        <rect x="14" y="14" width="7" height="7" rx="1" />
      </>
    ),
    targets: (
      <>
        <circle cx="12" cy="12" r="8" />
        <circle cx="12" cy="12" r="3" />
        <path d="M12 2v3M12 19v3M2 12h3M19 12h3" />
      </>
    ),
    scans: (
      <>
        <path d="M4 7V4h3M17 4h3v3M20 17v3h-3M7 20H4v-3" />
        <path d="M7 12h10M12 7v10" />
      </>
    ),
    findings: (
      <>
        <circle cx="11" cy="11" r="6" />
        <path d="m16 16 4 4" />
        <path d="M8 11h6M11 8v6" />
      </>
    ),
    reports: (
      <>
        <path d="M6 3h9l3 3v15H6z" />
        <path d="M15 3v4h4" />
        <path d="M9 11h6M9 15h6" />
      </>
    ),
    settings: (
      <>
        <circle cx="12" cy="12" r="3" />
        <path d="M19.4 15a1.7 1.7 0 0 0 .34 1.88l.06.06-2.83 2.83-.06-.06A1.7 1.7 0 0 0 15 19.4a1.7 1.7 0 0 0-1 .6 1.7 1.7 0 0 0-.4 1.1V21h-4v-.1A1.7 1.7 0 0 0 8.6 19.4a1.7 1.7 0 0 0-1.88.34l-.06.06-2.83-2.83.06-.06A1.7 1.7 0 0 0 4.6 15a1.7 1.7 0 0 0-.6-1 1.7 1.7 0 0 0-1.1-.4H3v-4h.1A1.7 1.7 0 0 0 4.6 8.6a1.7 1.7 0 0 0-.34-1.88l-.06-.06 2.83-2.83.06.06A1.7 1.7 0 0 0 9 4.6a1.7 1.7 0 0 0 1-.6 1.7 1.7 0 0 0 .4-1.1V3h4v.1A1.7 1.7 0 0 0 15.4 4.6a1.7 1.7 0 0 0 1.88-.34l.06-.06 2.83 2.83-.06.06A1.7 1.7 0 0 0 19.4 9c.35.28.58.65.6 1.1v4c-.02.45-.25.82-.6 1Z" />
      </>
    ),
  }

  return (
    <svg
      className="nav-icon"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.8"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      {paths[name]}
    </svg>
  )
}

function initials(name) {
  const parts = String(name || 'B')
    .trim()
    .split(/\s+/)
    .filter(Boolean)

  return parts
    .slice(0, 2)
    .map((part) => part[0]?.toUpperCase())
    .join('') || 'B'
}

export default function AppLayout() {
  const navigate = useNavigate()
  const location = useLocation()
  const [mobileOpen, setMobileOpen] = useState(false)
  const [workspaceSwitching, setWorkspaceSwitching] = useState(false)
  const [workspaceSwitchError, setWorkspaceSwitchError] = useState('')
  const [workspaceMenuOpen, setWorkspaceMenuOpen] = useState(false)
  const workspaceContextRef = useRef(null)

  useEffect(() => {
    window.scrollTo({
      top: 0,
      left: 0,
      behavior: 'auto',
    })
  }, [location.pathname])

  const {
    user,
    logout,
    organizations,
    switchOrganization,
  } = useAuth()

  function handleLogout() {
    logout()
    navigate('/login', { replace: true })
  }

  async function handleWorkspaceChange(organizationId) {
    if (
      !organizationId ||
      organizationId === user?.organization_id ||
      workspaceSwitching
    ) {
      setWorkspaceMenuOpen(false)
      return
    }

    setWorkspaceMenuOpen(false)
    setWorkspaceSwitching(true)
    setWorkspaceSwitchError('')

    try {
      await switchOrganization(organizationId)
      navigate('/dashboard', { replace: true })
    } catch (requestError) {
      setWorkspaceSwitchError(
        requestError.message ||
        'Unable to switch workspace.',
      )
    } finally {
      setWorkspaceSwitching(false)
    }
  }

  useEffect(() => {
    if (!workspaceMenuOpen) {
      return undefined
    }

    function closeWorkspaceMenu(event) {
      if (
        event.type === 'keydown'
        && event.key === 'Escape'
      ) {
        setWorkspaceMenuOpen(false)
        return
      }

      if (
        event.type === 'pointerdown'
        && workspaceContextRef.current
        && !workspaceContextRef.current.contains(event.target)
      ) {
        setWorkspaceMenuOpen(false)
      }
    }

    document.addEventListener('pointerdown', closeWorkspaceMenu)
    document.addEventListener('keydown', closeWorkspaceMenu)

    return () => {
      document.removeEventListener('pointerdown', closeWorkspaceMenu)
      document.removeEventListener('keydown', closeWorkspaceMenu)
    }
  }, [workspaceMenuOpen])

  function closeMobileNavigation() {
    setMobileOpen(false)
    setWorkspaceMenuOpen(false)
  }

  const activeOrganization =
    organizations.find(
      (organization) =>
        organization.id === user?.organization_id,
    )

  const activeWorkspaceName =
    activeOrganization?.name
    || user?.organization_name
    || 'BEACON Workspace'

  return (
    <div className="application">
      <DocumentTitle />
      <ApiProgressBeam />
      <ToastViewport />
      <BootSequence />
      <ConnectionStatus />
      <div className="app-ambient" aria-hidden="true" />

      <aside
        id="primary-navigation"
        className={
          mobileOpen
            ? 'sidebar mobile-open'
            : 'sidebar'
        }
      >
        <div className="sidebar-brand">
          <a
            className="brand-dashboard-link"
            href="/dashboard"
            target="_blank"
            rel="noopener noreferrer"
            aria-label="Open BEACON dashboard in a new tab"
          >
            <BrandMark
              size="sm"
              subtitle="Assessment Platform"
            />
          </a>

          <button
            className="sidebar-mobile-close"
            type="button"
            aria-label="Close navigation"
            onClick={closeMobileNavigation}
          >
            ×
          </button>
        </div>

        <div className="sidebar-section-label">
          Workspace
        </div>

        <nav className="sidebar-nav">
          <NavLink
            to="/dashboard"
            className={getNavClass}
            onClick={closeMobileNavigation}
          >
            <NavIcon name="dashboard" />
            <span>Dashboard</span>
          </NavLink>

          <NavLink
            to="/targets"
            className={getNavClass}
            onClick={closeMobileNavigation}
          >
            <NavIcon name="targets" />
            <span>Targets</span>
          </NavLink>

          <NavLink
            to="/scans"
            className={getNavClass}
            onClick={closeMobileNavigation}
          >
            <NavIcon name="scans" />
            <span>Assessments</span>
          </NavLink>

          <NavLink
            to="/findings"
            className={getNavClass}
            onClick={closeMobileNavigation}
          >
            <NavIcon name="findings" />
            <span>Findings</span>
          </NavLink>

          <NavLink
            to="/reports"
            className={getNavClass}
            onClick={closeMobileNavigation}
          >
            <NavIcon name="reports" />
            <span>Reports</span>
          </NavLink>
        </nav>

        <div
          className="sidebar-workspace-context"
          ref={workspaceContextRef}
        >
          <div className="sidebar-workspace-heading">
            <span>Active workspace</span>

            {organizations.length > 1 && (
              <small>
                {organizations.length} workspaces
              </small>
            )}
          </div>

          {organizations.length > 1 ? (
            <div className="sidebar-workspace-picker">
              <button
                type="button"
                className="sidebar-workspace-trigger"
                aria-label="Active workspace"
                aria-haspopup="listbox"
                aria-expanded={workspaceMenuOpen}
                disabled={workspaceSwitching}
                onClick={() =>
                  setWorkspaceMenuOpen(
                    (open) => !open,
                  )
                }
              >
                <span>{activeWorkspaceName}</span>
                <span
                  className="sidebar-workspace-chevron"
                  aria-hidden="true"
                >
                  ⌄
                </span>
              </button>

              {workspaceMenuOpen && (
                <div
                  className="sidebar-workspace-menu"
                  role="listbox"
                  aria-label="Available workspaces"
                >
                  {organizations.map((organization) => {
                    const selected =
                      organization.id === user?.organization_id

                    return (
                      <button
                        key={organization.id}
                        type="button"
                        role="option"
                        aria-selected={selected}
                        className={
                          selected
                            ? 'sidebar-workspace-option active'
                            : 'sidebar-workspace-option'
                        }
                        onClick={() =>
                          handleWorkspaceChange(organization.id)
                        }
                      >
                        <span>{organization.name}</span>
                        {selected && (
                          <small>Current</small>
                        )}
                      </button>
                    )
                  })}
                </div>
              )}
            </div>
          ) : (
            <strong className="sidebar-workspace-name">
              {activeWorkspaceName}
            </strong>
          )}

          <div className="sidebar-workspace-role">
            <span className="sidebar-workspace-role-dot" />
            <small>
              {workspaceSwitching
                ? 'Switching workspace…'
                : user?.organization_role || 'member'}
            </small>
          </div>

          {workspaceSwitchError && (
            <small className="sidebar-workspace-error">
              {workspaceSwitchError}
            </small>
          )}
        </div>

        <div className="sidebar-section-label sidebar-account-label">
          Account
        </div>

        <nav className="sidebar-nav sidebar-account-nav">
          <NavLink
            to="/settings"
            className={getNavClass}
            onClick={closeMobileNavigation}
          >
            <NavIcon name="settings" />
            <span>Settings</span>
          </NavLink>
        </nav>

        <div className="sidebar-security-card">
          <span className="security-card-dot" />
          <div>
            <strong>Authorized scanning only</strong>
            <p>
              Ownership verification is required before active assessment.
            </p>
          </div>
        </div>

        <div className="sidebar-user">
          <div className="sidebar-avatar">
            {initials(user?.full_name)}
          </div>

          <div className="sidebar-user-copy">
            <strong>{user?.full_name}</strong>
            <span>{user?.email}</span>
          </div>

          <button
            type="button"
            className="logout-button"
            onClick={handleLogout}
            title="Sign out"
          >
            ↗
          </button>
        </div>
      </aside>

      {mobileOpen && (
        <button
          type="button"
          className="mobile-backdrop"
          aria-label="Close navigation"
          onClick={closeMobileNavigation}
        />
      )}

      <main className="main-content">
        <header className="mobile-topbar">
          <button
            type="button"
            className="mobile-menu-button"
            aria-label="Open navigation"
            aria-controls="primary-navigation"
            aria-expanded={mobileOpen}
            onClick={() => setMobileOpen(true)}
          >
            <span />
            <span />
            <span />
          </button>

          <a
            className="brand-dashboard-link"
            href="/dashboard"
            target="_blank"
            rel="noopener noreferrer"
            aria-label="Open BEACON dashboard in a new tab"
          >
            <BrandMark
              size="xs"
              subtitle=""
            />
          </a>

          <span className="mobile-route-label">
            {location.pathname
              .split('/')
              .filter(Boolean)[0] || 'dashboard'}
          </span>
        </header>

        <div className="main-content-inner">
          <RouteViewport
            key={user?.organization_id || 'workspace'}
          />
        </div>
      </main>
    </div>
  )
}
