import {
  useEffect,
  useMemo,
  useState,
} from 'react'
import {
  Link,
  useNavigate,
  useSearchParams,
} from 'react-router'

import {
  acceptOrganizationInvitation,
  resolveOrganizationInvitation,
} from '../api/organization'
import { useAuth } from '../auth/useAuth'
import BrandMark from '../components/BrandMark'
import {
  ErrorAlert,
  LoadingState,
} from '../components/ui'


export default function InvitationPage() {
  const [searchParams] = useSearchParams()
  const navigate = useNavigate()
  const token = searchParams.get('token') || ''
  const {
    user,
    loading: authLoading,
    logout,
    switchOrganization,
  } = useAuth()

  const [invitation, setInvitation] = useState(null)
  const [loading, setLoading] = useState(true)
  const [accepting, setAccepting] = useState(false)
  const [error, setError] = useState('')

  useEffect(() => {
    let cancelled = false

    async function loadInvitation() {
      if (!token) {
        setError('This invitation link is incomplete.')
        setLoading(false)
        return
      }

      try {
        const result =
          await resolveOrganizationInvitation(token)

        if (!cancelled) {
          setInvitation(result)
          setError('')
        }
      } catch (requestError) {
        if (!cancelled) {
          setError(
            requestError.message ||
            'This invitation is invalid or has expired.',
          )
        }
      } finally {
        if (!cancelled) {
          setLoading(false)
        }
      }
    }

    loadInvitation()
    return () => {
      cancelled = true
    }
  }, [token])

  const invitePath = useMemo(
    () => `/invite?token=${encodeURIComponent(token)}`,
    [token],
  )

  const loginPath = useMemo(
    () => `/login?next=${encodeURIComponent(invitePath)}`,
    [invitePath],
  )

  const registerPath = useMemo(
    () => `/register?invitation=${encodeURIComponent(token)}`,
    [token],
  )

  const emailMatches = Boolean(
    user &&
    invitation &&
    String(user.email).toLowerCase() ===
      String(invitation.email).toLowerCase(),
  )

  async function acceptInvitation() {
    if (!emailMatches || accepting) {
      return
    }

    setAccepting(true)
    setError('')

    try {
      const organization =
        await acceptOrganizationInvitation(token)

      await switchOrganization(
        organization.id,
      )

      navigate('/dashboard', { replace: true })
    } catch (requestError) {
      setError(
        requestError.message ||
        'Unable to accept this invitation.',
      )
      setAccepting(false)
    }
  }

  async function signOut() {
    await logout()
    navigate(invitePath, { replace: true })
  }

  return (
    <main className="auth-page auth-invitation-page">
      <div className="auth-ambient" aria-hidden="true" />

      <section className="auth-visual-panel">
        <BrandMark
          size="lg"
          subtitle="Security Assessment Platform"
        />

        <div className="auth-visual-copy">
          <p className="eyebrow">TEAM ACCESS</p>
          <h1>
            Join the right
            <span> security workspace.</span>
          </h1>
          <p>
            BEACON organization membership keeps targets, assessments,
            findings, and reports isolated behind role-based access.
          </p>
        </div>
      </section>

      <section className="auth-form-panel">
        <div className="auth-mobile-brand">
          <BrandMark size="md" />
        </div>

        <div className="auth-panel">
          <div className="auth-heading">
            <p className="eyebrow">ORGANIZATION INVITATION</p>
            <h2>Join a BEACON workspace</h2>
            <p>
              Review the invitation, then use the account that owns
              the invited email address.
            </p>
          </div>

          <ErrorAlert message={error} />

          {(loading || authLoading) && (
            <LoadingState message="Validating invitation..." />
          )}

          {!loading && invitation && (
            <div className="invitation-summary">
              <div>
                <span>Workspace</span>
                <strong>{invitation.organization_name}</strong>
              </div>
              <div>
                <span>Invited account</span>
                <strong>{invitation.email}</strong>
              </div>
              <div>
                <span>Workspace role</span>
                <strong>{invitation.role}</strong>
              </div>
            </div>
          )}

          {!loading && !authLoading && invitation && !user && (
            <div className="invitation-actions">
              <Link className="primary-button auth-submit" to={loginPath}>
                Sign in to accept <span>→</span>
              </Link>
              <Link className="secondary-button" to={registerPath}>
                Create invited account
              </Link>
            </div>
          )}

          {!loading && !authLoading && invitation && user && emailMatches && (
            <div className="invitation-actions">
              <div className="invitation-account-state invitation-account-success">
                <span
                  className="invitation-account-mark"
                  aria-hidden="true"
                >
                  ✓
                </span>

                <div>
                  <strong>Ready to join this workspace</strong>
                  <p>
                    Signed in as <span>{user.email}</span>. Accepting adds
                    this workspace to your existing BEACON account.
                  </p>
                </div>
              </div>

              <button
                type="button"
                className="primary-button auth-submit"
                disabled={accepting}
                onClick={acceptInvitation}
              >
                {accepting ? 'Joining workspace...' : 'Accept invitation'}
                {!accepting && <span>→</span>}
              </button>
            </div>
          )}

          {!loading && !authLoading && invitation && user && !emailMatches && (
            <div className="invitation-actions">
              <div className="invitation-account-state invitation-account-warning">
                <span
                  className="invitation-account-mark"
                  aria-hidden="true"
                >
                  !
                </span>

                <div>
                  <strong>Different account signed in</strong>
                  <p>
                    Invitation: <span>{invitation.email}</span><br />
                    Current session: <span>{user.email}</span>
                  </p>
                </div>
              </div>

              <button
                type="button"
                className="secondary-button"
                onClick={signOut}
              >
                Switch account to continue
              </button>
            </div>
          )}
        </div>
      </section>
    </main>
  )
}
