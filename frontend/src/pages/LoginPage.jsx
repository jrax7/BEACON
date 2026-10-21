import {
  useState,
} from 'react'

import {
  Link,
  useLocation,
  useNavigate,
} from 'react-router'

import {
  useAuth,
} from '../auth/useAuth'
import BrandMark from '../components/BrandMark'
import SessionExpiredState from '../components/system/SessionExpiredState'
import {
  ErrorAlert,
  FormField,
  Input,
  SuccessAlert,
} from '../components/ui'


function isSafeLocalPath(
  candidate,
) {
  return (
    typeof candidate ===
      'string' &&
    candidate.startsWith('/') &&
    !candidate.startsWith('//') &&
    !candidate.includes('\\') &&
    !candidate.includes('\u0000')
  )
}


function getDestination(
  location,
) {
  const query =
    new URLSearchParams(
      location.search,
    )

  const requestedNext =
    query.get('next')

  if (
    isSafeLocalPath(
      requestedNext,
    )
  ) {
    return requestedNext
  }

  const requestedFrom =
    location.state?.from

  if (
    isSafeLocalPath(
      requestedFrom,
    )
  ) {
    return requestedFrom
  }

  return '/dashboard'
}


export default function LoginPage() {
  const { login } =
    useAuth()

  const navigate =
    useNavigate()

  const location =
    useLocation()

  const [email, setEmail] =
    useState('')

  const [password, setPassword] =
    useState('')

  const [error, setError] =
    useState('')

  const [
    verificationRequired,
    setVerificationRequired,
  ] = useState(false)

  const [submitting, setSubmitting] =
    useState(false)

  const message =
    location.state?.message

  const sessionExpired =
    location.state?.sessionExpired

  const isNewAccount =
    new URLSearchParams(
      location.search,
    ).get('welcome') === 'new'


  async function handleSubmit(event) {
    event.preventDefault()

    setError('')
    setVerificationRequired(false)
    setSubmitting(true)

    try {
      await login({
        email:
          email.trim(),
        password,
      })

      navigate(
        getDestination(
          location,
        ),
        {
          replace: true,
        },
      )
    } catch (requestError) {
      if (
        requestError.code ===
        'EMAIL_VERIFICATION_REQUIRED'
      ) {
        setVerificationRequired(
          true,
        )

        setError(
          'Email verification is required before you can sign in.',
        )

        return
      }

      setError(
        requestError.message ||
          'Unable to sign in.',
      )
    } finally {
      setSubmitting(false)
    }
  }


  return (
    <main className="auth-page">
      <div
        className="auth-ambient"
        aria-hidden="true"
      />

      <section className="auth-visual-panel">
        <BrandMark
          size="lg"
          subtitle="Security Assessment Platform"
        />

        <div className="auth-visual-copy">
          <p className="eyebrow">
            CONTROL PLANE
          </p>

          <h1>
            Security visibility,
            <span>
              {' '}
              without the noise.
            </span>
          </h1>

          <p>
            Register authorized targets, prove ownership, run constrained
            assessments, and track scanner telemetry from one workspace.
          </p>
        </div>

        <div
          className="auth-signal-grid"
          aria-hidden="true"
        >
          <span className="signal-node node-a" />
          <span className="signal-node node-b" />
          <span className="signal-node node-c" />
          <span className="signal-line line-a" />
          <span className="signal-line line-b" />

          <div className="auth-shield-orbit">
            <img
              src="/beacon-mark.svg"
              alt=""
            />
          </div>
        </div>

        <div className="auth-proof-row">
          <div>
            <span>01</span>
            <strong>
              Verify ownership
            </strong>
          </div>

          <div>
            <span>02</span>
            <strong>
              Assess safely
            </strong>
          </div>

          <div>
            <span>03</span>
            <strong>
              Review evidence
            </strong>
          </div>
        </div>
      </section>

      <section className="auth-form-panel">
        <div className="auth-mobile-brand">
          <BrandMark size="md" />
        </div>

        <div className="auth-panel">
          <div className="auth-heading">
            <p className="eyebrow">
              {isNewAccount
                ? 'ACCOUNT READY'
                : 'SECURE ACCESS'}
            </p>

            <h2>
              {isNewAccount
                ? 'Welcome to BEACON'
                : 'Welcome back'}
            </h2>

            <p>
              {isNewAccount
                ? 'Your account is ready. Sign in to enter your BEACON workspace.'
                : 'Sign in to manage targets, assessments, findings, and reports.'}
            </p>
          </div>

          <SuccessAlert
            message={message}
          />

          {sessionExpired && (
            <SessionExpiredState />
          )}

          <form
            className="auth-form"
            onSubmit={handleSubmit}
          >
            <ErrorAlert
              message={error}
            />

            <FormField
              label="Email address"
              htmlFor="auth-login-email-address"
            >
              <Input
                id="auth-login-email-address"
                type="email"
                required
                autoComplete="email"
                value={email}
                onChange={(event) =>
                  setEmail(
                    event.target.value,
                  )
                }
                placeholder="name@example.com"
              />
            </FormField>

            <FormField
              label="Password"
              htmlFor="auth-login-password"
            >
              <Input
                id="auth-login-password"
                type="password"
                required
                autoComplete="current-password"
                value={password}
                onChange={(event) =>
                  setPassword(
                    event.target.value,
                  )
                }
                placeholder="Enter your password"
              />
            </FormField>

            <div className="auth-inline-links">
              <Link to="/forgot-password">
                Forgot password?
              </Link>

              {verificationRequired && (
                <Link to="/verify-email">
                  Resend verification email
                </Link>
              )}
            </div>

            <button
              type="submit"
              className="primary-button auth-submit"
              disabled={submitting}
            >
              {submitting
                ? 'Authenticating...'
                : 'Sign in'}

              {!submitting && (
                <span>→</span>
              )}
            </button>
          </form>

          <p className="auth-footer">
            New to BEACON?{' '}
            <Link to="/register">
              Create an account
            </Link>
          </p>
        </div>
      </section>
    </main>
  )
}
