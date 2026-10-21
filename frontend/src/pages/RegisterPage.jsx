import {
  useEffect,
  useState,
} from 'react'

import {
  Link,
  useSearchParams,
} from 'react-router'

import {
  registerUser,
} from '../api/auth'
import {
  resolveOrganizationInvitation,
} from '../api/organization'
import BrandMark from '../components/BrandMark'
import TurnstileWidget from '../components/auth/TurnstileWidget'
import {
  ErrorAlert,
  FormField,
  Input,
  SuccessAlert,
} from '../components/ui'


export default function RegisterPage() {
  const [searchParams] =
    useSearchParams()

  const invitationToken =
    searchParams.get(
      'invitation',
    ) || ''

  const invitationSignInPath =
    invitationToken
      ? `/login?next=${encodeURIComponent(
          `/invite?token=${encodeURIComponent(invitationToken)}`,
        )}`
      : '/login'

  const [fullName, setFullName] =
    useState('')

  const [email, setEmail] =
    useState('')

  const [password, setPassword] =
    useState('')

  const [
    confirmPassword,
    setConfirmPassword,
  ] = useState('')

  const [
    turnstileToken,
    setTurnstileToken,
  ] = useState('')

  const [
    turnstileResetSignal,
    setTurnstileResetSignal,
  ] = useState(0)

  const [error, setError] =
    useState('')

  const [success, setSuccess] =
    useState('')

  const [
    registrationDisabled,
    setRegistrationDisabled,
  ] = useState(false)

  const [submitting, setSubmitting] =
    useState(false)


  useEffect(() => {
    let cancelled = false

    async function resolveInvitation() {
      if (!invitationToken) {
        return
      }

      try {
        const invitation =
          await resolveOrganizationInvitation(
            invitationToken,
          )

        if (!cancelled) {
          setEmail(
            invitation.email,
          )

          setError('')
        }
      } catch (requestError) {
        if (!cancelled) {
          setError(
            requestError.message
            || 'This invitation is invalid or has expired.',
          )
        }
      }
    }

    resolveInvitation()

    return () => {
      cancelled = true
    }
  }, [
    invitationToken,
  ])


  async function handleSubmit(event) {
    event.preventDefault()
    setError('')

    if (password.length < 12) {
      setError(
        'Password must contain at least 12 characters.',
      )
      return
    }

    if (
      password !==
      confirmPassword
    ) {
      setError(
        'Passwords do not match.',
      )
      return
    }

    setSubmitting(true)

    try {
      await registerUser({
        fullName:
          fullName.trim(),
        email:
          email.trim(),
        password,
        turnstileToken,
        invitationToken:
          invitationToken
          || null,
      })

      setSuccess(
        'Verification email sent. Check your inbox and verify your email address before signing in.',
      )

      setPassword('')
      setConfirmPassword('')
      setTurnstileToken('')

      setTurnstileResetSignal(
        (value) => value + 1,
      )
    } catch (requestError) {
      if (
        requestError.code ===
        'REGISTRATION_DISABLED'
      ) {
        setRegistrationDisabled(true)

        setError(
          'Registration is currently unavailable.',
        )

        return
      }

      setError(
        requestError.message ||
          'Unable to create account.',
      )

      setTurnstileToken('')

      setTurnstileResetSignal(
        (value) => value + 1,
      )
    } finally {
      setSubmitting(false)
    }
  }


  return (
    <main className="auth-page auth-register-page">
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
            AUTHORIZED ASSESSMENT
          </p>

          <h1>
            Build a trusted
            <span>
              {' '}
              security baseline.
            </span>
          </h1>

          <p>
            BEACON requires proof of target ownership before scans can run,
            keeping the assessment workflow controlled and auditable.
          </p>
        </div>

        <div className="auth-policy-card">
          <span className="policy-indicator" />

          <div>
            <strong>
              Safety gate enabled
            </strong>

            <p>
              DNS or file verification is required for every target.
            </p>
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
              CREATE WORKSPACE
            </p>

            <h2>
              Create your account
            </h2>

            <p>
              Register to manage authorized vulnerability-assessment targets.
            </p>
          </div>

          <SuccessAlert
            message={success}
          />

          <ErrorAlert
            message={error}
          />

          {!success &&
            !registrationDisabled && (
              <form
                className="auth-form"
                onSubmit={handleSubmit}
              >
                <FormField
              label="Full name"
              htmlFor="auth-register-full-name"
            >
              <Input
                id="auth-register-full-name"
                    type="text"
                    required
                    maxLength="200"
                    autoComplete="name"
                    value={fullName}
                    onChange={(event) =>
                      setFullName(
                        event.target.value,
                      )
                    }
                    placeholder="Your name"
                  />
            </FormField>

                <FormField
              label="Email address"
              htmlFor="auth-register-email-address"
            >
              <Input
                id="auth-register-email-address"
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
              htmlFor="auth-register-password"
            >
              <Input
                id="auth-register-password"
                    type="password"
                    required
                    minLength="12"
                    autoComplete="new-password"
                    value={password}
                    onChange={(event) =>
                      setPassword(
                        event.target.value,
                      )
                    }
                    placeholder="At least 12 characters"
                  />
            </FormField>

                <FormField
              label="Confirm password"
              htmlFor="auth-register-confirm-password"
            >
              <Input
                id="auth-register-confirm-password"
                    type="password"
                    required
                    minLength="12"
                    autoComplete="new-password"
                    value={confirmPassword}
                    onChange={(event) =>
                      setConfirmPassword(
                        event.target.value,
                      )
                    }
                    placeholder="Repeat your password"
                  />
            </FormField>

                <TurnstileWidget
                  action="registration"
                  onToken={
                    setTurnstileToken
                  }
                  resetSignal={
                    turnstileResetSignal
                  }
                />

                <button
                  type="submit"
                  className="primary-button auth-submit"
                  disabled={submitting}
                >
                  {submitting
                    ? 'Creating account...'
                    : 'Create account'}

                  {!submitting && (
                    <span>→</span>
                  )}
                </button>
              </form>
            )}

          {success && (
            <div className="auth-next-action">
              <Link
                className="primary-button auth-submit"
                to="/login?welcome=new"
              >
                Continue to sign in
                <span>→</span>
              </Link>
            </div>
          )}

          <p className="auth-footer">
            Already have an account?{' '}
            <Link to={invitationSignInPath}>
              Sign in
            </Link>
          </p>
        </div>
      </section>
    </main>
  )
}
