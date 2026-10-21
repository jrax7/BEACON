import {
  useEffect,
  useRef,
  useState,
} from 'react'

import {
  Link,
} from 'react-router'

import {
  resendVerification,
  verifyEmail,
} from '../api/auth'
import BrandMark from '../components/BrandMark'
import TurnstileWidget from '../components/auth/TurnstileWidget'
import {
  ErrorAlert,
  FormField,
  Input,
  SuccessAlert,
} from '../components/ui'


function readFragmentToken(
  hash,
) {
  const fragment =
    hash.startsWith('#')
      ? hash.slice(1)
      : hash

  if (!fragment) {
    return ''
  }

  if (
    fragment.startsWith(
      'token=',
    )
  ) {
    try {
      return decodeURIComponent(
        fragment.slice(6),
      )
    } catch {
      return ''
    }
  }

  try {
    const values =
      new URLSearchParams(
        fragment,
      )

    const namedToken =
      values.get('token')

    if (namedToken) {
      return namedToken
    }

    return decodeURIComponent(
      fragment,
    )
  } catch {
    return ''
  }
}


export default function VerifyEmailPage() {
  const fragmentTokenRef =
    useRef('')

  const verificationStartedRef =
    useRef(false)

  const [status, setStatus] =
    useState('verifying')

  const [verificationError, setVerificationError] =
    useState('')

  const [email, setEmail] =
    useState('')

  const [
    turnstileToken,
    setTurnstileToken,
  ] = useState('')

  const [
    resetSignal,
    setResetSignal,
  ] = useState(0)

  const [resendError, setResendError] =
    useState('')

  const [resendSuccess, setResendSuccess] =
    useState('')

  const [resending, setResending] =
    useState(false)


  useEffect(() => {
    if (
      verificationStartedRef.current
    ) {
      return
    }

    verificationStartedRef.current =
      true

    const token =
      readFragmentToken(
        window.location.hash,
      )

    window.history.replaceState(
      window.history.state,
      '',
      `${window.location.pathname}${window.location.search}`,
    )

    fragmentTokenRef.current =
      token

    if (!token) {
      setStatus('missing')

      setVerificationError(
        'This verification link does not contain a usable verification token.',
      )

      return
    }

    const submissionToken =
      fragmentTokenRef.current

    fragmentTokenRef.current = ''

    setStatus('verifying')

    verifyEmail(
      submissionToken,
    )
      .then(() => {
        setStatus('success')
      })
      .catch((requestError) => {
        setStatus('failure')

        setVerificationError(
          requestError.message ||
            'The verification link is invalid or has expired.',
        )
      })
  }, [])


  async function handleResend(event) {
    event.preventDefault()

    setResendError('')
    setResendSuccess('')
    setResending(true)

    try {
      await resendVerification({
        email:
          email.trim(),
        turnstileToken,
      })

      setResendSuccess(
        'If the account is eligible, a new verification email has been sent.',
      )

      setTurnstileToken('')

      setResetSignal(
        (value) => value + 1,
      )
    } catch (requestError) {
      setResendError(
        requestError.message ||
          'Unable to request another verification email.',
      )

      setTurnstileToken('')

      setResetSignal(
        (value) => value + 1,
      )
    } finally {
      setResending(false)
    }
  }


  return (
    <main className="auth-page auth-compact-page">
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
            EMAIL VERIFICATION
          </p>

          <h1>
            Confirm your identity
            <span>
              {' '}
              before secure access.
            </span>
          </h1>

          <p>
            Verification links are one-time credentials and are removed from
            the browser address immediately after this page opens.
          </p>
        </div>
      </section>

      <section className="auth-form-panel">
        <div className="auth-mobile-brand">
          <BrandMark size="md" />
        </div>

        <div className="auth-panel">
          <div className="auth-heading">
            <p className="eyebrow">
              VERIFY ACCOUNT
            </p>

            <h2>
              Email verification
            </h2>

            <p>
              BEACON is validating the one-time verification credential.
            </p>
          </div>

          {status === 'verifying' && (
            <div
              className="auth-status-card"
              role="status"
            >
              Verifying your email address...
            </div>
          )}

          {status === 'success' && (
            <>
              <SuccessAlert
                message="Email verification completed successfully."
              />

              <div className="auth-next-action">
                <Link
                  className="primary-button auth-submit"
                  to="/login?welcome=new"
                >
                  Continue to sign in
                  <span>→</span>
                </Link>
              </div>
            </>
          )}

          {status !== 'success' &&
            status !== 'verifying' && (
              <ErrorAlert
                message={
                  verificationError
                }
              />
            )}

          {status !== 'success' && (
            <div className="auth-secondary-flow">
              <div className="auth-heading auth-subheading">
                <h3>
                  Need another verification email?
                </h3>

                <p>
                  Request a new one-time verification link.
                </p>
              </div>

              <SuccessAlert
                message={
                  resendSuccess
                }
              />

              <form
                className="auth-form"
                onSubmit={handleResend}
              >
                <ErrorAlert
                  message={
                    resendError
                  }
                />

                <FormField
              label="Email address"
              htmlFor="auth-verifyemail-email-address"
            >
              <Input
                id="auth-verifyemail-email-address"
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

                <TurnstileWidget
                  action="verification_resend"
                  onToken={
                    setTurnstileToken
                  }
                  resetSignal={
                    resetSignal
                  }
                />

                <button
                  type="submit"
                  className="secondary-button auth-secondary-submit"
                  disabled={resending}
                >
                  {resending
                    ? 'Requesting...'
                    : 'Resend verification email'}
                </button>
              </form>
            </div>
          )}

          <p className="auth-footer">
            <Link to="/login">
              Return to sign in
            </Link>
          </p>
        </div>
      </section>
    </main>
  )
}
