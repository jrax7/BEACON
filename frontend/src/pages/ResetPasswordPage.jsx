import {
  useEffect,
  useRef,
  useState,
} from 'react'

import {
  Link,
} from 'react-router'

import {
  resetPassword,
} from '../api/auth'
import BrandMark from '../components/BrandMark'
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


export default function ResetPasswordPage() {
  const fragmentTokenRef =
    useRef('')

  const fragmentReadRef =
    useRef(false)

  const [tokenReady, setTokenReady] =
    useState(false)

  const [newPassword, setNewPassword] =
    useState('')

  const [
    confirmPassword,
    setConfirmPassword,
  ] = useState('')

  const [error, setError] =
    useState('')

  const [success, setSuccess] =
    useState('')

  const [submitting, setSubmitting] =
    useState(false)


  useEffect(() => {
    if (
      fragmentReadRef.current
    ) {
      return
    }

    fragmentReadRef.current =
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

    setTokenReady(
      Boolean(token),
    )

    if (!token) {
      setError(
        'This password-reset link does not contain a usable reset token.',
      )
    }
  }, [])


  async function handleSubmit(event) {
    event.preventDefault()

    setError('')

    if (
      newPassword.length < 12
    ) {
      setError(
        'Password must contain at least 12 characters.',
      )
      return
    }

    if (
      newPassword !==
      confirmPassword
    ) {
      setError(
        'Passwords do not match.',
      )
      return
    }

    const submissionToken =
      fragmentTokenRef.current

    fragmentTokenRef.current = ''

    setTokenReady(false)

    if (!submissionToken) {
      setError(
        'The reset token has already been used or is unavailable. Request a new password-reset email.',
      )
      return
    }

    setSubmitting(true)

    try {
      await resetPassword({
        resetToken:
          submissionToken,
        newPassword,
      })

      setSuccess(
        'Password reset successfully. All existing browser sessions have been revoked. Sign in again with your new password.',
      )

      setNewPassword('')
      setConfirmPassword('')
    } catch (requestError) {
      setError(
        requestError.message ||
          'The reset link is invalid or has expired. Request a new password-reset email.',
      )
    } finally {
      setSubmitting(false)
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
            PASSWORD RESET
          </p>

          <h1>
            Restore access
            <span>
              {' '}
              with a one-time credential.
            </span>
          </h1>

          <p>
            Reset credentials are removed from the browser address immediately
            and are never written to browser storage.
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
              SECURE RESET
            </p>

            <h2>
              Set a new password
            </h2>

            <p>
              Your new password must contain at least 12 characters.
            </p>
          </div>

          <SuccessAlert
            message={success}
          />

          {!success && (
            <form
              className="auth-form"
              onSubmit={handleSubmit}
            >
              <ErrorAlert
                message={error}
              />

              <FormField
              label="New password"
              htmlFor="auth-resetpassword-new-password"
            >
              <Input
                id="auth-resetpassword-new-password"
                  type="password"
                  required
                  minLength="12"
                  autoComplete="new-password"
                  value={newPassword}
                  onChange={(event) =>
                    setNewPassword(
                      event.target.value,
                    )
                  }
                  placeholder="At least 12 characters"
                  disabled={!tokenReady}
                />
            </FormField>

              <FormField
              label="Confirm password"
              htmlFor="auth-resetpassword-confirm-password"
            >
              <Input
                id="auth-resetpassword-confirm-password"
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
                  placeholder="Repeat your new password"
                  disabled={!tokenReady}
                />
            </FormField>

              <button
                type="submit"
                className="primary-button auth-submit"
                disabled={
                  submitting ||
                  !tokenReady
                }
              >
                {submitting
                  ? 'Resetting password...'
                  : 'Reset password'}

                {!submitting && (
                  <span>→</span>
                )}
              </button>
            </form>
          )}

          <div className="auth-inline-links auth-recovery-links">
            {success ? (
              <Link to="/login">
                Sign in with your new password
              </Link>
            ) : (
              <Link to="/forgot-password">
                Request a new reset link
              </Link>
            )}
          </div>
        </div>
      </section>
    </main>
  )
}
