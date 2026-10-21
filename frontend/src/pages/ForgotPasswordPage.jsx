import {
  useState,
} from 'react'

import {
  Link,
} from 'react-router'

import {
  forgotPassword,
} from '../api/auth'
import BrandMark from '../components/BrandMark'
import TurnstileWidget from '../components/auth/TurnstileWidget'
import {
  ErrorAlert,
  FormField,
  Input,
  SuccessAlert,
} from '../components/ui'


export default function ForgotPasswordPage() {
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

  const [error, setError] =
    useState('')

  const [success, setSuccess] =
    useState('')

  const [submitting, setSubmitting] =
    useState(false)


  async function handleSubmit(event) {
    event.preventDefault()

    setError('')
    setSuccess('')
    setSubmitting(true)

    try {
      await forgotPassword({
        email:
          email.trim(),
        turnstileToken,
      })

      setSuccess(
        'If an account exists for that email address, password-reset instructions have been sent.',
      )

      setTurnstileToken('')

      setResetSignal(
        (value) => value + 1,
      )
    } catch (requestError) {
      setError(
        requestError.message ||
          'Unable to submit the password-recovery request.',
      )

      setTurnstileToken('')

      setResetSignal(
        (value) => value + 1,
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
            ACCOUNT RECOVERY
          </p>

          <h1>
            Recover access
            <span>
              {' '}
              without exposing accounts.
            </span>
          </h1>

          <p>
            Recovery requests return the same response whether or not an
            account exists for the supplied address.
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
              PASSWORD RECOVERY
            </p>

            <h2>
              Forgot your password?
            </h2>

            <p>
              Enter your account email and we will send reset instructions
              when the account is eligible.
            </p>
          </div>

          <SuccessAlert
            message={success}
          />

          <form
            className="auth-form"
            onSubmit={handleSubmit}
          >
            <ErrorAlert
              message={error}
            />

            <FormField
              label="Email address"
              htmlFor="auth-forgotpassword-email-address"
            >
              <Input
                id="auth-forgotpassword-email-address"
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
              action="password_forgot"
              onToken={
                setTurnstileToken
              }
              resetSignal={
                resetSignal
              }
            />

            <button
              type="submit"
              className="primary-button auth-submit"
              disabled={submitting}
            >
              {submitting
                ? 'Submitting...'
                : 'Send reset instructions'}

              {!submitting && (
                <span>→</span>
              )}
            </button>
          </form>

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
