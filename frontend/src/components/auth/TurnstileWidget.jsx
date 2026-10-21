import {
  useEffect,
  useRef,
} from 'react'

const SITE_KEY = (
  import.meta.env
    .VITE_TURNSTILE_SITE_KEY ||
  ''
).trim()


export default function TurnstileWidget({
  action,
  onToken,
  resetSignal = 0,
}) {
  const containerRef =
    useRef(null)

  const widgetIdRef =
    useRef(null)


  useEffect(() => {
    if (!SITE_KEY) {
      onToken('')
      return undefined
    }

    let cancelled = false
    let timer = null

    function renderWidget() {
      if (
        cancelled ||
        widgetIdRef.current !== null ||
        !containerRef.current ||
        !window.turnstile
      ) {
        return Boolean(
          widgetIdRef.current !== null,
        )
      }

      widgetIdRef.current =
        window.turnstile.render(
          containerRef.current,
          {
            sitekey:
              SITE_KEY,

            action,

            callback(token) {
              onToken(token)
            },

            'expired-callback'() {
              onToken('')
            },

            'error-callback'() {
              onToken('')
            },
          },
        )

      return true
    }

    if (!renderWidget()) {
      timer =
        window.setInterval(
          () => {
            if (renderWidget()) {
              window.clearInterval(
                timer,
              )
              timer = null
            }
          },
          100,
        )
    }

    return () => {
      cancelled = true

      if (timer !== null) {
        window.clearInterval(
          timer,
        )
      }

      if (
        widgetIdRef.current !== null &&
        window.turnstile
      ) {
        window.turnstile.remove(
          widgetIdRef.current,
        )

        widgetIdRef.current =
          null
      }
    }
  }, [
    action,
    onToken,
  ])


  useEffect(() => {
    if (
      widgetIdRef.current !== null &&
      window.turnstile
    ) {
      window.turnstile.reset(
        widgetIdRef.current,
      )

      onToken('')
    }
  }, [
    resetSignal,
    onToken,
  ])


  if (!SITE_KEY) {
    return (
      <div
        className="turnstile-unconfigured"
        role="note"
      >
        Human verification is not configured for this environment.
      </div>
    )
  }


  return (
    <div className="turnstile-field">
      <div ref={containerRef} />
    </div>
  )
}
