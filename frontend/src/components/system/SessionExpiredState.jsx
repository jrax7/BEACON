export default function SessionExpiredState() {
  return (
    <div
      className="session-expired-state"
      role="alert"
    >
      <span className="session-expired-mark" aria-hidden="true">
        !
      </span>

      <div>
        <strong>Your secure session expired</strong>
        <p>
          Sign in again to continue. BEACON did not replay the interrupted request.
        </p>
      </div>
    </div>
  )
}
