/**
 * Consistent empty/loading/error/success messaging used across pages.
 * These wrap the shared CSS classes so every list/panel presents its
 * states the same way instead of hand-rolled markup per page.
 */

export function EmptyState({ title, message, className = '' }) {
  return (
    <div className={`empty-state ${className}`.trim()}>
      <strong>{title}</strong>
      {message && <p>{message}</p>}
    </div>
  )
}

export function LoadingState({ message = 'Loading...' }) {
  return (
    <p
      className="empty-state"
      role="status"
      aria-live="polite"
    >
      {message}
    </p>
  )
}

export function ErrorAlert({ message, className = '' }) {
  if (!message) return null

  return (
    <div className={`form-alert ${className}`.trim()} role="alert">
      {message}
    </div>
  )
}

export function SuccessAlert({ message, className = '' }) {
  if (!message) return null

  return (
    <div className={`form-success ${className}`.trim()} role="status">
      {message}
    </div>
  )
}
