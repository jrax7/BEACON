// Shared formatting helpers used across pages/components.
// Kept dependency-free and pure so they're easy to reuse and test.

export function formatDate(value) {
  if (!value) return '—'

  const date = new Date(value)

  if (Number.isNaN(date.getTime())) {
    return value
  }

  return date.toLocaleString()
}

export function formatDuration(seconds) {
  if (seconds === null || seconds === undefined) {
    return '—'
  }

  if (seconds < 60) {
    return `${seconds.toFixed(1)}s`
  }

  const minutes = Math.floor(seconds / 60)
  const remaining = Math.round(seconds % 60)

  return `${minutes}m ${remaining}s`
}

export function formatElapsed(seconds) {
  const safeSeconds = Math.max(0, Math.floor(seconds))
  const hours = Math.floor(safeSeconds / 3600)
  const minutes = Math.floor((safeSeconds % 3600) / 60)
  const remainingSeconds = safeSeconds % 60

  if (hours > 0) {
    return [hours, minutes, remainingSeconds]
      .map((part) => part.toString().padStart(2, '0'))
      .join(':')
  }

  return [minutes, remainingSeconds]
    .map((part) => part.toString().padStart(2, '0'))
    .join(':')
}

/** Normalizes a status/classification/severity string into a CSS-safe token. */
export function statusToken(value) {
  return String(value || '').toLowerCase().replaceAll('_', '-')
}

export function statusBadgeClass(status) {
  return `status-badge status-${statusToken(status)}`
}

export function severityBadgeClass(severity) {
  return `severity-pill severity-${statusToken(severity || 'informational')}`
}

export function pluralize(count, singular, plural = `${singular}s`) {
  return count === 1 ? singular : plural
}
