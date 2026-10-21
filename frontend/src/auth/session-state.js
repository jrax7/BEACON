let csrfToken = null
let authExpiredHandler = null
let sessionMetadataRefresher = null


export function getCsrfToken() {
  return csrfToken
}


export function setCsrfToken(
  value,
) {
  csrfToken =
    typeof value === 'string' &&
    value
      ? value
      : null
}


export function clearCsrfToken() {
  csrfToken = null
}


export function setAuthExpiredHandler(
  handler,
) {
  authExpiredHandler =
    typeof handler === 'function'
      ? handler
      : null

  return () => {
    if (
      authExpiredHandler ===
      handler
    ) {
      authExpiredHandler = null
    }
  }
}


export function notifyAuthExpired(
  error,
) {
  authExpiredHandler?.(
    error,
  )
}


export function setSessionMetadataRefresher(
  refresher,
) {
  sessionMetadataRefresher =
    typeof refresher === 'function'
      ? refresher
      : null

  return () => {
    if (
      sessionMetadataRefresher ===
      refresher
    ) {
      sessionMetadataRefresher =
        null
    }
  }
}


export async function refreshSessionMetadata() {
  if (!sessionMetadataRefresher) {
    return null
  }

  return sessionMetadataRefresher()
}


export function clearSessionState() {
  csrfToken = null
  authExpiredHandler = null
  sessionMetadataRefresher = null
}
