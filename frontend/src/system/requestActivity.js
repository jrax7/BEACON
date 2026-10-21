let activeRequests = 0
const listeners = new Set()

function emit() {
  for (const listener of listeners) listener()
}

export function beginRequestActivity() {
  activeRequests += 1
  emit()
}

export function endRequestActivity() {
  activeRequests = Math.max(0, activeRequests - 1)
  emit()
}

export function subscribeRequestActivity(listener) {
  listeners.add(listener)
  return () => listeners.delete(listener)
}

export function getRequestActivitySnapshot() {
  return activeRequests
}
