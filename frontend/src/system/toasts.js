let nextId = 1
let toasts = []
const listeners = new Set()

function emit() { for (const listener of listeners) listener() }
export function subscribeToasts(listener) { listeners.add(listener); return () => listeners.delete(listener) }
export function getToastsSnapshot() { return toasts }
export function dismissToast(id) { toasts = toasts.filter((toast) => toast.id !== id); emit() }
export function pushToast(message, { type = 'info', duration = 3600 } = {}) {
  const id = nextId++
  toasts = [...toasts, { id, message, type }]
  emit()
  if (duration > 0) window.setTimeout(() => dismissToast(id), duration)
  return id
}
