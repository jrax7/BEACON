import { useSyncExternalStore } from 'react'
import { dismissToast, getToastsSnapshot, subscribeToasts } from '../../system/toasts'

export default function ToastViewport() {
  const toasts = useSyncExternalStore(subscribeToasts, getToastsSnapshot)
  return (
    <div className="toast-viewport" aria-live="polite" aria-atomic="false">
      {toasts.map((toast) => (
        <div className={`toast toast-${toast.type}`} key={toast.id}>
          <span>{toast.message}</span>
          <button type="button" onClick={() => dismissToast(toast.id)} aria-label="Dismiss notification">×</button>
        </div>
      ))}
    </div>
  )
}
