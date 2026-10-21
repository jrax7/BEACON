import { useEffect, useRef } from 'react'

/**
 * Accessible confirmation dialog for destructive/irreversible actions
 * (archive, restore, permanent delete). Replaces scattered
 * `window.confirm(...)` calls with a consistent in-app pattern.
 */
export default function ConfirmDialog({
  open,
  title,
  description,
  confirmLabel = 'Confirm',
  cancelLabel = 'Cancel',
  tone = 'danger',
  busy = false,
  onConfirm,
  onCancel,
}) {
  const confirmButtonRef = useRef(null)

  useEffect(() => {
    if (!open) return undefined

    confirmButtonRef.current?.focus()

    function handleKeyDown(event) {
      if (event.key === 'Escape' && !busy) {
        onCancel()
      }
    }

    document.addEventListener('keydown', handleKeyDown)
    return () => document.removeEventListener('keydown', handleKeyDown)
  }, [open, busy, onCancel])

  if (!open) return null

  return (
    <div className="dialog-backdrop" role="presentation" onClick={() => !busy && onCancel()}>
      <div
        className="dialog-panel"
        role="alertdialog"
        aria-modal="true"
        aria-labelledby="confirm-dialog-title"
        onClick={(event) => event.stopPropagation()}
      >
        <h3 id="confirm-dialog-title">{title}</h3>
        {description && <p>{description}</p>}

        <div className="dialog-actions">
          <button
            type="button"
            className="secondary-button"
            onClick={onCancel}
            disabled={busy}
          >
            {cancelLabel}
          </button>
          <button
            type="button"
            ref={confirmButtonRef}
            className={tone === 'danger' ? 'danger-button' : 'primary-button'}
            onClick={onConfirm}
            disabled={busy}
          >
            {busy ? 'Working...' : confirmLabel}
          </button>
        </div>
      </div>
    </div>
  )
}
