import { useState } from 'react'

import Tooltip from './Tooltip'

export default function CopyValue({ value, displayValue, label = 'Copy value', className = '' }) {
  const [copied, setCopied] = useState(false)
  const fullValue = String(value ?? '')

  async function handleCopy() {
    if (!fullValue) return

    try {
      await navigator.clipboard.writeText(fullValue)
      setCopied(true)
      window.setTimeout(() => setCopied(false), 1200)
    } catch {
      setCopied(false)
    }
  }

  return (
    <span className={['ui-copy-value', className].filter(Boolean).join(' ')}>
      <code title={fullValue}>{displayValue ?? (fullValue || '—')}</code>
      {fullValue && (
        <Tooltip label={copied ? 'Copied' : label}>
          <button
            type="button"
            className="ui-copy-button"
            aria-label={copied ? 'Copied' : label}
            onClick={handleCopy}
          >
            {copied ? '✓' : 'Copy'}
          </button>
        </Tooltip>
      )}
    </span>
  )
}
