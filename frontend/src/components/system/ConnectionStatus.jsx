import {
  useEffect,
  useState,
} from 'react'

function readOnlineState() {
  if (typeof navigator === 'undefined') {
    return true
  }

  return navigator.onLine
}

export default function ConnectionStatus() {
  const [online, setOnline] = useState(readOnlineState)

  useEffect(() => {
    function handleOnline() {
      setOnline(true)
    }

    function handleOffline() {
      setOnline(false)
    }

    window.addEventListener('online', handleOnline)
    window.addEventListener('offline', handleOffline)
    return () => {
      window.removeEventListener('online', handleOnline)
      window.removeEventListener('offline', handleOffline)
    }
  }, [])

  if (online) {
    return null
  }

  return (
    <div
      className="connection-status-banner"
      role="status"
      aria-live="polite"
    >
      <span className="connection-status-dot" aria-hidden="true" />
      <div>
        <strong>Network connection lost</strong>
        <span>Restore connectivity before continuing BEACON operations.</span>
      </div>
    </div>
  )
}
