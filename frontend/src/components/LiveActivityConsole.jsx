import {
  useEffect,
  useRef,
} from 'react'

function formatTime(value) {
  const date = new Date(value)

  if (
    Number.isNaN(
      date.getTime(),
    )
  ) {
    return '--:--:--'
  }

  return date.toLocaleTimeString(
    [],
    {
      hour12: false,
    },
  )
}

export default function LiveActivityConsole({
  events,
  isLive,
}) {
  const consoleRef =
    useRef(null)

  useEffect(() => {
    if (!consoleRef.current) {
      return
    }

    consoleRef.current.scrollTop =
      consoleRef.current.scrollHeight
  }, [events])

  return (
    <section className="scan-console-card activity-card">
      <div className="terminal-titlebar">
        <div className="terminal-dots">
          <span />
          <span />
          <span />
        </div>

        <span>
          beacon@scanner — activity
        </span>

        <div
          className={
            isLive
              ? 'live-indicator live'
              : 'live-indicator'
          }
        >
          <span />

          {isLive
            ? 'LIVE'
            : 'ENDED'}
        </div>
      </div>

      <div
        className="activity-console"
        ref={consoleRef}
      >
        {events.length === 0 && (
          <p className="console-empty">
            Waiting for assessment
            activity...
          </p>
        )}

        {events.map(
          (event, index) => (
            <div
              className={
                `console-line console-${event.level}`
              }
              key={
                `${event.timestamp}-${event.event}-${index}`
              }
            >
              <span className="console-time">
                {formatTime(
                  event.timestamp,
                )}
              </span>

              <span className="console-component">
                [
                {event.component
                  .toUpperCase()
                  .padEnd(5, ' ')}
                ]
              </span>

              <span className="console-message">
                {event.message}
              </span>
            </div>
          ),
        )}

        <div className="console-prompt">
          <span>
            beacon@scanner:~$
          </span>

          <span
            className={
              isLive
                ? 'terminal-cursor active'
                : 'terminal-cursor'
            }
          />
        </div>
      </div>
    </section>
  )
}
