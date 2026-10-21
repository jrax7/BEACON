const LIFECYCLE_STATES = [
  'NEW',
  'TRIAGED',
  'ASSIGNED',
  'IN_REMEDIATION',
  'READY_FOR_RETEST',
  'RESOLVED',
]

const LABELS = {
  NEW: 'New',
  TRIAGED: 'Triaged',
  ASSIGNED: 'Assigned',
  IN_REMEDIATION: 'In remediation',
  READY_FOR_RETEST: 'Ready for retest',
  RESOLVED: 'Resolved',
}

function lifecyclePosition(currentIndex, index) {
  if (index < currentIndex) return 'complete'
  if (index === currentIndex) return 'current'
  return 'upcoming'
}

export default function FindingLifecycleRail({ currentState = 'NEW' }) {
  const resolvedIndex = LIFECYCLE_STATES.indexOf(currentState)
  const currentIndex = resolvedIndex >= 0 ? resolvedIndex : 0

  return (
    <nav
      className="finding-lifecycle-rail"
      aria-label="Finding remediation lifecycle"
    >
      {LIFECYCLE_STATES.map((state, index) => {
        const position = lifecyclePosition(currentIndex, index)

        return (
          <div
            key={state}
            className="finding-lifecycle-step"
            data-state={state}
            data-position={position}
            aria-current={position === 'current' ? 'step' : undefined}
          >
            <span className="finding-lifecycle-marker" aria-hidden="true">
              {position === 'complete' ? '✓' : String(index + 1).padStart(2, '0')}
            </span>

            <span className="finding-lifecycle-copy">
              <strong>{LABELS[state]}</strong>
              <small>
                {position === 'complete'
                  ? 'Complete'
                  : position === 'current'
                    ? 'Current'
                    : 'Upcoming'}
              </small>
            </span>

            {index < LIFECYCLE_STATES.length - 1 && (
              <span className="finding-lifecycle-line" aria-hidden="true" />
            )}
          </div>
        )
      })}
    </nav>
  )
}
