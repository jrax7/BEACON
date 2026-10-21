import { severityBadgeClass, statusBadgeClass } from '../../lib/format'

/**
 * Renders a status pill using the shared `.status-badge status-<value>` styles.
 * Use `variant="severity"` for finding severities (critical/high/medium/low/informational).
 */
export default function StatusBadge({ value, variant = 'status', className = '' }) {
  const badgeClass =
    variant === 'severity' ? severityBadgeClass(value) : statusBadgeClass(value)

  return <span className={`${badgeClass} ${className}`.trim()}>{value}</span>
}
