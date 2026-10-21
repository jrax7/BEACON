import { progressWidthClass } from '../../utils/progressWidthClass'
import { assessmentProfileLabel } from './helpers'
import { Link } from 'react-router'

import { formatDate, statusBadgeClass } from '../../lib/format'
import { canArchive, matchesFilter } from './helpers'

export default function ScanRow({
  scan,
  target,
  view,
  selected,
  actionBusy,
  onToggleSelected,
  allowLifecycle = true,
}) {
  const active = matchesFilter(scan, 'running')
  const selectable = view === 'archived' || canArchive(scan)

  return (
    <div className={selected ? 'scan-list-row lifecycle-row selected' : 'scan-list-row lifecycle-row'}>
      {allowLifecycle && (
        <label
          className={selectable ? 'scan-row-checkbox' : 'scan-row-checkbox disabled'}
          title={selectable ? 'Select assessment' : 'Active assessments cannot be archived'}
        >
          <input
            type="checkbox"
            checked={selected}
            disabled={!selectable || actionBusy}
            onChange={() => onToggleSelected(scan.id)}
          />
          <span aria-hidden="true" />
        </label>
      )}

      <Link className="lifecycle-row-link" to={`/scans/${scan.id}`}>
        <div className="scan-list-indicator">
          <span className={active ? 'pulse-dot active' : 'pulse-dot'} />
        </div>

        <div className="scan-list-target">
          <strong>{target?.hostname || 'Unknown target'}</strong>
          <span>{target?.normalized_url || scan.target_id}</span>

          <span className="scan-assessment-reference">
            <b>Assessment ID</b>
            <code>{scan.id}</code>
          </span>
        </div>

        <div className="scan-list-level">
          <span>Profile</span>
          <strong>{assessmentProfileLabel(scan)}</strong>
        </div>

        <div className="scan-list-progress">
          <div>
            <span>Status</span>
            <strong className={statusBadgeClass(scan.status)}>{scan.status}</strong>
          </div>
          <div className="mini-progress-track">
            <span
              className={progressWidthClass(
                scan.progress,
              )}
            />
          </div>
        </div>

        <div className="scan-list-time">
          <span>{view === 'archived' ? 'Archived' : 'Created'}</span>
          <strong>{formatDate(view === 'archived' ? scan.archived_at : scan.created_at)}</strong>
        </div>

        <span className="scan-list-arrow">→</span>
      </Link>
    </div>
  )
}
