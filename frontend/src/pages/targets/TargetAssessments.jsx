import { assessmentProfileLabel } from '../scans/helpers'
import { Link } from 'react-router'

import {
  Card,
  EmptyState,
  ErrorAlert,
  LoadingState,
  StatusBadge,
} from '../../components/ui'
import { formatDate } from '../../lib/format'

export default function TargetAssessments({
  target,
  activeScans = [],
  archivedScans = [],
  loading = false,
  error = '',
}) {
  const assessments = [
    ...activeScans,
    ...archivedScans,
  ]
    .filter(
      (scan) => scan.target_id === target.id,
    )
    .sort(
      (left, right) =>
        new Date(
          right.created_at || 0,
        ).getTime()
        - new Date(
          left.created_at || 0,
        ).getTime(),
    )

  return (
    <Card
      eyebrow="ASSESSMENTS"
      title="Assessment history"
      className="target-detail-section"
    >
      <p className="target-workspace-intro">
        Review active and historical assessments
        performed against this target.
      </p>

      {loading && (
        <LoadingState message="Loading target assessments..." />
      )}

      {!loading && error && (
        <ErrorAlert message={error} />
      )}

      {!loading
        && !error
        && assessments.length === 0
        && (
          <EmptyState
            title="No assessments yet"
            message="This target does not have assessment history."
          />
        )}

      {!loading
        && !error
        && assessments.length > 0
        && (
          <div className="target-assessment-list">
            {assessments.map((scan) => (
              <Link
                key={scan.id}
                className="target-assessment-row"
                to={`/scans/${scan.id}`}
              >
                <div>
                  <span className="detail-label">
                    ASSESSMENT
                  </span>
                  <strong className="mono-value">
                    {scan.id}
                  </strong>
                </div>

                <div>
                  <span className="detail-label">
                    PROFILE
                  </span>
                  <strong>
                    {assessmentProfileLabel(scan)}
                  </strong>
                </div>

                <div>
                  <span className="detail-label">
                    CREATED
                  </span>
                  <strong>
                    {formatDate(scan.created_at)}
                  </strong>
                </div>

                <StatusBadge value={scan.status} />

                <span
                  className="target-assessment-arrow"
                  aria-hidden="true"
                >
                  →
                </span>
              </Link>
            ))}
          </div>
        )}
    </Card>
  )
}
