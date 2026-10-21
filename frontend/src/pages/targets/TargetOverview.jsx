import { Link } from 'react-router'

import {
  Card,
  StatusBadge,
} from '../../components/ui'
import { formatDate } from '../../lib/format'
import { buildFindingsPath } from '../findings/helpers'
import { verificationMethodLabel } from './helpers'

export default function TargetOverview({ target }) {
  return (
    <Card
      eyebrow="OVERVIEW"
      title="Target information"
      headingActions={
        <Link
          className="text-link"
          to={buildFindingsPath({
            target_id: target.id,
          })}
        >
          View findings →
        </Link>
      }
      className="target-detail-section"
    >
      <div className="target-overview-status">
        <div>
          <span className="detail-label">OWNERSHIP STATUS</span>
          <strong>
            {target.verification_status === 'verified'
              ? 'Verified for authorized assessment'
              : 'Ownership verification required'}
          </strong>
        </div>

        <StatusBadge value={target.verification_status} />
      </div>

      <dl className="target-details-grid">
        <Detail
          label="Target ID"
          value={target.id}
          mono
        />

        <Detail
          label="Hostname"
          value={target.hostname}
        />

        <Detail
          label="Original URL"
          value={target.original_url}
          mono
        />

        <Detail
          label="Normalized URL"
          value={target.normalized_url}
          mono
        />

        <Detail
          label="Verification method"
          value={verificationMethodLabel(
            target.verification_method,
          )}
        />

        <Detail
          label="Verification status"
          value={target.verification_status}
        />

        <Detail
          label="Verified at"
          value={formatDate(target.verified_at)}
        />

        <Detail
          label="Verification expires"
          value={formatDate(
            target.verification_expires_at,
          )}
        />

        <Detail
          label="Created"
          value={formatDate(target.created_at)}
        />

        <Detail
          label="Updated"
          value={formatDate(target.updated_at)}
        />
      </dl>
    </Card>
  )
}

function Detail({
  label,
  value,
  mono = false,
}) {
  return (
    <div>
      <dt>{label}</dt>

      <dd>
        {mono
          ? <code>{value ?? '—'}</code>
          : value ?? '—'}
      </dd>
    </div>
  )
}
