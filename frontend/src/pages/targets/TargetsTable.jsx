import { Link } from 'react-router'

import { StatusBadge } from '../../components/ui'
import { formatDate } from '../../lib/format'

export default function TargetsTable({ targets }) {
  return (
    <div className="targets-table-wrapper">
      <table className="targets-table">
        <thead>
          <tr>
            <th>Target</th>
            <th>Method</th>
            <th>Status</th>
            <th>Verification expires</th>
            <th>Added</th>
            <th>Actions</th>
          </tr>
        </thead>

        <tbody>
          {targets.map((target) => (
            <tr key={target.id}>
              <td>
                <div className="target-identity">
                  <strong>
                    <Link className="target-link" to={`/targets/${target.id}`}>
                      {target.hostname}
                    </Link>
                  </strong>
                  <span>{target.normalized_url}</span>
                </div>
              </td>

              <td>{target.verification_method ? target.verification_method.toUpperCase() : '—'}</td>

              <td>
                <StatusBadge value={target.verification_status} />
              </td>

              <td>{formatDate(target.verification_expires_at)}</td>
              <td>{formatDate(target.created_at)}</td>

              <td>
                <Link className="table-action" to={`/targets/${target.id}`}>
                  View →
                </Link>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
