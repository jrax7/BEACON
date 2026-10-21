import { Link } from 'react-router'

import {
  StatusBadge,
} from '../../components/ui'
import { formatDate } from '../../lib/format'


function label(value) {
  return String(value || 'unknown')
    .replaceAll('_', ' ')
}


export default function FindingSummary({
  finding,
}) {
  const tools = (
    finding.sources || []
  )
    .map((source) => source.tool_name)
    .filter(Boolean)

  return (
    <section className="finding-detail-card finding-summary">
      <div className="finding-section-heading">
        <div>
          <p className="eyebrow">
            SUMMARY
          </p>
          <h2>{finding.title}</h2>
        </div>

        <StatusBadge
          value={finding.severity}
        />
      </div>

      <div className="finding-summary-grid">
        <div>
          <span>Classification</span>
          <strong>
            {label(
              finding.classification,
            )}
          </strong>
        </div>

        <div>
          <span>Confidence</span>
          <strong>
            {finding.confidence || '—'}
          </strong>
        </div>

        <div>
          <span>CWE</span>
          <strong>
            {finding.cwe_id || '—'}
          </strong>
        </div>

        <div>
          <span>Occurrences</span>
          <strong>
            {finding.occurrence_count}
          </strong>
        </div>

        <div>
          <span>Target</span>
          <strong>
            <Link
              to={`/targets/${finding.target_id}`}
            >
              {finding.target_hostname}
            </Link>
          </strong>
        </div>

        <div>
          <span>Assessment</span>
          <strong>
            <Link
              to={`/scans/${finding.scan_id}`}
            >
              {finding.scan_id}
            </Link>
          </strong>
        </div>

        <div>
          <span>Last observed</span>
          <strong>
            {formatDate(
              finding.last_observed_at,
            )}
          </strong>
        </div>
      </div>

      <div className="finding-source-list">
        <span>Sources</span>

        <div>
          {tools.length > 0
            ? tools.map((tool) => (
              <span
                className="findings-source"
                key={tool}
              >
                {tool}
              </span>
            ))
            : '—'}
        </div>
      </div>
    </section>
  )
}
