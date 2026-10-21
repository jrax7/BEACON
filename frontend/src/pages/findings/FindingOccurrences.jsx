import { formatDate } from '../../lib/format'


function EvidencePreview({
  evidence,
}) {
  if (
    !evidence ||
    typeof evidence !== 'object'
  ) {
    return 'Evidence not available'
  }

  const entries =
    Object.entries(evidence)

  if (entries.length === 0) {
    return 'Evidence not available'
  }

  return entries
    .map(([key, value]) => (
      `${key}: ${
        typeof value === 'object'
          ? JSON.stringify(value)
          : String(value)
      }`
    ))
    .join(' · ')
}


export default function FindingOccurrences({
  finding,
}) {
  const occurrences =
    finding.occurrences || []

  return (
    <section className="finding-detail-card">
      <div className="finding-section-heading">
        <div>
          <p className="eyebrow">
            PROVENANCE
          </p>
          <h2>Raw occurrences</h2>
        </div>

        <span className="section-count">
          {occurrences.length}
        </span>
      </div>

      <div className="finding-occurrence-list">
        {occurrences.map(
          (occurrence) => (
            <article
              className="finding-occurrence"
              key={occurrence.id}
            >
              <div className="finding-occurrence-heading">
                <div>
                  <strong>
                    {occurrence.title}
                  </strong>

                  <span>
                    {occurrence.tool_name}
                  </span>
                </div>

                <span>
                  {formatDate(
                    occurrence.created_at,
                  )}
                </span>
              </div>

              <dl className="finding-occurrence-grid">
                <div>
                  <dt>External finding ID</dt>
                  <dd>
                    {occurrence.external_finding_id ||
                      '—'}
                  </dd>
                </div>

                <div>
                  <dt>Severity</dt>
                  <dd>
                    {occurrence.severity ||
                      '—'}
                  </dd>
                </div>

                <div>
                  <dt>Confidence</dt>
                  <dd>
                    {occurrence.confidence ||
                      '—'}
                  </dd>
                </div>

                <div>
                  <dt>Affected URL</dt>
                  <dd>
                    {occurrence.affected_url ||
                      '—'}
                  </dd>
                </div>

                <div>
                  <dt>Affected port</dt>
                  <dd>
                    {occurrence.affected_port ||
                      '—'}
                  </dd>
                </div>
              </dl>

              <div className="finding-occurrence-evidence">
                <span>Evidence</span>
                <p>
                  {EvidencePreview({
                    evidence:
                      occurrence.evidence,
                  })}
                </p>
              </div>
            </article>
          ),
        )}

        {occurrences.length === 0 && (
          <p className="finding-muted">
            No raw occurrences are available.
          </p>
        )}
      </div>
    </section>
  )
}
