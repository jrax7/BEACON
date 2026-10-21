function EvidenceValues({
  evidence,
}) {
  if (
    !evidence ||
    typeof evidence !== 'object' ||
    Array.isArray(evidence) ||
    Object.keys(evidence).length === 0
  ) {
    return (
      <p className="finding-muted">
        Evidence not available
      </p>
    )
  }

  return (
    <dl className="finding-evidence-values">
      {Object.entries(evidence).map(
        ([key, value]) => (
          <div key={key}>
            <dt>{key}</dt>
            <dd>
              {typeof value === 'object'
                ? JSON.stringify(value)
                : String(value)}
            </dd>
          </div>
        ),
      )}
    </dl>
  )
}


export default function FindingEvidence({
  finding,
}) {
  const occurrences =
    finding.occurrences || []

  return (
    <section className="finding-detail-card">
      <div className="finding-section-heading">
        <div>
          <p className="eyebrow">
            EVIDENCE
          </p>
          <h2>Finding evidence</h2>
        </div>
      </div>

      <div className="finding-copy-block">
        <h3>Description</h3>
        <p>
          {finding.description ||
            'Description not available.'}
        </p>
      </div>

      <div className="finding-copy-block">
        <h3>Sample affected URLs</h3>

        {(
          finding.sample_affected_urls ||
          []
        ).length > 0 ? (
          <ul className="finding-url-list">
            {finding.sample_affected_urls.map(
              (url) => (
                <li key={url}>{url}</li>
              ),
            )}
          </ul>
        ) : (
          <p className="finding-muted">
            No affected URLs were recorded.
          </p>
        )}
      </div>

      <div className="finding-copy-block">
        <h3>Occurrence evidence</h3>

        {occurrences.length > 0 ? (
          occurrences.map(
            (occurrence) => (
              <article
                className="finding-evidence-occurrence"
                key={occurrence.id}
              >
                <div className="finding-evidence-context">
                  <span>
                    {occurrence.affected_url ||
                      'URL not recorded'}
                  </span>
                  <span>
                    Port:{' '}
                    {occurrence.affected_port ||
                      '—'}
                  </span>
                </div>

                <EvidenceValues
                  evidence={
                    occurrence.evidence
                  }
                />
              </article>
            ),
          )
        ) : (
          <p className="finding-muted">
            Evidence not available
          </p>
        )}
      </div>
    </section>
  )
}
