export default function FindingRemediation({
  finding,
}) {
  return (
    <section className="finding-detail-card">
      <div className="finding-section-heading">
        <div>
          <p className="eyebrow">
            REMEDIATION
          </p>
          <h2>Remediation</h2>
        </div>
      </div>

      {finding.remediation ? (
        <p className="finding-remediation-copy">
          {finding.remediation}
        </p>
      ) : (
        <p className="finding-muted">
          Remediation guidance is not available for this finding.
        </p>
      )}
    </section>
  )
}
