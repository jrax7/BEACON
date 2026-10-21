export default function VerificationInstructions({ verification }) {
  return (
    <section className="verification-card">
      <div className="section-heading">
        <div>
          <p className="eyebrow">OWNERSHIP VERIFICATION</p>
          <h2>Verification required</h2>
        </div>

        <span className="status-badge status-pending">Pending</span>
      </div>

      <p className="verification-intro">
        BEACON registered <strong>{verification.hostname}</strong>. Complete the ownership
        verification below before attempting a scan.
      </p>

      <div className="verification-grid">
        <div>
          <span className="detail-label">Method</span>
          <strong>{verification.method === 'dns' ? 'DNS TXT record' : 'Verification file'}</strong>
        </div>

        <div>
          <span className="detail-label">Target ID</span>
          <code>{verification.targetId}</code>
        </div>
      </div>

      <div className="verification-detail">
        <span className="detail-label">Verification location</span>
        <code className="verification-code">{verification.location}</code>
      </div>

      <div className="verification-detail">
        <span className="detail-label">Verification value</span>
        <code className="verification-code">{verification.value}</code>
      </div>

      <div className="verification-detail">
        <span className="detail-label">Instructions</span>
        <p className="verification-instructions">{verification.instructions}</p>
      </div>

      <div className="verification-notice">
        Save these instructions now. The verification value is not included in normal
        target-list responses.
      </div>
    </section>
  )
}
