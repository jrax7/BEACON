import DnsProviderHelp from '../../components/DnsProviderHelp'
import { Card, StatusBadge } from '../../components/ui'
import { formatDate } from '../../lib/format'

export default function VerificationPanel({
  target,
  isVerified,
  verification,
  onVerify,
  verifying,
  onRegenerate,
  regenerating,
  readOnly = false,
}) {
  return (
    <Card
      eyebrow="OWNERSHIP"
      title="Verification"
      className="target-detail-section"
      headingActions={<StatusBadge value={target.verification_status} />}
    >
      {isVerified ? (
        <div className="verification-summary verified-summary">
          <strong>Ownership verified</strong>
          <p>
            BEACON currently recognizes this target as verified. Verification expires at{' '}
            {formatDate(target.verification_expires_at)}.
          </p>
        </div>
      ) : (
        <div className="verification-summary">
          <strong>Ownership verification required</strong>
          <p>
            If you already deployed the existing verification value, you can attempt
            verification now. If you lost the value or instructions, generate a new one below.
          </p>
        </div>
      )}

      {verification && (
        <div className="generated-verification">
          <div className="verification-detail">
            <span className="detail-label">Verification location</span>
            <code className="verification-code">{verification.verification_location}</code>
          </div>

          <div className="verification-detail">
            <span className="detail-label">Verification value</span>
            <code className="verification-code">{verification.verification_value}</code>
          </div>

          <div className="verification-detail">
            <span className="detail-label">Instructions</span>
            <p className="verification-instructions">{verification.instructions}</p>
          </div>

          <div className="verification-notice">
            This value is displayed only as part of this regeneration response. BEACON stores
            only its hash.
          </div>

          {target.verification_method === 'dns' && (
            <DnsProviderHelp
              hostname={target.hostname}
              location={verification.verification_location}
              value={verification.verification_value}
            />
          )}
        </div>
      )}

      {!readOnly && (
        <div className="target-actions">
          {!isVerified && (
            <button
              type="button"
              className="primary-button detail-action-button"
              onClick={onVerify}
              disabled={verifying}
            >
              {verifying
                ? 'Verifying...'
                : target.verification_method === 'dns'
                  ? 'Verify DNS ownership'
                  : 'Verify file ownership'}
            </button>
          )}

          <button
            type="button"
            className="secondary-button detail-action-button"
            onClick={onRegenerate}
            disabled={regenerating}
          >
            {regenerating
              ? 'Generating...'
              : isVerified
                ? 'Regenerate verification'
                : 'Generate new instructions'}
          </button>
        </div>
      )}

      {isVerified && (
        <p className="action-warning">
          Regenerating verification will reset this target to Pending until ownership is
          verified again.
        </p>
      )}
    </Card>
  )
}
