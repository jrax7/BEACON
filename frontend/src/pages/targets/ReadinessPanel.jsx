import { Card } from '../../components/ui'

export default function ReadinessPanel({
  isVerified,
  onLaunchScan,
  launchingScan,
  readOnly = false,
}) {
  return (
    <Card eyebrow="ASSESSMENT READINESS" title="Assessment status" className="target-detail-section">
      <div className={isVerified ? 'readiness-card ready' : 'readiness-card not-ready'}>
        <strong>{isVerified ? 'Ready for assessment' : 'Not ready for assessment'}</strong>

        <p>
          {isVerified
            ? 'Ownership is verified. Review the network readiness checklist below before starting an authorized assessment.'
            : 'Ownership verification must succeed before BEACON can launch a security assessment against this target.'}
        </p>

        {isVerified && !readOnly && (
          <button
            type="button"
            className="primary-button scan-launch-button"
            onClick={onLaunchScan}
            disabled={launchingScan}
          >
            {launchingScan ? 'Launching assessment...' : 'Launch Assessment'}
          </button>
        )}
      </div>

      <div className="readiness-guide">
        <div className="readiness-guide-heading">
          <div>
            <span className="detail-label">PRE-SCAN CHECKLIST</span>
            <strong>Prepare the target path</strong>
          </div>
          <span className="readiness-profile">Assessment · HTTP/S</span>
        </div>

        <div className="readiness-steps">
          <article>
            <span>01</span>
            <div>
              <strong>Keep the web service reachable</strong>
              <p>
                The constrained web assessment currently discovers TCP 80 and 443, then runs web checks only
                against the verified target URL and its configured web port.
              </p>
            </div>
          </article>

          <article>
            <span>02</span>
            <div>
              <strong>Allow the scanner path, not unrelated ports</strong>
              <p>
                If a firewall, reverse proxy, or WAF restricts source traffic, allow the BEACON
                scanner egress address to reach the target web service. Do not expose extra
                inbound ports just for the assessment.
              </p>
            </div>
          </article>

          <article>
            <span>03</span>
            <div>
              <strong>Account for WAF and rate limits</strong>
              <p>
                Security controls can throttle or terminate automated HTTP requests. Use an
                approved maintenance window or a scoped allow rule when your policy permits it.
              </p>
            </div>
          </article>

          <article>
            <span>04</span>
            <div>
              <strong>Watch telemetry during the run</strong>
              <p>
                The assessment page shows each scanner, failures, warnings, runtime, and Nikto
                request progress so connectivity problems can be identified while the job is
                running.
              </p>
            </div>
          </article>
        </div>

        <div className="readiness-note">
          <strong>Production note:</strong> deploy BEACON with a stable scanner egress IP before
          creating firewall or WAF allow rules. Container addresses in the local development lab
          are not suitable as permanent allowlist entries.
        </div>
      </div>
    </Card>
  )
}
