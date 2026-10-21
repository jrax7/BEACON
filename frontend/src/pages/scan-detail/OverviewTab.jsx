import { Link } from 'react-router'

import ScanPipeline from '../../components/ScanPipeline'
import { severityBadgeClass } from '../../lib/format'
import { buildFindingsPath } from '../findings/helpers'
import { displayToolName, getToolOutcome } from './helpers'
import { AssessmentMetadata } from './parts'

export default function OverviewTab({
  assessmentRuntime, scan, telemetry, target, summary }) {
  const warningTools = telemetry.tool_runs.filter((tool) => tool.warning)
  const failedTools = telemetry.tool_runs.filter((tool) => tool.status === 'failed')

  return (
    <div className="assessment-tab-panel">
      {scan.failure_reason && (
        <section className="scan-console-card failure-panel">
          <p className="scan-kicker">FAILURE</p>
          <h2>Assessment failed</h2>
          <p>{scan.failure_reason}</p>
        </section>
      )}

      {summary && (
        <section className="scan-console-card findings-summary-card">
          <div className="console-card-heading">
            <div>
              <p className="scan-kicker">RESULTS</p>
              <h2>Assessment summary</h2>
            </div>
            <span className={severityBadgeClass(summary.highest_security_severity || 'informational')}>
              Highest security severity: {summary.highest_security_severity || 'none'}
            </span>

            <Link
              className="text-link"
              to={buildFindingsPath({
                scan_id: scan.id,
              })}
            >
              View findings →
            </Link>
          </div>

          <div className="result-metric-grid">
            <div>
              <span>Security issues</span>
              <strong>{summary.security_issue_count ?? 0}</strong>
            </div>
            <div>
              <span>Attack surface</span>
              <strong>{summary.attack_surface_count ?? 0}</strong>
            </div>
            <div>
              <span>Observations</span>
              <strong>{summary.observation_count ?? 0}</strong>
            </div>
            <div>
              <span>Limitations</span>
              <strong>{summary.limitation_count ?? 0}</strong>
            </div>
          </div>
        </section>
      )}

      <div className="assessment-overview-grid">
        <ScanPipeline
          scan={scan}
          telemetry={telemetry}
          assessmentRuntime={assessmentRuntime}
        />

        <section className="scan-console-card posture-card">
          <div className="console-card-heading">
            <div>
              <p className="scan-kicker">POSTURE</p>
              <h2>Assessment signals</h2>
            </div>
            <span className="console-heading-meta">{telemetry.tool_runs.length} engines</span>
          </div>

          <div className="scanner-outcome-list">
            {telemetry.tool_runs.map((tool) => {
              const outcome = getToolOutcome(tool)

              return (
                <div
                  className="scanner-outcome-row"
                  key={tool.id}
                  data-state={outcome}
                >
                  <span
                    className={`scanner-signal-dot scanner-signal-${outcome}`}
                    aria-hidden="true"
                  />

                  <div>
                    <strong>{displayToolName(tool.tool_name)}</strong>
                    <span>{tool.tool_version || 'Version unavailable'}</span>
                  </div>

                  <span className={`scanner-mini-state scanner-${outcome}`}>
                    {outcome}
                  </span>
                </div>
              )
            })}
          </div>

          {warningTools.length > 0 && (
            <div className="overview-warning-stack">
              {warningTools.map((tool) => (
                <div className="overview-warning" key={tool.id}>
                  <strong>{displayToolName(tool.tool_name)} warning</strong>
                  <p>{tool.warning}</p>
                </div>
              ))}
            </div>
          )}

          {failedTools.length === 0 && warningTools.length === 0 && (
            <div className="overview-clean-state">
              <span className="overview-clean-dot" />
              No scanner execution warnings were recorded.
            </div>
          )}
        </section>
      </div>

      {assessmentRuntime
        ?.engine_version
        === 'v2'
        && (
          <section className="scan-console-card engine-v2-coverage-panel">
            <div className="console-card-heading">
              <div>
                <p className="scan-kicker">
                  ENGINE V2 COVERAGE
                </p>

                <h2>
                  Coverage and limitations
                </h2>
              </div>

              <span className="console-heading-meta">
                {assessmentRuntime
                  .current_stage_label
                  || 'Assessment state'}
              </span>
            </div>

            <div className="engine-v2-coverage-summary">
              <div>
                <span>Current stage</span>
                <strong>
                  {assessmentRuntime
                    .current_stage_label
                    || '—'}
                </strong>
              </div>

              <div>
                <span>Elapsed</span>
                <strong>
                  {assessmentRuntime
                    .elapsed_seconds
                    === null
                    || assessmentRuntime
                    .elapsed_seconds
                    === undefined
                    ? '—'
                    : `${assessmentRuntime
                      .elapsed_seconds}s`}
                </strong>
              </div>

              <div>
                <span>Engines completed</span>
                <strong>
                  {assessmentRuntime
                    .coverage
                    ?.engines_completed
                    ?? 0}
                  {' / '}
                  {assessmentRuntime
                    .coverage
                    ?.engines_total
                    ?? 0}
                </strong>
              </div>

              <div>
                <span>Incomplete engines</span>
                <strong>
                  {assessmentRuntime
                    .coverage
                    ?.engines_incomplete
                    ?? 0}
                </strong>
              </div>
            </div>

            {assessmentRuntime
              .coverage
              && !assessmentRuntime
                .coverage
                .detailed_metrics_available
              && (
                <div className="engine-v2-coverage-notice">
                  <strong>
                    Detailed coverage counters unavailable
                  </strong>

                  <p>
                    Detailed URL/service coverage is not persisted
                    for this assessment, so BEACON does not invent
                    those counters. Engine execution state and
                    limitations below come from persisted records.
                  </p>
                </div>
              )}

            {assessmentRuntime
              .coverage
              ?.limitations
              ?.length > 0
              ? (
                <div className="engine-v2-limitations">
                  <span className="detail-label">
                    COVERAGE LIMITATIONS
                  </span>

                  <ul>
                    {assessmentRuntime
                      .coverage
                      .limitations
                      .map(
                        (
                          limitation,
                        ) => (
                          <li key={limitation}>
                            {limitation}
                          </li>
                        ),
                      )}
                  </ul>
                </div>
              )
              : (
                <p className="engine-v2-no-limitations">
                  No persisted engine execution
                  limitation has been recorded.
                </p>
              )}
          </section>
        )}

      <AssessmentMetadata scan={scan} target={target} />
    </div>
  )
}
