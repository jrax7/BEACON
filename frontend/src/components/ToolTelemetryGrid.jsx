import { progressWidthClass } from '../utils/progressWidthClass'
function formatDuration(seconds) {
  if (
    seconds === null ||
    seconds === undefined
  ) {
    return '—'
  }

  if (seconds < 60) {
    return `${seconds.toFixed(1)}s`
  }

  const minutes = Math.floor(seconds / 60)
  const remaining = Math.round(seconds % 60)

  return `${minutes}m ${remaining}s`
}

function displayToolName(name) {
  const names = {
    nmap: 'Nmap',
    zap: 'OWASP ZAP',
    nikto: 'Nikto',
  }

  return names[name] || name
}

function getToolOutcome(tool) {
  if (tool.status === 'failed') return 'failed'
  if (tool.warning || tool.status === 'skipped') return 'warning'
  if (tool.status === 'completed') return 'completed'
  if (tool.status === 'running') return 'running'
  return 'pending'
}

function requestLabel(tool) {
  if (!tool.completed_requests) return null

  if (tool.estimated_total_requests) {
    return `${tool.completed_requests.toLocaleString()} / ~${tool.estimated_total_requests.toLocaleString()}`
  }

  return tool.completed_requests.toLocaleString()
}

function LegacyToolTelemetryGrid({
  tools,
}) {
  return (
    <section className="scan-console-card tool-section">
      <div className="console-card-heading">
        <div>
          <p className="scan-kicker">TOOL TELEMETRY</p>
          <h2>Scanner execution</h2>
        </div>

        <span className="console-heading-meta">
          {tools.length} engines
        </span>
      </div>

      <div className="tool-grid">
        {tools.map((tool) => {
          const outcome = getToolOutcome(tool)
          const requests = requestLabel(tool)

          return (
            <article
              className={`tool-card tool-${outcome}`}
              key={tool.id}
            >
              <div className="tool-card-top">
                <div>
                  <span className="tool-name">
                    {displayToolName(tool.tool_name)}
                  </span>
                  <span className="tool-version">
                    {tool.tool_version
                      ? `v${tool.tool_version}`
                      : tool.status === 'running'
                        ? 'detecting version...'
                        : 'version unavailable'}
                  </span>
                </div>

                <span className="tool-status">
                  <span className="tool-status-dot" />
                  {outcome}
                </span>
              </div>

              {tool.status === 'running' &&
                tool.progress_percent !== null &&
                tool.progress_percent !== undefined && (
                  <div className="tool-live-progress">
                    <div className="tool-progress-heading">
                      <span>Live progress</span>
                      <strong>{tool.progress_percent}%</strong>
                    </div>
                    <div className="tool-progress-track">
                      <span
                        className={progressWidthClass(
                          tool.progress_percent,
                        )}
                      />
                    </div>
                    {requests && (
                      <small>{requests} requests</small>
                    )}
                  </div>
                )}

              {tool.status === 'running' &&
                (tool.progress_percent === null ||
                  tool.progress_percent === undefined) && (
                  <div className="tool-indeterminate">
                    <span />
                    Scanner running — waiting for native progress telemetry
                  </div>
                )}

              <div className="tool-stats">
                <div>
                  <span>Findings</span>
                  <strong>{tool.finding_count}</strong>
                </div>

                <div>
                  <span>Runtime</span>
                  <strong>{formatDuration(tool.duration_seconds)}</strong>
                </div>

                <div>
                  <span>Exit</span>
                  <strong>{tool.exit_code ?? '—'}</strong>
                </div>

                {requests && (
                  <div>
                    <span>Requests</span>
                    <strong>{requests}</strong>
                  </div>
                )}

                {tool.request_error_count !== null &&
                  tool.request_error_count !== undefined && (
                    <div>
                      <span>HTTP errors</span>
                      <strong>{tool.request_error_count}</strong>
                    </div>
                  )}
              </div>

              {tool.progress_message && tool.status === 'running' && (
                <div className="tool-progress-message">
                  {tool.progress_message}
                </div>
              )}

              {tool.warning && (
                <div className="tool-warning">
                  <strong>Warning</strong>
                  <span>{tool.warning}</span>
                </div>
              )}

              {tool.error_message && (
                <div className="tool-error">
                  <strong>Failure</strong>
                  <span>{tool.error_message}</span>
                </div>
              )}
            </article>
          )
        })}
      </div>
    </section>
  )
}

function formatEngineRuntime(
  value,
) {
  if (
    value === null
    || value === undefined
  ) {
    return '—'
  }

  const seconds = Math.max(
    0,
    Number(value),
  )

  if (!Number.isFinite(seconds)) {
    return '—'
  }

  if (seconds < 60) {
    return `${Math.floor(seconds)}s`
  }

  const minutes = Math.floor(
    seconds / 60,
  )

  const remaining = Math.floor(
    seconds % 60,
  )

  return `${minutes}m ${remaining}s`
}


function formatEngineTimestamp(
  value,
) {
  if (!value) {
    return '—'
  }

  const date = new Date(
    value,
  )

  if (
    Number.isNaN(
      date.getTime(),
    )
  ) {
    return value
  }

  return date.toLocaleString()
}


function metricLabel(
  key,
) {
  const labels = {
    completed_requests:
      'Completed requests',
    estimated_total_requests:
      'Estimated requests',
    request_error_count:
      'Request errors',
    finding_count:
      'Findings reported',
  }

  return (
    labels[key]
    || key.replaceAll(
      '_',
      ' ',
    )
  )
}


function EngineV2ToolTelemetryGrid({
  engines,
}) {
  return (
    <section
      className={
        'scan-console-card '
        + 'tool-section '
        + 'engine-v2-tool-section'
      }
    >
      <div className="console-card-heading">
        <div>
          <p className="scan-kicker">
            ENGINE EXECUTION
          </p>

          <h2>
            Persisted scanner telemetry
          </h2>
        </div>

        <span className="console-heading-meta">
          {engines.length} engines
        </span>
      </div>

      <div className="engine-v2-tool-grid">
        {engines.map(
          (engine) => {
            const metrics = (
              Object.entries(
                engine.metrics
                || {},
              )
            )

            return (
              <article
                key={engine.engine}
                className={
                  'engine-v2-tool-card '
                  + `engine-state-${engine.status}`
                }
                data-state={engine.status}
              >
                {engine.status === 'running' && (
                  <span
                    className="engine-v2-tool-signal"
                    aria-hidden="true"
                  />
                )}
                <div className="engine-v2-tool-heading">
                  <div>
                    <span className="detail-label">
                      {engine.engine}
                    </span>

                    <strong>
                      {engine.status}
                    </strong>
                  </div>

                  <span className="engine-v2-tool-profile-state">
                    {engine.profile_enabled
                      ? 'Profile enabled'
                      : 'Profile disabled'}
                  </span>
                </div>

                <dl className="engine-v2-tool-facts">
                  <div>
                    <dt>Version</dt>
                    <dd>
                      {engine.tool_version
                        || '—'}
                    </dd>
                  </div>

                  <div>
                    <dt>Elapsed</dt>
                    <dd>
                      {formatEngineRuntime(
                        engine.elapsed_seconds,
                      )}
                    </dd>
                  </div>

                  <div>
                    <dt>Attempt</dt>
                    <dd>
                      {engine.attempt
                        ?? '—'}
                    </dd>
                  </div>

                  <div>
                    <dt>Exit code</dt>
                    <dd>
                      {engine.exit_code
                        ?? '—'}
                    </dd>
                  </div>

                  <div>
                    <dt>Last heartbeat</dt>
                    <dd>
                      {formatEngineTimestamp(
                        engine.last_heartbeat_at,
                      )}
                    </dd>
                  </div>

                  <div>
                    <dt>Completed</dt>
                    <dd>
                      {formatEngineTimestamp(
                        engine.completed_at,
                      )}
                    </dd>
                  </div>
                </dl>

                <div className="engine-v2-tool-metrics">
                  <span className="detail-label">
                    TRUSTWORTHY METRICS
                  </span>

                  {metrics.length === 0 ? (
                    <p>
                      Not reported
                    </p>
                  ) : (
                    <dl>
                      {metrics.map(
                        (
                          [
                            key,
                            value,
                          ],
                        ) => (
                          <div key={key}>
                            <dt>
                              {metricLabel(
                                key,
                              )}
                            </dt>

                            <dd>
                              {value}
                            </dd>
                          </div>
                        ),
                      )}
                    </dl>
                  )}
                </div>

                {(engine.failure_message
                  || engine.skipped_reason)
                  && (
                    <div className="engine-v2-tool-message">
                      <strong>
                        {engine.failure_message
                          ? 'Execution limitation'
                          : 'Skipped'}
                      </strong>

                      <p>
                        {engine.failure_message
                          || engine.skipped_reason}
                      </p>
                    </div>
                  )}
              </article>
            )
          },
        )}
      </div>
    </section>
  )
}


export default function ToolTelemetryGrid({
  tools = [],
  engines = null,
}) {
  if (
    Array.isArray(
      engines,
    )
  ) {
    return (
      <EngineV2ToolTelemetryGrid
        engines={engines}
      />
    )
  }

  return (
    <LegacyToolTelemetryGrid
      tools={tools}
    />
  )
}
