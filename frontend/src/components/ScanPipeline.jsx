import { progressWidthClass } from '../utils/progressWidthClass'
function getTool(
  telemetry,
  toolName,
) {
  return telemetry.tool_runs.find(
    (tool) =>
      tool.tool_name === toolName,
  )
}

function toolStageStatus(tool) {
  if (!tool) {
    return 'pending'
  }

  if (tool.status === 'running') {
    return 'active'
  }

  if (tool.status === 'failed') {
    return 'failed'
  }

  if (
    tool.status === 'skipped' ||
    tool.warning
  ) {
    return 'warning'
  }

  if (tool.status === 'completed') {
    return 'completed'
  }

  return 'pending'
}

function buildStages(
  scan,
  telemetry,
) {
  const nmap =
    getTool(telemetry, 'nmap')

  const zap =
    getTool(telemetry, 'zap')

  const nikto =
    getTool(telemetry, 'nikto')

  const scanComplete =
    scan.status === 'completed'

  const scanFailed =
    scan.status === 'failed'

  const toolsTerminal =
    [nmap, zap, nikto]
      .filter(Boolean)
      .every(
        (tool) =>
          [
            'completed',
            'failed',
            'skipped',
          ].includes(tool.status),
      )

  let processingStatus = 'pending'

  if (scanComplete) {
    processingStatus = 'completed'
  } else if (scanFailed) {
    processingStatus = 'failed'
  } else if (
    toolsTerminal &&
    telemetry.active_stage ===
      'finalizing'
  ) {
    processingStatus = 'active'
  }

  let finalStatus = 'pending'

  if (scanComplete) {
    finalStatus =
      telemetry.outcome ===
      'completed_with_warnings'
        ? 'warning'
        : 'completed'
  } else if (scanFailed) {
    finalStatus = 'failed'
  } else if (
    telemetry.active_stage ===
    'finalizing'
  ) {
    finalStatus = 'active'
  }

  return [
    {
      id: 'preparation',
      label: 'Target preparation',
      description:
        scan.started_at
          ? 'Target validated and worker started'
          : 'Waiting for the assessment worker',
      status:
        scan.started_at
          ? 'completed'
          : scan.status === 'queued'
            ? 'active'
            : 'pending',
    },
    {
      id: 'nmap',
      label:
        'Nmap network discovery',
      status:
        toolStageStatus(nmap),
      tool: nmap,
    },
    {
      id: 'zap',
      label:
        'OWASP ZAP passive analysis',
      status:
        toolStageStatus(zap),
      tool: zap,
    },
    {
      id: 'nikto',
      label:
        'Nikto web server analysis',
      status:
        toolStageStatus(nikto),
      tool: nikto,
    },
    {
      id: 'processing',
      label:
        'Findings processing',
      description:
        'Normalize and persist scanner observations',
      status:
        processingStatus,
    },
    {
      id: 'finalization',
      label:
        'Assessment finalization',
      description:
        telemetry.active_stage_label,
      status:
        finalStatus,
    },
  ]
}

function formatDuration(seconds) {
  if (
    seconds === null ||
    seconds === undefined
  ) {
    return null
  }

  if (seconds < 60) {
    return `${seconds.toFixed(1)}s`
  }

  const minutes =
    Math.floor(seconds / 60)

  const remaining =
    Math.round(seconds % 60)

  return `${minutes}m ${remaining}s`
}

function getMarker(status) {
  const markers = {
    completed: '✓',
    active: '●',
    warning: '!',
    failed: '×',
    pending: '○',
  }

  return markers[status] || '○'
}

function LegacyScanPipeline({
  scan,
  telemetry,
}) {
  const stages =
    buildStages(
      scan,
      telemetry,
    )

  return (
    <section className="scan-console-card pipeline-card">
      <div className="console-card-heading">
        <div>
          <p className="scan-kicker">
            SCAN PIPELINE
          </p>

          <h2>
            Assessment stages
          </h2>
        </div>

        <span className="pipeline-count">
          {
            stages.filter(
              (stage) =>
                [
                  'completed',
                  'warning',
                ].includes(
                  stage.status,
                ),
            ).length
          }
          /{stages.length}
        </span>
      </div>

      <div className="pipeline-list">
        {stages.map(
          (stage, index) => (
            <article
              className={
                `pipeline-stage stage-${stage.status}`
              }
              key={stage.id}
            >
              <div className="pipeline-rail">
                <span className="stage-marker">
                  {getMarker(
                    stage.status,
                  )}
                </span>

                {index <
                  stages.length - 1 && (
                  <span className="stage-line" />
                )}
              </div>

              <div className="stage-content">
                <div className="stage-title-row">
                  <strong>
                    {stage.label}
                  </strong>

                  <span className="stage-state">
                    {stage.status}
                  </span>
                </div>

                {stage.tool?.status === 'running' &&
                  stage.tool.progress_percent !== null &&
                  stage.tool.progress_percent !== undefined && (
                    <div className="stage-native-progress">
                      <div>
                        <span>Native scanner progress</span>
                        <strong>{stage.tool.progress_percent}%</strong>
                      </div>
                      <div className="stage-progress-track">
                        <span
                          className={progressWidthClass(
                            stage.tool.progress_percent,
                          )}
                        />
                      </div>
                    </div>
                  )}

                {stage.tool && (
                  <div className="stage-meta">
                    {stage.tool.tool_version && (
                      <span>
                        v{
                          stage.tool
                            .tool_version
                        }
                      </span>
                    )}

                    <span>
                      {
                        stage.tool
                          .finding_count
                      }{' '}
                      {
                        stage.tool
                          .finding_count === 1
                          ? 'observation'
                          : 'findings'
                      }
                    </span>

                    {formatDuration(
                      stage.tool
                        .duration_seconds,
                    ) && (
                      <span>
                        {formatDuration(
                          stage.tool
                            .duration_seconds,
                        )}
                      </span>
                    )}
                  </div>
                )}

                {stage.description && (
                  <p className="stage-description">
                    {
                      stage.description
                    }
                  </p>
                )}

                {stage.tool?.warning && (
                  <div className="stage-warning">
                    {
                      stage.tool
                        .warning
                    }
                  </div>
                )}

                {stage.tool
                  ?.error_message && (
                  <div className="stage-error">
                    {
                      stage.tool
                        .error_message
                    }
                  </div>
                )}
              </div>
            </article>
          ),
        )}
      </div>
    </section>
  )
}

const ENGINE_V2_LABELS = {
  nmap: 'Nmap service discovery',
  httpx: 'httpx HTTP classification',
  katana: 'Katana application discovery',
  sslyze: 'SSLyze TLS assessment',
  nuclei: 'Nuclei vulnerability checks',
  zap: 'OWASP ZAP assessment',
  nikto: 'Nikto server checks',
}


function engineV2StateLabel(
  state,
) {
  const labels = {
    pending: 'Pending',
    queued: 'Queued',
    running: 'Running',
    completed: 'Completed',
    failed: 'Failed',
    timed_out: 'Timed out',
    cancelled: 'Cancelled',
    skipped: 'Skipped',
    interrupted: 'Interrupted',
  }

  return (
    labels[state]
    || state
    || 'Pending'
  )
}


function engineV2StagePosition(
  state,
) {
  if (state === 'running') {
    return 'current'
  }

  if (state === 'completed') {
    return 'complete'
  }

  if (
    state === 'pending'
    || state === 'queued'
  ) {
    return 'upcoming'
  }

  return 'terminal'
}


function scopeStageState(
  runtime,
  executions,
) {
  if (
    runtime.current_stage
    === 'scope_authorization'
  ) {
    return 'running'
  }

  if (
    runtime.status === 'queued'
    || runtime.status === 'pending'
  ) {
    return 'pending'
  }

  if (
    runtime.status === 'cancelled'
  ) {
    return 'cancelled'
  }

  if (
    executions.some(
      (engine) => (
        engine.profile_enabled
        && ![
          'pending',
          'queued',
        ].includes(
          engine.status,
        )
      ),
    )
    || [
      'completed',
      'failed',
    ].includes(
      runtime.status,
    )
  ) {
    return 'completed'
  }

  return 'pending'
}


function postProcessingState(
  runtime,
) {
  if (
    runtime.current_stage
    === 'post_processing'
  ) {
    return 'running'
  }

  if (
    runtime.status === 'completed'
  ) {
    return 'completed'
  }

  if (
    runtime.status === 'failed'
  ) {
    return 'failed'
  }

  if (
    runtime.status === 'cancelled'
  ) {
    return 'cancelled'
  }

  return 'pending'
}


function EngineV2Pipeline({
  runtime,
}) {
  const executions = (
    runtime.engine_executions
    || []
  )

  const stages = [
    {
      key: 'scope_authorization',
      label: 'Scope and authorization',
      state: scopeStageState(
        runtime,
        executions,
      ),
      detail:
        'Verified target and per-assessment authorization checks.',
    },

    ...executions.map(
      (engine) => ({
        key: engine.engine,
        label:
          ENGINE_V2_LABELS[
            engine.engine
          ]
          || engine.engine,
        state: engine.status,
        detail: (
          engine.failure_message
          || engine.skipped_reason
          || (
            engine.profile_enabled
              ? null
              : 'Disabled by profile.'
          )
        ),
        version:
          engine.tool_version,
      }),
    ),

    {
      key: 'post_processing',
      label:
        'Normalization, correlation, and coverage',
      state:
        postProcessingState(
          runtime,
        ),
      detail:
        'Scanner evidence is normalized and correlated after engine execution.',
    },
  ]

  return (
    <section
      className={
        'scan-console-card '
        + 'pipeline-card '
        + 'engine-v2-pipeline'
      }
    >
      <div className="console-card-heading">
        <div>
          <p className="scan-kicker">
            ENGINE V2 PIPELINE
          </p>

          <h2>
            Persisted execution stages
          </h2>
        </div>

        <span className="console-heading-meta">
          Stage-based
        </span>
      </div>

      <p className="engine-v2-pipeline-note">
        BEACON shows persisted stage state.
        It does not manufacture a precise
        completion percentage.
      </p>

      <div className="engine-v2-stage-list">
        {stages.map(
          (
            stage,
            index,
          ) => (
            <div
              key={stage.key}
              className={
                'engine-v2-stage '
                + `stage-state-${stage.state}`
              }
              data-stage={
                stage.key
              }
            data-state={stage.state}
            data-position={engineV2StagePosition(
              stage.state,
            )}
            aria-current={
              stage.state === 'running'
                ? 'step'
                : undefined
            }
            >
              <div className="engine-v2-stage-rail">
                <span className="engine-v2-stage-marker">
                  {stage.state === 'completed'
                    ? '✓'
                    : stage.state === 'running'
                      ? '●'
                      : stage.state === 'failed'
                        ? '!'
                        : stage.state === 'timed_out'
                          ? '!'
                          : stage.state === 'cancelled'
                            ? '×'
                            : stage.state === 'interrupted'
                              ? '!'
                              : stage.state === 'skipped'
                                ? '–'
                                : '○'}
                </span>

                {stage.state === 'running' && (
                  <span
                    className="engine-v2-stage-signal"
                    aria-hidden="true"
                  />
                )}

                {index < stages.length - 1 && (
                  <span className="engine-v2-stage-line" />
                )}
              </div>

              <div className="engine-v2-stage-copy">
                <div className="engine-v2-stage-heading">
                  <strong>
                    {stage.label}
                  </strong>

                  <span>
                    {engineV2StateLabel(
                      stage.state,
                    )}
                  </span>
                </div>

                {stage.state === 'running' && (
                  <div className="engine-v2-stage-live-copy">
                    <span aria-hidden="true" />
                    Active persisted stage
                  </div>
                )}

                {stage.version && (
                  <small>
                    Version {stage.version}
                  </small>
                )}

                {stage.detail && (
                  <p>
                    {stage.detail}
                  </p>
                )}
              </div>
            </div>
          ),
        )}
      </div>
    </section>
  )
}


export default function ScanPipeline(
  props,
) {
  if (
    props.assessmentRuntime
      ?.engine_version
    === 'v2'
  ) {
    return (
      <EngineV2Pipeline
        runtime={
          props.assessmentRuntime
        }
      />
    )
  }

  return (
    <LegacyScanPipeline
      {...props}
    />
  )
}
