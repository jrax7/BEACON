import LiveActivityConsole
  from '../../components/LiveActivityConsole'
import ScanPipeline
  from '../../components/ScanPipeline'
import ToolTelemetryGrid
  from '../../components/ToolTelemetryGrid'


export default function TelemetryTab({
  scan,
  telemetry,
  isLive,
  assessmentRuntime,
}) {
  const isEngineV2 = (
    assessmentRuntime
      ?.engine_version
    === 'v2'
  )

  return (
    <div className="assessment-tab-panel">
      <div className="assessment-primary-grid">
        <ScanPipeline
          scan={scan}
          telemetry={telemetry}
          assessmentRuntime={
            assessmentRuntime
          }
        />

        <LiveActivityConsole
          events={
            telemetry.events
          }
          isLive={isLive}
        />
      </div>

      <ToolTelemetryGrid
        tools={
          telemetry.tool_runs
        }
        engines={
          isEngineV2
            ? (
              assessmentRuntime
                .engine_executions
            )
            : null
        }
      />

      <section className="scan-console-card telemetry-note-card">
        <p className="scan-kicker">
          TELEMETRY BEHAVIOR
        </p>

        <h2>
          {isLive
            ? 'Live polling active'
            : 'Assessment polling stopped'}
        </h2>

        <p>
          {isLive
            ? (
              isEngineV2
                ? (
                  'BEACON refreshes persisted Engine v2 '
                  + 'stage state and safe scanner telemetry '
                  + 'every two seconds while this assessment '
                  + 'is active.'
                )
                : (
                  'BEACON refreshes assessment state and '
                  + 'safe scanner telemetry every two seconds '
                  + 'while this run is active.'
                )
            )
            : (
              'The assessment is in a terminal state, '
              + 'so automatic scan and telemetry polling '
              + 'is no longer running.'
            )}
        </p>
      </section>
    </div>
  )
}
