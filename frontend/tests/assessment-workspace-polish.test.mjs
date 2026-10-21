import assert from 'node:assert/strict'
import fs from 'node:fs'
import test from 'node:test'

function source(path) {
  return fs.readFileSync(
    new URL(`../${path}`, import.meta.url),
    'utf8',
  )
}

test('assessment detail adds contextual breadcrumbs from live assessment context', () => {
  const page = source(
    'src/pages/scan-detail/ScanDetailPage.jsx',
  )

  assert.match(
    page,
    /Breadcrumbs/,
  )

  assert.match(
    page,
    /target\?\.hostname/,
  )

  assert.match(
    page,
    /scan\.id\.slice\(0,\s*8\)/,
  )

  assert.match(
    page,
    /activeTab/,
  )

  assert.match(
    page,
    /Assessments/,
  )
})

test('assessment workspace preserves tabs, query-state navigation, and live polling', () => {
  const page = source(
    'src/pages/scan-detail/ScanDetailPage.jsx',
  )

  assert.match(
    page,
    /useSearchParams/,
  )

  assert.match(
    page,
    /setSearchParams\(\{\s*tab\s*\}\)/,
  )

  for (const label of [
    'Overview',
    'Findings',
    'Telemetry',
    'Reports',
  ]) {
    assert.match(
      page,
      new RegExp(`label="${label}"`),
    )
  }

  assert.match(
    page,
    /window\.setInterval\(loadScan,\s*2000\)/,
  )
})

test('report workspace exposes a stronger reporting hierarchy', () => {
  const reports = source(
    'src/pages/scan-detail/ReportsTab.jsx',
  )

  assert.match(
    reports,
    /className="report-heading-copy"/,
  )

  assert.match(
    reports,
    /className="report-snapshot-card"/,
  )

  assert.match(
    reports,
    /className="report-lifecycle-tabs"/,
  )

  assert.match(
    reports,
    /className="report-title"/,
  )

  assert.match(
    reports,
    /className="report-generated-at"/,
  )

  assert.match(
    reports,
    /className="report-download-action"/,
  )

  assert.match(
    reports,
    /className="report-lifecycle-guidance"/,
  )
})

test('report workspace preserves generation, download, and lifecycle behavior', () => {
  const reports = source(
    'src/pages/scan-detail/ReportsTab.jsx',
  )

  for (const token of [
    'requestScanReports',
    'downloadReport',
    'archiveReports',
    'restoreReports',
    'deleteReports',
    'canGenerateReports',
    'canLifecycleReports',
    'canDeleteReports',
  ]) {
    assert.match(
      reports,
      new RegExp(token),
    )
  }

  assert.match(
    reports,
    /Generate HTML \+ PDF/,
  )

  assert.match(
    reports,
    /Download ↓/,
  )
})


test('report typography uses readable shared text tokens', () => {
  const styles = source(
    'src/styles/pages/scan-detail.css',
  )

  assert.match(
    styles,
    /\.report-heading-copy/,
  )

  assert.match(
    styles,
    /\.report-snapshot-card/,
  )

  assert.match(
    styles,
    /\.report-title/,
  )

  assert.match(
    styles,
    /\.report-generated-at/,
  )

  assert.match(
    styles,
    /\.report-download-action/,
  )

  assert.match(
    styles,
    /var\(--text-soft\)/,
  )

  assert.match(
    styles,
    /var\(--text-muted\)/,
  )
})

test('archive and delete guidance remains visually secondary', () => {
  const reports = source(
    'src/pages/scan-detail/ReportsTab.jsx',
  )

  const styles = source(
    'src/styles/pages/scan-detail.css',
  )

  assert.match(
    reports,
    /className="report-lifecycle-guidance"/,
  )

  assert.match(
    reports,
    /Archive first, delete second\./,
  )

  assert.match(
    styles,
    /\.report-lifecycle-guidance/,
  )

  assert.match(
    styles,
    /\.report-lifecycle-guidance p[\s\S]*?color:\s*var\(--text-muted\)/,
  )
})


test(
  'Engine v2 detail polling loads the rich assessment state without replacing legacy telemetry',
  async () => {
    const {
      readFileSync,
    } = await import(
      'node:fs'
    )

    const page = readFileSync(
      new URL(
        '../src/pages/scan-detail/ScanDetailPage.jsx',
        import.meta.url,
      ),
      'utf8',
    )

    assert.match(
      page,
      /getAssessment/,
    )

    assert.match(
      page,
      /engine_version === 'v2'/,
    )

    assert.match(
      page,
      /setAssessmentRuntime/,
    )

    assert.match(
      page,
      /assessmentRuntime=\{assessmentRuntime\}/,
    )

    assert.match(
      page,
      /getScanTelemetry/,
    )
  },
)


test(
  'Engine v2 pipeline renders persisted stage state instead of fabricated workflow percentage',
  async () => {
    const {
      readFileSync,
    } = await import(
      'node:fs'
    )

    const pipeline = readFileSync(
      new URL(
        '../src/components/ScanPipeline.jsx',
        import.meta.url,
      ),
      'utf8',
    )

    const page = readFileSync(
      new URL(
        '../src/pages/scan-detail/ScanDetailPage.jsx',
        import.meta.url,
      ),
      'utf8',
    )

    assert.match(
      pipeline,
      /EngineV2Pipeline/,
    )

    assert.match(
      pipeline,
      /engine_executions/,
    )

    assert.match(
      pipeline,
      /scope_authorization/,
    )

    assert.match(
      pipeline,
      /post_processing/,
    )

    assert.match(
      page,
      /Stage-based/,
    )
  },
)


test(
  'Engine v2 telemetry distinguishes unavailable metrics from a real zero',
  async () => {
    const {
      readFileSync,
    } = await import(
      'node:fs'
    )

    const telemetry = readFileSync(
      new URL(
        '../src/components/ToolTelemetryGrid.jsx',
        import.meta.url,
      ),
      'utf8',
    )

    assert.match(
      telemetry,
      /Not reported/,
    )

    assert.match(
      telemetry,
      /profile_enabled/,
    )

    assert.match(
      telemetry,
      /failure_message/,
    )

    assert.match(
      telemetry,
      /last_heartbeat_at/,
    )

    assert.match(
      telemetry,
      /engine\.metrics/,
    )
  },
)


test(
  'Engine v2 overview makes coverage limitations and unavailable detailed counters explicit',
  async () => {
    const {
      readFileSync,
    } = await import(
      'node:fs'
    )

    const overview = readFileSync(
      new URL(
        '../src/pages/scan-detail/OverviewTab.jsx',
        import.meta.url,
      ),
      'utf8',
    )

    assert.match(
      overview,
      /Coverage and limitations/,
    )

    assert.match(
      overview,
      /Detailed URL\/service coverage is not persisted/,
    )

    assert.match(
      overview,
      /engines_incomplete/,
    )

    assert.match(
      overview,
      /limitations/,
    )
  },
)


test(
  'Engine v2 running-state motion respects reduced-motion preference',
  async () => {
    const {
      readFileSync,
    } = await import(
      'node:fs'
    )

    const styles = readFileSync(
      new URL(
        '../src/styles/pages/scan-detail.css',
        import.meta.url,
      ),
      'utf8',
    )

    assert.match(
      styles,
      /@keyframes engine-v2-running-pulse/,
    )

    assert.match(
      styles,
      /prefers-reduced-motion:\s*reduce/,
    )

    assert.match(
      styles,
      /\.engine-v2-stage\.stage-state-running/,
    )

    assert.match(
      styles,
      /animation:\s*none/,
    )
  },
)
