import assert from 'node:assert/strict'
import fs from 'node:fs'
import test from 'node:test'

function read(path) {
  return fs.readFileSync(
    new URL(`../${path}`, import.meta.url),
    'utf8',
  )
}

test('Engine v2 pipeline exposes persisted state and position without fabricated progress', () => {
  const pipeline = read('src/components/ScanPipeline.jsx')

  assert.match(pipeline, /function engineV2StagePosition/)
  assert.match(pipeline, /data-state=\{stage\.state\}/)
  assert.match(pipeline, /data-position=\{engineV2StagePosition/)
  assert.match(pipeline, /aria-current=/)
  assert.doesNotMatch(pipeline, /runtime\.progress_percent/)
  assert.match(pipeline, /does not manufacture a precise/)
})

test('only a persisted running stage receives the BEACON scan signal', () => {
  const pipeline = read('src/components/ScanPipeline.jsx')

  assert.match(
    pipeline,
    /stage\.state === 'running'[\s\S]*engine-v2-stage-signal/,
  )
  assert.match(pipeline, /engine-v2-stage-live-copy/)
})
test('overview scanner outcomes expose a state signal that only animates while running', () => {
  const overview = read('src/pages/scan-detail/OverviewTab.jsx')
  const styles = read('src/styles/pages/scan-detail.css')

  assert.match(overview, /scanner-signal-dot/)
  assert.match(overview, /data-state=\{outcome\}/)
  assert.match(styles, /\.scanner-signal-running/)
  assert.match(styles, /\.scanner-signal-completed/)
  assert.match(styles, /\.scanner-signal-failed/)
  assert.match(styles, /\.scanner-signal-warning/)
})

test('Engine v2 telemetry cards expose persisted engine state and running-only signal', () => {
  const grid = read('src/components/ToolTelemetryGrid.jsx')

  assert.match(grid, /data-state=\{engine\.status\}/)
  assert.match(grid, /engine-v2-tool-signal/)
  assert.match(
    grid,
    /engine\.status === 'running'[\s\S]*engine-v2-tool-signal/,
  )
})

test('assessment detail loading and cancel actions consume shared feedback primitives', () => {
  const page = read('src/pages/scan-detail/ScanDetailPage.jsx')

  assert.match(page, /SkeletonList/)
  assert.match(page, /Spinner/)
  assert.match(page, /aria-busy=\{cancelBusy\}/)
  assert.doesNotMatch(page, /assessment-loader-ring/)
})
test('assessment signature motion uses centralized tokens and respects reduced motion', () => {
  const styles = read('src/styles/pages/scan-detail.css')

  for (const selector of [
    '.engine-v2-stage-signal',
    '.engine-v2-stage-live-copy',
    '.engine-v2-tool-signal',
    '.scanner-signal-dot',
  ]) {
    assert.match(
      styles,
      new RegExp(selector.replace('.', '\\.')),
    )
  }

  assert.match(styles, /var\(--motion-standard\)/)
  assert.match(styles, /var\(--motion-page\)/)
  assert.match(styles, /prefers-reduced-motion:\s*reduce/)
})
