import assert from 'node:assert/strict'
import fs from 'node:fs'
import test from 'node:test'

function source(path) {
  try {
    return fs.readFileSync(
      new URL(`../${path}`, import.meta.url),
      'utf8',
    )
  } catch (error) {
    if (error.code === 'ENOENT') {
      return ''
    }

    throw error
  }
}

test('reports client lists global reports by lifecycle state', () => {
  const api = source(
    'src/api/reports.js',
  )

  assert.match(
    api,
    /export function listReports/,
  )

  assert.match(
    api,
    /new URLSearchParams\(\{\s*archived\s*\}\)/,
  )

  assert.match(
    api,
    /`\/reports\?\$\{parameters\}`/,
  )
})

test('application exposes the global reports route', () => {
  const app = source(
    'src/App.jsx',
  )

  assert.match(
    app,
    /import ReportsPage from ['"]\.\/pages\/reports\/ReportsPage['"]/,
  )

  assert.match(
    app,
    /path="\/reports"/,
  )

  assert.match(
    app,
    /<ReportsPage \/>/,
  )
})

test('reports workspace loads active and archived global reports', () => {
  const page = source(
    'src/pages/reports/ReportsPage.jsx',
  )

  assert.match(
    page,
    /listReports\(\s*['"]active['"]\s*\)/,
  )

  assert.match(
    page,
    /listReports\(\s*['"]archived['"]\s*\)/,
  )

  assert.match(
    page,
    /target_hostname/,
  )

  assert.match(
    page,
    /target_url/,
  )

  assert.match(
    page,
    /scan_id/,
  )
})

test('reports workspace searches joined report context locally', () => {
  const page = source(
    'src/pages/reports/ReportsPage.jsx',
  )

  const helpers = source(
    'src/pages/reports/helpers.js',
  )

  assert.match(
    page,
    /const \[search,\s*setSearch\]\s*=\s*useState\(['"]{2}\)/,
  )

  assert.match(
    page,
    /type="search"/,
  )

  assert.match(
    page,
    /matchesReportSearch\(/,
  )

  assert.match(
    helpers,
    /export function matchesReportSearch/,
  )

  assert.match(
    helpers,
    /target_hostname/,
  )

  assert.match(
    helpers,
    /target_url/,
  )

  assert.match(
    helpers,
    /scan_id/,
  )

  assert.match(
    helpers,
    /format/,
  )
})

test('reports workspace downloads reports and links to assessments', () => {
  const page = source(
    'src/pages/reports/ReportsPage.jsx',
  )

  assert.match(
    page,
    /downloadReport/,
  )

  assert.match(
    page,
    /\/scans\/\$\{report\.scan_id\}/,
  )

  assert.match(
    page,
    /Download/,
  )
})

test('normal users retain report lifecycle controls', () => {
  const page = source(
    'src/pages/reports/ReportsPage.jsx',
  )

  for (const token of [
    'archiveReports',
    'restoreReports',
    'deleteReports',
  ]) {
    assert.match(
      page,
      new RegExp(token),
    )
  }

  assert.match(
    page,
    /PERMISSIONS\.REPORT_LIFECYCLE/,
  )

  assert.match(
    page,
    /PERMISSIONS\.REPORT_DELETE/,
  )

  assert.match(
    page,
    /\{canLifecycleReports && visibleReports\.length > 0 && \(/,
  )

  assert.match(
    page,
    /\{canLifecycleReports && selectedReportIds\.length > 0 && \(/,
  )

  assert.match(
    page,
    /allowLifecycle=\{canLifecycleReports\}/,
  )

  assert.match(
    page,
    /canDeleteReports/,
  )
})


test('demo reports workspace remains read and download only', () => {
  const page = source(
    'src/pages/reports/ReportsPage.jsx',
  )

  assert.match(
    page,
    /const isDemo\s*=\s*isDemoUser\(user\)/,
  )

  assert.match(
    page,
    /const canLifecycleReports\s*=\s*!isDemo[\s\S]*?PERMISSIONS\.REPORT_LIFECYCLE/,
  )

  assert.match(
    page,
    /const canDeleteReports\s*=\s*!isDemo[\s\S]*?PERMISSIONS\.REPORT_DELETE/,
  )

  assert.match(
    page,
    /allowLifecycle=\{canLifecycleReports\}/,
  )

  assert.match(
    page,
    /downloadReport/,
  )
})


test('global reports do not perform per-row scan or target lookups', () => {
  const page = source(
    'src/pages/reports/ReportsPage.jsx',
  )

  assert.doesNotMatch(
    page,
    /\bgetScan\b/,
  )

  assert.doesNotMatch(
    page,
    /\bgetTarget\b/,
  )

  assert.doesNotMatch(
    page,
    /\blistScans\b/,
  )

  assert.doesNotMatch(
    page,
    /\blistTargets\b/,
  )
})
