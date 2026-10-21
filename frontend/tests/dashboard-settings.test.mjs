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

test('dashboard uses the shared header with New Assessment as its primary action', () => {
  const page = source(
    'src/pages/dashboard/DashboardPage.jsx',
  )

  assert.match(
    page,
    /<PageHeader/,
  )

  assert.match(
    page,
    /to="\/scans\/new"/,
  )

  assert.match(
    page,
    /\+ New Assessment/,
  )
})

test('dashboard uses one global report request without per-assessment summary requests', () => {
  const page = source(
    'src/pages/dashboard/DashboardPage.jsx',
  )

  assert.match(
    page,
    /import \{\s*listReports\s*\} from ['"]\.\.\/\.\.\/api\/reports['"]/,
  )

  const reportRequests = page.match(
    /listReports\(\s*['"]all['"]\)/g,
  ) || []

  assert.equal(
    reportRequests.length,
    1,
    'Dashboard must make exactly one global report-list request.',
  )

  assert.doesNotMatch(
    page,
    /\bgetScanSummary\b/,
  )

  assert.doesNotMatch(
    page,
    /\blistScanReports\b/,
  )
})

test('dashboard exposes the four approved workspace metrics', () => {
  const page = source(
    'src/pages/dashboard/DashboardPage.jsx',
  )

  for (const label of [
    'Targets',
    'Assessments',
    'Active assessments',
    'Reports',
  ]) {
    assert.match(
      page,
      new RegExp(
        `<span>${label}</span>`,
      ),
    )
  }

  assert.doesNotMatch(
    page,
    /Verification coverage/,
  )
})

test('needs attention is derived from unverified targets and failed assessments', () => {
  const page = source(
    'src/pages/dashboard/DashboardPage.jsx',
  )

  assert.match(
    page,
    /Needs Attention/,
  )

  assert.match(
    page,
    /verification_status\s*!==\s*['"]verified['"]/,
  )

  assert.match(
    page,
    /scan\.status\s*===\s*['"]failed['"]/,
  )
})

test('dashboard exposes a concise recent reports workspace', () => {
  const page = source(
    'src/pages/dashboard/DashboardPage.jsx',
  )

  assert.match(
    page,
    /Recent Reports/,
  )

  assert.match(
    page,
    /recentReports/,
  )

  assert.match(
    page,
    /target_hostname/,
  )

  assert.match(
    page,
    /report\.format/,
  )

  assert.match(
    page,
    /report\.generated_at/,
  )

  assert.match(
    page,
    /\/scans\/\$\{report\.scan_id\}/,
  )
})

test('application exposes the protected Settings workspace', () => {
  const app = source(
    'src/App.jsx',
  )

  assert.match(
    app,
    /import SettingsPage from ['"]\.\/pages\/settings\/SettingsPage['"]/,
  )

  assert.match(
    app,
    /path="\/settings"/,
  )

  assert.match(
    app,
    /<SettingsPage \/>/,
  )
})

test('settings shows real authenticated account and session context', () => {
  const page = source(
    'src/pages/settings/SettingsPage.jsx',
  )

  assert.match(
    page,
    /useAuth\(\)/,
  )

  assert.match(
    page,
    /Operator profile/,
  )

  assert.match(
    page,
    /Authenticated/,
  )

  for (const field of [
    'full_name',
    'email',
    'role',
    'is_active',
  ]) {
    assert.match(
      page,
      new RegExp(field),
    )
  }

  assert.doesNotMatch(
    page,
    /Notifications|Theme|Preferences/,
  )
})

test('account profile no longer lives on the dashboard', () => {
  const dashboard = source(
    'src/pages/dashboard/DashboardPage.jsx',
  )

  assert.doesNotMatch(
    dashboard,
    /Operator profile/,
  )

  assert.doesNotMatch(
    dashboard,
    /account-card/,
  )
})
