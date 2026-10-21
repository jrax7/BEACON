import assert from 'node:assert/strict'
import fs from 'node:fs'
import test from 'node:test'

function source(path) {
  return fs.readFileSync(
    new URL(`../${path}`, import.meta.url),
    'utf8',
  )
}

test('sidebar exposes the streamlined workspace navigation', () => {
  const layout = source('src/components/AppLayout.jsx')

  for (const label of [
    'Dashboard',
    'Targets',
    'Assessments',
    'Reports',
    'Settings',
  ]) {
    assert.match(layout, new RegExp(`>${label}<`))
  }
})

test('application preserves scan routes and adds workflow routes', () => {
  const app = source('src/App.jsx')

  assert.match(app, /path="\/scans"/)
  assert.match(app, /path="\/scans\/:scanId"/)
  assert.match(app, /path="\/scans\/new"/)
  assert.match(app, /path="\/reports"/)
  assert.match(app, /path="\/settings"/)
})

test('target detail exposes the approved five workspaces', () => {
  const page = source('src/pages/targets/TargetDetailPage.jsx')

  for (const tab of [
    'overview',
    'verification',
    'readiness',
    'assessments',
    'settings',
  ]) {
    assert.match(page, new RegExp(`['"]${tab}['"]`))
  }
})

test(
  'new assessment page exposes the profile-aware Engine v2 workflow',
  async () => {
    const {
      readFileSync,
    } = await import('node:fs')

    const page = readFileSync(
      new URL(
        '../src/pages/scans/NewAssessmentPage.jsx',
        import.meta.url,
      ),
      'utf8',
    )

    assert.match(
      page,
      /listAssessmentProfiles/,
    )

    assert.match(
      page,
      /Assessment profile/,
    )

    assert.match(
      page,
      /Infrastructure Extension/,
    )
  },
)

test('top-level reports use a dedicated report listing client', () => {
  const page = source('src/pages/reports/ReportsPage.jsx')
  const api = source('src/api/reports.js')

  assert.match(page, /listReports/)
  assert.match(api, /\/reports\?/)
})

test('settings contains authenticated account context', () => {
  const page = source('src/pages/settings/SettingsPage.jsx')

  assert.match(page, /Operator profile/)
  assert.match(page, /Authenticated/)
})
