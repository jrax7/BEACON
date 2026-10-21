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

test('target detail defines the five approved workspaces', () => {
  const page = source('src/pages/targets/TargetDetailPage.jsx')

  assert.match(page, /useSearchParams/)
  assert.match(page, /overview/)
  assert.match(page, /verification/)
  assert.match(page, /readiness/)
  assert.match(page, /assessments/)
  assert.match(page, /settings/)
  assert.match(page, /<Tabs/)
})

test('target overview is extracted from the controller page', () => {
  const overview = source('src/pages/targets/TargetOverview.jsx')

  assert.match(overview, /Target information/)
  assert.match(overview, /target-details-grid/)
  assert.match(overview, /verificationMethodLabel/)
})

test('target assessment history loads active and archived assessments', () => {
  const page = source('src/pages/targets/TargetDetailPage.jsx')
  const assessments = source('src/pages/targets/TargetAssessments.jsx')

  assert.match(page, /listScans\(\s*['"]active['"]\s*\)/)
  assert.match(page, /listScans\(\s*['"]archived['"]\s*\)/)
  assert.match(page, /activeTab === ['"]assessments['"]/)

  assert.match(assessments, /scan\.target_id === target\.id/)
  assert.match(assessments, /\/scans\/\$\{scan\.id\}/)
  assert.match(assessments, /message="This target does not have assessment history\."/)
})

test('target settings owns destructive target controls', () => {
  const detail = source('src/pages/targets/TargetDetailPage.jsx')
  const settings = source('src/pages/targets/TargetSettings.jsx')

  assert.doesNotMatch(
    detail,
    /\{!isDemo && \(\s*<DangerZone/,
  )

  assert.match(settings, /DangerZone/)
  assert.match(settings, /readOnly/)
  assert.match(settings, /\{!readOnly &&/)
})

test('readiness uses assessment terminology and separates its action', () => {
  const readiness = source('src/pages/targets/ReadinessPanel.jsx')
  const styles = source('src/styles/pages/targets.css')

  assert.match(readiness, /Launch Assessment/)
  assert.doesNotMatch(readiness, /Launch Basic Scan/)

  assert.match(
    styles,
    /\.scan-launch-button\s*\{[^}]*margin-top:\s*var\(--space-5\)/s,
  )
})

test('target detail exposes contextual breadcrumbs', () => {
  const page = source('src/pages/targets/TargetDetailPage.jsx')

  assert.match(page, /breadcrumbs=/)
  assert.match(page, /target\.hostname/)
  assert.match(page, /activeTab/)
})
