import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { test } from 'node:test'


function readSource(relativePath) {
  return readFileSync(
    new URL(
      `../src/${relativePath}`,
      import.meta.url,
    ),
    'utf8',
  )
}


test(
  'demo access policy identifies only the demo role',
  async () => {
    const access =
      await import(
        '../src/auth/demo-access.js'
      )

    assert.equal(
      access.isDemoUser({
        role: 'demo',
      }),
      true,
    )

    assert.equal(
      access.isDemoUser({
        role: 'user',
      }),
      false,
    )

    assert.equal(
      access.isDemoUser(null),
      false,
    )

    assert.equal(
      access.isDemoUser(undefined),
      false,
    )
  },
)


test(
  'dashboard keeps the permitted assessment launch without target registration',
  () => {
    const source = readSource(
      'pages/dashboard/DashboardPage.jsx',
    )

    assert.match(
      source,
      /to="\/scans\/new"/,
    )

    assert.match(
      source,
      /\+ New Assessment/,
    )

    assert.doesNotMatch(
      source,
      /\+ Register target/,
    )
  },
)


test(
  'targets page hides target registration for demo users',
  () => {
    const source = readSource(
      'pages/targets/TargetsPage.jsx',
    )

    assert.match(
      source,
      /const isDemo\s*=\s*isDemoUser\(user\)/,
    )

    assert.match(
      source,
      /PERMISSIONS\.TARGET_CREATE/,
    )

    assert.match(
      source,
      /const canCreateTargets\s*=\s*!isDemo[\s\S]*?PERMISSIONS\.TARGET_CREATE/,
    )

    assert.match(
      source,
      /\{canCreateTargets && \(\s*<TargetRegistrationForm/,
    )
  },
)


test(
  'target detail keeps assessment launch but hides target mutations',
  () => {
    const detail = readSource(
      'pages/targets/TargetDetailPage.jsx',
    )

    const verification = readSource(
      'pages/targets/VerificationPanel.jsx',
    )

    const readiness = readSource(
      'pages/targets/ReadinessPanel.jsx',
    )

    const settings = readSource(
      'pages/targets/TargetSettings.jsx',
    )

    assert.match(
      detail,
      /const isDemo\s*=\s*isDemoUser\(user\)/,
    )

    assert.match(
      detail,
      /const canVerifyTarget\s*=\s*!isDemo[\s\S]*?PERMISSIONS\.TARGET_VERIFY/,
    )

    assert.match(
      detail,
      /const canDeleteTarget\s*=\s*!isDemo[\s\S]*?PERMISSIONS\.TARGET_DELETE/,
    )

    assert.match(
      detail,
      /const canCreateAssessment\s*=\s*isDemo[\s\S]*?PERMISSIONS\.ASSESSMENT_CREATE/,
    )

    assert.match(
      detail,
      /readOnly=\{!canVerifyTarget\}/,
    )

    assert.match(
      detail,
      /readOnly=\{!canDeleteTarget\}/,
    )

    assert.match(
      detail,
      /readOnly=\{!canCreateAssessment\}/,
    )

    assert.match(
      verification,
      /\{!readOnly && \(\s*<div className="target-actions">/,
    )

    assert.match(
      settings,
      /\{!readOnly &&/,
    )

    assert.match(
      settings,
      /<DangerZone/,
    )

    assert.match(
      readiness,
      /isVerified && !readOnly/,
    )

    assert.match(
      readiness,
      /Launch Assessment/,
    )
  },
)


test(
  'assessment history hides lifecycle controls for demo users',
  () => {
    const page = readSource(
      'pages/scans/ScansPage.jsx',
    )

    const row = readSource(
      'pages/scans/ScanRow.jsx',
    )

    assert.match(
      page,
      /const isDemo\s*=\s*isDemoUser\(user\)/,
    )

    assert.match(
      page,
      /const canLifecycleAssessments\s*=\s*!isDemo[\s\S]*?PERMISSIONS\.ASSESSMENT_LIFECYCLE/,
    )

    assert.match(
      page,
      /const canDeleteAssessments\s*=\s*!isDemo[\s\S]*?PERMISSIONS\.ASSESSMENT_DELETE/,
    )

    assert.match(
      page,
      /\{canLifecycleAssessments && visibleScans\.length > 0 && \(/,
    )

    assert.match(
      page,
      /\{canLifecycleAssessments && selectedIds\.size > 0 && \(/,
    )

    assert.match(
      page,
      /allowLifecycle=\{canLifecycleAssessments\}/,
    )

    assert.match(
      page,
      /\{canDeleteAssessments && \(/,
    )

    assert.match(
      row,
      /allowLifecycle = true/,
    )

    assert.match(
      row,
      /\{allowLifecycle && \(\s*<label/,
    )
  },
)


test(
  'report view keeps generation and download but hides lifecycle controls',
  () => {
    const detail = readSource(
      'pages/scan-detail/ScanDetailPage.jsx',
    )

    const reports = readSource(
      'pages/scan-detail/ReportsTab.jsx',
    )

    assert.match(
      detail,
      /const isDemo\s*=\s*isDemoUser\(user\)/,
    )

    assert.match(
      detail,
      /const canGenerateReports\s*=\s*isDemo[\s\S]*?PERMISSIONS\.REPORT_GENERATE/,
    )

    assert.match(
      detail,
      /const canLifecycleReports\s*=\s*!isDemo[\s\S]*?PERMISSIONS\.REPORT_LIFECYCLE/,
    )

    assert.match(
      detail,
      /const canDeleteReports\s*=\s*!isDemo[\s\S]*?PERMISSIONS\.REPORT_DELETE/,
    )

    assert.match(
      detail,
      /canGenerateReports=\{canGenerateReports\}/,
    )

    assert.match(
      detail,
      /canLifecycleReports=\{canLifecycleReports\}/,
    )

    assert.match(
      detail,
      /canDeleteReports=\{canDeleteReports\}/,
    )

    assert.match(
      reports,
      /\{canLifecycleReports && visibleReports\.length > 0 && \(/,
    )

    assert.match(
      reports,
      /\{canLifecycleReports && \(\s*<input\s+className="report-select-checkbox"/,
    )

    assert.match(
      reports,
      /\{canDeleteReports && \(\s*<ConfirmDialog/,
    )

    assert.match(
      reports,
      /Generate HTML \+ PDF/,
    )

    assert.match(
      reports,
      /Download ↓/,
    )
  },
)
