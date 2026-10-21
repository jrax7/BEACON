import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import test from 'node:test'


function read(relativePath) {
  return readFileSync(
    new URL(
      `../${relativePath}`,
      import.meta.url,
    ),
    'utf8',
  )
}


test(
  'application exposes the guided new assessment route',
  () => {
    const app = read('src/App.jsx')

    assert.match(
      app,
      /path="\/scans\/new"/,
    )

    assert.match(
      app,
      /<NewAssessmentPage\s*\/>/,
    )
  },
)


test(
  'assessment API client exposes Engine v2 profile and launch requests',
  () => {
    const client = read(
      'src/api/assessments.js',
    )

    assert.match(
      client,
      /listAssessmentProfiles/,
    )

    assert.match(
      client,
      /'\/assessment-profiles'/,
    )

    assert.match(
      client,
      /createAssessment/,
    )

    assert.match(
      client,
      /'\/assessments'/,
    )

    for (const field of [
      'target_id',
      'profile',
      'assessment_mode',
      'active_testing_confirmed',
      'infrastructure',
    ]) {
      assert.match(
        client,
        new RegExp(field),
      )
    }
  },
)


test(
  'wizard loads registered targets and Engine v2 profile metadata',
  () => {
    const page = read(
      'src/pages/scans/NewAssessmentPage.jsx',
    )

    assert.match(
      page,
      /listTargets\(\s*\)/,
    )

    assert.match(
      page,
      /listAssessmentProfiles\(\s*\)/,
    )

    assert.match(
      page,
      /selectedProfile/,
    )

    assert.match(
      page,
      /profile\.engines/,
    )
  },
)


test(
  'wizard exposes profile mode scope authorization and review sections',
  () => {
    const page = read(
      'src/pages/scans/NewAssessmentPage.jsx',
    )

    for (const label of [
      'Choose target',
      'Assessment profile',
      'Mode and scope',
      'Authorization',
      'Review and launch',
    ]) {
      assert.match(
        page,
        new RegExp(label),
      )
    }
  },
)


test(
  'profile cards surface active impact duration and destructive safety metadata',
  () => {
    const page = read(
      'src/pages/scans/NewAssessmentPage.jsx',
    )

    assert.match(
      page,
      /active_web_testing/,
    )

    assert.match(
      page,
      /destructive_testing_enabled/,
    )

    assert.match(
      page,
      /total_timeout_seconds/,
    )

    assert.match(
      page,
      /Impact/,
    )

    assert.match(
      page,
      /Destructive testing/,
    )
  },
)


test(
  'Standard and Deep active profiles require explicit active authorization',
  () => {
    const page = read(
      'src/pages/scans/NewAssessmentPage.jsx',
    )

    assert.match(
      page,
      /activeTestingConfirmed/,
    )

    assert.match(
      page,
      /active_web_testing/,
    )

    assert.match(
      page,
      /active testing\s+authorization/i,
    )
  },
)


test(
  'Infrastructure Extension is exposed only for the Deep profile',
  () => {
    const page = read(
      'src/pages/scans/NewAssessmentPage.jsx',
    )

    assert.match(
      page,
      /selectedProfile\?\.name === 'deep'/,
    )

    assert.match(
      page,
      /Infrastructure Extension/,
    )

    assert.match(
      page,
      /authorized_ips/,
    )

    assert.match(
      page,
      /authorized_cidrs/,
    )
  },
)


test(
  'Deep infrastructure requires exact scope and separate attestations',
  () => {
    const page = read(
      'src/pages/scans/NewAssessmentPage.jsx',
    )

    assert.match(
      page,
      /isIpAddress/,
    )

    assert.match(
      page,
      /isCidr/,
    )

    assert.match(
      page,
      /broadPortScanAllowed/,
    )

    assert.match(
      page,
      /networkActiveChecksAllowed/,
    )

    assert.match(
      page,
      /thirdPartyExcluded/,
    )

    assert.match(
      page,
      /infrastructureReady/,
    )
  },
)


test(
  'normal launch uses Engine v2 assessment API and opens assessment detail',
  () => {
    const page = read(
      'src/pages/scans/NewAssessmentPage.jsx',
    )

    const client = read(
      'src/api/assessments.js',
    )

    assert.match(
      page,
      /createAssessment\(/,
    )

    assert.match(
      page,
      /assessmentMode,/,
    )

    assert.match(
      page,
      /activeTestingConfirmed:/,
    )

    assert.match(
      client,
      /assessment_mode:\s*assessmentMode/,
    )

    assert.match(
      client,
      /active_testing_confirmed:\s*activeTestingConfirmed/,
    )

    assert.match(
      client,
      /infrastructure,/,
    )

    assert.match(
      page,
      /navigate\(\s*`\/scans\/\$\{assessment\.id\}`/,
    )
  },
)


test(
  'demo compatibility remains on the constrained legacy Basic assessment path',
  () => {
    const page = read(
      'src/pages/scans/NewAssessmentPage.jsx',
    )

    assert.match(
      page,
      /isDemo/,
    )

    assert.match(
      page,
      /createScan\(/,
    )

    assert.match(
      page,
      /Legacy/,
    )
  },
)


test(
  'wizard styles provide profile scope authorization and responsive layouts',
  () => {
    const styles = read(
      'src/styles/pages/scans.css',
    )

    for (const selector of [
      '.assessment-profile-options',
      '.assessment-profile-option',
      '.assessment-mode-options',
      '.assessment-scope-panel',
      '.assessment-authorization-panel',
      '.assessment-infrastructure-panel',
      '.assessment-attestation-list',
      '.assessment-review-safety',
    ]) {
      assert.match(
        styles,
        new RegExp(
          selector.replace('.', '\\.'),
        ),
      )
    }

    assert.match(
      styles,
      /@media \(max-width: 720px\)/,
    )
  },
)
