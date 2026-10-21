import assert from 'node:assert/strict'
import fs from 'node:fs'
import test from 'node:test'


function source(path) {
  return fs.readFileSync(
    new URL(
      `../${path}`,
      import.meta.url,
    ),
    'utf8',
  )
}


test(
  'assessment wizard exposes the five approved stages',
  () => {
    const page = source(
      'src/pages/scans/NewAssessmentPage.jsx',
    )

    assert.match(
      page,
      /ASSESSMENT_WIZARD_STAGES/,
    )

    for (const stage of [
      'Target',
      'Profile',
      'Scope and authorization',
      'Review',
      'Launch',
    ]) {
      assert.match(
        page,
        new RegExp(
          `['"]${stage}['"]`,
        ),
      )
    }

    assert.match(
      page,
      /assessment-wizard-v2/,
    )

    assert.match(
      page,
      /Assessment creation progress/,
    )

    assert.match(
      page,
      /aria-current/,
    )
  },
)


test(
  'wizard retains existing assessment validation and launch clients',
  () => {
    const page = source(
      'src/pages/scans/NewAssessmentPage.jsx',
    )

    for (const token of [
      'listTargets',
      'listAssessmentProfiles',
      'createAssessment',
      'createScan',
      'authorizationReady',
      'infrastructureReady',
      'canLaunch',
      'activeTestingConfirmed',
    ]) {
      assert.match(
        page,
        new RegExp(token),
      )
    }
  },
)


test(
  'finding retest starts a fresh assessment workflow',
  () => {
    const panel = source(
      'src/pages/findings/FindingWorkflowPanel.jsx',
    )

    assert.match(
      panel,
      /useNavigate/,
    )

    assert.match(
      panel,
      /createFindingRetest/,
    )

    assert.match(
      panel,
      /retest_id/,
    )

    assert.match(
      panel,
      /finding_id/,
    )

    assert.match(
      panel,
      /target_id/,
    )

    assert.match(
      panel,
      /\/scans\/new\?/,
    )

    assert.doesNotMatch(
      panel,
      /listScans/,
    )
  },
)


test(
  'fresh wizard assessment is linked to requested retest',
  () => {
    const api = source(
      'src/api/findings.js',
    )

    const page = source(
      'src/pages/scans/NewAssessmentPage.jsx',
    )

    assert.match(
      api,
      /export function linkFindingRetest/,
    )

    assert.match(
      api,
      /\/findings\/retests\/\$\{encodeURIComponent\(/,
    )

    assert.match(
      page,
      /useSearchParams/,
    )

    assert.match(
      page,
      /searchParams\.get\(\s*['"]retest_id['"]\s*,?\s*\)/,
    )

    assert.match(
      page,
      /searchParams\.get\(\s*['"]finding_id['"]\s*,?\s*\)/,
    )

    assert.match(
      page,
      /searchParams\.get\(\s*['"]target_id['"]\s*,?\s*\)/,
    )

    assert.match(
      page,
      /linkFindingRetest\(\s*retestId,\s*scan\.id/,
    )

    assert.match(
      page,
      /linkFindingRetest\(\s*retestId,\s*assessment\.id/,
    )
  },
)


test(
  'retest wizard cannot silently switch target',
  () => {
    const page = source(
      'src/pages/scans/NewAssessmentPage.jsx',
    )

    assert.match(
      page,
      /retestTargetId/,
    )

    assert.match(
      page,
      /selectedTarget\?\.id\s*!==\s*retestTargetId/,
    )

    assert.match(
      page,
      /Retest must use the original finding target/,
    )
  },
)


test(
  'wizard stages provide textual state and reduced motion',
  () => {
    const page = source(
      'src/pages/scans/NewAssessmentPage.jsx',
    )

    const styles = source(
      'src/styles/pages/scans.css',
    )

    assert.match(
      page,
      /Complete/,
    )

    assert.match(
      page,
      /Current/,
    )

    assert.match(
      page,
      /Upcoming/,
    )

    assert.match(
      styles,
      /\.assessment-wizard-v2/,
    )

    assert.match(
      styles,
      /prefers-reduced-motion:\s*reduce/,
    )
  },
)
