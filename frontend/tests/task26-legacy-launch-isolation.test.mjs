import assert from 'node:assert/strict'
import {
  readFileSync,
} from 'node:fs'
import {
  test,
} from 'node:test'


function source(
  relativePath,
) {
  return readFileSync(
    new URL(
      `../${relativePath}`,
      import.meta.url,
    ),
    'utf8',
  )
}


test(
  'target readiness routes normal users into the guided Engine v2 workflow',
  () => {
    const detail = source(
      'src/pages/targets/TargetDetailPage.jsx',
    )

    assert.doesNotMatch(
      detail,
      /\bcreateScan\s*\(/,
    )

    assert.match(
      detail,
      /\/scans\/new/,
    )
  },
)


test(
  'legacy createScan remains isolated to the demo branch of New Assessment',
  () => {
    const page = source(
      'src/pages/scans/NewAssessmentPage.jsx',
    )

    const demoBranch = page.indexOf(
      'if (isDemo)',
    )

    const legacyLaunch = page.indexOf(
      'createScan(',
      demoBranch,
    )

    const v2Launch = page.indexOf(
      'createAssessment(',
      demoBranch,
    )

    assert.ok(
      demoBranch >= 0,
    )

    assert.ok(
      legacyLaunch > demoBranch,
    )

    assert.ok(
      v2Launch > legacyLaunch,
    )
  },
)
