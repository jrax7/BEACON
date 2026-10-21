import assert from 'node:assert/strict'
import {
  readFileSync,
} from 'node:fs'
import {
  dirname,
  resolve,
} from 'node:path'
import {
  test,
} from 'node:test'
import {
  fileURLToPath,
} from 'node:url'

import * as scanHelpers from '../src/pages/scans/helpers.js'


const currentDirectory = dirname(
  fileURLToPath(
    import.meta.url,
  ),
)

const frontendRoot = resolve(
  currentDirectory,
  '..',
)


function source(
  relativePath,
) {
  return readFileSync(
    resolve(
      frontendRoot,
      relativePath,
    ),
    'utf8',
  )
}


test(
  'legacy Basic transport remains isolated for compatibility',
  () => {
    const api = source(
      'src/api/scans.js',
    )

    assert.match(
      api,
      /export function createScan/,
    )

    assert.match(
      api,
      /scan_level:\s*['"]basic['"]/,
    )
  },
)


test(
  'assessment profile labels prefer Engine v2 metadata over legacy scan level',
  () => {
    assert.equal(
      typeof (
        scanHelpers
          .assessmentProfileLabel
      ),
      'function',
    )

    if (
      typeof (
        scanHelpers
          .assessmentProfileLabel
      )
      !== 'function'
    ) {
      return
    }

    const label = (
      scanHelpers
        .assessmentProfileLabel
    )

    assert.equal(
      label({
        profile: 'quick',
        scan_level: 'basic',
        engine_version: 'v2',
      }),
      'Quick',
    )

    assert.equal(
      label({
        profile: 'standard',
        scan_level: 'basic',
        engine_version: 'v2',
      }),
      'Standard',
    )

    assert.equal(
      label({
        profile: 'deep',
        scan_level: 'basic',
        engine_version: 'v2',
      }),
      'Deep',
    )

    assert.equal(
      label({
        profile: null,
        scan_level: 'basic',
        engine_version: null,
      }),
      'Legacy',
    )

    assert.equal(
      label({
        profile: null,
        scan_level: null,
        engine_version: null,
      }),
      'Legacy',
    )
  },
)


test(
  'primary product surfaces no longer present Basic as an assessment profile',
  () => {
    const productSurfaces = [
      'src/pages/dashboard/DashboardPage.jsx',
      'src/pages/reports/ReportsPage.jsx',
      'src/pages/scan-detail/parts.jsx',
      'src/pages/scan-detail/ScanDetailPage.jsx',
      'src/pages/scans/NewAssessmentPage.jsx',
      'src/pages/scans/ScanRow.jsx',
      'src/pages/scans/ScansPage.jsx',
      'src/pages/targets/ReadinessPanel.jsx',
      'src/pages/targets/TargetAssessments.jsx',
    ]

    for (
      const relativePath
      of productSurfaces
    ) {
      assert.doesNotMatch(
        source(
          relativePath,
        ),
        /\bBasic\b/,
        (
          relativePath
          + ' still exposes Basic '
          + 'as primary product language'
        ),
      )
    }
  },
)
