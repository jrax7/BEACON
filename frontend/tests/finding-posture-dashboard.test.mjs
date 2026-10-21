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
  'findings API exposes authoritative posture',
  () => {
    const api = source(
      'src/api/findings.js',
    )

    assert.match(
      api,
      /export function getFindingPosture/,
    )

    assert.match(
      api,
      /['"`]\/findings\/posture['"`]/,
    )
  },
)


test(
  'dashboard loads authoritative finding posture',
  () => {
    const page = source(
      'src/pages/dashboard/DashboardPage.jsx',
    )

    assert.match(
      page,
      /getFindingPosture/,
    )

    assert.match(
      page,
      /setPosture/,
    )

    assert.match(
      page,
      /Security posture/,
    )

    assert.match(
      page,
      /VULNERABILITY POSTURE/,
    )
  },
)


test(
  'dashboard exposes complete remediation posture',
  () => {
    const page = source(
      'src/pages/dashboard/DashboardPage.jsx',
    )

    for (const token of [
      'Active findings',
      'New observations',
      'Persisting',
      'Regressed',
      'Resolved',
      'Awaiting triage',
      'Awaiting assignment',
      'In remediation',
      'Awaiting retest',
      'Risk accepted',
      'False positive',
      'Severity breakdown',
    ]) {
      assert.match(
        page,
        new RegExp(token),
      )
    }
  },
)


test(
  'posture metrics deep link through canonical findings helper',
  () => {
    const page = source(
      'src/pages/dashboard/DashboardPage.jsx',
    )

    assert.match(
      page,
      /buildFindingsPath\(\{\s*observation_state:\s*['"]NEW['"]/,
    )

    assert.match(
      page,
      /buildFindingsPath\(\{\s*observation_state:\s*['"]PERSISTING['"]/,
    )

    assert.match(
      page,
      /buildFindingsPath\(\{\s*observation_state:\s*['"]REGRESSED['"]/,
    )

    assert.match(
      page,
      /buildFindingsPath\(\{\s*observation_state:\s*['"]RESOLVED['"]/,
    )

    assert.match(
      page,
      /lifecycle_state:\s*['"]READY_FOR_RETEST['"]/,
    )

    assert.match(
      page,
      /disposition:\s*['"]RISK_ACCEPTED['"]/,
    )

    assert.match(
      page,
      /disposition:\s*['"]FALSE_POSITIVE['"]/,
    )

    assert.match(
      page,
      /severity/,
    )
  },
)


test(
  'posture presentation supports reduced motion',
  () => {
    const styles = source(
      'src/styles/pages/dashboard.css',
    )

    assert.match(
      styles,
      /\.dashboard-posture-card/,
    )

    assert.match(
      styles,
      /\.posture-metric/,
    )

    assert.match(
      styles,
      /prefers-reduced-motion:\s*reduce/,
    )
  },
)
