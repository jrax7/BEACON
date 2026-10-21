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


test('findings path helper builds canonical scoped workspace links', async () => {
  const helpers = await import(
    new URL(
      '../src/pages/findings/helpers.js',
      import.meta.url,
    )
  )

  assert.equal(
    typeof helpers.buildFindingsPath,
    'function',
  )

  assert.equal(
    helpers.buildFindingsPath(),
    '/findings',
  )

  assert.equal(
    helpers.buildFindingsPath({
      severity: 'high',
    }),
    '/findings?severity=high',
  )

  assert.equal(
    helpers.buildFindingsPath({
      target_id: 'target-123',
    }),
    '/findings?target_id=target-123',
  )

  assert.equal(
    helpers.buildFindingsPath({
      scan_id: 'scan-456',
    }),
    '/findings?scan_id=scan-456',
  )

  assert.equal(
    helpers.buildFindingsPath({
      classification: 'security_issue',
      tool: 'zap',
      q: 'cors',
    }),
    '/findings?tool=zap&classification=security_issue&q=cors',
  )
})


test(
  'dashboard uses authoritative posture instead of list-derived finding counts',
  () => {
    const dashboard = source(
      'src/pages/dashboard/DashboardPage.jsx',
    )

    assert.match(
      dashboard,
      /View findings/,
    )

    assert.match(
      dashboard,
      /to=\{buildFindingsPath\(\)\}/,
    )

    assert.match(
      dashboard,
      /getFindingPosture/,
    )

    assert.doesNotMatch(
      dashboard,
      /\blistFindings\b/,
    )
  },
)


test('target overview links into findings scoped by the real target id', () => {
  const overview = source(
    'src/pages/targets/TargetOverview.jsx',
  )

  assert.match(
    overview,
    /buildFindingsPath/,
  )

  assert.match(
    overview,
    /target_id:\s*target\.id/,
  )

  assert.match(
    overview,
    /to=\{buildFindingsPath\(\{\s*target_id:\s*target\.id,?\s*\}\)\}/,
  )

  assert.match(
    overview,
    /View findings/i,
  )
})


test('assessment overview links into findings scoped by the real scan id', () => {
  const overview = source(
    'src/pages/scan-detail/OverviewTab.jsx',
  )

  assert.match(
    overview,
    /buildFindingsPath/,
  )

  assert.match(
    overview,
    /scan_id:\s*scan\.id/,
  )

  assert.match(
    overview,
    /to=\{buildFindingsPath\(\{\s*scan_id:\s*scan\.id,?\s*\}\)\}/,
  )

  assert.match(
    overview,
    /View findings/i,
  )
})


test('assessment Findings tab exposes the global Findings workspace action', () => {
  const findings = source(
    'src/pages/scan-detail/FindingsTab.jsx',
  )

  assert.match(
    findings,
    /buildFindingsPath/,
  )

  assert.match(
    findings,
    /scan_id:\s*scan\.id/,
  )

  assert.match(
    findings,
    /Open in Findings workspace/,
  )

  assert.match(
    findings,
    /to=\{buildFindingsPath\(\{\s*scan_id:\s*scan\.id,?\s*\}\)\}/,
  )
})


test('cross-navigation does not duplicate findings query strings ad hoc', () => {
  const files = [
    source(
      'src/pages/dashboard/DashboardPage.jsx',
    ),
    source(
      'src/pages/targets/TargetOverview.jsx',
    ),
    source(
      'src/pages/scan-detail/OverviewTab.jsx',
    ),
    source(
      'src/pages/scan-detail/FindingsTab.jsx',
    ),
  ].join('\n')

  assert.doesNotMatch(
    files,
    /['"`]\/findings\?/,
  )
})
