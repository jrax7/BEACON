import assert from 'node:assert/strict'
import fs from 'node:fs'
import test from 'node:test'

function source(path) {
  return fs.readFileSync(
    new URL(`../${path}`, import.meta.url),
    'utf8',
  )
}

test('assessment search matches useful assessment and target fields', async () => {
  const helpers = await import(
    '../src/pages/scans/helpers.js'
  )

  assert.equal(
    typeof helpers.matchesAssessmentSearch,
    'function',
  )

  const scan = {
    id: '0113de44-acde-1234',
    target_id: 'target-01',
    scan_level: 'basic',
    status: 'completed',
  }

  const target = {
    hostname: 'lab-target',
    normalized_url: 'http://lab-target:3001',
  }

  assert.equal(
    helpers.matchesAssessmentSearch(
      scan,
      target,
      '',
    ),
    true,
  )

  assert.equal(
    helpers.matchesAssessmentSearch(
      scan,
      target,
      '0113de44',
    ),
    true,
  )

  assert.equal(
    helpers.matchesAssessmentSearch(
      scan,
      target,
      'LAB-TARGET',
    ),
    true,
  )

  assert.equal(
    helpers.matchesAssessmentSearch(
      scan,
      target,
      '3001',
    ),
    true,
  )

  assert.equal(
    helpers.matchesAssessmentSearch(
      scan,
      target,
      'completed',
    ),
    true,
  )

  assert.equal(
    helpers.matchesAssessmentSearch(
      scan,
      target,
      'basic',
    ),
    true,
  )

  assert.equal(
    helpers.matchesAssessmentSearch(
      scan,
      target,
      'does-not-exist',
    ),
    false,
  )
})

test('assessments page provides search and status filtering together', () => {
  const page = source(
    'src/pages/scans/ScansPage.jsx',
  )

  assert.match(
    page,
    /const \[search,\s*setSearch\]\s*=\s*useState\(['"]{2}\)/,
  )

  assert.match(
    page,
    /type="search"/,
  )

  assert.match(
    page,
    /placeholder="Search assessments"/,
  )

  assert.match(
    page,
    /matchesAssessmentSearch\(/,
  )

  assert.match(
    page,
    /matchesFilter\(scan,\s*filter\)/,
  )
})

test('assessments page launches the guided new assessment workflow', () => {
  const page = source(
    'src/pages/scans/ScansPage.jsx',
  )

  assert.match(
    page,
    /to="\/scans\/new"/,
  )

  assert.match(
    page,
    /\+ New Assessment/,
  )

  assert.doesNotMatch(
    page,
    />\s*Launch from target\s*</,
  )
})

test('assessment history preserves lifecycle and demo restrictions', () => {
  const page = source(
    'src/pages/scans/ScansPage.jsx',
  )

  assert.match(
    page,
    /view === ['"]archived['"]/,
  )

  assert.match(
    page,
    /FILTERS\.map/,
  )

  assert.match(
    page,
    /PERMISSIONS\.ASSESSMENT_LIFECYCLE/,
  )

  assert.match(
    page,
    /PERMISSIONS\.ASSESSMENT_DELETE/,
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
})


test('assessment rows expose an assessment reference for easier lookup', () => {
  const row = source(
    'src/pages/scans/ScanRow.jsx',
  )

  assert.match(
    row,
    /Assessment ID/,
  )

  assert.match(
    row,
    /\{scan\.id\}/,
  )
})
