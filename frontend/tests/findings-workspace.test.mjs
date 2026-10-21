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

test('application exposes findings list and detail routes', () => {
  const app = source(
    'src/App.jsx',
  )

  assert.match(
    app,
    /import FindingsPage from ['"]\.\/pages\/findings\/FindingsPage['"]/,
  )

  assert.match(
    app,
    /import FindingDetailPage from ['"]\.\/pages\/findings\/FindingDetailPage['"]/,
  )

  assert.match(
    app,
    /path="\/findings"/,
  )

  assert.match(
    app,
    /<FindingsPage \/>/,
  )

  assert.match(
    app,
    /path="\/findings\/:findingId"/,
  )

  assert.match(
    app,
    /<FindingDetailPage \/>/,
  )
})

test('sidebar exposes Findings between Assessments and Reports', () => {
  const layout = source(
    'src/components/AppLayout.jsx',
  )

  assert.match(
    layout,
    /to="\/findings"/,
  )

  assert.match(
    layout,
    /<span>Findings<\/span>/,
  )

  const assessmentsIndex =
    layout.indexOf('<span>Assessments</span>')

  const findingsIndex =
    layout.indexOf('<span>Findings</span>')

  const reportsIndex =
    layout.indexOf('<span>Reports</span>')

  assert.notEqual(
    assessmentsIndex,
    -1,
  )

  assert.notEqual(
    findingsIndex,
    -1,
  )

  assert.notEqual(
    reportsIndex,
    -1,
  )

  assert.ok(
    assessmentsIndex < findingsIndex,
    'Findings must appear after Assessments.',
  )

  assert.ok(
    findingsIndex < reportsIndex,
    'Findings must appear before Reports.',
  )
})

test('Findings navigation uses a dedicated icon key', () => {
  const layout = source(
    'src/components/AppLayout.jsx',
  )

  assert.match(
    layout,
    /findings:\s*\(/,
  )

  assert.match(
    layout,
    /<NavIcon name="findings" \/>/,
  )
})

test('findings API client exposes list and detail requests', () => {
  const api = source(
    'src/api/findings.js',
  )

  assert.match(
    api,
    /import \{\s*apiRequest\s*\} from ['"]\.\/client['"]/,
  )

  assert.match(
    api,
    /export function listFindings/,
  )

  assert.match(
    api,
    /new URLSearchParams\(\)/,
  )

  assert.match(
    api,
    /\/findings/,
  )

  assert.match(
    api,
    /export function getFinding/,
  )

  assert.match(
    api,
    /encodeURIComponent\(\s*findingId\s*,?\s*\)/,
  )
})

test('findings helpers expose canonical filters and detail paths', () => {
  const helpers = source(
    'src/pages/findings/helpers.js',
  )

  assert.match(
    helpers,
    /export const FINDING_SEVERITIES/,
  )

  for (const severity of [
    'critical',
    'high',
    'medium',
    'low',
    'informational',
  ]) {
    assert.match(
      helpers,
      new RegExp(`['"]${severity}['"]`),
    )
  }

  assert.match(
    helpers,
    /export const FINDING_CLASSIFICATIONS/,
  )

  for (const classification of [
    'security_issue',
    'attack_surface',
    'observation',
    'limitation',
  ]) {
    assert.match(
      helpers,
      new RegExp(`['"]${classification}['"]`),
    )
  }

  assert.match(
    helpers,
    /export function parseFindingFilters/,
  )

  assert.match(
    helpers,
    /export function buildFindingSearch/,
  )

  assert.match(
    helpers,
    /export function findingDetailPath/,
  )

  assert.match(
    helpers,
    /encodeURIComponent\(\s*findingId\s*,?\s*\)/,
  )
})

test('placeholder findings pages use shared workspace primitives', () => {
  const listPage = source(
    'src/pages/findings/FindingsPage.jsx',
  )

  const detailPage = source(
    'src/pages/findings/FindingDetailPage.jsx',
  )

  for (const page of [
    listPage,
    detailPage,
  ]) {
    assert.match(
      page,
      /PageHeader/,
    )

    assert.match(
      page,
      /LoadingState|EmptyState/,
    )
  }
})


test('findings helpers ignore invalid URL enums and preserve search as q', async () => {
  const helpers = await import(
    new URL(
      '../src/pages/findings/helpers.js',
      import.meta.url,
    )
  )

  const filters = helpers.parseFindingFilters(
    new URLSearchParams(
      'severity=bogus&classification=unknown&q=header&tool=zap',
    ),
  )

  assert.deepEqual(
    filters,
    {
      q: 'header',
      tool: 'zap',
    },
  )

  const search = helpers.buildFindingSearch({
    q: 'content security',
    severity: 'high',
  })

  assert.equal(
    search.get('q'),
    'content security',
  )

  assert.equal(
    search.get('severity'),
    'high',
  )
})


test('findings page loads API results from URL-backed filters', () => {
  const page = source(
    'src/pages/findings/FindingsPage.jsx',
  )

  assert.match(
    page,
    /useSearchParams/,
  )

  assert.doesNotMatch(
    page,
    /useAuth/,
  )

  assert.match(
    page,
    /listFindings/,
  )

  assert.match(
    page,
    /parseFindingFilters/,
  )

  assert.match(
    page,
    /listFindings\(\s*filters,?\s*\)/,
  )

  assert.match(
    page,
    /setLoading/,
  )

  assert.match(
    page,
    /setError/,
  )

  assert.match(
    page,
    /setData/,
  )
})


test('findings page writes filter changes back to the URL', () => {
  const page = source(
    'src/pages/findings/FindingsPage.jsx',
  )

  assert.match(
    page,
    /setSearchParams/,
  )

  assert.match(
    page,
    /buildFindingSearch/,
  )

  assert.match(
    page,
    /handleFilterChange/,
  )

  assert.match(
    page,
    /handleReset/,
  )

  assert.match(
    page,
    /offset/,
  )
})


test('findings filter controls expose the canonical workspace filters', () => {
  const filters = source(
    'src/pages/findings/FindingsFilters.jsx',
  )

  for (const label of [
    'Search',
    'Severity',
    'Confidence',
    'Target',
    'Assessment',
    'Source tool',
    'Classification',
  ]) {
    assert.match(
      filters,
      new RegExp(label, 'i'),
    )
  }

  assert.match(
    filters,
    /type="search"/,
  )

  assert.match(
    filters,
    /FINDING_SEVERITIES/,
  )

  assert.match(
    filters,
    /FINDING_CLASSIFICATIONS/,
  )

  assert.match(
    filters,
    /Reset filters/,
  )

  assert.match(
    filters,
    /onChange/,
  )

  assert.match(
    filters,
    /onReset/,
  )
})


test('findings workspace exposes loading error retry and both empty states', () => {
  const page = source(
    'src/pages/findings/FindingsPage.jsx',
  )

  assert.match(
    page,
    /LoadingState/,
  )

  assert.match(
    page,
    /ErrorAlert/,
  )

  assert.match(
    page,
    /Retry/,
  )

  assert.match(
    page,
    /No findings yet/,
  )

  assert.match(
    page,
    /No findings match/,
  )

  assert.match(
    page,
    /hasActiveFilters/,
  )
})


test('findings table renders investigation context and detail links', () => {
  const table = source(
    'src/pages/findings/FindingsTable.jsx',
  )

  assert.match(
    table,
    /findingDetailPath/,
  )

  for (const field of [
    'severity',
    'title',
    'classification',
    'confidence',
    'target_hostname',
    'scan_id',
    'sources',
    'occurrence_count',
    'last_observed_at',
  ]) {
    assert.match(
      table,
      new RegExp(field),
    )
  }

  assert.match(
    table,
    /StatusBadge/,
  )

  assert.match(
    table,
    /formatDate/,
  )

  assert.match(
    table,
    /to=\{findingDetailPath\(item\.id\)\}/,
  )
})


test('findings workspace uses dedicated Phase 14-style page CSS', () => {
  const appStyles = source(
    'src/App.css',
  )

  const styles = source(
    'src/styles/pages/findings.css',
  )

  assert.match(
    appStyles,
    /styles\/pages\/findings\.css/,
  )

  assert.match(
    styles,
    /\.findings-/,
  )

  assert.match(
    styles,
    /findings-table/,
  )

  assert.match(
    styles,
    /findings-filter/,
  )
})


test('finding detail loads the decoded workspace finding from the API', () => {
  const page = source(
    'src/pages/findings/FindingDetailPage.jsx',
  )

  assert.match(
    page,
    /useParams/,
  )

  assert.doesNotMatch(
    page,
    /useAuth/,
  )

  assert.match(
    page,
    /getFinding/,
  )

  assert.match(
    page,
    /findingId/,
  )

  assert.match(
    page,
    /decodeURIComponent/,
  )

  assert.match(
    page,
    /getFinding\(\s*decodedFindingId,?\s*\)/,
  )

  assert.match(
    page,
    /setLoading/,
  )

  assert.match(
    page,
    /setFinding/,
  )

  assert.match(
    page,
    /setError/,
  )
})


test('finding detail distinguishes not-found from generic API errors', () => {
  const page = source(
    'src/pages/findings/FindingDetailPage.jsx',
  )

  assert.match(
    page,
    /status\s*===\s*404/,
  )

  assert.match(
    page,
    /Finding not found/,
  )

  assert.match(
    page,
    /Unable to load finding/,
  )

  assert.match(
    page,
    /Retry/,
  )

  assert.match(
    page,
    /handleRetry/,
  )
})


test('finding summary exposes severity classification confidence and context', () => {
  const summary = source(
    'src/pages/findings/FindingSummary.jsx',
  )

  for (const field of [
    'severity',
    'classification',
    'confidence',
    'cwe_id',
    'occurrence_count',
    'sources',
    'target_hostname',
    'target_id',
    'scan_id',
    'last_observed_at',
  ]) {
    assert.match(
      summary,
      new RegExp(field),
    )
  }

  assert.match(
    summary,
    /StatusBadge/,
  )

  assert.match(
    summary,
    /\/targets\//,
  )

  assert.match(
    summary,
    /\/scans\//,
  )

  assert.match(
    summary,
    /formatDate/,
  )
})


test('finding evidence renders stored description URLs ports and structured evidence', () => {
  const evidence = source(
    'src/pages/findings/FindingEvidence.jsx',
  )

  assert.match(
    evidence,
    /description/,
  )

  assert.match(
    evidence,
    /sample_affected_urls/,
  )

  assert.match(
    evidence,
    /affected_url/,
  )

  assert.match(
    evidence,
    /affected_port/,
  )

  assert.match(
    evidence,
    /evidence/,
  )

  assert.match(
    evidence,
    /Object\.entries/,
  )

  assert.match(
    evidence,
    /Evidence not available/,
  )
})


test('finding occurrences preserve raw scanner provenance', () => {
  const occurrences = source(
    'src/pages/findings/FindingOccurrences.jsx',
  )

  assert.match(
    occurrences,
    /finding\.occurrences\s*\|\|\s*\[\]/,
  )

  assert.match(
    occurrences,
    /occurrences\.map\(/,
  )

  assert.doesNotMatch(
    occurrences,
    /finding\.occurrences\.map\(/,
  )

  for (const field of [
    'tool_name',
    'external_finding_id',
    'title',
    'severity',
    'confidence',
    'affected_url',
    'affected_port',
    'created_at',
    'evidence',
  ]) {
    assert.match(
      occurrences,
      new RegExp(field),
    )
  }

  assert.match(
    occurrences,
    /\.map\(/,
  )

  assert.match(
    occurrences,
    /formatDate/,
  )
})


test('finding remediation renders only stored API remediation with an explicit missing state', () => {
  const remediation = source(
    'src/pages/findings/FindingRemediation.jsx',
  )

  assert.match(
    remediation,
    /finding\.remediation/,
  )

  assert.match(
    remediation,
    /Remediation/,
  )

  assert.match(
    remediation,
    /Remediation guidance is not available for this finding/,
  )

  assert.doesNotMatch(
    remediation,
    /generateRemediation|suggestRemediation|recommendedFix/,
  )
})


test('finding detail composes investigation sections and secondary metadata', () => {
  const page = source(
    'src/pages/findings/FindingDetailPage.jsx',
  )

  for (const component of [
    'FindingSummary',
    'FindingEvidence',
    'FindingOccurrences',
    'FindingRemediation',
  ]) {
    assert.match(
      page,
      new RegExp(component),
    )
  }

  for (const field of [
    'issue_key',
    'scan_id',
    'target_id',
    'cwe_id',
    'source_count',
    'requires_manual_validation',
  ]) {
    assert.match(
      page,
      new RegExp(field),
    )
  }

  assert.match(
    page,
    /to="\/findings"/,
  )

  assert.match(
    page,
    /Back to Findings/,
  )
})
