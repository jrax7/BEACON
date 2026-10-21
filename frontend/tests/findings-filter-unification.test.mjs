import assert from 'node:assert/strict'
import fs from 'node:fs'
import test from 'node:test'

const findingsApi = fs.readFileSync(
  new URL(
    '../src/api/findings.js',
    import.meta.url,
  ),
  'utf8',
)

test(
  'findings API collects source tools across the complete owned findings collection',
  () => {
    assert.match(
      findingsApi,
      /export\s+async\s+function\s+listFindingSourceTools\s*\(/,
      'findings API should export listFindingSourceTools',
    )

    assert.match(
      findingsApi,
      /listFindings\s*\(/,
      'source-tool metadata should reuse authenticated listFindings',
    )

    assert.match(
      findingsApi,
      /limit\s*:\s*100/,
      'source-tool collection should use the maximum Findings page size',
    )

    assert.match(
      findingsApi,
      /offset/,
      'source-tool collection should track Findings pagination offset',
    )

    assert.match(
      findingsApi,
      /source\.tool_name/,
      'source-tool collection should extract scanner provenance',
    )

    assert.match(
      findingsApi,
      /total/,
      'source-tool collection should continue against the Findings total',
    )
  },
)


async function loadFindingHelpers() {
  return import(
    new URL(
      '../src/pages/findings/helpers.js',
      import.meta.url,
    )
  )
}

function requireHelper(
  helpers,
  name,
) {
  assert.equal(
    typeof helpers[name],
    'function',
    `${name} should be exported`,
  )

  return helpers[name]
}


test(
  'target options use authenticated human-readable target metadata',
  async () => {
    const helpers =
      await loadFindingHelpers()

    const buildTargetOptions =
      requireHelper(
        helpers,
        'buildTargetOptions',
      )

    const options =
      buildTargetOptions([
        {
          id: 'target-1',
          hostname: 'lab-target',
          normalized_url:
            'https://lab-target/',
        },
        {
          id: 'target-2',
          hostname: '',
          normalized_url:
            'https://example.test/',
        },
      ])

    assert.deepEqual(
      options,
      [
        {
          value: 'target-1',
          label: 'lab-target',
        },
        {
          value: 'target-2',
          label:
            'https://example.test/',
        },
      ],
    )
  },
)


test(
  'assessment options are human-readable newest-first and target scoped',
  async () => {
    const helpers =
      await loadFindingHelpers()

    const buildAssessmentOptions =
      requireHelper(
        helpers,
        'buildAssessmentOptions',
      )

    const targets = [
      {
        id: 'target-1',
        hostname: 'lab-target',
      },
      {
        id: 'target-2',
        hostname: 'example.com',
      },
    ]

    const scans = [
      {
        id:
          '1777ba38-1111-2222-3333-444444444444',
        target_id: 'target-1',
        created_at:
          '2026-08-22T10:00:00Z',
      },
      {
        id:
          '99aa88bb-1111-2222-3333-444444444444',
        target_id: 'target-2',
        created_at:
          '2026-08-23T10:00:00Z',
      },
      {
        id:
          '11223344-1111-2222-3333-444444444444',
        target_id: 'target-1',
        created_at:
          '2026-08-21T10:00:00Z',
      },
    ]

    const all =
      buildAssessmentOptions(
        scans,
        targets,
        '',
      )

    assert.deepEqual(
      all.map((option) => option.value),
      [
        '99aa88bb-1111-2222-3333-444444444444',
        '1777ba38-1111-2222-3333-444444444444',
        '11223344-1111-2222-3333-444444444444',
      ],
    )

    assert.equal(
      all[1].label,
      'lab-target · 1777ba38 · Aug 22, 2026',
    )

    const scoped =
      buildAssessmentOptions(
        scans,
        targets,
        'target-1',
      )

    assert.deepEqual(
      scoped.map(
        (option) => option.value,
      ),
      [
        '1777ba38-1111-2222-3333-444444444444',
        '11223344-1111-2222-3333-444444444444',
      ],
    )
  },
)


test(
  'source tool options deduplicate case-insensitively',
  async () => {
    const helpers =
      await loadFindingHelpers()

    const buildSourceToolOptions =
      requireHelper(
        helpers,
        'buildSourceToolOptions',
      )

    const options =
      buildSourceToolOptions([
        'zap',
        'Zap',
        'ZAP',
        'Nikto',
        'nmap',
        'Custom Scanner',
        ' custom scanner ',
      ])

    assert.equal(
      options.length,
      4,
    )

    const byValue =
      new Map(
        options.map(
          (option) => [
            option.value,
            option.label,
          ],
        ),
      )

    assert.equal(
      byValue.get('zap'),
      'ZAP',
    )

    assert.equal(
      byValue.get('nikto'),
      'Nikto',
    )

    assert.equal(
      byValue.get('nmap'),
      'Nmap',
    )

    assert.equal(
      byValue.get('custom scanner'),
      'Custom Scanner',
    )
  },
)


test(
  'option resolution rejects unknown identifiers and supports tool case variants',
  async () => {
    const helpers =
      await loadFindingHelpers()

    const resolveFindingOptionValue =
      requireHelper(
        helpers,
        'resolveFindingOptionValue',
      )

    const options = [
      {
        value: 'target-1',
        label: 'lab-target',
      },
    ]

    assert.equal(
      resolveFindingOptionValue(
        'target-1',
        options,
        false,
      ),
      'target-1',
    )

    assert.equal(
      resolveFindingOptionValue(
        'another-users-target',
        options,
        false,
      ),
      '',
    )

    assert.equal(
      resolveFindingOptionValue(
        'ZAP',
        [
          {
            value: 'zap',
            label: 'ZAP',
          },
        ],
        true,
      ),
      'zap',
    )
  },
)


test(
  'target changes reconcile the selected assessment without losing unrelated filters',
  async () => {
    const helpers =
      await loadFindingHelpers()

    const reconcileAssessmentForTarget =
      requireHelper(
        helpers,
        'reconcileAssessmentForTarget',
      )

    const scans = [
      {
        id: 'scan-a',
        target_id: 'target-1',
      },
      {
        id: 'scan-b',
        target_id: 'target-2',
      },
    ]

    const current = {
      target_id: 'target-1',
      scan_id: 'scan-a',
      severity: 'high',
    }

    assert.deepEqual(
      reconcileAssessmentForTarget(
        current,
        'target-1',
        scans,
      ),
      current,
    )

    assert.deepEqual(
      reconcileAssessmentForTarget(
        current,
        'target-2',
        scans,
      ),
      {
        target_id: 'target-2',
        severity: 'high',
      },
    )

    assert.deepEqual(
      reconcileAssessmentForTarget(
        current,
        '',
        scans,
      ),
      {
        scan_id: 'scan-a',
        severity: 'high',
      },
    )

    assert.deepEqual(
      reconcileAssessmentForTarget(
        {
          target_id: 'target-1',
          scan_id: 'unknown-scan',
          severity: 'medium',
        },
        'target-2',
        scans,
      ),
      {
        target_id: 'target-2',
        severity: 'medium',
      },
    )
  },
)


test(
  'findings page loads authenticated filter metadata',
  () => {
    const page = fs.readFileSync(
      new URL(
        '../src/pages/findings/FindingsPage.jsx',
        import.meta.url,
      ),
      'utf8',
    )

    assert.match(
      page,
      /listTargets/,
      'FindingsPage should use authenticated target metadata',
    )

    assert.match(
      page,
      /listTargets\(\s*\)/,
      'FindingsPage should load targets through the authenticated session',
    )

    assert.match(
      page,
      /listScans/,
      'FindingsPage should use authenticated assessment metadata',
    )

    assert.match(
      page,
      /listScans\(\s*['"]all['"]\s*,?\s*\)/,
      'FindingsPage should load active and archived assessments',
    )

    assert.match(
      page,
      /listFindingSourceTools/,
      'FindingsPage should load source tools from authenticated findings',
    )

    assert.match(
      page,
      /listFindingSourceTools\(\s*\)/,
      'FindingsPage should load source-tool metadata through the authenticated session',
    )

    assert.match(
      page,
      /Promise\.all\s*\(/,
      'Findings metadata should load together',
    )
  },
)


test(
  'findings metadata state is independent from findings result state',
  () => {
    const page = fs.readFileSync(
      new URL(
        '../src/pages/findings/FindingsPage.jsx',
        import.meta.url,
      ),
      'utf8',
    )

    for (const stateName of [
      'targets',
      'scans',
      'sourceToolNames',
      'metadataLoading',
      'metadataError',
    ]) {
      assert.match(
        page,
        new RegExp(
          `\\b${stateName}\\b`,
        ),
        `${stateName} state should exist`,
      )
    }

    assert.match(
      page,
      /setMetadataError/,
      'metadata errors should have their own state',
    )

    assert.match(
      page,
      /setError/,
      'findings result errors should remain separate',
    )
  },
)


test(
  'findings page derives safe URL-backed selector values',
  () => {
    const page = fs.readFileSync(
      new URL(
        '../src/pages/findings/FindingsPage.jsx',
        import.meta.url,
      ),
      'utf8',
    )

    for (const helper of [
      'buildTargetOptions',
      'buildAssessmentOptions',
      'buildSourceToolOptions',
      'resolveFindingOptionValue',
      'reconcileAssessmentForTarget',
    ]) {
      assert.match(
        page,
        new RegExp(
          `\\b${helper}\\b`,
        ),
        `FindingsPage should use ${helper}`,
      )
    }

    for (const valueName of [
      'targetOptions',
      'assessmentOptions',
      'sourceToolOptions',
      'selectedTargetValue',
      'selectedAssessmentValue',
      'selectedToolValue',
    ]) {
      assert.match(
        page,
        new RegExp(
          `\\b${valueName}\\b`,
        ),
        `${valueName} should be derived`,
      )
    }

    assert.match(
      page,
      /handleTargetChange/,
      'Target changes should use dedicated reconciliation logic',
    )

    assert.match(
      page,
      /reconcileAssessmentForTarget\s*\(/,
      'Target changes should reconcile incompatible assessments',
    )
  },
)


function loadFindingsFiltersSource() {
  return fs.readFileSync(
    new URL(
      '../src/pages/findings/FindingsFilters.jsx',
      import.meta.url,
    ),
    'utf8',
  )
}


test(
  'findings target assessment and source filters are metadata-backed selects',
  () => {
    const filters =
      loadFindingsFiltersSource()

    for (const controlId of [
      'findings-target',
      'findings-assessment',
      'findings-tool',
    ]) {
      assert.match(
        filters,
        new RegExp(
          `<Select[\\s\\S]{0,500}?id="${controlId}"`,
        ),
        `${controlId} should be a select control`,
      )
    }

    assert.match(
      filters,
      /All targets/,
    )

    assert.match(
      filters,
      /All assessments/,
    )

    assert.match(
      filters,
      /All source tools/,
    )

    assert.doesNotMatch(
      filters,
      /placeholder="Target ID"/,
      'Target UUID input should be removed',
    )

    assert.doesNotMatch(
      filters,
      /placeholder="Assessment ID"/,
      'Assessment UUID input should be removed',
    )

    assert.doesNotMatch(
      filters,
      /placeholder="e\.g\. ZAP"/,
      'Source Tool free-text input should be removed',
    )
  },
)


test(
  'metadata-backed findings selects use resolved safe values',
  () => {
    const filters =
      loadFindingsFiltersSource()

    assert.match(
      filters,
      /value=\{selectedTargetValue\}/,
      'Target should use its resolved authorized value',
    )

    assert.match(
      filters,
      /value=\{selectedAssessmentValue\}/,
      'Assessment should use its resolved authorized value',
    )

    assert.match(
      filters,
      /value=\{selectedToolValue\}/,
      'Source Tool should use its resolved canonical value',
    )

    assert.match(
      filters,
      /targetOptions\.map/,
      'Target should render authenticated options',
    )

    assert.match(
      filters,
      /assessmentOptions\.map/,
      'Assessment should render authenticated options',
    )

    assert.match(
      filters,
      /sourceToolOptions\.map/,
      'Source Tool should render provenance options',
    )
  },
)


test(
  'metadata-backed findings selectors preserve URL change semantics',
  () => {
    const filters =
      loadFindingsFiltersSource()

    assert.match(
      filters,
      /onTargetChange\s*\(\s*event\.target\.value\s*,?\s*\)/,
      'Target changes should use target reconciliation',
    )

    assert.match(
      filters,
      /onChange\s*\(\s*['"]scan_id['"]\s*,\s*event\.target\.value\s*,?\s*\)/,
      'Assessment changes should update scan_id',
    )

    assert.match(
      filters,
      /onChange\s*\(\s*['"]tool['"]\s*,\s*event\.target\.value\s*,?\s*\)/,
      'Source Tool changes should update tool',
    )

    assert.match(
      filters,
      /type="search"/,
      'Search must remain the free-text search control',
    )
  },
)


test(
  'findings filter metadata failures remain nonfatal and visible',
  () => {
    const filters =
      loadFindingsFiltersSource()

    assert.match(
      filters,
      /\bmetadataLoading\b/,
      'metadata loading state should reach the filters',
    )

    assert.match(
      filters,
      /\bmetadataError\b/,
      'metadata error state should reach the filters',
    )

    assert.match(
      filters,
      /metadataError[\s\S]*?\{/,
      'metadata failures should render a filter-level message',
    )
  },
)


function loadFindingsCss() {
  return fs.readFileSync(
    new URL(
      '../src/styles/pages/findings.css',
      import.meta.url,
    ),
    'utf8',
  )
}


test(
  'findings filters expose dedicated responsive field hooks',
  () => {
    const filters =
      loadFindingsFiltersSource()

    for (const className of [
      'findings-filter-target',
      'findings-filter-assessment',
      'findings-filter-severity',
      'findings-filter-confidence',
      'findings-filter-tool',
      'findings-filter-classification',
    ]) {
      assert.match(
        filters,
        new RegExp(
          `\\b${className}\\b`,
        ),
        `${className} should identify its responsive field`,
      )
    }
  },
)


test(
  'findings controls use the BEACON dark form treatment',
  () => {
    const css =
      loadFindingsCss()

    assert.match(
      css,
      /\.findings-filter input,[\s\S]*?\.findings-filter select[\s\S]*?border:\s*1px solid var\(--border\)/,
      'Findings inputs and selects should use the shared border token',
    )

    assert.match(
      css,
      /\.findings-filter input,[\s\S]*?\.findings-filter select[\s\S]*?border-radius:\s*var\(--radius-md\)/,
      'Findings controls should use the shared radius token',
    )

    assert.match(
      css,
      /\.findings-filter input,[\s\S]*?\.findings-filter select[\s\S]*?background:\s*rgba\(8,\s*5,\s*6,/,
      'Findings controls should use the dark BEACON control surface',
    )

    assert.match(
      css,
      /\.findings-filter input,[\s\S]*?\.findings-filter select[\s\S]*?color:\s*var\(--text\)/,
      'Findings controls should use BEACON text color',
    )

    assert.match(
      css,
      /\.findings-filter input::placeholder[\s\S]*?color:\s*var\(--text-faint\)/,
      'Search placeholder should use muted BEACON text',
    )

    assert.match(
      css,
      /\.findings-filter select:disabled[\s\S]*?cursor:\s*not-allowed/,
      'Loading metadata selects should expose a disabled visual state',
    )
  },
)


test(
  'findings filter panel uses restrained workspace hierarchy',
  () => {
    const css =
      loadFindingsCss()

    assert.match(
      css,
      /\.findings-filter-panel[\s\S]*?border:\s*1px solid var\(--border\)/,
      'Filter panel should use the normal BEACON border',
    )

    assert.match(
      css,
      /\.findings-filter-panel[\s\S]*?border-radius:\s*var\(--radius-md\)/,
      'Filter panel should align with workspace panel radius',
    )

    assert.match(
      css,
      /\.findings-filter-panel[\s\S]*?background:\s*rgba\(8,\s*5,\s*6,/,
      'Filter panel should use a restrained dark workspace surface',
    )

    assert.match(
      css,
      /\.findings-filter-metadata-error[\s\S]*?grid-column:\s*1\s*\/\s*-1/,
      'Metadata errors should span the filter grid without replacing results',
    )
  },
)


test(
  'findings mobile filters follow investigation-first order without form overflow',
  () => {
    const css =
      loadFindingsCss()

    assert.doesNotMatch(
      css,
      /@media\s*\(max-width:\s*700px\)/,
      'Duplicate 700px Findings breakpoint should be consolidated',
    )

    assert.match(
      css,
      /@media\s*\(max-width:\s*720px\)[\s\S]*?\.findings-search-filter[\s\S]*?order:\s*1/,
      'Search should be first on mobile',
    )

    const expectedOrder = [
      ['findings-filter-target', 2],
      ['findings-filter-assessment', 3],
      ['findings-filter-severity', 4],
      ['findings-filter-confidence', 5],
      ['findings-filter-tool', 6],
      ['findings-filter-classification', 7],
      ['findings-filter-actions', 8],
    ]

    for (const [
      className,
      order,
    ] of expectedOrder) {
      assert.match(
        css,
        new RegExp(
          `@media\\s*\\(max-width:\\s*720px\\)[\\s\\S]*?\\.${className}[\\s\\S]*?order:\\s*${order}`,
        ),
        `${className} should use mobile order ${order}`,
      )
    }

    assert.match(
      css,
      /\.findings-filter-panel[\s\S]*?min-width:\s*0/,
      'Filter grid should be allowed to shrink without horizontal overflow',
    )

    assert.match(
      css,
      /\.findings-table-wrapper[\s\S]*?overflow-x:\s*auto/,
      'Investigation table should retain horizontal scrolling',
    )
  },
)
