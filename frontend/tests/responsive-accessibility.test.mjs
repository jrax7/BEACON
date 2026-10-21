import assert from 'node:assert/strict'
import fs from 'node:fs'
import test from 'node:test'

function source(path) {
  return fs.readFileSync(
    new URL(`../${path}`, import.meta.url),
    'utf8',
  )
}

test('responsive layout preserves the required Phase 14 breakpoints', () => {
  const styles = source(
    'src/styles/responsive.css',
  )

  assert.match(
    styles,
    /@media \(max-width:\s*980px\)/,
  )

  assert.match(
    styles,
    /@media \(max-width:\s*720px\)/,
  )

  assert.match(
    styles,
    /@media \(max-width:\s*480px\)/,
  )

  assert.match(
    styles,
    /@media \(prefers-reduced-motion:\s*reduce\)/,
  )
})

test('mobile navigation exposes its open state to assistive technology', () => {
  const layout = source(
    'src/components/AppLayout.jsx',
  )

  assert.match(
    layout,
    /id="primary-navigation"/,
  )

  assert.match(
    layout,
    /aria-controls="primary-navigation"/,
  )

  assert.match(
    layout,
    /aria-expanded=\{mobileOpen\}/,
  )
})

test('assessment workspace exposes proper tab semantics', () => {
  const page = source(
    'src/pages/scan-detail/ScanDetailPage.jsx',
  )

  const parts = source(
    'src/pages/scan-detail/parts.jsx',
  )

  assert.match(
    page,
    /className="assessment-tabs"[\s\S]*?role="tablist"/,
  )

  assert.match(
    parts,
    /role="tab"/,
  )

  assert.match(
    parts,
    /aria-selected=\{active\}/,
  )
})

test('report lifecycle controls expose proper tab semantics', () => {
  const reports = source(
    'src/pages/scan-detail/ReportsTab.jsx',
  )

  assert.match(
    reports,
    /className="report-lifecycle-tabs"[\s\S]*?role="tablist"/,
  )

  assert.match(
    reports,
    /role="tab"/,
  )

  assert.match(
    reports,
    /aria-selected=\{reportView === 'active'\}/,
  )

  assert.match(
    reports,
    /aria-selected=\{reportView === 'archived'\}/,
  )
})

test('assessment and report tabs expose visible keyboard focus', () => {
  const styles = source(
    'src/styles/pages/scan-detail.css',
  )

  assert.match(
    styles,
    /\.assessment-tab:focus-visible/,
  )

  assert.match(
    styles,
    /\.report-lifecycle-tabs button:focus-visible/,
  )

  assert.match(
    styles,
    /outline:\s*2px solid var\(--accent-bright\)/,
  )
})

test('responsive report layout follows the renamed download action', () => {
  const styles = source(
    'src/styles/responsive.css',
  )

  assert.match(
    styles,
    /\.report-row \.report-download-action/,
  )

  assert.doesNotMatch(
    styles,
    /\.report-row \.table-action/,
  )
})

test('shared navigation controls retain visible focus treatment', () => {
  const layoutStyles = source(
    'src/styles/layout.css',
  )

  const componentStyles = source(
    'src/styles/components.css',
  )

  assert.match(
    layoutStyles,
    /\.nav-item:focus-visible/,
  )

  assert.match(
    layoutStyles,
    /\.mobile-menu-button:focus-visible/,
  )

  assert.match(
    layoutStyles,
    /\.sidebar-mobile-close:focus-visible/,
  )

  assert.match(
    componentStyles,
    /\.workspace-tab:focus-visible/,
  )

  assert.match(
    componentStyles,
    /\.breadcrumbs a:focus-visible/,
  )
})


test('findings filters use explicit accessible labels for every control', () => {
  const filters = source(
    'src/pages/findings/FindingsFilters.jsx',
  )

  const controls = [
    ['findings-search', 'Search'],
    ['findings-severity', 'Severity'],
    ['findings-confidence', 'Confidence'],
    ['findings-target', 'Target'],
    ['findings-assessment', 'Assessment'],
    ['findings-tool', 'Source tool'],
    ['findings-classification', 'Classification'],
  ]

  for (const [id, label] of controls) {
    assert.match(
      filters,
      new RegExp(
        `<label[^>]*htmlFor=["']${id}["'][^>]*>[\\s\\S]*?${label}`,
      ),
    )

    assert.match(
      filters,
      new RegExp(
        `(?:Input|Select)[^>]*id=["']${id}["']`,
      ),
    )
  }
})


test('findings retry reset and detail navigation remain semantic controls', () => {
  const filters = source(
    'src/pages/findings/FindingsFilters.jsx',
  )

  const page = source(
    'src/pages/findings/FindingsPage.jsx',
  )

  const table = source(
    'src/pages/findings/FindingsTable.jsx',
  )

  assert.match(
    filters,
    /<button[\s\S]*?type="button"[\s\S]*?Reset filters/,
  )

  assert.match(
    page,
    /<button[\s\S]*?type="button"[\s\S]*?Retry/,
  )

  assert.match(
    table,
    /to=\{findingDetailPath\(item\.id\)\}[\s\S]*?\{item\.title\}/,
  )
})


test('findings mobile layout preserves the investigation-critical columns', () => {
  const styles = source(
    'src/styles/pages/findings.css',
  )

  assert.match(
    styles,
    /@media \(max-width:\s*720px\)/,
  )

  for (const hiddenColumn of [
    3,
    4,
    6,
    9,
  ]) {
    assert.match(
      styles,
      new RegExp(
        `\\.findings-table th:nth-child\\(${hiddenColumn}\\)[\\s\\S]*?display:\\s*none`,
      ),
    )

    assert.match(
      styles,
      new RegExp(
        `\\.findings-table td:nth-child\\(${hiddenColumn}\\)[\\s\\S]*?display:\\s*none`,
      ),
    )
  }

  assert.match(
    styles,
    /@media \(max-width:\s*720px\)[\s\S]*?\.findings-table\s*\{[\s\S]*?min-width:\s*720px/,
  )
})


test('findings detail content contains long evidence without page overflow', () => {
  const styles = source(
    'src/styles/pages/findings.css',
  )

  assert.match(
    styles,
    /\.finding-detail-layout\s*,\s*\.finding-detail-card\s*\{[^}]*min-width:\s*0/,
  )

  assert.match(
    styles,
    /\.finding-url-list\s*\{[\s\S]*?overflow-wrap:\s*anywhere/,
  )

  assert.match(
    styles,
    /\.finding-evidence-values dd\s*\{[\s\S]*?overflow-wrap:\s*anywhere/,
  )

  assert.match(
    styles,
    /\.finding-occurrence-evidence p\s*\{[\s\S]*?overflow-wrap:\s*anywhere/,
  )

  assert.match(
    styles,
    /\.findings-table-wrapper\s*\{[\s\S]*?overflow-x:\s*auto/,
  )
})


test('findings interactive controls expose visible keyboard focus', () => {
  const styles = source(
    'src/styles/pages/findings.css',
  )

  assert.match(
    styles,
    /\.findings-filter input:focus-visible/,
  )

  assert.match(
    styles,
    /\.findings-filter select:focus-visible/,
  )

  assert.match(
    styles,
    /\.findings-title-cell a:focus-visible/,
  )

  assert.match(
    styles,
    /\.findings-context-link:focus-visible/,
  )

  assert.match(
    styles,
    /outline:\s*2px solid var\(--accent-bright\)/,
  )
})


test('shared loading and error states expose status semantics', () => {
  const states = source(
    'src/components/ui/StateMessage.jsx',
  )

  assert.match(
    states,
    /role="alert"/,
  )

  assert.match(
    states,
    /role="status"/,
  )

  assert.match(
    states,
    /aria-live="polite"/,
  )
})
