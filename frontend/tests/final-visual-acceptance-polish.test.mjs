import assert from 'node:assert/strict'
import fs from 'node:fs'
import test from 'node:test'

function read(path) {
  return fs.readFileSync(
    new URL(`../${path}`, import.meta.url),
    'utf8',
  )
}

test('dashboard summary metrics are keyboard-accessible navigation cards', () => {
  const page = read('src/pages/dashboard/DashboardPage.jsx')
  const css = read('src/styles/pages/dashboard.css')

  for (const destination of ['/targets', '/scans', '/reports']) {
    assert.match(page, new RegExp(`to=["']${destination}["']`))
  }

  assert.match(page, /metric-card-link/)
  assert.match(css, /\.metric-card-link:focus-visible/)
  assert.match(css, /cursor:\s*pointer/)
})
test('findings workspace uses the finalized visual-system typography and surfaces', () => {
  const filters = read('src/pages/findings/FindingWorkflowFilters.jsx')
  const css = read('src/styles/pages/findings.css')

  assert.match(filters, /import[\s\S]*Select[\s\S]*from ['"]\.\.\/\.\.\/components\/ui['"]/)
  assert.doesNotMatch(filters, /<select\b/)
  assert.match(css, /\/\* Final visual system: findings workspace convergence \*\//)
  assert.match(css, /\.findings-filter > span[\s\S]*font-family:\s*var\(--font-sans\)/)
  assert.match(css, /\.findings-table th[\s\S]*font-family:\s*var\(--font-sans\)/)
  assert.match(css, /\.findings-title-cell a[\s\S]*color:\s*var\(--text-primary\)/)
  assert.match(css, /\.findings-results[\s\S]*background:\s*var\(--surface-card\)/)
})
