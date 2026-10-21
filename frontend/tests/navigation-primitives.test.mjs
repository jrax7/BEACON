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

test('shared text tokens provide readable secondary contrast', () => {
  const tokens = source('src/styles/tokens.css')

  assert.match(tokens, /--text-soft:\s*#cbbcc0;/)
  assert.match(tokens, /--text-muted:\s*#a78f96;/)
  assert.match(tokens, /--text-faint:\s*#8d747b;/)
})

test('breadcrumbs provide an accessible contextual trail', () => {
  const breadcrumbs = source('src/components/ui/Breadcrumbs.jsx')

  assert.match(breadcrumbs, /aria-label="Breadcrumb"/)
  assert.match(breadcrumbs, /<Link/)
  assert.match(breadcrumbs, /breadcrumb-separator/)
})

test('workspace tabs expose accessible tab semantics', () => {
  const tabs = source('src/components/ui/Tabs.jsx')

  assert.match(tabs, /role="tablist"/)
  assert.match(tabs, /role="tab"/)
  assert.match(tabs, /aria-selected=/)
  assert.match(tabs, /workspace-tab/)
})

test('PageHeader supports contextual breadcrumbs', () => {
  const header = source('src/components/ui/PageHeader.jsx')

  assert.match(header, /Breadcrumbs/)
  assert.match(header, /breadcrumbs/)
})

test('sidebar separates reports and account settings', () => {
  const layout = source('src/components/AppLayout.jsx')

  assert.match(layout, /to="\/reports"/)
  assert.match(layout, /<span>Reports<\/span>/)

  assert.match(layout, />\s*Account\s*</)
  assert.match(layout, /to="\/settings"/)
  assert.match(layout, /<span>Settings<\/span>/)
})

test('shell brand opens the dashboard in a new tab', () => {
  const layout = source('src/components/AppLayout.jsx')

  const dashboardLinks = layout.match(
    /href="\/dashboard"[\s\S]*?target="_blank"[\s\S]*?rel="noopener noreferrer"/g,
  ) || []

  assert.equal(dashboardLinks.length, 2)
  assert.match(layout, /aria-label="Open BEACON dashboard in a new tab"/)
})
