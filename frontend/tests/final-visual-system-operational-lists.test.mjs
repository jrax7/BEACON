import assert from 'node:assert/strict'
import { existsSync, readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import test from 'node:test'
const root = process.cwd()
const at = (path) => resolve(root, path)
const read = (path) => readFileSync(at(path), 'utf8')

test('shared technical identity primitives exist and are exported', () => {
  for (const file of ['CopyValue.jsx', 'Tooltip.jsx', 'Avatar.jsx']) {
    assert.ok(existsSync(at(`src/components/ui/${file}`)), `${file} must exist`)
  }
  const index = read('src/components/ui/index.js')
  for (const name of ['CopyValue', 'Tooltip', 'Avatar']) {
    assert.match(index, new RegExp(`export \\{ default as ${name} \\}`))
  }
})

test('Findings list filters consume the shared dark Input and Select primitives', () => {
  const source = read('src/pages/findings/FindingsFilters.jsx')
  assert.match(source, /\bInput\b/)
  assert.match(source, /\bSelect\b/)
  assert.doesNotMatch(source, /<(input|select)\b/)
  assert.match(source, /Reset filters/)
})

test('Assessment and Report search fields consume the shared Input primitive', () => {
  for (const path of ['src/pages/scans/ScansPage.jsx', 'src/pages/reports/ReportsPage.jsx']) {
    const source = read(path)
    assert.match(source, /\bInput\b/, `${path} must use Input for search`)
    assert.doesNotMatch(source, /<input\s*\n\s*type="search"/, `${path} must not own its search input`)
  }
})

test('Report integrity metadata exposes full checksum copy without losing lifecycle/download behavior', () => {
  const source = read('src/pages/reports/ReportsPage.jsx')
  assert.match(source, /CopyValue/)
  assert.match(source, /checksum_sha256/)
  assert.match(source, /downloadReport/)
  assert.match(source, /archiveReports/)
  assert.match(source, /restoreReports/)
})

test('Settings member identity consumes the shared Avatar primitive', () => {
  const source = read('src/pages/settings/SettingsPage.jsx')
  assert.match(source, /\bAvatar\b/)
  assert.match(source, /settings-member-avatar/)
})

test('technical copy and tooltip primitives have accessible interaction hooks and shared styling', () => {
  const copy = read('src/components/ui/CopyValue.jsx')
  const tooltip = read('src/components/ui/Tooltip.jsx')
  const css = read('src/styles/primitives.css')
  assert.match(copy, /navigator\.clipboard\.writeText/)
  assert.match(copy, /aria-label=/)
  assert.match(tooltip, /role="tooltip"/)
  assert.match(css, /\.ui-copy-value/)
  assert.match(css, /\.ui-tooltip/)
})
