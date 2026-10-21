import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import test from 'node:test'
const root = process.cwd()
const read = (path) => readFileSync(resolve(root, path), 'utf8')

test('Settings consumes shared form primitives instead of raw native controls', () => {
  const page = read('src/pages/settings/SettingsPage.jsx')
  assert.match(page, /\bInput\b/)
  assert.match(page, /\bSelect\b/)
  assert.match(page, /\bFormField\b/)
  assert.doesNotMatch(page, /<select\b/)
  assert.doesNotMatch(page, /className="target-actions"/)
})

test('Settings explicitly distinguishes workspace authorization from account classification', () => {
  const page = read('src/pages/settings/SettingsPage.jsx')
  assert.match(page, /Workspace role/)
  assert.match(page, /Account role/)
  assert.match(page, /permissions within the current organization/i)
  assert.match(page, /separate from organization membership authorization/i)
})

test('Settings gives members dedicated identity, email, role, and action layout hooks', () => {
  const page = read('src/pages/settings/SettingsPage.jsx')
  const css = read('src/styles/pages/settings.css')
  for (const hook of ['settings-member-row', 'settings-member-avatar', 'settings-member-email', 'settings-member-actions', 'settings-invite-form']) {
    assert.ok(page.includes(hook) || css.includes(`.${hook}`), `${hook} must be part of Settings design`)
  }
  assert.match(css, /\.settings-member-email[\s\S]*text-overflow:\s*ellipsis/)
  assert.match(css, /@media \(max-width: 560px\)/)
})

test('shared Select is dark and retains native semantics', () => {
  const select = read('src/components/ui/Select.jsx')
  const primitives = read('src/styles/primitives.css')
  assert.match(select, /<select\b/)
  assert.match(primitives, /\.ui-select\s*\{[^}]*color-scheme:\s*dark/s)
})
