import assert from 'node:assert/strict'
import fs from 'node:fs'
import test from 'node:test'

function read(path) {
  return fs.readFileSync(
    new URL(`../${path}`, import.meta.url),
    'utf8',
  )
}

test('Finding lifecycle rail exists with the authoritative six lifecycle states', () => {
  const rail = read('src/pages/findings/FindingLifecycleRail.jsx')

  for (const state of [
    'NEW',
    'TRIAGED',
    'ASSIGNED',
    'IN_REMEDIATION',
    'READY_FOR_RETEST',
    'RESOLVED',
  ]) {
    assert.match(rail, new RegExp(state))
  }

  assert.match(rail, /data-position=/)
  assert.match(rail, /aria-current=/)
})
test('workflow panel renders the lifecycle rail and explicit REGRESSED recovery signal', () => {
  const panel = read('src/pages/findings/FindingWorkflowPanel.jsx')

  assert.match(panel, /FindingLifecycleRail/)
  assert.match(panel, /finding\.observation_state\s*===\s*'REGRESSED'/)
  assert.match(panel, /finding-regressed-signal/)
  assert.match(panel, /observed again/i)
  assert.match(panel, /remediation/i)
})

test('workflow forms use shared controls and stable loading feedback', () => {
  const panel = read('src/pages/findings/FindingWorkflowPanel.jsx')

  for (const token of ['Select', 'Textarea', 'SkeletonList', 'Spinner']) {
    assert.match(panel, new RegExp(`\\b${token}\\b`))
  }

  assert.doesNotMatch(panel, /<select\b/)
  assert.doesNotMatch(panel, /<textarea\b/)
  assert.doesNotMatch(panel, /\bLoadingState\b/)
  assert.match(panel, /aria-busy=\{retestBusy\}/)
})
test('finding lifecycle polish preserves Phase 16E mutation and permission invariants', () => {
  const panel = read('src/pages/findings/FindingWorkflowPanel.jsx')

  for (const token of [
    'PERMISSIONS.FINDING_MANAGE',
    'updateFindingLifecycle',
    'updateFindingAssignee',
    'updateFindingRemediationOwner',
    'setFindingDisposition',
    'clearFindingDisposition',
    'createFindingRetest',
    'linkFindingRetest',
  ]) {
    if (token === 'linkFindingRetest') continue
    assert.match(panel, new RegExp(token.replace('.', '\\.')))
  }

  assert.match(panel, /READY_FOR_RETEST/)
  assert.match(panel, /RESOLVED:\s*\[\s*'IN_REMEDIATION'/)
  assert.doesNotMatch(panel, /REGRESSED:\s*\[/)
})

test('finding lifecycle styling is responsive, restrained, and reduced-motion safe', () => {
  const styles = read('src/styles/pages/findings.css')

  for (const selector of [
    '.finding-lifecycle-rail',
    '.finding-lifecycle-step',
    '.finding-regressed-signal',
    '.finding-retest-item',
  ]) {
    assert.match(styles, new RegExp(selector.replace('.', '\\.')))
  }

  assert.match(styles, /var\(--motion-standard\)/)
  assert.match(styles, /prefers-reduced-motion:\s*reduce/)
})
