import assert from 'node:assert/strict'
import fs from 'node:fs'
import test from 'node:test'

function read(path) {
  return fs.readFileSync(
    new URL(`../${path}`, import.meta.url),
    'utf8',
  )
}

test('New Assessment uses the shared control and loading system', () => {
  const page = read('src/pages/scans/NewAssessmentPage.jsx')

  for (const token of ['Checkbox', 'Textarea', 'SkeletonList', 'Spinner']) {
    assert.match(page, new RegExp(`\\b${token}\\b`))
  }

  assert.doesNotMatch(page, /<textarea\b/)
  assert.doesNotMatch(page, /type=["']checkbox["']/)
  assert.doesNotMatch(page, /\bLoadingState\b/)
})

test('New Assessment presents one authoritative five-stage progress system', () => {
  const page = read('src/pages/scans/NewAssessmentPage.jsx')

  assert.match(page, /assessment-wizard-v2/)
  assert.match(page, /data-state=\{state\}/)
  assert.match(page, /assessment-wizard-v2-signal/)
  assert.doesNotMatch(page, /assessment-workflow-steps profile-aware/)
  assert.doesNotMatch(page, /function WorkflowStep/)
})

test('launch console exposes real async state without artificial delay', () => {
  const page = read('src/pages/scans/NewAssessmentPage.jsx')

  assert.match(page, /assessment-launch-console/)
  assert.match(page, /assessment-launch-readiness/)
  assert.match(page, /aria-busy=\{launching\}/)
  assert.match(page, /launching\s*&&\s*\(\s*<Spinner/)
  assert.doesNotMatch(page, /setTimeout\s*\(/)
})

test('wizard polish preserves the sensitive launch and retest invariants', () => {
  const page = read('src/pages/scans/NewAssessmentPage.jsx')

  for (const token of [
    'createAssessment',
    'createScan',
    'linkFindingRetest',
    'authorizationReady',
    'infrastructureReady',
    'Retest must use the original finding target',
    'third_party_infrastructure_attested_excluded',
  ]) {
    assert.match(page, new RegExp(token))
  }
})
test('wizard styling has a BEACON signal treatment and reduced-motion fallback', () => {
  const styles = read('src/styles/pages/scans.css')

  for (const selector of [
    '.assessment-wizard-v2-signal',
    '.assessment-launch-console',
    '.assessment-launch-readiness',
    '.assessment-launch-state',
  ]) {
    assert.match(
      styles,
      new RegExp(selector.replace('.', '\\.')),
    )
  }

  assert.match(styles, /var\(--motion-standard\)/)
  assert.match(styles, /var\(--motion-page\)/)
  assert.match(styles, /prefers-reduced-motion:\s*reduce/)
})
