import assert from 'node:assert/strict'
import { existsSync, readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import test from 'node:test'
const root = process.cwd()
const at = (path) => resolve(root, path)
const read = (path) => readFileSync(at(path), 'utf8')

test('shared skeleton system supports semantic variants and reusable list loading', () => {
  assert.ok(existsSync(at('src/components/ui/SkeletonList.jsx')))
  const skeleton = read('src/components/ui/Skeleton.jsx')
  const list = read('src/components/ui/SkeletonList.jsx')
  const index = read('src/components/ui/index.js')
  assert.match(skeleton, /variant/)
  assert.match(skeleton, /ui-skeleton-/)
  assert.match(list, /role="status"/)
  assert.match(list, /aria-label=/)
  assert.match(list, /variant="row"/)
  assert.match(index, /SkeletonList/)
})

test('Dashboard uses layout-stable metric and list skeletons instead of loading dashes/text', () => {
  const page = read('src/pages/dashboard/DashboardPage.jsx')
  assert.match(page, /\bSkeleton\b/)
  assert.match(page, /\bSkeletonList\b/)
  assert.match(page, /variant="metric"/)
  assert.doesNotMatch(page, /Loading assessments\.\.\./)
  assert.doesNotMatch(page, /Loading reports\.\.\./)
  assert.doesNotMatch(page, /\? '—'/)
})

test('Targets Assessments and Reports list workspaces use shared skeleton rows', () => {
  for (const path of [
    'src/pages/targets/TargetsPage.jsx',
    'src/pages/scans/ScansPage.jsx',
    'src/pages/reports/ReportsPage.jsx',
  ]) {
    const source = read(path)
    assert.match(source, /\bSkeletonList\b/, `${path} must use SkeletonList`)
    assert.doesNotMatch(
      source,
      /<p className="empty-state">[\s\S]{0,80}?Loading (?:targets|assessments|reports)/,
      `${path} must not retain text-only list loading`,
    )
  }
})

test('report download emits success feedback only after the real download action', () => {
  const source = read('src/pages/reports/ReportsPage.jsx')
  assert.match(source, /pushToast/)
  const clickIndex = source.indexOf('anchor.click()')
  const toastIndex = source.indexOf('pushToast(', clickIndex)
  assert.ok(clickIndex >= 0, 'existing browser download click must remain')
  assert.ok(toastIndex > clickIndex, 'download toast must occur after the actual click')
  assert.doesNotMatch(source, /setTimeout\([^)]*download/i)
})

test('skeleton styling defines metric row and reduced-motion treatments', () => {
  const css = read('src/styles/primitives.css')
  assert.match(css, /\.ui-skeleton-metric/)
  assert.match(css, /\.ui-skeleton-row/)
  assert.match(css, /\.ui-skeleton-list/)
  assert.match(css, /@media \(prefers-reduced-motion: reduce\)[\s\S]*\.ui-skeleton/s)
})
