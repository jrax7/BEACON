import assert from 'node:assert/strict'
import { existsSync, readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import test from 'node:test'

const root = process.cwd()
const at = (path) => resolve(root, path)
const read = (path) => readFileSync(at(path), 'utf8')

const required = [
  'src/system/requestActivity.js',
  'src/system/toasts.js',
  'src/system/bootSession.js',
  'src/system/routeMetadata.js',
  'src/components/system/ApiProgressBeam.jsx',
  'src/components/system/RouteViewport.jsx',
  'src/components/system/ToastViewport.jsx',
  'src/components/system/BootSequence.jsx',
  'src/components/system/DocumentTitle.jsx',
]

test('cross-application system modules exist', () => {
  for (const path of required) {
    assert.ok(existsSync(at(path)), `${path} must exist`)
  }
})

test('API client observes request activity without changing session and CSRF invariants', () => {
  const client = read('src/api/client.js')
  assert.match(client, /beginRequestActivity/)
  assert.match(client, /endRequestActivity/)
  assert.match(client, /credentials:\s*['"]same-origin['"]/)
  assert.match(client, /refreshSessionMetadata/)
  assert.match(client, /Never replay the rejected unsafe request/)
  assert.doesNotMatch(client, /Authorization\s*:/)
})

test('request activity uses a subscription store and counts concurrent work', () => {
  const source = read('src/system/requestActivity.js')
  assert.match(source, /subscribeRequestActivity/)
  assert.match(source, /getRequestActivitySnapshot/)
  assert.match(source, /activeRequests/)
  assert.match(source, /Math\.max\(0/)
})

test('application shell mounts centralized progress, route, toast, title, and boot systems', () => {
  const layout = read('src/components/AppLayout.jsx')
  for (const name of ['ApiProgressBeam', 'RouteViewport', 'ToastViewport', 'BootSequence', 'DocumentTitle']) {
    assert.match(layout, new RegExp(name), `AppLayout must mount ${name}`)
  }
  assert.doesNotMatch(layout, /<Outlet\s*\/>/, 'AppLayout should delegate outlet rendering to RouteViewport')
})

test('route viewport and shell motion are centralized and reduced-motion safe', () => {
  const route = read('src/components/system/RouteViewport.jsx')
  const css = read('src/styles/components.css')
  assert.match(route, /useLocation/)
  assert.match(route, /<Outlet\s*\/>/)
  assert.match(css, /\.route-viewport/)
  assert.match(css, /\.api-progress-beam/)
  assert.match(css, /\.toast-viewport/)
  assert.match(css, /@media \(prefers-reduced-motion: reduce\)/)
})

test('route metadata provides safe BEACON document titles for primary routes', () => {
  const source = read('src/system/routeMetadata.js')
  for (const label of ['Dashboard', 'Targets', 'Assessments', 'Findings', 'Reports', 'Settings']) {
    assert.ok(source.includes(label), `route metadata must include ${label}`)
  }
  assert.match(source, /BEACON/)
})

test('toast infrastructure exposes a single centralized notification surface', () => {
  const store = read('src/system/toasts.js')
  const viewport = read('src/components/system/ToastViewport.jsx')
  assert.match(store, /pushToast/)
  assert.match(store, /dismissToast/)
  assert.match(store, /subscribeToasts/)
  assert.match(viewport, /aria-live=/)
})
