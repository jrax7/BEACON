import assert from 'node:assert/strict'
import fs from 'node:fs'
import test from 'node:test'

function read(path) {
  return fs.readFileSync(
    new URL(`../${path}`, import.meta.url),
    'utf8',
  )
}

test('application shell exposes a browser connection-lost banner', () => {
  const layout = read('src/components/AppLayout.jsx')
  const status = read('src/components/system/ConnectionStatus.jsx')

  assert.match(layout, /ConnectionStatus/)
  assert.match(status, /navigator\.onLine/)
  assert.match(status, /addEventListener\(['"]offline['"]/)
  assert.match(status, /addEventListener\(['"]online['"]/)
  assert.match(status, /connection-status-banner/)
  assert.match(status, /role="status"/)
})

test('expired browser sessions are distinguished from ordinary signed-out state', () => {
  const context = read('src/auth/AuthContext.jsx')
  const route = read('src/auth/ProtectedRoute.jsx')
  const login = read('src/pages/LoginPage.jsx')
  const expired = read('src/components/system/SessionExpiredState.jsx')

  assert.match(context, /sessionExpired/)
  assert.match(context, /setSessionExpired\(true\)/)
  assert.match(context, /setAuthExpiredHandler/)
  assert.match(route, /sessionExpired/)
  assert.match(route, /state=\{\{[\s\S]*sessionExpired/)
  assert.match(login, /SessionExpiredState/)
  assert.match(login, /location\.state\?\.sessionExpired/)
  assert.match(expired, /session-expired-state/)
  assert.match(expired, /role="alert"/)
})
test('major protected detail and settings loaders use layout-stable skeletons', () => {
  const expectations = [
    'src/auth/ProtectedRoute.jsx',
    'src/pages/targets/TargetDetailPage.jsx',
    'src/pages/findings/FindingDetailPage.jsx',
    'src/pages/settings/SettingsPage.jsx',
  ]

  for (const path of expectations) {
    const source = read(path)
    assert.match(source, /SkeletonList/, `${path} must use SkeletonList`)
  }

  assert.doesNotMatch(
    read('src/pages/targets/TargetDetailPage.jsx'),
    /Loading target\.\.\./,
  )
  assert.doesNotMatch(
    read('src/pages/findings/FindingDetailPage.jsx'),
    /Loading finding\.\.\./,
  )
  assert.doesNotMatch(
    read('src/pages/settings/SettingsPage.jsx'),
    /Loading workspace\.\.\.|Loading members\.\.\./,
  )
})

test('final convergence preserves wildcard routing semantics', () => {
  const app = read('src/App.jsx')

  assert.match(app, /path="\*"[\s\S]*?<Navigate[\s\S]*?to="\/dashboard"[\s\S]*?replace/)
})
test('system-state styling is centralized, responsive, and reduced-motion safe', () => {
  const layout = read('src/styles/layout.css')
  const auth = read('src/styles/pages/auth.css')

  assert.match(layout, /\.connection-status-banner/)
  assert.match(auth, /\.session-expired-state/)
  assert.match(layout, /var\(--z-progress\)/)
  assert.match(layout, /prefers-reduced-motion:\s*reduce/)
})

test('session expiry remains set until authentication or explicit logout clears it', () => {
  const context = read('src/auth/AuthContext.jsx')
  const expiredHandler = context.match(
    /setAuthExpiredHandler\([\s\S]*?setSessionMetadataRefresher/,
  )?.[0] || ''

  assert.match(expiredHandler, /setSessionExpired\(true\)/)
  assert.doesNotMatch(
    expiredHandler,
    /setSessionExpired\(false\)/,
  )

  assert.match(
    context,
    /logoutUser\(\)[\s\S]*?setSessionExpired\(false\)/,
  )
})
