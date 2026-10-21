import assert from 'node:assert/strict'
import fs from 'node:fs'
import test from 'node:test'

function source(path) {
  return fs.readFileSync(
    new URL(`../${path}`, import.meta.url),
    'utf8',
  )
}

test(
  'interactive login does not toggle route-level session loading',
  () => {
    const authContext =
      source('src/auth/AuthContext.jsx')

    const loginStart =
      authContext.indexOf(
        '  const login =',
      )

    const logoutStart =
      authContext.indexOf(
        '  const logout =',
        loginStart,
      )

    assert.notEqual(
      loginStart,
      -1,
      'AuthContext login callback must exist',
    )

    assert.notEqual(
      logoutStart,
      -1,
      'AuthContext logout callback must exist',
    )

    const loginBlock =
      authContext.slice(
        loginStart,
        logoutStart,
      )

    assert.doesNotMatch(
      loginBlock,
      /setLoading\s*\(/,
      'interactive login must not replace PublicOnlyRoute with the global loader',
    )
  },
)

test(
  'login page owns submission and failed-login feedback locally',
  () => {
    const loginPage =
      source('src/pages/LoginPage.jsx')

    assert.match(
      loginPage,
      /const \[submitting,\s*setSubmitting\]\s*=\s*useState\(false\)/s,
    )

    assert.match(
      loginPage,
      /catch \(requestError\)[\s\S]*setError\(/,
    )

    assert.match(
      loginPage,
      /<ErrorAlert[\s\S]*message=\{error\}/,
    )
  },
)
