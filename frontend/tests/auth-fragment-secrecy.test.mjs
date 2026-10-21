import assert from 'node:assert/strict'
import {
  existsSync,
  readFileSync,
} from 'node:fs'
import test from 'node:test'
import {
  fileURLToPath,
} from 'node:url'

const frontendRoot =
  fileURLToPath(
    new URL('../', import.meta.url),
  )

function source(relativePath) {
  const path =
    fileURLToPath(
      new URL(
        relativePath,
        `file://${frontendRoot}`,
      ),
    )

  if (!existsSync(path)) {
    return ''
  }

  return readFileSync(
    path,
    'utf8',
  )
}

function assertFragmentSecretContract(
  page,
  submissionFunction,
) {
  assert.match(
    page,
    /window\.location\.hash/,
  )

  assert.match(
    page,
    /history\.replaceState/,
  )

  assert.match(
    page,
    /useRef/,
  )

  assert.match(
    page,
    /fragmentTokenRef\.current/,
  )

  assert.match(
    page,
    new RegExp(
      `${submissionFunction}\\(`,
    ),
  )

  assert.doesNotMatch(
    page,
    /localStorage|sessionStorage/,
  )

  assert.doesNotMatch(
    page,
    /console\.(?:log|debug|info|warn|error)/,
  )

  assert.doesNotMatch(
    page,
    /URLSearchParams\(\s*window\.location\.search/,
  )
}


test(
  'verification consumes its secret from the fragment and removes the fragment immediately',
  () => {
    const page =
      source(
        'src/pages/VerifyEmailPage.jsx',
      )

    assertFragmentSecretContract(
      page,
      'verifyEmail',
    )

    const consumeIndex =
      page.indexOf(
        "fragmentTokenRef.current = ''",
      )

    const submitIndex =
      page.indexOf(
        'verifyEmail(',
      )

    assert.ok(
      consumeIndex >= 0 &&
        submitIndex >= 0 &&
        consumeIndex < submitIndex,
      'verification token must be cleared from component memory before submission',
    )
  },
)


test(
  'password reset consumes its secret from the fragment once without storage or logging',
  () => {
    const page =
      source(
        'src/pages/ResetPasswordPage.jsx',
      )

    assertFragmentSecretContract(
      page,
      'resetPassword',
    )

    const consumeIndex =
      page.indexOf(
        "fragmentTokenRef.current = ''",
      )

    const submitIndex =
      page.indexOf(
        'resetPassword(',
      )

    assert.ok(
      consumeIndex >= 0 &&
        submitIndex >= 0 &&
        consumeIndex < submitIndex,
      'reset token must be cleared from component memory before submission',
    )
  },
)
