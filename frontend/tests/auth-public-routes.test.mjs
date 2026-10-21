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

function pathFor(relativePath) {
  return new URL(
    relativePath,
    `file://${frontendRoot}`,
  )
}

function source(relativePath) {
  const path =
    fileURLToPath(
      pathFor(relativePath),
    )

  if (!existsSync(path)) {
    return ''
  }

  return readFileSync(
    path,
    'utf8',
  )
}

function composeSource() {
  const path =
    process.env.BEACON_COMPOSE_PATH

  if (!path) {
    return ''
  }

  return readFileSync(
    path,
    'utf8',
  )
}

function composeServiceBlock(
  compose,
  serviceName,
) {
  const lines =
    compose.split(/\r?\n/)

  const start =
    lines.findIndex(
      (line) =>
        line === `  ${serviceName}:`,
    )

  if (start < 0) {
    return ''
  }

  let end = lines.length

  for (
    let index = start + 1;
    index < lines.length;
    index += 1
  ) {
    if (
      /^  [A-Za-z0-9_-]+:\s*$/.test(
        lines[index],
      )
    ) {
      end = index
      break
    }
  }

  return lines
    .slice(start, end)
    .join('\n')
}


test(
  'public account lifecycle routes expose verification forgot and reset pages',
  () => {
    const app =
      source('src/App.jsx')

    assert.match(
      app,
      /path=["']\/verify-email["']/,
    )

    assert.match(
      app,
      /path=["']\/forgot-password["']/,
    )

    assert.match(
      app,
      /path=["']\/reset-password["']/,
    )

    assert.match(
      app,
      /VerifyEmailPage/,
    )

    assert.match(
      app,
      /ForgotPasswordPage/,
    )

    assert.match(
      app,
      /ResetPasswordPage/,
    )
  },
)


test(
  'registration forgot and verification resend use Turnstile while normal login does not',
  () => {
    const register =
      source(
        'src/pages/RegisterPage.jsx',
      )

    const forgot =
      source(
        'src/pages/ForgotPasswordPage.jsx',
      )

    const verify =
      source(
        'src/pages/VerifyEmailPage.jsx',
      )

    const login =
      source(
        'src/pages/LoginPage.jsx',
      )

    assert.match(
      register,
      /TurnstileWidget/,
    )

    assert.match(
      forgot,
      /TurnstileWidget/,
    )

    assert.match(
      verify,
      /TurnstileWidget/,
    )

    assert.doesNotMatch(
      login,
      /TurnstileWidget/,
    )
  },
)


test(
  'frontend auth API exposes public lifecycle and password change requests',
  () => {
    const auth =
      source(
        'src/api/auth.js',
      )

    for (
      const endpoint of [
        '/auth/email/verify',
        '/auth/email/verification/resend',
        '/auth/password/forgot',
        '/auth/password/reset',
        '/auth/password/change',
      ]
    ) {
      assert.match(
        auth,
        new RegExp(
          endpoint.replace(
            /\//g,
            '\\/',
          ),
        ),
      )
    }

    assert.match(
      auth,
      /turnstile_token/,
    )

    assert.match(
      auth,
      /current_password/,
    )

    assert.match(
      auth,
      /new_password/,
    )
  },
)


test(
  'Turnstile uses only the public Vite site key and official Cloudflare script',
  () => {
    const component =
      source(
        'src/components/auth/TurnstileWidget.jsx',
      )

    const html =
      source('index.html')

    const dockerfile =
      source('Dockerfile')

    assert.match(
      component,
      /VITE_TURNSTILE_SITE_KEY/,
    )

    assert.match(
      html,
      /https:\/\/challenges\.cloudflare\.com\/turnstile\/v0\/api\.js/,
    )

    assert.match(
      dockerfile,
      /ARG\s+VITE_TURNSTILE_SITE_KEY/,
    )

    assert.match(
      dockerfile,
      /ENV\s+VITE_TURNSTILE_SITE_KEY=/,
    )

    assert.doesNotMatch(
      `${component}\n${html}\n${dockerfile}`,
      /TURNSTILE_SECRET_KEY|SMTP_|JWT_SECRET|CSRF_SECRET/,
    )
  },
)


test(
  'frontend compose build passes only the public Turnstile site key',
  {
    skip:
      !process.env.BEACON_COMPOSE_PATH,
  },
  () => {
    const compose =
      composeSource()

    const frontend =
      composeServiceBlock(
        compose,
        'frontend',
      )

    assert.match(
      frontend,
      /VITE_TURNSTILE_SITE_KEY/,
    )

    assert.doesNotMatch(
      frontend,
      /TURNSTILE_SECRET_KEY|SMTP_|JWT_SECRET|CSRF_SECRET/,
    )
  },
)


test(
  'login accepts only local next paths and exposes recovery routes without Turnstile',
  () => {
    const login =
      source(
        'src/pages/LoginPage.jsx',
      )

    assert.match(
      login,
      /URLSearchParams/,
    )

    assert.match(
      login,
      /get\(['"]next['"]\)/,
    )

    assert.match(
      login,
      /startsWith\(['"]\/['"]\)/,
    )

    assert.match(
      login,
      /startsWith\(['"]\/\/['"]\)/,
    )

    assert.match(
      login,
      /EMAIL_VERIFICATION_REQUIRED/,
    )

    assert.match(
      login,
      /\/forgot-password/,
    )

    assert.match(
      login,
      /\/verify-email/,
    )

    assert.doesNotMatch(
      login,
      /TurnstileWidget/,
    )
  },
)


test(
  'registration exposes sent disabled and verification states',
  () => {
    const register =
      source(
        'src/pages/RegisterPage.jsx',
      )

    assert.match(
      register,
      /verification email/i,
    )

    assert.match(
      register,
      /REGISTRATION_DISABLED/,
    )

    assert.match(
      register,
      /TurnstileWidget/,
    )
  },
)


test(
  'new accounts receive first-time sign-in copy while normal login remains returning-user copy',
  () => {
    const register =
      source(
        'src/pages/RegisterPage.jsx',
      )

    const verify =
      source(
        'src/pages/VerifyEmailPage.jsx',
      )

    const login =
      source(
        'src/pages/LoginPage.jsx',
      )

    assert.match(
      register,
      /\/login\?welcome=new/,
    )

    assert.match(
      verify,
      /\/login\?welcome=new/,
    )

    assert.match(
      login,
      /get\(['"]welcome['"]\)\s*===\s*['"]new['"]/,
    )

    assert.match(
      login,
      /Welcome to BEACON/,
    )

    assert.match(
      login,
      /Welcome back/,
    )
  },
)


test(
  'Settings exposes current new and confirmation password change flow',
  () => {
    const settings =
      source(
        'src/pages/settings/SettingsPage.jsx',
      )

    assert.match(
      settings,
      /submitPasswordChange|changePassword/,
    )

    assert.match(
      settings,
      /currentPassword/,
    )

    assert.match(
      settings,
      /newPassword/,
    )

    assert.match(
      settings,
      /confirmPassword/,
    )

    assert.match(
      settings,
      /logout/,
    )

    assert.match(
      settings,
      /\/login/,
    )
  },
)
