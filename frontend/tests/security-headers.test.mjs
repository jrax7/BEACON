import assert from 'node:assert/strict'
import {
  readdirSync,
  readFileSync,
  statSync,
} from 'node:fs'
import {
  join,
} from 'node:path'
import test from 'node:test'
import {
  fileURLToPath,
} from 'node:url'


const frontendRoot =
  fileURLToPath(
    new URL(
      '../',
      import.meta.url,
    ),
  )


function source(relativePath) {
  return readFileSync(
    join(
      frontendRoot,
      relativePath,
    ),
    'utf8',
  )
}


function blockForLocation(
  nginx,
  locationPattern,
) {
  const match =
    nginx.match(
      new RegExp(
        `location\\s+${locationPattern}\\s*\\{([\\s\\S]*?)\\n\\s{4}\\}`,
      ),
    )

  assert.ok(
    match,
    `missing Nginx location ${locationPattern}`,
  )

  return match[1]
}


function sourceFiles(
  directory,
) {
  const result = []

  for (
    const entry
    of readdirSync(directory)
  ) {
    const path =
      join(
        directory,
        entry,
      )

    const stats =
      statSync(path)

    if (stats.isDirectory()) {
      result.push(
        ...sourceFiles(path),
      )

      continue
    }

    if (
      path.endsWith('.js') ||
      path.endsWith('.jsx')
    ) {
      result.push(path)
    }
  }

  return result
}


test(
  'Nginx emits the approved browser security headers',
  () => {
    const nginx =
      source(
        'nginx.conf',
      )

    assert.match(
      nginx,
      /add_header\s+Strict-Transport-Security\s+"max-age=31536000; includeSubDomains"\s+always;/,
    )

    assert.doesNotMatch(
      nginx,
      /Strict-Transport-Security[^\n]*preload/i,
    )

    assert.match(
      nginx,
      /add_header\s+X-Content-Type-Options\s+"?nosniff"?\s+always;/,
    )

    assert.match(
      nginx,
      /add_header\s+Referrer-Policy\s+"?strict-origin-when-cross-origin"?\s+always;/,
    )

    assert.match(
      nginx,
      /add_header\s+Permissions-Policy\s+"camera=\(\), microphone=\(\), geolocation=\(\), payment=\(\), usb=\(\)"\s+always;/,
    )
  },
)


test(
  'CSP matches the approved Turnstile and Google Fonts browser policy',
  () => {
    const nginx =
      source(
        'nginx.conf',
      )

    const match =
      nginx.match(
        /add_header\s+Content-Security-Policy\s+"([^"]+)"\s+always;/,
      )

    assert.ok(
      match,
      'Content-Security-Policy header is required',
    )

    const csp =
      match[1]

    const directives = [
      "default-src 'self';",
      "script-src 'self' 'nonce-$request_id' https://challenges.cloudflare.com;",
      "style-src 'self' https://fonts.googleapis.com;",
      "font-src 'self' https://fonts.gstatic.com;",
      "img-src 'self' data:;",
      "connect-src 'self' https://challenges.cloudflare.com;",
      'frame-src https://challenges.cloudflare.com;',
      "object-src 'none';",
      "base-uri 'self';",
      "form-action 'self';",
      "frame-ancestors 'none';",
    ]

    for (
      const directive
      of directives
    ) {
      assert.ok(
        csp.includes(
          directive,
        ),
        `missing CSP directive: ${directive}`,
      )
    }

    assert.doesNotMatch(
      csp,
      /'unsafe-inline'/,
    )

    assert.doesNotMatch(
      csp,
      /'unsafe-eval'/,
    )

    assert.doesNotMatch(
      csp,
      /(?:^|\s)\*(?:\s|;|$)/,
    )

    const externalOrigins =
      [
        ...csp.matchAll(
          /https:\/\/[A-Za-z0-9.-]+/g,
        ),
      ].map(
        (entry) =>
          entry[0],
      )

    assert.deepEqual(
      [
        ...new Set(
          externalOrigins,
        ),
      ].sort(),
      [
        'https://challenges.cloudflare.com',
        'https://fonts.googleapis.com',
        'https://fonts.gstatic.com',
      ].sort(),
    )
  },
)


test(
  'API proxy overwrites trusted forwarding headers and disables caching',
  () => {
    const nginx =
      source(
        'nginx.conf',
      )

    const api =
      blockForLocation(
        nginx,
        '\\/api\\/',
      )

    assert.match(
      api,
      /proxy_pass\s+http:\/\/\$backend_upstream;/,
    )

    assert.match(
      api,
      /proxy_set_header\s+Host\s+\$proxy_host;/,
    )

    assert.match(
      api,
      /proxy_set_header\s+X-Real-IP\s+\$remote_addr;/,
    )

    assert.match(
      api,
      /proxy_set_header\s+X-Forwarded-For\s+\$remote_addr;/,
    )

    assert.doesNotMatch(
      api,
      /\$proxy_add_x_forwarded_for/,
    )

    assert.match(
      api,
      /proxy_set_header\s+X-Forwarded-Proto\s+\$scheme;/,
    )

    assert.match(
      api,
      /proxy_hide_header\s+Cache-Control;/,
    )

    assert.match(
      api,
      /add_header\s+Cache-Control\s+"no-store"\s+always;/,
    )
  },
)


test(
  'health proxy and SPA fallback remain available',
  () => {
    const nginx =
      source(
        'nginx.conf',
      )

    const health =
      blockForLocation(
        nginx,
        '=\\s*\\/health',
      )

    assert.match(
      health,
      /proxy_pass\s+http:\/\/\$backend_upstream;/,
    )

    assert.match(
      health,
      /proxy_set_header\s+X-Forwarded-For\s+\$remote_addr;/,
    )

    assert.doesNotMatch(
      health,
      /\$proxy_add_x_forwarded_for/,
    )

    assert.match(
      nginx,
      /try_files\s+\$uri\s+\$uri\/\s+\/index\.html;/,
    )
  },
)


test(
  'React production source contains no inline style attributes',
  () => {
    const src =
      join(
        frontendRoot,
        'src',
      )

    const violations = []

    for (
      const filename
      of sourceFiles(src)
    ) {
      const contents =
        readFileSync(
          filename,
          'utf8',
        )

      if (
        /style\s*=\s*\{\{/.test(
          contents,
        )
      ) {
        violations.push(
          filename.replace(
            `${frontendRoot}/`,
            '',
          ),
        )
      }
    }

    assert.deepEqual(
      violations,
      [],
    )
  },
)
