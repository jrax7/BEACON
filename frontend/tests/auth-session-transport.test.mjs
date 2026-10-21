import assert from 'node:assert/strict'
import {
  readFile,
  readdir,
} from 'node:fs/promises'
import path from 'node:path'
import test from 'node:test'
import {
  pathToFileURL,
} from 'node:url'


const root = new URL(
  '../',
  import.meta.url,
)

const sourceRoot = new URL(
  '../src/',
  import.meta.url,
)


async function source(
  relativePath,
) {
  return readFile(
    new URL(
      `../${relativePath}`,
      import.meta.url,
    ),
    'utf8',
  )
}


async function walk(
  directory,
) {
  const entries = await readdir(
    directory,
    {
      withFileTypes: true,
    },
  )

  const files = []

  for (const entry of entries) {
    const absolute = path.join(
      directory,
      entry.name,
    )

    if (entry.isDirectory()) {
      files.push(
        ...await walk(
          absolute,
        ),
      )
      continue
    }

    if (
      absolute.endsWith('.js') ||
      absolute.endsWith('.jsx')
    ) {
      files.push(
        absolute,
      )
    }
  }

  return files
}


test(
  'browser API client uses same-origin sessions and in-memory CSRF',
  async () => {
    const client = await source(
      'src/api/client.js',
    )

    assert.match(
      client,
      /credentials:\s*['"]same-origin['"]/,
    )

    assert.match(
      client,
      /X-CSRF-Token/,
    )

    assert.doesNotMatch(
      client,
      /Authorization/,
    )

    assert.doesNotMatch(
      client,
      /Bearer/,
    )

    assert.doesNotMatch(
      client,
      /\btoken\s*=\s*null\b/,
    )
  },
)


test(
  'session state keeps CSRF only in module memory',
  async () => {
    const state = await source(
      'src/auth/session-state.js',
    )

    assert.match(
      state,
      /let csrfToken = null/,
    )

    assert.match(
      state,
      /setCsrfToken/,
    )

    assert.match(
      state,
      /clearSessionState/,
    )

    assert.match(
      state,
      /setAuthExpiredHandler/,
    )

    assert.match(
      state,
      /setSessionMetadataRefresher/,
    )

    assert.doesNotMatch(
      state,
      /sessionStorage/,
    )

    assert.doesNotMatch(
      state,
      /localStorage/,
    )

    assert.doesNotMatch(
      state,
      /document\.cookie/,
    )
  },
)


test(
  'auth API uses JSON browser login and exposes session lifecycle calls',
  async () => {
    const auth = await source(
      'src/api/auth.js',
    )

    assert.match(
      auth,
      /body:\s*\{\s*email,\s*password,\s*\}/s,
    )

    assert.doesNotMatch(
      auth,
      /URLSearchParams/,
    )

    assert.match(
      auth,
      /export function getCurrentUser\(\)/,
    )

    assert.match(
      auth,
      /export function logoutUser\(\)/,
    )

    assert.match(
      auth,
      /['"]\/auth\/logout['"]/,
    )
  },
)


test(
  'AuthContext is server authoritative and never persists browser bearer auth',
  async () => {
    const context = await source(
      'src/auth/AuthContext.jsx',
    )

    assert.match(
      context,
      /await getCurrentUser\(\)/,
    )

    assert.match(
      context,
      /await loginUser\(/,
    )

    assert.match(
      context,
      /await logoutUser\(\)/,
    )

    assert.match(
      context,
      /setAuthExpiredHandler/,
    )

    assert.match(
      context,
      /setSessionMetadataRefresher/,
    )

    assert.doesNotMatch(
      context,
      /sessionStorage/,
    )

    assert.doesNotMatch(
      context,
      /localStorage/,
    )

    assert.doesNotMatch(
      context,
      /access_token/,
    )

    assert.doesNotMatch(
      context,
      /TOKEN_STORAGE_KEY/,
    )

    assert.doesNotMatch(
      context,
      /const \[token,/,
    )
  },
)


test(
  'React runtime contains no browser Bearer transport or persisted auth storage',
  async () => {
    const rootPath = path.resolve(
      new URL(
        '.',
        sourceRoot,
      ).pathname,
    )

    const files = await walk(
      rootPath,
    )

    const violations = []

    for (const filename of files) {
      const contents = await readFile(
        filename,
        'utf8',
      )

      if (
        contents.includes(
          'sessionStorage',
        )
      ) {
        violations.push(
          `${filename}: sessionStorage`,
        )
      }

      if (
        contents.includes(
          'localStorage',
        )
      ) {
        violations.push(
          `${filename}: localStorage`,
        )
      }

      if (
        contents.includes(
          'Bearer ',
        )
      ) {
        violations.push(
          `${filename}: Bearer`,
        )
      }

      if (
        /headers?\.Authorization|requestHeaders\.Authorization/.test(
          contents,
        )
      ) {
        violations.push(
          `${filename}: Authorization header`,
        )
      }

      if (
        contents.includes(
          'access_token',
        )
      ) {
        violations.push(
          `${filename}: access_token`,
        )
      }
    }

    assert.deepEqual(
      violations,
      [],
    )
  },
)


test(
  'API modules no longer accept browser token parameters',
  async () => {
    const apiDirectory = path.resolve(
      new URL(
        '../src/api/',
        import.meta.url,
      ).pathname,
    )

    const files = await readdir(
      apiDirectory,
    )

    const violations = []

    for (const entry of files) {
      if (!entry.endsWith('.js')) {
        continue
      }

      const filename = path.join(
        apiDirectory,
        entry,
      )

      const contents = await readFile(
        filename,
        'utf8',
      )

      const signaturePattern =
        /export\s+(?:async\s+)?function\s+\w+\s*\(\s*token\b/

      if (
        signaturePattern.test(
          contents,
        )
      ) {
        violations.push(
          entry,
        )
      }
    }

    assert.deepEqual(
      violations,
      [],
    )
  },
)


test(
  'API client request behavior distinguishes GET unsafe CSRF 401 403 and CSRF refresh',
  async () => {
    const stateUrl = pathToFileURL(
      path.resolve(
        new URL(
          '../src/auth/session-state.js',
          import.meta.url,
        ).pathname,
      ),
    )

    const clientUrl = pathToFileURL(
      path.resolve(
        new URL(
          '../src/api/client.js',
          import.meta.url,
        ).pathname,
      ),
    )

    // Keep session-state on its canonical file URL so the test
    // and client.js share the same in-memory module instance.

    const state = await import(
      stateUrl.href
    )

    const client = await import(
      clientUrl.href
    )

    state.clearSessionState()

    const originalFetch =
      globalThis.fetch

    try {
      const requests = []

      state.setCsrfToken(
        'csrf-memory-value',
      )

      globalThis.fetch = async (
        url,
        options,
      ) => {
        requests.push({
          url,
          options,
        })

        return new Response(
          JSON.stringify({
            ok: true,
          }),
          {
            status: 200,
            headers: {
              'Content-Type':
                'application/json',
            },
          },
        )
      }

      await client.apiRequest(
        '/targets',
      )

      assert.equal(
        requests[0]
          .options
          .credentials,
        'same-origin',
      )

      assert.equal(
        requests[0]
          .options
          .headers[
            'X-CSRF-Token'
          ],
        undefined,
      )

      await client.apiRequest(
        '/targets',
        {
          method: 'POST',
          body: {
            url:
              'https://example.com',
          },
        },
      )

      assert.equal(
        requests[1]
          .options
          .credentials,
        'same-origin',
      )

      assert.equal(
        requests[1]
          .options
          .headers[
            'X-CSRF-Token'
          ],
        'csrf-memory-value',
      )

      assert.equal(
        requests[1]
          .options
          .headers
          .Authorization,
        undefined,
      )


      let expiredCalls = 0

      state.setAuthExpiredHandler(
        () => {
          expiredCalls += 1
        },
      )

      globalThis.fetch = async () =>
        new Response(
          JSON.stringify({
            detail: {
              code:
                'AUTH_REQUIRED',
              message:
                'Authentication is required.',
            },
          }),
          {
            status: 401,
            headers: {
              'Content-Type':
                'application/json',
            },
          },
        )

      await assert.rejects(
        client.apiRequest(
          '/targets',
        ),
      )

      assert.equal(
        expiredCalls,
        1,
      )


      let refreshCalls = 0

      state.setSessionMetadataRefresher(
        async () => {
          refreshCalls += 1
        },
      )

      let csrfFetchCalls = 0

      globalThis.fetch = async () => {
        csrfFetchCalls += 1

        return new Response(
          JSON.stringify({
            detail: {
              code:
                'CSRF_INVALID',
              message:
                'The CSRF token is invalid.',
            },
          }),
          {
            status: 403,
            headers: {
              'Content-Type':
                'application/json',
            },
          },
        )
      }

      await assert.rejects(
        client.apiRequest(
          '/targets',
          {
            method: 'POST',
            body: {
              url:
                'https://example.com',
            },
          },
        ),
      )

      assert.equal(
        refreshCalls,
        1,
      )

      // The failed unsafe request is never replayed.
      assert.equal(
        csrfFetchCalls,
        1,
      )

      // CSRF failure itself is not authentication expiry.
      assert.equal(
        expiredCalls,
        1,
      )


      globalThis.fetch = async () =>
        new Response(
          JSON.stringify({
            detail: {
              code:
                'ACCOUNT_INACTIVE',
              message:
                'Forbidden.',
            },
          }),
          {
            status: 403,
            headers: {
              'Content-Type':
                'application/json',
            },
          },
        )

      await assert.rejects(
        client.apiRequest(
          '/targets',
        ),
      )

      assert.equal(
        expiredCalls,
        1,
      )

      assert.equal(
        refreshCalls,
        1,
      )

    } finally {
      globalThis.fetch =
        originalFetch

      state.clearSessionState()
    }
  },
)


test(
  'runtime auth consumers contain no legacy token props or useAuth token destructuring',
  async () => {
    const rootPath = path.resolve(
      new URL(
        '.',
        sourceRoot,
      ).pathname,
    )

    const files = await walk(
      rootPath,
    )

    const violations = []

    for (const filename of files) {
      const contents = await readFile(
        filename,
        'utf8',
      )

      if (
        /\btoken=\{token\}/.test(
          contents,
        )
      ) {
        violations.push(
          `${filename}: token prop`,
        )
      }

      if (
        /const\s*\{[^}]*\btoken\b[^}]*\}\s*=\s*useAuth\(/s.test(
          contents,
        )
      ) {
        violations.push(
          `${filename}: useAuth token`,
        )
      }
    }

    assert.deepEqual(
      violations,
      [],
    )
  },
)
