import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import test from 'node:test'

const envExampleUrl = new URL(
  '../../.env.example',
  import.meta.url,
)

test(
  '.env.example documents the public Turnstile site key required by the frontend build',
  async () => {
    const source = await readFile(
      envExampleUrl,
      'utf8',
    )

    assert.match(
      source,
      /^VITE_TURNSTILE_SITE_KEY=/m,
    )
  },
)
