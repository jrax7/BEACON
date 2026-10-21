import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { test } from 'node:test'

const source = readFileSync(
  new URL(
    '../src/components/AppLayout.jsx',
    import.meta.url,
  ),
  'utf8',
)

test(
  'navigation resets window scroll when route changes',
  () => {
    assert.match(
      source,
      /useEffect/,
      'AppLayout must react to route changes.',
    )

    assert.match(
      source,
      /window\.scrollTo\(\s*\{\s*top:\s*0,\s*left:\s*0/,
      'Route changes must reset the viewport to the top.',
    )

    assert.match(
      source,
      /\[location\.pathname\]/,
      'Scroll reset must be tied to pathname changes.',
    )
  },
)
