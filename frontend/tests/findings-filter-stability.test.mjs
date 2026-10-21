import assert from 'node:assert/strict'
import fs from 'node:fs'
import test from 'node:test'

const page = fs.readFileSync(
  new URL(
    '../src/pages/findings/FindingsPage.jsx',
    import.meta.url,
  ),
  'utf8',
)

test(
  'findings filters are stable for unchanged URL state',
  () => {
    assert.match(
      page,
      /\buseMemo\b/,
      'FindingsPage should memoize parsed URL filters',
    )

    assert.match(
      page,
      /const\s+filters\s*=\s*useMemo\([\s\S]*?parseFindingFilters\([\s\S]*?queryString[\s\S]*?\)[\s\S]*?\[\s*queryString\s*,?\s*\]/,
      'filters should be derived from queryString with useMemo',
    )

    assert.match(
      page,
      /useEffect\([\s\S]*?\},\s*\[\s*filters,\s*retryCount,\s*\]\s*\)/,
      'the request effect should depend on the stable filters object',
    )

    assert.doesNotMatch(
      page,
      /\[\s*queryString,\s*retryCount,\s*\]/,
      'the request effect should not bypass its filters dependency',
    )
  },
)
