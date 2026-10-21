import assert from 'node:assert/strict'
import { existsSync, readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import test from 'node:test'

const root = process.cwd()

function pathFor(relativePath) {
  return resolve(root, relativePath)
}

function read(relativePath) {
  return readFileSync(pathFor(relativePath), 'utf8')
}

function assertContainsAll(source, values, label) {
  for (const value of values) {
    assert.ok(
      source.includes(value),
      `${label} must contain ${JSON.stringify(value)}`,
    )
  }
}

test('final visual system uses Geist for human-readable UI and retains JetBrains Mono for technical values', () => {
  const html = read('index.html')
  const indexCss = read('src/index.css')

  assert.match(
    html,
    /family=Geist(?::|&|%3A)/,
    'index.html must load Geist',
  )
  assert.doesNotMatch(
    html,
    /family=Sora(?::|&|%3A)/,
    'Sora must no longer be the primary BEACON UI font',
  )

  assert.match(
    html,
    /family=JetBrains\+Mono(?::|&|%3A)/,
    'JetBrains Mono must remain available for technical values',
  )

  assert.match(
    indexCss,
    /font-family:\s*var\(--font-sans\)/,
    'global UI typography must consume the centralized sans token',
  )
})

test('tokens.css defines the centralized semantic visual-system foundation', () => {
  const tokens = read('src/styles/tokens.css')

  assertContainsAll(
    tokens,
    [
      '--font-sans:',
      '--font-mono:',
      '--font-weight-regular:',
      '--font-weight-medium:',
      '--font-weight-semibold:',
      '--font-weight-bold:',
      '--text-size-page-title:',
      '--text-size-section-title:',
      '--text-size-card-title:',
      '--text-size-body:',
      '--text-size-body-small:',
      '--text-size-control:',
      '--text-size-label:',
      '--text-size-caption:',
      '--line-height-heading:',
      '--line-height-body:',
      '--surface-app:',
      '--surface-workspace:',
      '--surface-card:',
      '--surface-card-hover:',
      '--border-subtle:',
      '--border-standard:',
      '--border-emphasis:',
      '--text-primary:',
      '--text-secondary:',
      '--text-tertiary:',
      '--brand-primary:',
      '--brand-hover:',
      '--brand-active:',
      '--brand-soft:',
      '--severity-critical:',
      '--severity-high:',
      '--severity-medium:',
      '--severity-low:',
      '--severity-info:',
      '--control-height-md: 44px',
      '--z-sticky:',
      '--z-nav:',
      '--z-dropdown:',
      '--z-progress:',
      '--z-tooltip:',
      '--z-modal-backdrop:',
      '--z-modal:',
      '--z-toast:',
    ],
    'tokens.css',
  )
})

test('motion.css defines one centralized BEACON motion vocabulary with reduced-motion support', () => {
  const relativePath = 'src/styles/motion.css'

  assert.ok(
    existsSync(pathFor(relativePath)),
    'src/styles/motion.css must exist',
  )

  const motion = read(relativePath)

  assertContainsAll(
    motion,
    [
      '--motion-instant:',
      '--motion-fast:',
      '--motion-standard:',
      '--motion-page:',
      '--motion-deliberate:',
      '--ease-standard:',
      '--ease-enter:',
      '--ease-exit:',
      '--ease-emphasized:',
      '@media (prefers-reduced-motion: reduce)',
    ],
    'motion.css',
  )
})

test('App.css loads centralized motion before reusable/page styling', () => {
  const appCss = read('src/App.css')

  const baseIndex = appCss.indexOf("@import './styles/base.css';")
  const motionIndex = appCss.indexOf("@import './styles/motion.css';")
  const primitiveIndex = appCss.indexOf("@import './styles/primitives.css';")

  assert.ok(baseIndex >= 0, 'App.css must continue importing base.css')
  assert.ok(motionIndex >= 0, 'App.css must import motion.css')
  assert.ok(primitiveIndex >= 0, 'App.css must continue importing primitives.css')

  assert.ok(
    baseIndex < motionIndex && motionIndex < primitiveIndex,
    'motion.css must load after base.css and before primitives.css',
  )
})

test('shared form and loading primitives exist and are exported from components/ui', () => {
  const expectedFiles = [
    'Button.jsx',
    'Input.jsx',
    'Select.jsx',
    'Textarea.jsx',
    'Checkbox.jsx',
    'FormField.jsx',
    'Skeleton.jsx',
    'Spinner.jsx',
  ]

  for (const file of expectedFiles) {
    assert.ok(
      existsSync(pathFor(`src/components/ui/${file}`)),
      `src/components/ui/${file} must exist`,
    )
  }

  const index = read('src/components/ui/index.js')

  assertContainsAll(
    index,
    [
      "export { default as Button } from './Button'",
      "export { default as Input } from './Input'",
      "export { default as Select } from './Select'",
      "export { default as Textarea } from './Textarea'",
      "export { default as Checkbox } from './Checkbox'",
      "export { default as FormField } from './FormField'",
      "export { default as Skeleton } from './Skeleton'",
      "export { default as Spinner } from './Spinner'",
    ],
    'components/ui/index.js',
  )
})

test('foundation keeps semantic native controls instead of replacing them with custom div widgets', () => {
  const controlContracts = [
    ['src/components/ui/Button.jsx', /<button\b/],
    ['src/components/ui/Input.jsx', /<input\b/],
    ['src/components/ui/Select.jsx', /<select\b/],
    ['src/components/ui/Textarea.jsx', /<textarea\b/],
  ]

  for (const [relativePath, semanticElement] of controlContracts) {
    assert.ok(
      existsSync(pathFor(relativePath)),
      `${relativePath} must exist before its semantic contract can pass`,
    )

    assert.match(
      read(relativePath),
      semanticElement,
      `${relativePath} must retain its native semantic HTML control`,
    )
  }
})

test('the visual polish phase does not add a heavy animation framework', () => {
  const packageJson = JSON.parse(read('package.json'))

  const dependencies = {
    ...(packageJson.dependencies ?? {}),
    ...(packageJson.devDependencies ?? {}),
  }

  for (const packageName of [
    'framer-motion',
    '@react-spring/web',
    'react-spring',
    'gsap',
  ]) {
    assert.equal(
      dependencies[packageName],
      undefined,
      `${packageName} must not be introduced for the foundation`,
    )
  }
})
