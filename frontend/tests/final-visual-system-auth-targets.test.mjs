import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import test from 'node:test'
const root = process.cwd()
const read = (path) => readFileSync(resolve(root, path), 'utf8')

const authPages = [
  'src/pages/LoginPage.jsx',
  'src/pages/RegisterPage.jsx',
  'src/pages/VerifyEmailPage.jsx',
  'src/pages/ForgotPasswordPage.jsx',
  'src/pages/ResetPasswordPage.jsx',
]

test('all authentication text/password/email controls consume the shared Input and FormField system', () => {
  for (const path of authPages) {
    const source = read(path)
    assert.doesNotMatch(source, /<input\b/, `${path} must not own raw inputs`)
    if (source.includes('type="email"') || source.includes('type="password"') || source.includes('type="text"')) {
      assert.match(source, /\bInput\b/, `${path} must use Input`)
      assert.match(source, /\bFormField\b/, `${path} must use FormField`)
    }
  }
})

test('target registration consumes shared Input Select and FormField without changing verification options', () => {
  const source = read('src/pages/targets/TargetRegistrationForm.jsx')
  assert.match(source, /\bInput\b/)
  assert.match(source, /\bSelect\b/)
  assert.match(source, /\bFormField\b/)
  assert.doesNotMatch(source, /<(input|select)\b/)
  assert.match(source, /value="file"/)
  assert.match(source, /value="dns"/)
  assert.match(source, /Verification file/)
  assert.match(source, /DNS TXT record/)
})

test('auth surfaces use centralized motion tokens and keep reduced-motion behavior', () => {
  const css = read('src/styles/pages/auth.css')
  assert.match(css, /var\(--motion-(?:fast|standard|page|deliberate)\)/)
  assert.match(css, /var\(--ease-(?:standard|enter|exit|emphasized)\)/)
  assert.match(css, /@media \(prefers-reduced-motion: reduce\)/)
})

test('target controls inherit the shared dark design system rather than browser-native select appearance', () => {
  const css = read('src/styles/pages/targets.css')
  const primitives = read('src/styles/primitives.css')
  assert.match(primitives, /\.ui-select\s*\{[^}]*color-scheme:\s*dark/s)
  assert.match(css, /\.target-form/)
})
