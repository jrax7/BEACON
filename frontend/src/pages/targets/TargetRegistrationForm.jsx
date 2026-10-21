import { useState } from 'react'

import { createTarget } from '../../api/targets'
import { Card, ErrorAlert, FormField, Input, Select } from '../../components/ui'

export default function TargetRegistrationForm({ onCreated }) {
  const [url, setUrl] = useState('')
  const [verificationMethod, setVerificationMethod] = useState('file')
  const [creating, setCreating] = useState(false)
  const [createError, setCreateError] = useState('')

  async function handleSubmit(event) {
    event.preventDefault()

    setCreateError('')
    setCreating(true)

    try {
      const created = await createTarget( { url: url.trim(), verificationMethod })
      onCreated(created)
      setUrl('')
    } catch (requestError) {
      setCreateError(requestError.message || 'Unable to create target.')
    } finally {
      setCreating(false)
    }
  }

  return (
    <Card eyebrow="NEW TARGET" title="Register target">
      <form className="target-form" onSubmit={handleSubmit}>
        <ErrorAlert message={createError} />

        <FormField label="Target URL" htmlFor="target-registration-url">
          <Input
            id="target-registration-url"
            type="url"
            required
            minLength="8"
            maxLength="2048"
            value={url}
            onChange={(event) => setUrl(event.target.value)}
            placeholder="https://example.com"
          />
        </FormField>

        <FormField label="Ownership verification" htmlFor="target-verification-method">
          <Select
            id="target-verification-method"
            value={verificationMethod}
            onChange={(event) => setVerificationMethod(event.target.value)}
          >
            <option value="file">Verification file</option>
            <option value="dns">DNS TXT record</option>
          </Select>
        </FormField>

        <button type="submit" className="primary-button target-submit" disabled={creating}>
          {creating ? 'Registering...' : 'Register target'}
        </button>
      </form>
    </Card>
  )
}
