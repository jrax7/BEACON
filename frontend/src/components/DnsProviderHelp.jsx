import { useMemo, useState } from 'react'

function getRelativeRecordName(
  location,
  hostname,
) {
  if (!location || !hostname) {
    return location || ''
  }

  const normalizedLocation =
    location
      .replace(/\.$/, '')
      .toLowerCase()

  const normalizedHostname =
    hostname
      .replace(/\.$/, '')
      .toLowerCase()

  const suffix =
    `.${normalizedHostname}`

  if (
    normalizedLocation.endsWith(
      suffix,
    )
  ) {
    return location.slice(
      0,
      -suffix.length,
    )
  }

  return location
}

export default function DnsProviderHelp({
  hostname,
  location,
  value,
}) {
  const [
    provider,
    setProvider,
  ] = useState('cloudflare')

  const relativeName =
    useMemo(
      () =>
        getRelativeRecordName(
          location,
          hostname,
        ),
      [
        location,
        hostname,
      ],
    )

  return (
    <section className="dns-help">
      <div className="dns-help-heading">
        <div>
          <p className="eyebrow">
            DNS PROVIDER HELP
          </p>

          <h3>
            Add the verification record
          </h3>
        </div>

        <label className="provider-selector">
          <span>
            Provider
          </span>

          <select
            value={provider}
            onChange={(event) =>
              setProvider(
                event.target.value,
              )
            }
          >
            <option value="cloudflare">
              Cloudflare
            </option>

            <option value="route53">
              Amazon Route 53
            </option>

            <option value="godaddy">
              GoDaddy
            </option>

            <option value="other">
              Other DNS provider
            </option>
          </select>
        </label>
      </div>

      <div className="dns-values-grid">
        <DnsValue
          label="Record type"
          value="TXT"
        />

        <DnsValue
          label="Record name"
          value={relativeName}
        />

        <DnsValue
          label="Full record name"
          value={location}
        />

        <DnsValue
          label="Content / Value"
          value={value}
        />
      </div>

      {provider === 'cloudflare' && (
        <ol className="dns-steps">
          <li>
            Open the domain in the
            Cloudflare dashboard.
          </li>

          <li>
            Go to
            <strong>
              {' '}DNS → Records
            </strong>.
          </li>

          <li>
            Select
            <strong>
              {' '}Add record
            </strong>.
          </li>

          <li>
            Set
            <strong>
              {' '}Type
            </strong>
            {' '}to
            <strong>
              {' '}TXT
            </strong>.
          </li>

          <li>
            Enter the displayed
            <strong>
              {' '}Record name
            </strong>
            {' '}in the Name field.
          </li>

          <li>
            Enter the displayed
            verification value in
            <strong>
              {' '}Content
            </strong>.
          </li>

          <li>
            Leave TTL at
            <strong>
              {' '}Auto
            </strong>
            {' '}unless your DNS policy
            requires otherwise.
          </li>

          <li>
            Save the record, then return
            to BEACON and select
            <strong>
              {' '}Verify DNS ownership
            </strong>.
          </li>
        </ol>
      )}

      {provider === 'route53' && (
        <ol className="dns-steps">
          <li>
            Open the Route 53 hosted zone
            for the target domain.
          </li>

          <li>
            Select
            <strong>
              {' '}Create record
            </strong>.
          </li>

          <li>
            Enter the displayed record
            name.
          </li>

          <li>
            Set
            <strong>
              {' '}Record type
            </strong>
            {' '}to
            <strong>
              {' '}TXT
            </strong>.
          </li>

          <li>
            Enter the BEACON verification
            value as the record value.
          </li>

          <li>
            Use Simple routing unless
            your DNS design requires
            something else.
          </li>

          <li>
            Create the record, then
            return to BEACON and verify
            ownership.
          </li>
        </ol>
      )}

      {provider === 'godaddy' && (
        <ol className="dns-steps">
          <li>
            Open your domain in GoDaddy.
          </li>

          <li>
            Open
            <strong>
              {' '}DNS
            </strong>
            {' '}to view the DNS records.
          </li>

          <li>
            Select
            <strong>
              {' '}Add New Record
            </strong>.
          </li>

          <li>
            Choose
            <strong>
              {' '}TXT
            </strong>
            {' '}as the record type.
          </li>

          <li>
            Enter the displayed record
            name and verification value.
          </li>

          <li>
            Save the record, then return
            to BEACON and verify
            ownership.
          </li>
        </ol>
      )}

      {provider === 'other' && (
        <ol className="dns-steps">
          <li>
            Open the authoritative DNS
            provider for this domain.
          </li>

          <li>
            Create a new
            <strong>
              {' '}TXT
            </strong>
            {' '}record.
          </li>

          <li>
            Use the displayed record name.
          </li>

          <li>
            Use the displayed verification
            value as the TXT content.
          </li>

          <li>
            Save the record and return to
            BEACON to verify ownership.
          </li>
        </ol>
      )}

      <div className="dns-help-note">
        Some DNS providers automatically
        append the zone name. If the
        provider asks for only a host or
        name, use the Record name above.
        If it expects a fully qualified
        name, use Full record name.
      </div>
    </section>
  )
}

function DnsValue({
  label,
  value,
}) {
  return (
    <div>
      <span className="detail-label">
        {label}
      </span>

      <code>
        {value}
      </code>
    </div>
  )
}
