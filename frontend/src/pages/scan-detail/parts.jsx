// Small presentational pieces shared by two or more scan-detail tabs.

import { assessmentProfileLabel } from '../scans/helpers'
import { formatDate } from '../../lib/format'

export function AssessmentTab({ active, label, count, live = false, onClick }) {
  return (
    <button
      type="button"
      role="tab"
      aria-selected={active}
      className={active ? 'assessment-tab active' : 'assessment-tab'}
      onClick={onClick}
    >
      <span>{label}</span>
      {live && <span className="tab-live-dot" title="Live assessment" />}
      {count !== undefined && count !== null && (
        <span className="assessment-tab-count">{count}</span>
      )}
    </button>
  )
}

export function FindingSelect({ label, value, onChange, options }) {
  return (
    <label className="finding-filter-field">
      <span>{label}</span>
      <select value={value} onChange={(event) => onChange(event.target.value)}>
        {options.map(([optionValue, optionLabel]) => (
          <option value={optionValue} key={optionValue}>
            {optionLabel}
          </option>
        ))}
      </select>
    </label>
  )
}

export function UnavailablePanel({ kicker, title, message }) {
  return (
    <section className="scan-console-card unavailable-tab-card">
      <p className="scan-kicker">{kicker}</p>
      <h2>{title}</h2>
      <p>{message}</p>
    </section>
  )
}

function Meta({ label, value, mono = false }) {
  return (
    <div>
      <dt>{label}</dt>
      <dd>{mono ? <code>{value}</code> : value}</dd>
    </div>
  )
}

export function AssessmentMetadata({ scan, target }) {
  return (
    <section className="scan-console-card assessment-meta-card">
      <div className="console-card-heading">
        <div>
          <p className="scan-kicker">ASSESSMENT METADATA</p>
          <h2>Runtime details</h2>
        </div>
      </div>

      <dl className="assessment-meta-grid">
        <Meta label="Target" value={target?.normalized_url || scan.target_id} />
        <Meta label="Status" value={scan.status} />
        <Meta label="Started" value={formatDate(scan.started_at)} />
        <Meta label="Completed" value={formatDate(scan.completed_at)} />
        <Meta label="Profile" value={assessmentProfileLabel(scan)} />
        <Meta label="Target ID" value={scan.target_id} mono />
      </dl>
    </section>
  )
}
