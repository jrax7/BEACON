export default function FormField({ label, htmlFor, hint, error, children, className = '' }) {
  return (
    <div className={['ui-field', className].filter(Boolean).join(' ')}>
      {label ? <label className="ui-field-label" htmlFor={htmlFor}>{label}</label> : null}
      {children}
      {error ? <p className="ui-field-error">{error}</p> : hint ? <p className="ui-field-hint">{hint}</p> : null}
    </div>
  )
}
