export default function Tooltip({ label, children, className = '' }) {
  return (
    <span className={['ui-tooltip', className].filter(Boolean).join(' ')}>
      {children}
      <span className="ui-tooltip-content" role="tooltip">{label}</span>
    </span>
  )
}
