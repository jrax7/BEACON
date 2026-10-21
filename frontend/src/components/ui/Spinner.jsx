export default function Spinner({ className = '', label = 'Loading' }) {
  return <span className={['ui-spinner', className].filter(Boolean).join(' ')} role="status" aria-label={label} />
}
