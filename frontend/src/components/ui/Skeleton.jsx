export default function Skeleton({ variant = 'text', className = '', ...props }) {
  return (
    <span
      aria-hidden="true"
      className={['ui-skeleton', `ui-skeleton-${variant}`, className].filter(Boolean).join(' ')}
      {...props}
    />
  )
}
