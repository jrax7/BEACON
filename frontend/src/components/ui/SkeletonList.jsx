import Skeleton from './Skeleton'

export default function SkeletonList({ rows = 3, label = 'Loading content', className = '' }) {
  return (
    <div
      className={['ui-skeleton-list', className].filter(Boolean).join(' ')}
      role="status"
      aria-label={label}
    >
      {Array.from({ length: rows }, (_, index) => (
        <Skeleton key={index} variant="row" />
      ))}
    </div>
  )
}
