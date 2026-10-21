function initials(label) {
  return String(label || 'BEACON')
    .trim()
    .split(/\s+/)
    .filter(Boolean)
    .slice(0, 2)
    .map((part) => part[0]?.toUpperCase())
    .join('') || 'B'
}

export default function Avatar({ label = '', size = 'md', className = '' }) {
  return (
    <span
      className={['ui-avatar', `ui-avatar-${size}`, className].filter(Boolean).join(' ')}
      aria-hidden="true"
    >
      {initials(label)}
    </span>
  )
}
