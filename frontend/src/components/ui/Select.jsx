export default function Select({ className = '', children, ...props }) {
  return <select className={['ui-control', 'ui-select', className].filter(Boolean).join(' ')} {...props}>{children}</select>
}
