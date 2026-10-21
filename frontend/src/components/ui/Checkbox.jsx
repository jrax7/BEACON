export default function Checkbox({ className = '', ...props }) {
  return <input type="checkbox" className={['ui-checkbox', className].filter(Boolean).join(' ')} {...props} />
}
