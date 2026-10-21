export default function Button({ variant = 'primary', className = '', type = 'button', ...props }) {
  const classes = [`ui-button`, `ui-button-${variant}`, className].filter(Boolean).join(' ')
  return <button type={type} className={classes} {...props} />
}
