/**
 * Generic content section card, matching `.content-card` styling.
 * `eyebrow`/`title` render the shared `.section-heading` pattern; pass
 * `headingActions` for a trailing badge/button/count in that row.
 */
export default function Card({
  eyebrow,
  title,
  headingActions,
  className = '',
  bodyClassName = '',
  children,
  as: Component = 'section',
}) {
  const hasHeading = Boolean(eyebrow || title || headingActions)

  return (
    <Component className={`content-card ${className}`.trim()}>
      {hasHeading && (
        <div className="section-heading">
          <div>
            {eyebrow && <p className="eyebrow">{eyebrow}</p>}
            {title && <h2>{title}</h2>}
          </div>
          {headingActions}
        </div>
      )}

      <div className={bodyClassName}>{children}</div>
    </Component>
  )
}
