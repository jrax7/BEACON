import Breadcrumbs from './Breadcrumbs'

/**
 * Standard page header: optional breadcrumbs + eyebrow + title +
 * description on the left, optional actions/stats on the right.
 */
export default function PageHeader({
  eyebrow,
  title,
  description,
  actions,
  breadcrumbs,
  className = '',
}) {
  return (
    <header className={`page-header ${className}`.trim()}>
      <div>
        {breadcrumbs && <Breadcrumbs items={breadcrumbs} />}
        {eyebrow && <p className="eyebrow">{eyebrow}</p>}
        <h1>{title}</h1>
        {description && <p>{description}</p>}
      </div>

      {actions && (
        <div className="page-header-actions">
          {actions}
        </div>
      )}
    </header>
  )
}
