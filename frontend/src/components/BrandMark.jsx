export default function BrandMark({
  size = 'md',
  showText = true,
  subtitle = 'Security Assessment Platform',
  className = '',
}) {
  return (
    <div
      className={`beacon-brand beacon-brand-${size} ${className}`.trim()}
    >
      <img
        className="beacon-brand-image"
        src="/beacon-mark.svg"
        alt=""
        aria-hidden="true"
      />

      {showText && (
        <div className="beacon-brand-copy">
          <strong>BEACON</strong>
          <span>{subtitle}</span>
        </div>
      )}
    </div>
  )
}
