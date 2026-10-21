export default function Tabs({
  items = [],
  activeKey,
  onChange,
  ariaLabel = 'Workspace navigation',
}) {
  return (
    <div className="workspace-tabs" role="tablist" aria-label={ariaLabel}>
      {items.map((item) => (
        <button
          key={item.key}
          type="button"
          role="tab"
          aria-selected={activeKey === item.key}
          className={
            activeKey === item.key
              ? 'workspace-tab active'
              : 'workspace-tab'
          }
          onClick={() => onChange(item.key)}
        >
          <span>{item.label}</span>

          {item.count !== undefined && (
            <strong>{item.count}</strong>
          )}
        </button>
      ))}
    </div>
  )
}
