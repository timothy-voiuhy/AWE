export function Spinner({ label = 'Loading…', size = 'default' }: { label?: string; size?: 'default' | 'small' }) {
  return (
    <div className={`awe-spinner${size === 'small' ? ' awe-spinner-sm' : ''}`} role="status" aria-live="polite">
      <div className="awe-spinner-orbit">
        <span className="awe-spinner-ring" />
        <span className="awe-spinner-ring awe-spinner-ring-2" />
        <span className="awe-spinner-core" />
      </div>
      {label && <span className="awe-spinner-label">{label}</span>}
      <span className="awe-sr-only">{label || 'Loading'}</span>
    </div>
  )
}
