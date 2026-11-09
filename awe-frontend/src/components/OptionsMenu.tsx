import { useEffect, useRef, type ReactNode } from 'react'

export function OptionsMenu({ children, label = 'Page options' }: { children: ReactNode; label?: string }) {
  const ref = useRef<HTMLDetailsElement>(null)

  useEffect(() => {
    const closeOutside = (event: PointerEvent) => {
      if (!ref.current?.contains(event.target as Node)) ref.current?.removeAttribute('open')
    }
    document.addEventListener('pointerdown', closeOutside)
    return () => document.removeEventListener('pointerdown', closeOutside)
  }, [])

  return <details className="page-options" ref={ref} onKeyDown={event => {
    if (event.key === 'Escape') {
      ref.current?.removeAttribute('open')
      ref.current?.querySelector('summary')?.focus()
    }
  }}>
    <summary aria-label={label} title={label}><span aria-hidden="true">⋮</span></summary>
    <div className="page-options-panel" onClick={event => {
      const action = (event.target as HTMLElement).closest('button, a')
      if (action && !action.hasAttribute('disabled')) ref.current?.removeAttribute('open')
    }}>{children}</div>
  </details>
}
