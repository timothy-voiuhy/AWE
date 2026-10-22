import { lazy, Suspense } from 'react'

const MarkdownRenderer = lazy(() => import('./MarkdownRenderer'))

export function MarkdownContent({ source, className = '' }: { source: string; className?: string }) {
  return <div className={`markdown-content ${className}`}>
    <Suspense fallback={<div className="markdown-loading">Rendering…</div>}>
      <MarkdownRenderer source={source} />
    </Suspense>
  </div>
}
