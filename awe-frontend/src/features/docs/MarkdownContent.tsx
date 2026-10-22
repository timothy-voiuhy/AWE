import { lazy, Suspense } from 'react'
import { Spinner } from '../../components/Spinner'

const MarkdownRenderer = lazy(() => import('./MarkdownRenderer'))

export function MarkdownContent({ source, className = '' }: { source: string; className?: string }) {
  return <div className={`markdown-content ${className}`}>
    <Suspense fallback={<div className="markdown-loading"><Spinner size="small" label="Rendering…" /></div>}>
      <MarkdownRenderer source={source} />
    </Suspense>
  </div>
}
