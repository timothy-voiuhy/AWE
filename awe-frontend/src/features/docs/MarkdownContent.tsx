import ReactMarkdown from 'react-markdown'
import remarkGfm from 'remark-gfm'

export function MarkdownContent({ source, className = '' }: { source: string; className?: string }) {
  return <div className={`markdown-content ${className}`}>
    <ReactMarkdown remarkPlugins={[remarkGfm]}>{source}</ReactMarkdown>
  </div>
}
