import ReactMarkdown from 'react-markdown'
import remarkGfm from 'remark-gfm'

// Default export so React.lazy can code-split react-markdown + remark-gfm
// (~200 KB) out of the main bundle; MarkdownContent wraps this in Suspense.
export default function MarkdownRenderer({ source }: { source: string }) {
  return <ReactMarkdown remarkPlugins={[remarkGfm]}>{source}</ReactMarkdown>
}
