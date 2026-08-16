import { useSearchParams } from 'react-router-dom'

import { MarkdownContent } from './MarkdownContent'

type DocEntry = {
  slug: string
  title: string
  summary: string
  order: number
  source: string
}

const rawDocs = import.meta.glob('../../docs/**/*.md', { query: '?raw', import: 'default', eager: true }) as Record<string, string>

function parseDoc(path: string, raw: string): DocEntry {
  const slug = path.split('/').pop()?.replace(/\.md$/, '') || path
  const match = raw.match(/^---\n([\s\S]*?)\n---\n?([\s\S]*)$/)
  const frontmatter = match?.[1] || ''
  const source = match?.[2] || raw
  const meta = Object.fromEntries(frontmatter.split('\n').map(line => {
    const index = line.indexOf(':')
    return index > 0 ? [line.slice(0, index).trim(), line.slice(index + 1).trim()] : ['', '']
  }).filter(([key]) => key))
  const heading = source.match(/^#\s+(.+)$/m)?.[1]
  return {
    slug,
    title: meta.title || heading || slug.replaceAll('-', ' '),
    summary: meta.summary || '',
    order: Number(meta.order || 1000),
    source,
  }
}

const docs = Object.entries(rawDocs).map(([path, raw]) => parseDoc(path, raw)).sort((a, b) => a.order - b.order || a.title.localeCompare(b.title))

export function DocsPage() {
  const [searchParams, setSearchParams] = useSearchParams()
  const selectedSlug = searchParams.get('doc') || docs[0]?.slug || ''
  const selected = docs.find(doc => doc.slug === selectedSlug) || docs[0]

  return <main className="page feature-page docs-page">
    <header className="page-header docs-header"><div><p className="eyebrow">Documentation</p><h1>AWE Docs</h1><p className="muted">Markdown-backed operator and developer guidance. Add files under <code>src/docs</code> to extend this section.</p></div></header>
    <section className="docs-workbench">
      <aside className="panel docs-sidebar"><header><b>Documents</b><span>{docs.length} file{docs.length === 1 ? '' : 's'}</span></header>{docs.map(doc => <button className={doc.slug === selected?.slug ? 'selected' : ''} onClick={() => setSearchParams({ doc: doc.slug })} key={doc.slug}><b>{doc.title}</b>{doc.summary && <span>{doc.summary}</span>}</button>)}</aside>
      <article className="panel docs-document">{selected ? <MarkdownContent source={selected.source} /> : <div className="empty">No documentation files were found.</div>}</article>
    </section>
  </main>
}
