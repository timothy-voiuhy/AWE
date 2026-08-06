import { useMemo, useState } from 'react'
import { Link, useParams } from 'react-router-dom'

export function ComparerPage() {
  const { projectId = '' } = useParams()
  const [left, setLeft] = useState('')
  const [right, setRight] = useState('')
  const comparison = useMemo(() => {
    const a = left.split('\n'); const b = right.split('\n'); const count = Math.max(a.length, b.length)
    return Array.from({ length: count }, (_, index) => ({ index: index + 1, left: a[index] ?? '', right: b[index] ?? '', same: a[index] === b[index] }))
  }, [left, right])
  const changed = comparison.filter((line) => !line.same).length

  return <main className="page feature-page">
    <Link className="back-link" to={`/projects/${projectId}`}>← Project workspace</Link>
    <header className="page-header"><div><p className="eyebrow">Utilities</p><h1>Comparer</h1><p className="muted">Compare requests, responses, tokens, or arbitrary text line by line.</p></div><span className="difference-count">{changed} changed lines</span></header>
    <section className="editor-grid"><label className="panel editor-panel"><span>Original</span><textarea value={left} onChange={(event) => setLeft(event.target.value)} spellCheck={false} /></label><label className="panel editor-panel"><span>Modified</span><textarea value={right} onChange={(event) => setRight(event.target.value)} spellCheck={false} /></label></section>
    <section className="panel diff-panel">{comparison.map((line) => <div className={line.same ? 'diff-same' : 'diff-changed'} key={line.index}><b>{line.index}</b><code>{line.left || ' '}</code><code>{line.right || ' '}</code></div>)}</section>
  </main>
}
