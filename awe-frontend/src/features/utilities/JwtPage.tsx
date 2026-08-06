import { useMemo, useState } from 'react'
import { Link, useParams } from 'react-router-dom'

function decodePart(value: string): unknown {
  const normalized = value.replace(/-/g, '+').replace(/_/g, '/')
  const padded = normalized.padEnd(Math.ceil(normalized.length / 4) * 4, '=')
  return JSON.parse(new TextDecoder().decode(Uint8Array.from(atob(padded), (char) => char.charCodeAt(0))))
}

export function JwtPage() {
  const { projectId = '' } = useParams()
  const [token, setToken] = useState('')
  const decoded = useMemo(() => {
    if (!token.trim()) return { header: null, payload: null, signature: '', error: '' }
    try {
      const parts = token.trim().split('.')
      if (parts.length !== 3) throw new Error('A JWT must have three dot-separated segments')
      return { header: decodePart(parts[0]), payload: decodePart(parts[1]), signature: parts[2], error: '' }
    } catch (error) { return { header: null, payload: null, signature: '', error: error instanceof Error ? error.message : 'Invalid JWT' } }
  }, [token])

  return <main className="page feature-page">
    <Link className="back-link" to={`/projects/${projectId}`}>← Project workspace</Link>
    <header className="page-header"><div><p className="eyebrow">Token analysis</p><h1>JWT Inspector</h1><p className="muted">Inspect token structure locally. Decoding does not verify the signature.</p></div></header>
    <label className="panel editor-panel token-input"><span>Encoded token</span><textarea value={token} onChange={(event) => setToken(event.target.value)} placeholder="eyJhbGciOi…" spellCheck={false} />{decoded.error && <small className="error">{decoded.error}</small>}</label>
    <section className="jwt-grid"><article className="panel json-card"><span>Header</span><pre>{decoded.header ? JSON.stringify(decoded.header, null, 2) : '—'}</pre></article><article className="panel json-card"><span>Payload</span><pre>{decoded.payload ? JSON.stringify(decoded.payload, null, 2) : '—'}</pre></article><article className="panel json-card signature-card"><span>Signature</span><pre>{decoded.signature || '—'}</pre></article></section>
  </main>
}
