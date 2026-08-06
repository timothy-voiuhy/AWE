import { useMemo, useState } from 'react'
import { Link, useParams } from 'react-router-dom'

type Transform = 'base64-encode' | 'base64-decode' | 'url-encode' | 'url-decode' | 'hex-encode' | 'hex-decode'

function transform(value: string, operation: Transform): string {
  const bytes = new TextEncoder().encode(value)
  switch (operation) {
    case 'base64-encode': return btoa(String.fromCharCode(...bytes))
    case 'base64-decode': return new TextDecoder().decode(Uint8Array.from(atob(value.trim()), (char) => char.charCodeAt(0)))
    case 'url-encode': return encodeURIComponent(value)
    case 'url-decode': return decodeURIComponent(value)
    case 'hex-encode': return [...bytes].map((byte) => byte.toString(16).padStart(2, '0')).join('')
    case 'hex-decode': {
      const clean = value.replace(/\s+/g, '')
      if (!/^[0-9a-f]*$/i.test(clean) || clean.length % 2) throw new Error('Hex input must contain complete byte pairs')
      return new TextDecoder().decode(Uint8Array.from(clean.match(/../g) ?? [], (pair) => Number.parseInt(pair, 16)))
    }
  }
}

export function DecoderPage() {
  const { projectId = '' } = useParams()
  const [input, setInput] = useState('')
  const [operation, setOperation] = useState<Transform>('base64-decode')
  const result = useMemo(() => {
    try { return { value: input ? transform(input, operation) : '', error: '' } }
    catch (error) { return { value: '', error: error instanceof Error ? error.message : 'Invalid input' } }
  }, [input, operation])

  return <main className="page feature-page">
    <Link className="back-link" to={`/projects/${projectId}`}>← Project workspace</Link>
    <header className="page-header"><div><p className="eyebrow">Utilities</p><h1>Decoder</h1><p className="muted">Encode and decode common web data formats locally in your browser.</p></div></header>
    <section className="panel utility-toolbar"><label>Operation<select value={operation} onChange={(event) => setOperation(event.target.value as Transform)}><option value="base64-decode">Base64 decode</option><option value="base64-encode">Base64 encode</option><option value="url-decode">URL decode</option><option value="url-encode">URL encode</option><option value="hex-decode">Hex decode</option><option value="hex-encode">Hex encode</option></select></label><button onClick={() => setInput('')}>Clear</button></section>
    <section className="editor-grid"><label className="panel editor-panel"><span>Input</span><textarea value={input} onChange={(event) => setInput(event.target.value)} placeholder="Paste encoded or plain text…" spellCheck={false} /></label><label className="panel editor-panel"><span>Output</span><textarea value={result.value} readOnly placeholder="Transformed output appears here" spellCheck={false} />{result.error && <small className="error">{result.error}</small>}</label></section>
  </main>
}
