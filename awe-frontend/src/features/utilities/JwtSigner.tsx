import { useEffect, useRef, useState } from 'react'
import { jwtAlgorithms, signJwt, type JwtAlgorithm } from './jwtSigning'
import './jwt-signer.css'

function sameJson(left: string, right: string) {
  try { return JSON.stringify(JSON.parse(left)) === JSON.stringify(JSON.parse(right)) } catch { return false }
}

export function JwtSigner({ header, payload, onGenerated, onUse, onClose }: { header: string; payload: string; onGenerated: (token: string, header: string) => void; onUse: (token: string) => void; onClose: () => void }) {
  const [algorithm, setAlgorithm] = useState<JwtAlgorithm | ''>('HS256')
  const [material, setMaterial] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')
  const [result, setResult] = useState<{ token: string; header: string; payload: string; algorithm: string; material: string }>()
  const latest = useRef({ header, payload, algorithm, material })
  latest.current = { header, payload, algorithm, material }
  let parsedAlgorithm = ''
  try { parsedAlgorithm = JSON.parse(header).alg || '' } catch { /* Report JSON errors when signing. */ }
  const hasHeader = Boolean(header)
  useEffect(() => { if (hasHeader) setAlgorithm(jwtAlgorithms.includes(parsedAlgorithm as JwtAlgorithm) ? parsedAlgorithm as JwtAlgorithm : '') }, [parsedAlgorithm, hasHeader])
  const stale = Boolean(result && (!sameJson(header, result.header) || !sameJson(payload, result.payload) || algorithm !== result.algorithm || material !== result.material))

  async function generate() {
    if (!algorithm) { setError('Choose a supported signing algorithm.'); return }
    setBusy(true); setError(''); setNotice('')
    const source = { header, payload, algorithm, material }
    try {
      const signed = await signJwt(header, payload, algorithm, material)
      if (Object.entries(source).some(([key, value]) => latest.current[key as keyof typeof source] !== value)) throw new Error('The inputs changed during signing. Generate the token again.')
      setResult({ ...source, ...signed })
      onGenerated(signed.token, signed.header)
    } catch (caught) { setError(caught instanceof Error ? caught.message : 'Token signing failed.') }
    finally { setBusy(false) }
  }

  async function copy(bearer: boolean) {
    if (!result || stale) return
    try {
      const text = bearer ? `Authorization: Bearer ${result.token}` : result.token
      if (navigator.clipboard?.writeText) await navigator.clipboard.writeText(text)
      else {
        const field = document.createElement('textarea'); field.value = text; document.body.appendChild(field); field.select()
        const copied = document.execCommand('copy'); field.remove()
        if (!copied) throw new Error('Clipboard access is unavailable. Select and copy the generated token.')
      }
      setNotice(bearer ? 'Authorization header copied.' : 'JWT copied.')
    } catch { setNotice('Clipboard access is unavailable. Select and copy the generated token.') }
  }

  return <section className="panel jwt-signer" aria-label="JWT signing">
    <header><div><b id="jwt-sign-dialog-title">Sign edited JWT</b><span>Creates a compact header.payload.signature token. Signing keys stay in this page’s memory.</span></div><button type="button" className="subtle" aria-label="Close JWT signing dialog" onClick={onClose}>×</button></header>
    <div className="jwt-signing-fields"><label>Signing algorithm<select value={algorithm} disabled={busy} onChange={event => { setAlgorithm(event.target.value as JwtAlgorithm); setNotice('') }}><option value="" disabled>Choose an algorithm</option>{jwtAlgorithms.map(value => <option key={value}>{value}</option>)}</select></label>
      {algorithm.startsWith('HS') ? <label>Signing secret<input type="password" autoComplete="off" value={material} disabled={busy} onChange={event => { setMaterial(event.target.value); setNotice('') }} placeholder="HMAC secret (UTF-8 text)" /></label> : <label>Signing private key<textarea autoComplete="off" spellCheck={false} value={material} disabled={busy} onChange={event => { setMaterial(event.target.value); setNotice('') }} placeholder="-----BEGIN PRIVATE KEY-----" /></label>}
      <button type="button" className="jwt-success" disabled={busy || !header.trim() || !payload.trim()} onClick={() => void generate()}>{busy ? 'Signing…' : 'Sign and generate JWT'}</button></div>
    <p className="muted">The selected algorithm is written into the header. HMAC needs the shared secret; RSA/PSS/ECDSA need the matching private key. The receiving application decides whether to accept the token.</p>
    {error && <p className="error" role="alert">{error}</p>}
    {result && <div className="jwt-signed-result"><label>Generated compact JWT<textarea readOnly spellCheck={false} value={result.token} /></label><nav><button type="button" disabled={stale || busy} onClick={() => void copy(false)}>Copy JWT</button><button type="button" disabled={stale || busy} onClick={() => void copy(true)}>Copy Bearer header</button><button type="button" disabled={stale || busy} onClick={() => onUse(result.token)}>Use as input token</button></nav>{stale && <p role="status">Inputs changed. Sign again to include your latest edits.</p>}</div>}
    {notice && !stale && <p role="status">{notice}</p>}
  </section>
}
