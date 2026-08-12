import { ChangeEvent, FormEvent, useEffect, useRef, useState } from 'react'
import { Terminal } from '@xterm/xterm'
import { FitAddon } from '@xterm/addon-fit'
import '@xterm/xterm/css/xterm.css'
import { useMutation, useQuery } from '@tanstack/react-query'
import { Link, useParams } from 'react-router-dom'
import { api } from '../../api/client'

const rejectedKeyExtensions = new Set([
  '7z', 'avi', 'bmp', 'doc', 'docx', 'exe', 'gif', 'gz', 'jpeg', 'jpg', 'mov',
  'mp3', 'mp4', 'pdf', 'png', 'ppt', 'pptx', 'rar', 'svg', 'tar', 'webp', 'xls',
  'xlsx', 'zip',
])

export function TerminalPage() {
  const { projectId = '' } = useParams()
  const profiles = useQuery({ queryKey: ['terminal-profiles', projectId], queryFn: () => api.listTerminalProfiles(projectId) })
  const [index, setIndex] = useState(0)
  const [password, setPassword] = useState('')
  const [privateKey, setPrivateKey] = useState('')
  const [passphrase, setPassphrase] = useState('')
  const [trustHostKey, setTrustHostKey] = useState(false)
  const [error, setError] = useState('')
  const [connected, setConnected] = useState(false)
  const hostRef = useRef<HTMLDivElement>(null)
  const termRef = useRef<Terminal | null>(null)
  const fitRef = useRef<FitAddon | null>(null)
  const socket = useRef<WebSocket | null>(null)
  const intentionalClose = useRef(false)
  const profile = profiles.data?.[index]
  const keyStorage = (profileId: string) => `awe-terminal-key-${projectId}-${profileId}`
  const passphraseStorage = (profileId: string) => `awe-terminal-pass-${projectId}-${profileId}`

  useEffect(() => {
    if (!profile) {
      setPrivateKey('')
      setPassphrase('')
      return
    }
    setPrivateKey(sessionStorage.getItem(keyStorage(profile.id)) || '')
    setPassphrase(sessionStorage.getItem(passphraseStorage(profile.id)) || '')
    setPassword('')
    setTrustHostKey(false)
    setError('')
  }, [profile?.id, projectId])

  function send(message: object) {
    const ws = socket.current
    if (ws?.readyState === WebSocket.OPEN) ws.send(JSON.stringify(message))
  }

  function fitTerminal() {
    fitRef.current?.fit()
    const term = termRef.current
    if (term) { term.focus(); send({ type: 'resize', cols: term.cols, rows: term.rows }) }
  }

  function disconnect() {
    intentionalClose.current = true
    send({ type: 'close' })
    socket.current?.close(1000, 'Disconnected by user')
  }

  const connect = useMutation({
    mutationFn: () => api.createTerminalSession(projectId, {
      host: profile!.host,
      port: profile!.port,
      username: profile!.username,
      password,
      private_key: password ? '' : privateKey,
      key_passphrase: password ? '' : passphrase,
      trust_host_key: trustHostKey,
    }),
    onSuccess: session => {
      if (profile && privateKey) {
        sessionStorage.setItem(keyStorage(profile.id), privateKey)
        sessionStorage.setItem(passphraseStorage(profile.id), passphrase)
      }
      setPassword(''); setError('')
      const protocol = location.protocol === 'https:' ? 'wss' : 'ws'
      const ws = new WebSocket(`${protocol}://${location.host}/api/v1/projects/${projectId}/terminal/sessions/${session.id}/stream`)
      intentionalClose.current = false
      socket.current = ws
      ws.onopen = () => { setConnected(true); setError(''); requestAnimationFrame(fitTerminal) }
      ws.onmessage = e => termRef.current?.write(e.data)
      ws.onclose = event => {
        if (socket.current === ws) socket.current = null
        setConnected(false)
        if (intentionalClose.current) { intentionalClose.current = false; setError(''); return }
        const reason = event.reason || (event.code === 1006 ? 'unexpected network or server disconnect' : `close code ${event.code}`)
        setError(`Terminal disconnected: ${reason}. Reconnect to start a new session.`)
      }
      ws.onerror = () => setError('Terminal connection encountered a network error.')
    },
  })

  useEffect(() => {
    if (!hostRef.current) return
    const term = new Terminal({ cursorBlink: true, fontFamily: 'ui-monospace,monospace', fontSize: 13, theme: { background: '#0d0d15', foreground: '#cdd6f4', cursor: '#89b4fa' } })
    const fit = new FitAddon()
    term.loadAddon(fit); term.open(hostRef.current); fit.fit(); termRef.current = term; fitRef.current = fit
    term.onData(data => send({ type: 'input', data }))
    const resize = () => { fit.fit(); send({ type: 'resize', cols: term.cols, rows: term.rows }) }
    window.addEventListener('resize', resize)
    return () => { window.removeEventListener('resize', resize); socket.current?.close(); fitRef.current = null; term.dispose() }
  }, [])

  useEffect(() => {
    if (!connected) return
    const frame = requestAnimationFrame(fitTerminal)
    return () => cancelAnimationFrame(frame)
  }, [connected])

  function submit(e: FormEvent) {
    e.preventDefault()
    if (!profile) return
    if (!password && !privateKey) { setError('Enter an SSH password or load a private key.'); return }
    setError(''); connect.mutate()
  }

  function readKey(e: ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0]
    if (!file) return
    e.target.value = ''
    if (file.size > 100_000) { setError('Private keys are limited to 100 KB.'); return }
    const extension = file.name.includes('.') ? file.name.split('.').pop()!.toLowerCase() : ''
    if (rejectedKeyExtensions.has(extension) || /^(image|audio|video)\//.test(file.type)) {
      setError('That file type is not suitable for an SSH private key.'); return
    }
    const reader = new FileReader()
    reader.onload = () => { setPrivateKey(String(reader.result || '')); setError('') }
    reader.readAsText(file)
  }

  return <main className={`page feature-page terminal-page${connected ? ' terminal-live' : ''}`}>
    {!connected && <><Link className="back-link" to={`/projects/${projectId}`}>← Project workspace</Link>
    <header className="page-header"><div><p className="eyebrow">Remote operations</p><h1>Terminal</h1><p className="muted">Interactive SSH session through the AWE backend broker.</p></div><div className="terminal-actions"><span className="live-dot">Disconnected</span><Link className="button-link" to={`/projects/${projectId}/terminal/config`}>⚙ Configure</Link></div></header>
    <form className="panel terminal-session-bar" onSubmit={submit}>
      <select value={index} onChange={e => setIndex(Number(e.target.value))}>{profiles.data?.map((item, i) => <option value={i} key={item.id}>{item.name} · {item.host}</option>)}</select>
      <div className="terminal-auth-choice">
        <input type="password" value={password} onChange={e => setPassword(e.target.value)} placeholder="SSH password (or use a key)" />
        <span>or</span>
        <label className="file-button">Choose private key<input type="file" onChange={readKey} /></label>
        <textarea value={privateKey} onChange={e => { setPrivateKey(e.target.value); setError('') }} placeholder="Paste private SSH key here" aria-label="Private SSH key" />
        <input className="terminal-key-passphrase" type="password" value={passphrase} onChange={e => setPassphrase(e.target.value)} placeholder="Key passphrase (optional)" disabled={!privateKey} />
      </div>
      <label className="host-key-trust"><input type="checkbox" checked={trustHostKey} onChange={e => setTrustHostKey(e.target.checked)} /><span>Trust this host key</span></label>
      <button disabled={!profile || connect.isPending || connected}>{connect.isPending ? 'Connecting…' : connected ? 'Connected' : 'Connect'}</button>
    </form>
    {trustHostKey && <p className="muted host-key-warning">Only enable this after confirming the target address. It bypasses SSH host identity verification for this connection.</p>}
    {!profiles.data?.length && <div className="panel empty">Create a connection profile first.</div>}
    {(error || connect.isError) && <p className="error">{error || ((connect.error as Error)?.message)}</p>}</>}
    {connected && <header className="terminal-live-toolbar"><div><span className="live-dot active">Connected</span><b>{profile?.username}@{profile?.host}:{profile?.port}</b></div><small>Scroll history with the mouse wheel · click anywhere to focus</small><nav><Link to={`/projects/${projectId}/terminal/config`} onClick={disconnect}>Configure</Link><button className="subtle" onClick={fitTerminal}>Fit</button><button className="danger" onClick={disconnect}>Disconnect</button></nav></header>}
    <section className="panel terminal-panel" onClick={() => termRef.current?.focus()} onWheel={() => termRef.current?.focus()}><div ref={hostRef} /></section>
  </main>
}
