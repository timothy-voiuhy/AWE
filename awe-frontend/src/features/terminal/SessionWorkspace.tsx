import { useEffect, useRef, useState } from 'react'
import { Terminal } from '@xterm/xterm'
import { FitAddon } from '@xterm/addon-fit'
import '@xterm/xterm/css/xterm.css'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Link, useParams, useSearchParams } from 'react-router-dom'
import { OptionsMenu } from '../../components/OptionsMenu'
import { runtime, type ManagedSession } from '../../api/runtime'

function SessionTerminal({ projectId, session, onDetach }: { projectId: string; session: ManagedSession; onDetach: () => void }) {
  const host = useRef<HTMLDivElement>(null)
  const socket = useRef<WebSocket>()
  const [writable, setWritable] = useState(false)
  const [ready, setReady] = useState(false)
  const [error, setError] = useState('')
  useEffect(() => {
    setReady(false)
    const terminal = new Terminal({ cursorBlink: true, disableStdin: true, fontSize: 13, theme: { background: '#0d0d15' } })
    const fit = new FitAddon(); terminal.loadAddon(fit); terminal.open(host.current!); fit.fit()
    const ws = new WebSocket(`${location.protocol === 'https:' ? 'wss' : 'ws'}://${location.host}/api/v1/projects/${projectId}/sessions/interactive/${session.id}/stream`)
    socket.current = ws
    let cursor = 0
    const enableInput = () => { terminal.options.disableStdin = false; setReady(true) }
    const readyTimer = window.setTimeout(enableInput, 800)
    const send = (value: object) => { if (ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify(value)) }
    const resize = () => { fit.fit(); send({ type: 'resize', cols: terminal.cols, rows: terminal.rows }) }
    terminal.onData(data => send({ type: 'input', data }))
    ws.onmessage = event => {
      const message = JSON.parse(event.data)
      if (message.type === 'error') { setError(message.message); return }
      setWritable(message.writable)
      let text = ''
      let hasTerminalOutput = false
      for (const item of message.events || []) if (item.sequence > cursor) {
        if (item.stream === 'terminal' || item.stream === 'system') text += item.data
        hasTerminalOutput ||= item.stream === 'terminal'
        cursor = item.sequence
      }
      if (text) terminal.write(text, hasTerminalOutput ? enableInput : undefined)
    }
    ws.onopen = resize
    ws.onclose = () => setError('Detached from session. Attach again to reconnect.')
    window.addEventListener('resize', resize)
    return () => { window.clearTimeout(readyTimer); window.removeEventListener('resize', resize); ws.close(); terminal.dispose() }
  }, [projectId, session.id])
  return <section><div className="runtime-toolbar"><b>{session.label}</b><span>{!ready ? 'Attaching…' : writable ? 'You have control' : 'Read-only viewer'}</span><button onClick={() => socket.current?.send(JSON.stringify({ type: 'take_control' }))}>Take control</button><button onClick={onDetach}>Detach</button></div>{error && <p className="error">{error}</p>}<div className="managed-terminal" ref={host} /></section>
}

export function SessionWorkspace() {
  const { projectId = '' } = useParams()
  const [params, setParams] = useSearchParams()
  const qc = useQueryClient()
  const dialog = useRef<HTMLDialogElement>(null)
  const [kind, setKind] = useState('tcp')
  const [host, setHost] = useState('')
  const [port, setPort] = useState(0)
  const [label, setLabel] = useState('')
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [peer, setPeer] = useState('')
  const [runId, setRunId] = useState(params.get('run') || '')
  const sessions = useQuery({ queryKey: ['interactive-sessions', projectId], queryFn: () => runtime.sessions(projectId), refetchInterval: 1500 })
  const create = useMutation({ mutationFn: () => runtime.createSession(projectId, { kind, host, port, label, username, password, expected_peer: peer, run_id: runId }), onSuccess: session => { setPassword(''); dialog.current?.close(); setParams({ session: session.id }); void qc.invalidateQueries({ queryKey: ['interactive-sessions', projectId] }) } })
  const terminate = useMutation({ mutationFn: (id: string) => runtime.terminate(projectId, id), onSuccess: () => qc.invalidateQueries({ queryKey: ['interactive-sessions', projectId] }) })
  const active = sessions.data?.find(s => s.id === params.get('session'))
  return <main className="page feature-page"><header className="panel runtime-toolbar"><b>Interactive sessions</b><OptionsMenu label="Session options"><button onClick={() => dialog.current?.showModal()}>New connection or listener</button><Link to={`/projects/${projectId}/terminal`}>SSH profiles</Link><Link to={`/projects/${projectId}/runs`}>Tool runs</Link></OptionsMenu></header>
    {(sessions.error || terminate.error) && <p className="error">{(sessions.error || terminate.error)?.message}</p>}
    <section className="runtime-workbench"><aside className="panel runtime-list">{sessions.data?.map(s => <article key={s.id}><button onClick={() => setParams({ session: s.id })}><b>{s.label}</b><span>{s.kind} · {s.status}</span><small>{s.host}{s.port ? `:${s.port}` : ''}</small></button><button className="danger" disabled={s.status === 'terminated'} onClick={() => terminate.mutate(s.id)}>Terminate</button></article>)}{!sessions.data?.length && <p>No sessions yet. Start an interactive tool or create a connection.</p>}</aside><article className="panel runtime-detail">{active ? <><p>{active.kind} · {active.status} · {active.message}</p><SessionTerminal key={active.id} projectId={projectId} session={active} onDetach={() => setParams({})} /><Link to={`/projects/${projectId}/runs/${active.run_id}`}>Transcript, artifacts, and evidence</Link></> : <p>Select a session to attach. Closing this page detaches without terminating the process.</p>}</article></section>
    <dialog ref={dialog} className="graph-tool-dialog" aria-labelledby="session-create-title"><section className="panel runtime-evidence"><header className="runtime-toolbar"><b id="session-create-title">New interactive connection</b><button onClick={() => dialog.current?.close()}>Close</button></header><label>Connection type<select value={kind} onChange={e => { setKind(e.target.value); setPort(0) }}><option value="tcp">Outbound TCP shell</option><option value="listener">Inbound callback listener</option><option value="ssh">SSH</option></select></label><label>Associated run ID (optional)<input value={runId} onChange={e => setRunId(e.target.value)} /></label><label>Label<input value={label} onChange={e => setLabel(e.target.value)} /></label>{kind !== 'listener' && <label>Host<input value={host} onChange={e => setHost(e.target.value)} /></label>}<label>{kind === 'listener' ? 'Listening port (0 chooses an available port)' : 'Port'}<input type="number" value={port} onChange={e => setPort(Number(e.target.value))} /></label>{kind === 'listener' && <label>Expected peer IP (optional)<input value={peer} onChange={e => setPeer(e.target.value)} /></label>}{kind === 'ssh' && <><label>Username<input value={username} onChange={e => setUsername(e.target.value)} /></label><label>Password<input type="password" value={password} onChange={e => setPassword(e.target.value)} /></label></>}{create.error && <p className="error">{create.error.message}</p>}<button disabled={create.isPending} onClick={() => create.mutate()}>{create.isPending ? 'Connecting…' : kind === 'listener' ? 'Start listener' : 'Connect'}</button></section></dialog>
  </main>
}
