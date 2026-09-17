import { FormEvent, useEffect, useRef, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import RFB from '@novnc/novnc'
import { useParams } from 'react-router-dom'
import { api } from '../../api/client'

export function BrowserPage() {
  const { projectId = '' } = useParams()
  const queryClient = useQueryClient()
  const [sessionId, setSessionId] = useState('')
  const [url, setUrl] = useState('')
  const [error, setError] = useState('')
  const [connected, setConnected] = useState(false)
  const canvasHost = useRef<HTMLDivElement>(null)
  const rfb = useRef<RFB | null>(null)
  const editingUrl = useRef(false)
  const sessions = useQuery({
    queryKey: ['browser', projectId],
    queryFn: () => api.listBrowserSessions(projectId),
    refetchInterval: 5000,
  })

  useEffect(() => {
    if (!sessionId && sessions.data?.[0]) {
      setSessionId(sessions.data[0].id)
      setUrl(sessions.data[0].url)
    }
  }, [sessions.data, sessionId])

  useEffect(() => {
    const host = canvasHost.current
    if (!sessionId || !host) return

    host.replaceChildren()
    setConnected(false)
    setError('')
    const protocol = location.protocol === 'https:' ? 'wss' : 'ws'
    const connection = new RFB(host, `${protocol}://${location.host}/api/v1/projects/${projectId}/browser/sessions/${sessionId}/vnc`)
    connection.scaleViewport = true
    connection.resizeSession = false
    connection.viewOnly = false
    connection.addEventListener('connect', () => setConnected(true))
    connection.addEventListener('disconnect', () => setConnected(false))
    connection.addEventListener('securityfailure', () => setError('The browser VNC connection was rejected.'))
    rfb.current = connection

    return () => {
      connection.disconnect()
      if (rfb.current === connection) rfb.current = null
      host.replaceChildren()
      setConnected(false)
    }
  }, [sessionId, projectId])

  const create = useMutation({
    mutationFn: () => api.createBrowserSession(projectId),
    onSuccess: session => {
      setSessionId(session.id)
      setUrl(session.url)
      void queryClient.invalidateQueries({ queryKey: ['browser', projectId] })
    },
  })
  const navigate = useMutation({
    mutationFn: () => api.navigateBrowser(projectId, sessionId, url),
    onSuccess: session => {
      editingUrl.current = false
      setUrl(session.url)
      void queryClient.invalidateQueries({ queryKey: ['browser', projectId] })
    },
  })
  const close = useMutation({
    mutationFn: () => api.closeBrowserSession(projectId, sessionId),
    onSuccess: () => {
      setSessionId('')
      void queryClient.invalidateQueries({ queryKey: ['browser', projectId] })
    },
  })

  const active = sessions.data?.find(item => item.id === sessionId)

  function submit(event: FormEvent) {
    event.preventDefault()
    setError('')
    if (!/^https?:\/\//i.test(url)) {
      setError('Use an http:// or https:// URL inside the project scope.')
      return
    }
    navigate.mutate()
  }

  return <main className="page feature-page browser-page">
    <header className="page-header">
      <div><p className="eyebrow">Controlled browser</p><h1>Browser</h1><p className="muted">Interactive Chromium desktop routed through AWE’s proxy.</p></div>
      <button onClick={() => create.mutate()} disabled={create.isPending}>{create.isPending ? 'Starting…' : 'New session'}</button>
    </header>
    <section className="browser-toolbar panel">
      <select value={sessionId} onChange={event => { setSessionId(event.target.value); const session = sessions.data?.find(item => item.id === event.target.value); if (session) setUrl(session.url) }}>
        <option value="">Select a session</option>
        {sessions.data?.map(session => <option value={session.id} key={session.id}>{session.title || 'New tab'} · {session.id.slice(0, 8)}</option>)}
      </select>
      <form onSubmit={submit}>
        <input value={url} onChange={event => { editingUrl.current = true; setUrl(event.target.value) }} placeholder="https://target.example" disabled={!sessionId} />
        <button disabled={!sessionId || navigate.isPending}>{navigate.isPending ? 'Loading…' : 'Go'}</button>
      </form>
      {sessionId && <button className="danger" onClick={() => close.mutate()}>Close</button>}
    </section>
    {(error || create.isError || navigate.isError) && <p className="error">{error || ((create.error || navigate.error) as Error)?.message}</p>}
    {active && <section className="browser-stage panel">
      <div className="browser-stage-head"><span>{active.title || 'Loading'} · {active.url}</span><small>{connected ? '● Live VNC' : '○ Connecting'}</small></div>
      <div ref={canvasHost} className="browser-vnc" tabIndex={0} aria-label="Interactive remote browser desktop" />
      <p className="muted">Click the remote desktop to focus it. Keyboard, scrolling, tabs, downloads, and browser chrome are handled by VNC.</p>
    </section>}
    {!active && <div className="panel empty">Create a browser session to begin.</div>}
  </main>
}
