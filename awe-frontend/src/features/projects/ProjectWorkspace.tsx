import { FormEvent, useEffect, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Link, useParams } from 'react-router-dom'

import { api, ScopeConfig, ScopeEntryType } from '../../api/client'

const emptyScope: ScopeConfig = { entries: [], include_subdomains: true }

export function ProjectWorkspace() {
  const { projectId = '' } = useParams()
  const queryClient = useQueryClient()
  const project = useQuery({
    queryKey: ['projects', projectId],
    queryFn: () => api.getProject(projectId),
    enabled: Boolean(projectId),
  })
  const scopeQuery = useQuery({
    queryKey: ['projects', projectId, 'scope'],
    queryFn: () => api.getScope(projectId),
    enabled: Boolean(projectId),
  })
  const pipelines = useQuery({ queryKey: ['pipelines'], queryFn: api.listPipelines })
  const runs = useQuery({
    queryKey: ['projects', projectId, 'pipeline-runs'],
    queryFn: () => api.listPipelineRuns(projectId),
    refetchInterval: (query) => query.state.data?.some((run) => ['queued', 'running', 'stopping'].includes(run.status)) ? 5000 : false,
  })
  const activeRun = runs.data?.find((run) => ['queued', 'running', 'stopping'].includes(run.status))
  const [target, setTarget] = useState('')
  const [scope, setScope] = useState<ScopeConfig>(emptyScope)
  const [entryValue, setEntryValue] = useState('')
  const [entryType, setEntryType] = useState<ScopeEntryType>('domain')
  const [entryDirection, setEntryDirection] = useState<'in' | 'out'>('in')

  useEffect(() => { if (project.data) setTarget(project.data.target) }, [project.data])
  useEffect(() => { if (scopeQuery.data) setScope(scopeQuery.data) }, [scopeQuery.data])
  useEffect(() => {
    if (!activeRun) return
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
    const socket = new WebSocket(`${protocol}//${window.location.host}/api/v1/projects/${projectId}/pipeline-runs/${activeRun.id}/events`)
    socket.onmessage = () => void queryClient.invalidateQueries({ queryKey: ['projects', projectId, 'pipeline-runs'] })
    socket.onerror = () => socket.close()
    return () => socket.close()
  }, [activeRun?.id, projectId, queryClient])

  const saveTarget = useMutation({
    mutationFn: () => api.updateProject(projectId, { target: target.trim() }),
    onSuccess: (data) => queryClient.setQueryData(['projects', projectId], data),
  })
  const saveScope = useMutation({
    mutationFn: (next: ScopeConfig) => api.updateScope(projectId, next),
    onSuccess: (data) => {
      setScope(data)
      queryClient.setQueryData(['projects', projectId, 'scope'], data)
    },
  })
  const startRun = useMutation({
    mutationFn: (pipelineKey: string) => api.startPipelineRun(projectId, pipelineKey),
    onSuccess: () => void queryClient.invalidateQueries({ queryKey: ['projects', projectId, 'pipeline-runs'] }),
  })
  const cancelRun = useMutation({
    mutationFn: (jobId: string) => api.cancelPipelineRun(projectId, jobId),
    onSuccess: () => void queryClient.invalidateQueries({ queryKey: ['projects', projectId, 'pipeline-runs'] }),
  })

  function addEntry(event: FormEvent) {
    event.preventDefault()
    const value = entryValue.trim()
    if (!value) return
    const next = {
      ...scope,
      entries: [...scope.entries, { value, entry_type: entryType, in_scope: entryDirection === 'in' }],
    }
    setScope(next)
    setEntryValue('')
    saveScope.mutate(next)
  }

  function removeEntry(index: number) {
    const next = { ...scope, entries: scope.entries.filter((_, itemIndex) => itemIndex !== index) }
    setScope(next)
    saveScope.mutate(next)
  }

  function toggleSubdomains() {
    const next = { ...scope, include_subdomains: !scope.include_subdomains }
    setScope(next)
    saveScope.mutate(next)
  }

  if (project.isPending || scopeQuery.isPending) return <main className="page"><p className="muted">Loading workspace…</p></main>
  if (project.isError || scopeQuery.isError) return <main className="page"><p className="error">Could not load this project.</p></main>

  return (
    <main className="page">
      <Link className="back-link" to="/projects">← All projects</Link>
      <header className="page-header workspace-header">
        <div><p className="eyebrow">Project workspace</p><h1>{project.data.name}</h1></div>
        <span className="status"><i /> Saved remotely</span>
      </header>

      <section className="panel target-panel">
        <div><p className="eyebrow">Primary target</p><h2>Where should AWE focus?</h2><p className="muted">Use an absolute URL or hostname.</p></div>
        <form onSubmit={(event) => { event.preventDefault(); saveTarget.mutate() }}>
          <label>Target<input value={target} onChange={(event) => setTarget(event.target.value)} placeholder="https://example.com" /></label>
          <button disabled={saveTarget.isPending}>{saveTarget.isPending ? 'Saving…' : 'Save target'}</button>
        </form>
      </section>

      <section className="scope-layout">
        <div className="panel scope-editor">
          <div className="scope-heading"><div><p className="eyebrow">Boundaries</p><h2>Scope rules</h2></div><label className="toggle"><input type="checkbox" checked={scope.include_subdomains} onChange={toggleSubdomains} /> Include subdomains</label></div>
          <form className="scope-form" onSubmit={addEntry}>
            <select value={entryDirection} onChange={(event) => setEntryDirection(event.target.value as 'in' | 'out')}><option value="in">In scope</option><option value="out">Excluded</option></select>
            <select value={entryType} onChange={(event) => setEntryType(event.target.value as ScopeEntryType)}><option>domain</option><option>wildcard</option><option>url</option><option>regex</option></select>
            <input value={entryValue} onChange={(event) => setEntryValue(event.target.value)} placeholder="example.com" />
            <button>Add rule</button>
          </form>
          <div className="scope-list">
            {scope.entries.length === 0 && <div className="empty compact">No restrictions. All targets are currently in scope.</div>}
            {scope.entries.map((entry, index) => (
              <div className={`scope-row ${entry.in_scope ? 'scope-in' : 'scope-out'}`} key={`${entry.value}-${index}`}>
                <span className="rule-direction">{entry.in_scope ? 'IN' : 'OUT'}</span><span className="rule-type">{entry.entry_type}</span><code>{entry.value}</code><button onClick={() => removeEntry(index)}>Remove</button>
              </div>
            ))}
          </div>
          {saveScope.isError && <p className="error">Scope could not be saved. Reload before making more changes.</p>}
        </div>
        <aside className="panel scope-help"><p className="eyebrow">Matching order</p><h2>Exclusions always win</h2><p>Out-of-scope rules override matching inclusions. Domain rules include child hosts when the subdomain option is enabled.</p><dl><dt>domain</dt><dd>Exact host or its subdomains</dd><dt>wildcard</dt><dd>Apex and every child host</dd><dt>url</dt><dd>Host and path prefix</dd><dt>regex</dt><dd>Advanced host expression</dd></dl></aside>
      </section>

      <section className="pipeline-section">
        <div className="section-title"><h2>Available pipelines</h2><span>{pipelines.data?.length ?? 0}</span></div>
        <p className="muted">Templates are loaded from AWE's existing pipeline catalogue. Execution controls are being moved out of Qt next.</p>
        {pipelines.isError && <p className="error">The pipeline catalogue is unavailable.</p>}
        <div className="pipeline-grid">
          {pipelines.data?.map((pipeline) => {
            const run = runs.data?.find((item) => item.pipeline_key === pipeline.key)
            const active = run && ['queued', 'running', 'stopping'].includes(run.status)
            return (
              <article className="pipeline-card" key={pipeline.key}>
                <div><span className="category-tag">{pipeline.category}</span><h3>{pipeline.name}</h3><p>{pipeline.description}</p></div>
                {run && <div className={`run-state run-${run.status}`}><span>{run.status}</span><strong>{run.progress_total ? `${run.progress_completed}/${run.progress_total}` : '—'}</strong></div>}
                <footer><span>{pipeline.steps.length} tools</span><span>{Math.max(...pipeline.steps.map((step) => step.stage)) + 1} stages</span>{active ? <button className="cancel-button" disabled={run.status === 'stopping'} onClick={() => cancelRun.mutate(run.id)}>{run.status === 'stopping' ? 'Stopping…' : 'Cancel'}</button> : <button disabled={startRun.isPending || !project.data.target} onClick={() => startRun.mutate(pipeline.key)}>Run</button>}</footer>
              </article>
            )
          })}
        </div>
        {(startRun.isError || cancelRun.isError) && <p className="error">{(startRun.error ?? cancelRun.error)?.message}</p>}
        {runs.data?.[0] && <div className="panel live-console"><div className="console-head"><span>Latest run</span><strong>{runs.data[0].pipeline_key} · {runs.data[0].status}</strong></div><pre>{runs.data[0].events.filter((event) => event.type === 'pipeline.tool_log').slice(-30).map((event) => `[${String(event.data.tool_key)}] ${String(event.data.line)}`).join('\n') || runs.data[0].message || 'Waiting for pipeline output…'}</pre></div>}
      </section>

    </main>
  )
}
