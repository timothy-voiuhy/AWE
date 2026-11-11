import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import { runtime, type RunEvent, type ToolRun } from '../../api/runtime'
import { RunStatus, runType } from './runPresentation'

function fileSize(bytes: number) {
  return bytes < 1024 ? `${bytes} B` : bytes < 1024 * 1024 ? `${(bytes / 1024).toFixed(1)} KB` : `${(bytes / 1024 / 1024).toFixed(1)} MB`
}

export function RunDetail({ projectId, runId, nameFor }: { projectId: string; runId: string; nameFor: (run: ToolRun) => string }) {
  const qc = useQueryClient()
  const [tab, setTab] = useState('Overview')
  const [search, setSearch] = useState('')
  const [cursor, setCursor] = useState(0)
  const [history, setHistory] = useState<RunEvent[]>([])
  const [title, setTitle] = useState('Tool output')
  const [interpretation, setInterpretation] = useState('')
  const [start, setStart] = useState(1)
  const [end, setEnd] = useState(100)
  const [artifactId, setArtifactId] = useState('')
  const [entityIds, setEntityIds] = useState('')
  const [investigationId, setInvestigationId] = useState('')
  const run = useQuery({ queryKey: ['run', projectId, runId], queryFn: () => runtime.run(projectId, runId), refetchInterval: 2000 })
  const logs = useQuery({ queryKey: ['run-events', projectId, runId, cursor, search], queryFn: () => runtime.events(projectId, runId, cursor, search), enabled: tab === 'Logs', refetchInterval: 1500 })
  const artifacts = useQuery({ queryKey: ['run-artifacts', projectId, runId], queryFn: () => runtime.artifacts(projectId, runId), refetchInterval: ['running', 'queued'].includes(run.data?.status || '') ? 2000 : false })
  const sessions = useQuery({ queryKey: ['run-sessions', projectId, runId], queryFn: () => runtime.sessions(projectId), enabled: tab === 'Sessions', refetchInterval: 2000 })
  const refresh = useMutation({ mutationFn: () => runtime.refreshArtifacts(projectId, runId), onSuccess: () => qc.invalidateQueries({ queryKey: ['run-artifacts', projectId, runId] }) })
  const promote = useMutation({ mutationFn: () => runtime.evidence(projectId, runId, { title, interpretation, start_sequence: start, end_sequence: end, artifact_id: artifactId, investigation_id: investigationId, entity_ids: entityIds.split(',').map(s => s.trim()).filter(Boolean) }), onSuccess: () => qc.invalidateQueries({ queryKey: ['projects', projectId, 'evidence'] }) })
  const error = run.error || logs.error || artifacts.error || sessions.error || refresh.error || promote.error
  const data = run.data
  const events = [...history, ...(logs.data?.events || [])]
  const associatedSessions = sessions.data?.filter(session => session.run_id === runId) || []
  const source = data?.source_metadata
  const artifactBase = `/api/v1/projects/${projectId}/runs/${runId}/artifacts`

  return <article className="panel runtime-detail">
    {error && <p className="error" role="alert">{error.message}</p>}
    {!data ? <div className="runtime-empty"><b>{run.isPending ? 'Loading run…' : 'Run unavailable'}</b><p>{run.isPending ? 'Retrieving execution details and outputs.' : 'Select another run from history or try refreshing the page.'}</p></div> : <>
      <header className="run-detail-heading"><div><span className="run-type-label">{runType(data)}</span><h1>{nameFor(data)}</h1><time dateTime={data.created_at}>{new Date(data.created_at).toLocaleString()}</time></div><RunStatus status={data.status} /></header>
      <div className="run-detail-id"><span>Run</span><code>{runId}</code>{data.session_id && <Link to={`/projects/${projectId}/terminal/sessions?session=${data.session_id}`}>Open session ↗</Link>}</div>
      <nav className="runtime-tabs" role="tablist" aria-label="Run output">{['Overview', 'Logs', 'Results', 'Artifacts', 'Sessions', 'Evidence'].map(name => <button role="tab" id={`run-tab-${name}`} aria-selected={tab === name} aria-controls="run-output-panel" className={tab === name ? 'selected' : ''} key={name} onClick={() => setTab(name)}>{name}{name === 'Artifacts' && !!artifacts.data?.length && <span>{artifacts.data.length}</span>}</button>)}</nav>
      <section id="run-output-panel" role="tabpanel" aria-labelledby={`run-tab-${tab}`} className="run-tab-content">
        {tab === 'Overview' && <>
          <p className="run-message">{data.message || (data.status === 'running' ? 'Execution is in progress. Output updates automatically.' : 'Review the recorded outputs below.')}</p>
          <dl className="run-facts"><div><dt>Execution</dt><dd>{data.execution_kind || (data.kind.startsWith('poc.build.') ? 'Image build' : 'Batch')}</dd></div><div><dt>Exit code</dt><dd>{data.exit_code ?? 'Not reported'}</dd></div><div><dt>Recorded events</dt><dd>{data.last_sequence ?? 0}</dd></div><div><dt>Artifacts</dt><dd>{artifacts.data?.length ?? '—'}</dd></div></dl>
          {data.parser_error && <p className="error">Parser warning: {data.parser_error}</p>}
          {data.logs_truncated && <p className="error">Transcript recording reached its size limit.</p>}
          <div className="run-overview-section"><b>Outputs</b><div className="run-output-channels">{(data.output_channels || ['logs']).map(channel => <button className="subtle" key={channel} onClick={() => setTab(channel === 'logs' ? 'Logs' : channel === 'session' ? 'Sessions' : channel === 'artifacts' ? 'Artifacts' : 'Results')}>{channel === 'structured' ? 'Structured results' : channel === 'session' ? 'Interactive sessions' : channel}</button>)}</div></div>
          {data.image && <div className="run-overview-section"><b>Container image</b><code className="run-source-value">{data.image}</code></div>}
          {source && <div className="run-overview-section"><b>Source snapshot</b>{source.repository && <a href={source.repository} target="_blank" rel="noopener noreferrer">{source.repository}</a>}<code className="run-source-value">{source.revision || source.sha256}</code></div>}
          {!!data.parameters && <details className="run-parameters"><summary>Run parameters</summary><pre>{JSON.stringify(data.parameters, null, 2)}</pre></details>}
        </>}
        {tab === 'Logs' && <>
          <div className="runtime-toolbar"><input aria-label="Search run output" placeholder="Find in output…" value={search} onChange={event => { setSearch(event.target.value); setCursor(0); setHistory([]) }} /><a className="button-link subtle" href={`/api/v1/projects/${projectId}/runs/${runId}/transcript`}>Download transcript</a></div>
          <div className="run-console"><header><span><i aria-hidden="true" />Recorded output</span><small>{events.length} events shown</small></header><pre className="runtime-log">{events.length ? events.map(event => <span className={`run-log-line stream-${event.stream}`} key={event.sequence}><small>{event.sequence} · {event.stream}</small><span>{event.data.replace(/\n$/, '')}</span></span>) : <span className="run-log-placeholder">{logs.isPending ? 'Loading output…' : search ? 'No output matches your search.' : 'No output recorded yet.'}</span>}</pre></div>
          <footer className="run-output-footer"><span>Output refreshes automatically.</span><button className="subtle" disabled={!logs.data?.events.length} onClick={() => { setHistory(previous => [...previous, ...(logs.data?.events || [])].slice(-1000)); setCursor(logs.data?.cursor || 0) }}>Load next output</button></footer>
        </>}
        {tab === 'Results' && <><div className="run-section-heading"><div><b>Structured results</b><p>Parsed output and graph ingestion details.</p></div><Link className="button-link subtle" to={`/projects/${projectId}/results`}>Open Results ↗</Link></div>{data.parsing_status && <p className="muted">Parsing: {data.parsing_status.replaceAll('_', ' ')}</p>}{data.result && Object.keys(data.result).length ? <pre className="run-json">{JSON.stringify(data.result, null, 2)}</pre> : <div className="runtime-empty"><b>No structured results</b><p>This run may produce logs, files, or an interactive session. Review those outputs and save your interpretation as evidence.</p></div>}</>}
        {tab === 'Artifacts' && <>
          <div className="run-section-heading"><div><b>Collected files</b><p>Downloads and previews from this run.</p></div><button className="subtle" onClick={() => refresh.mutate()} disabled={refresh.isPending}>{refresh.isPending ? 'Collecting…' : 'Refresh artifacts'}</button></div>
          {data.artifacts_truncated && <p className="error">Artifact collection reached its size limit.</p>}
          {artifacts.isPending ? <p className="muted">Loading artifacts…</p> : !artifacts.data?.length ? <div className="runtime-empty"><b>No artifacts collected</b><p>Files written to the tool’s output directory will appear here. Refresh after the tool creates a file.</p></div> : <div className="run-artifacts">{artifacts.data.map(artifact => <article className="runtime-artifact" key={artifact.id}><div className="run-artifact-name"><span aria-hidden="true">▧</span><div><a href={`${artifactBase}/${artifact.id}`}>{artifact.name}</a><small>{artifact.mime_type} · {fileSize(artifact.size)}</small></div></div><details><summary>File checksum</summary><code>{artifact.sha256}</code></details><div className="run-artifact-actions">{(artifact.mime_type.startsWith('text/') || ['image/png', 'image/jpeg', 'image/gif', 'image/webp', 'application/json'].includes(artifact.mime_type)) && <a className="button-link subtle" target="_blank" rel="noopener noreferrer" href={`${artifactBase}/${artifact.id}?preview=true`}>Preview ↗</a>}<button className="subtle" onClick={() => { setArtifactId(artifact.id); setTitle(artifact.name); promote.reset(); setTab('Evidence') }}>Use as evidence</button></div></article>)}</div>}
        </>}
        {tab === 'Sessions' && <><div className="run-section-heading"><div><b>Associated sessions</b><p>Attach to a console or connect a callback listener.</p></div></div>{sessions.isPending ? <p className="muted">Loading sessions…</p> : associatedSessions.length ? <div className="run-session-list">{associatedSessions.map(session => <Link key={session.id} to={`/projects/${projectId}/terminal/sessions?session=${session.id}`}><div><b>{session.label}</b><span>{session.kind}</span></div><RunStatus status={session.status} /></Link>)}</div> : <div className="runtime-empty"><b>No sessions attached</b><p>Associate a connection with this run to keep its output and evidence together.</p></div>}<Link className="button-link subtle" to={`/projects/${projectId}/terminal/sessions?run=${runId}`}>Create an associated connection or callback listener</Link></>}
        {tab === 'Evidence' && <>
          <div className="run-section-heading"><div><b>Save research evidence</b><p>Keep your interpretation linked to the original run and source output.</p></div></div>
          <div className="runtime-evidence run-evidence-form"><label className="run-field-wide">Evidence title<input value={title} onChange={event => setTitle(event.target.value)} /></label><label className="run-field-wide">Researcher interpretation<textarea value={interpretation} onChange={event => setInterpretation(event.target.value)} placeholder="What did you observe, and why does it matter?" /></label>{artifactId ? <div className="run-field-wide run-evidence-source"><b>File: {artifacts.data?.find(item => item.id === artifactId)?.name || artifactId}</b><button className="subtle" onClick={() => setArtifactId('')}>Use log range instead</button></div> : <><label>First event<input type="number" min="1" value={start} onChange={event => setStart(Number(event.target.value))} /></label><label>Last event<input type="number" min={start} value={end} onChange={event => setEnd(Number(event.target.value))} /></label></>}<details className="run-field-wide"><summary>Link to an investigation or graph entities</summary><div className="run-evidence-links"><label>Investigation ID (optional)<input value={investigationId} onChange={event => setInvestigationId(event.target.value)} /></label><label>Graph entity IDs (comma-separated, optional)<input value={entityIds} onChange={event => setEntityIds(event.target.value)} /></label></div></details><footer className="run-field-wide"><button disabled={!title.trim() || (!artifactId && (start < 1 || end < start)) || promote.isPending} onClick={() => promote.mutate()}>{promote.isPending ? 'Saving…' : 'Save evidence'}</button>{promote.isSuccess && <p className="success" role="status">Evidence saved with source provenance.</p>}</footer></div>
        </>}
      </section>
    </>}
  </article>
}
