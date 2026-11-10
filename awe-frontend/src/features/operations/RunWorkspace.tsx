import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Link, useParams } from 'react-router-dom'
import { runtime, type RunEvent } from '../../api/runtime'
import { OptionsMenu } from '../../components/OptionsMenu'

export function RunWorkspace() {
  const { projectId = '', runId = '' } = useParams()
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
  const runs = useQuery({ queryKey: ['runs', projectId], queryFn: () => runtime.runs(projectId), refetchInterval: 2000 })
  const run = useQuery({ queryKey: ['run', projectId, runId], queryFn: () => runtime.run(projectId, runId), enabled: !!runId, refetchInterval: 2000 })
  const logs = useQuery({ queryKey: ['run-events', projectId, runId, cursor, search], queryFn: () => runtime.events(projectId, runId, cursor, search), enabled: !!runId && tab === 'Logs', refetchInterval: 1500 })
  const artifacts = useQuery({ queryKey: ['run-artifacts', projectId, runId], queryFn: () => runtime.artifacts(projectId, runId), enabled: !!runId })
  const sessions = useQuery({ queryKey: ['run-sessions', projectId, runId], queryFn: () => runtime.sessions(projectId), enabled: !!runId && tab === 'Sessions', refetchInterval: 2000 })
  const refresh = useMutation({ mutationFn: () => runtime.refreshArtifacts(projectId, runId), onSuccess: () => qc.invalidateQueries({ queryKey: ['run-artifacts', projectId, runId] }) })
  const promote = useMutation({ mutationFn: () => runtime.evidence(projectId, runId, { title, interpretation, start_sequence: start, end_sequence: end, artifact_id: artifactId, investigation_id: investigationId, entity_ids: entityIds.split(',').map(s => s.trim()).filter(Boolean) }), onSuccess: () => qc.invalidateQueries({ queryKey: ['projects', projectId, 'evidence'] }) })
  const error = run.error || logs.error || artifacts.error || refresh.error || promote.error
  return <main className="page feature-page run-workspace"><header className="panel"><b>Tool runs</b><OptionsMenu label="Run options"><Link to={`/projects/${projectId}/network/tools`}>Tool catalog</Link><Link to={`/projects/${projectId}/terminal/sessions`}>Interactive sessions</Link></OptionsMenu></header>
    {error && <p className="error">{error.message}</p>}
    <section className="runtime-workbench"><aside className="panel runtime-list">{runs.data?.map(item => <Link key={item.id} to={`/projects/${projectId}/runs/${item.id}`} onClick={() => { setCursor(0); setHistory([]) }}><b>{item.kind}</b><span>{item.status}</span><small>{item.id}</small></Link>)}</aside>
      <article className="panel runtime-detail">{!runId ? <p>Select a tool run to inspect its outputs.</p> : <><header><b>{run.data?.kind}</b><span>{run.data?.status}</span></header><nav className="runtime-tabs">{['Overview', 'Logs', 'Results', 'Artifacts', 'Sessions', 'Evidence'].map(name => <button className={tab === name ? 'selected' : ''} key={name} onClick={() => setTab(name)}>{name}</button>)}</nav>
        {tab === 'Overview' && <div><p>{run.data?.message || 'Execution is tracked independently from findings.'}</p><p>Exit code: {run.data?.exit_code ?? 'Pending'}</p>{run.data?.parser_error && <p className="error">Parser warning: {run.data.parser_error}</p>}{run.data?.logs_truncated && <p className="error">Transcript recording reached its size limit.</p>}<Link to={`/projects/${projectId}/network/transforms`}>Transforms</Link></div>}
        {tab === 'Logs' && <><div className="runtime-toolbar"><input aria-label="Search run output" placeholder="Search output" value={search} onChange={e => { setSearch(e.target.value); setCursor(0); setHistory([]) }} /><a href={`/api/v1/projects/${projectId}/runs/${runId}/transcript`}>Download transcript</a></div><pre className="runtime-log">{[...history, ...(logs.data?.events || [])].map(e => <span key={e.sequence}>{e.sequence} [{e.stream}] {e.data}{'\n'}</span>)}</pre><button disabled={!logs.data?.events.length} onClick={() => { setHistory(previous => [...previous, ...(logs.data?.events || [])].slice(-1000)); setCursor(logs.data?.cursor || 0) }}>Load next output</button></>}
        {tab === 'Results' && <><p>Parsed results and graph ingestion are separate from execution success.</p><pre>{JSON.stringify(run.data?.result || {}, null, 2)}</pre><Link to={`/projects/${projectId}/results`}>Open Results</Link></>}
        {tab === 'Artifacts' && <><button onClick={() => refresh.mutate()} disabled={refresh.isPending}>Refresh artifacts</button>{run.data?.artifacts_truncated && <p>Artifact collection reached its size limit.</p>}{artifacts.data?.map(a => <article className="runtime-artifact" key={a.id}><a href={`/api/v1/projects/${projectId}/runs/${runId}/artifacts/${a.id}`}>{a.name}</a><span>{a.mime_type} · {a.size} bytes</span><small>{a.sha256}</small>{(a.mime_type.startsWith('text/') || ['image/png', 'image/jpeg', 'image/gif', 'image/webp', 'application/json'].includes(a.mime_type)) && <a target="_blank" rel="noopener noreferrer" href={`/api/v1/projects/${projectId}/runs/${runId}/artifacts/${a.id}?preview=true`}>Preview</a>}<button onClick={() => { setArtifactId(a.id); setTitle(a.name); setTab('Evidence') }}>Use as evidence</button></article>)}</>}
        {tab === 'Sessions' && <>{sessions.data?.filter(s => s.run_id === runId).map(s => <Link key={s.id} to={`/projects/${projectId}/terminal/sessions?session=${s.id}`}>{s.label} · {s.status}</Link>)}<Link to={`/projects/${projectId}/terminal/sessions?run=${runId}`}>Create an associated connection or callback listener</Link></>}
        {tab === 'Evidence' && <div className="runtime-evidence"><label>Investigation ID (optional)<input value={investigationId} onChange={e => setInvestigationId(e.target.value)} /></label><label>Graph entity IDs (comma-separated, optional)<input value={entityIds} onChange={e => setEntityIds(e.target.value)} /></label></div>}
        {tab === 'Evidence' && <section className="runtime-evidence"><label>Evidence title<input value={title} onChange={e => setTitle(e.target.value)} /></label><label>Researcher interpretation<textarea value={interpretation} onChange={e => setInterpretation(e.target.value)} /></label>{artifactId ? <p>Selected artifact: {artifactId} <button onClick={() => setArtifactId('')}>Use log range instead</button></p> : <><label>First event<input type="number" min="1" value={start} onChange={e => setStart(Number(e.target.value))} /></label><label>Last event<input type="number" min="1" value={end} onChange={e => setEnd(Number(e.target.value))} /></label></>}<button disabled={!title || promote.isPending} onClick={() => promote.mutate()}>Save evidence</button>{promote.isSuccess && <p className="success">Evidence saved with source provenance.</p>}</section>}
      </>}</article></section>
  </main>
}
