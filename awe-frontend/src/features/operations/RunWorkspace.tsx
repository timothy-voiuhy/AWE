import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Link, useParams } from 'react-router-dom'
import { api } from '../../api/client'
import { runtime, type ToolRun } from '../../api/runtime'
import { OptionsMenu } from '../../components/OptionsMenu'
import { RunDetail } from './RunDetail'
import { activeRunStatuses, RunStatus, runType } from './runPresentation'
import './run-workspace.css'

export function RunWorkspace() {
  const { projectId = '', runId = '' } = useParams()
  const [search, setSearch] = useState('')
  const [filter, setFilter] = useState('all')
  const runs = useQuery({ queryKey: ['runs', projectId], queryFn: () => runtime.runs(projectId), refetchInterval: 2000 })
  const tools = useQuery({ queryKey: ['docker', 'tools'], queryFn: api.listDockerTools })
  const items = [...(runs.data || [])].sort((a, b) => b.created_at.localeCompare(a.created_at))
  const nameFor = (item: ToolRun) => {
    const key = item.tool_key || item.kind.split('.').pop()
    return tools.data?.find(tool => tool.key === key)?.display_name || key?.replaceAll('_', ' ') || item.kind
  }
  const counts = { all: items.length, active: items.filter(item => activeRunStatuses.has(item.status)).length, completed: items.filter(item => item.status === 'completed').length, failed: items.filter(item => item.status === 'failed').length }
  const visible = items.filter(item => (filter === 'all' || (filter === 'active' ? activeRunStatuses.has(item.status) : item.status === filter)) && `${nameFor(item)} ${item.kind} ${item.id} ${item.message || ''}`.toLowerCase().includes(search.toLowerCase()))

  return <main className="page feature-page run-workspace">
    <header className="panel run-workspace-header"><div><b>Tool runs</b><span>Execution history, output, and evidence</span></div><OptionsMenu label="Run options"><Link to={`/projects/${projectId}/network/transforms`}>Transforms & tools</Link><Link to={`/projects/${projectId}/terminal/sessions`}>Interactive sessions</Link></OptionsMenu></header>
    <nav className="run-summary" aria-label="Filter tool runs">{(['all', 'active', 'completed', 'failed'] as const).map(value => <button key={value} aria-pressed={filter === value} onClick={() => setFilter(value)}><span>{value === 'all' ? 'All runs' : value}</span><b>{counts[value]}</b></button>)}</nav>
    {runs.isError && <p className="error" role="alert">{runs.error.message}</p>}
    <section className="runtime-workbench">
      <aside className="panel run-history" aria-label="Run history">
        <header><b>History</b><span>{visible.length} {visible.length === 1 ? 'run' : 'runs'}</span></header>
        <div className="run-history-search"><input aria-label="Search tool runs" placeholder="Search tools, IDs, or messages…" value={search} onChange={event => setSearch(event.target.value)} /></div>
        <nav className="run-history-items" aria-label="Tool run selection">
          {runs.isPending ? <p className="muted run-list-message">Loading runs…</p> : visible.length ? visible.map(item => <Link key={item.id} to={`/projects/${projectId}/runs/${item.id}`} aria-current={runId === item.id ? 'page' : undefined}>
            <div className="run-history-heading"><b>{nameFor(item)}</b><RunStatus status={item.status} /></div>
            <span>{runType(item)}</span><p>{item.message || 'Open to inspect output'}</p>
            <footer><time dateTime={item.created_at}>{new Date(item.created_at).toLocaleString(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' })}</time><code>{item.id.slice(0, 8)}</code></footer>
          </Link>) : <div className="run-list-message"><b>{items.length ? 'No matching runs' : 'No runs yet'}</b><p>{items.length ? 'Try another search or status filter.' : 'Run a transform or register a PoC to start recording output.'}</p>{(search || filter !== 'all') && <button className="subtle" onClick={() => { setSearch(''); setFilter('all') }}>Clear filters</button>}</div>}
        </nav>
      </aside>
      {runId ? <RunDetail key={`${projectId}:${runId}`} projectId={projectId} runId={runId} nameFor={nameFor} /> : <article className="panel runtime-detail run-selection-empty"><div className="runtime-empty"><span className="run-empty-glyph" aria-hidden="true">▤</span><b>{items.length ? 'Your output, in one place' : 'Ready for your first run'}</b><p>{items.length ? 'Choose a run from history to review its transcript, files, sessions, and evidence.' : 'Start a transform or build a PoC. Its execution history and outputs will appear here.'}</p><Link className="button-link" to={`/projects/${projectId}/network/transforms`}>Open transforms</Link></div></article>}
    </section>
  </main>
}
