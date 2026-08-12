import { FormEvent, useEffect, useMemo, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Link, useNavigate, useParams } from 'react-router-dom'

import { api, AuthSessionEntry, MethodologyStatus, ScopeConfig, ScopeEntryType, TrafficEntry } from '../../api/client'

type WorkbenchTab = 'target' | 'scope' | 'sessions' | 'flow' | 'notes'
const emptyScope: ScopeConfig = { entries: [], include_subdomains: true }
const emptySession = (): Omit<AuthSessionEntry, 'id'> => ({ name: 'New Session', headers: [], params: [] })

function displayHost(target: string) {
  try { return new URL(target).host } catch { return target || 'No target configured' }
}

function displayUrl(entry: TrafficEntry) {
  const raw = entry.request?.url
  if (typeof raw === 'string' && raw) return raw
  return `https://${entry.host}${entry.path || '/'}`
}

function requestHeaders(entry: TrafficEntry) {
  const value = entry.request?.headers
  if (Array.isArray(value)) return Object.fromEntries(value.map((item) => Array.isArray(item) ? [String(item[0]), String(item[1] ?? '')] : ['', '']).filter(([key]) => key))
  if (value && typeof value === 'object') return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, Array.isArray(item) ? item.join(', ') : String(item)]))
  return {}
}

function requestBody(entry: TrafficEntry) {
  const value = entry.request?.body ?? entry.request?.body_text
  return typeof value === 'string' ? value : value ? JSON.stringify(value) : ''
}

function formatDate(value?: string | null) {
  if (!value) return '—'
  const date = new Date(value)
  return Number.isNaN(date.valueOf()) ? value : date.toLocaleString()
}

const methodologyStatuses: MethodologyStatus[] = ['not_tested', 'in_progress', 'tested_clean', 'vulnerable', 'na']
const methodologyStatusLabels: Record<MethodologyStatus, string> = { not_tested: 'Not tested', in_progress: 'In progress', tested_clean: 'Clean', vulnerable: 'Vulnerable!', na: 'N/A' }

function escapeMarkdownHtml(value: string) {
  return value.replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;').replaceAll('"', '&quot;')
}

function renderMarkdownInline(value: string) {
  const codeTokens: string[] = []
  let html = escapeMarkdownHtml(value).replace(/`([^`]+)`/g, (_, code: string) => {
    const token = `AWEINCODE${codeTokens.length}X`
    codeTokens.push(`<code>${code}</code>`)
    return token
  })
  html = html.replace(/\[([^\]]+)\]\((https?:\/\/[^\s)]+)\)/g, '<a href="$2" target="_blank" rel="noreferrer">$1</a>')
  html = html.replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>')
  html = html.replace(/__([^_]+)__/g, '<strong>$1</strong>')
  html = html.replace(/\*([^*]+)\*/g, '<em>$1</em>')
  html = html.replace(/_([^_]+)_/g, '<em>$1</em>')
  return html.replace(/AWEINCODE(\d+)X/g, (_, index: string) => codeTokens[Number(index)] ?? '')
}

function renderMarkdown(markdown: string) {
  const lines = markdown.replaceAll('\r\n', '\n').split('\n')
  const html: string[] = []
  let paragraph: string[] = []
  let code: string[] | null = null
  let codeLanguage = ''
  const flushParagraph = () => {
    if (!paragraph.length) return
    html.push(`<p>${renderMarkdownInline(paragraph.join(' '))}</p>`)
    paragraph = []
  }
  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index]
    const fence = line.match(/^\s*```\s*([\w+-]*)\s*$/)
    if (fence) {
      if (code) {
        const languageClass = codeLanguage ? ` class="language-${codeLanguage}"` : ''
        html.push(`<pre><code${languageClass}>${escapeMarkdownHtml(code.join('\n'))}</code></pre>`)
        code = null
        codeLanguage = ''
      } else {
        flushParagraph()
        code = []
        codeLanguage = (fence[1] || '').replace(/[^\w+-]/g, '')
      }
      continue
    }
    if (code) { code.push(line); continue }
    if (!line.trim()) { flushParagraph(); continue }
    const heading = line.match(/^\s*(#{1,6})\s+(.+?)\s*#*\s*$/)
    if (heading) { flushParagraph(); const level = heading[1].length; html.push(`<h${level}>${renderMarkdownInline(heading[2])}</h${level}>`); continue }
    if (/^\s*([-*_])(?:\s*\1){2,}\s*$/.test(line)) { flushParagraph(); html.push('<hr />'); continue }
    if (/^\s*[-*+]\s+/.test(line)) {
      flushParagraph(); const items: string[] = []
      while (index < lines.length && /^\s*[-*+]\s+/.test(lines[index])) { items.push(`<li>${renderMarkdownInline(lines[index].replace(/^\s*[-*+]\s+/, ''))}</li>`); index += 1 }
      index -= 1; html.push(`<ul>${items.join('')}</ul>`); continue
    }
    if (/^\s*\d+[.)]\s+/.test(line)) {
      flushParagraph(); const items: string[] = []
      while (index < lines.length && /^\s*\d+[.)]\s+/.test(lines[index])) { items.push(`<li>${renderMarkdownInline(lines[index].replace(/^\s*\d+[.)]\s+/, ''))}</li>`); index += 1 }
      index -= 1; html.push(`<ol>${items.join('')}</ol>`); continue
    }
    if (/^\s*>\s?/.test(line)) {
      flushParagraph(); const quote: string[] = []
      while (index < lines.length && /^\s*>\s?/.test(lines[index])) { quote.push(renderMarkdownInline(lines[index].replace(/^\s*>\s?/, ''))); index += 1 }
      index -= 1; html.push(`<blockquote>${quote.join('<br />')}</blockquote>`); continue
    }
    paragraph.push(line.trim())
  }
  if (code) html.push(`<pre><code>${escapeMarkdownHtml(code.join('\n'))}</code></pre>`)
  flushParagraph()
  return html.join('')
}

function SessionRows({ rows, onChange }: { rows: string[][]; onChange: (rows: string[][]) => void }) {
  return <div className="target-session-rows">
    {rows.map((row, index) => <div className="target-session-row" key={`${index}-${row[0]}`}>
      <input value={row[0] ?? ''} placeholder="Name" onChange={(event) => onChange(rows.map((item, rowIndex) => rowIndex === index ? [event.target.value, item[1] ?? ''] : item))} />
      <input value={row[1] ?? ''} placeholder="Value" onChange={(event) => onChange(rows.map((item, rowIndex) => rowIndex === index ? [item[0] ?? '', event.target.value] : item))} />
      <button type="button" className="ghost-button" onClick={() => onChange(rows.filter((_, rowIndex) => rowIndex !== index))}>×</button>
    </div>)}
    <button type="button" className="subtle-button" onClick={() => onChange([...rows, ['', '']])}>＋ Add row</button>
  </div>
}

export function ProjectWorkspace() {
  const { projectId = '' } = useParams()
  const navigate = useNavigate()
  const queryClient = useQueryClient()
  const [tab, setTab] = useState<WorkbenchTab>('target')
  const [target, setTarget] = useState('')
  const [scope, setScope] = useState<ScopeConfig>(emptyScope)
  const [entryValue, setEntryValue] = useState('')
  const [entryType, setEntryType] = useState<ScopeEntryType>('domain')
  const [entryDirection, setEntryDirection] = useState<'in' | 'out'>('in')
  const [notes, setNotes] = useState('')
  const [notesLoaded, setNotesLoaded] = useState(false)
  const [selectedSessionId, setSelectedSessionId] = useState('')
  const [sessionDraft, setSessionDraft] = useState<Omit<AuthSessionEntry, 'id'>>(emptySession)

  const project = useQuery({ queryKey: ['projects', projectId], queryFn: () => api.getProject(projectId), enabled: Boolean(projectId) })
  const scopeQuery = useQuery({ queryKey: ['projects', projectId, 'scope'], queryFn: () => api.getScope(projectId), enabled: Boolean(projectId) })
  const notesQuery = useQuery({ queryKey: ['projects', projectId, 'notes'], queryFn: () => api.getNotes(projectId), enabled: Boolean(projectId) })
  const authSessions = useQuery({ queryKey: ['projects', projectId, 'auth-sessions'], queryFn: () => api.listAuthSessions(projectId), enabled: Boolean(projectId) })
  const traffic = useQuery({ queryKey: ['projects', projectId, 'traffic'], queryFn: () => api.listTraffic(projectId), enabled: Boolean(projectId), staleTime: 10_000 })
  const results = useQuery({ queryKey: ['projects', projectId, 'results'], queryFn: () => api.listProjectResults(projectId), enabled: Boolean(projectId), staleTime: 10_000 })
  const sessions = useQuery({ queryKey: ['projects', projectId, 'sessions'], queryFn: () => api.listSessions(projectId), enabled: Boolean(projectId) })
  const methodology = useQuery({ queryKey: ['projects', projectId, 'methodology'], queryFn: () => api.listMethodology(projectId), enabled: Boolean(projectId) })
  const runs = useQuery({
    queryKey: ['projects', projectId, 'pipeline-runs'],
    queryFn: () => api.listPipelineRuns(projectId),
    enabled: Boolean(projectId),
    refetchInterval: (query) => query.state.data?.some((run) => ['queued', 'running', 'stopping'].includes(run.status)) ? 3_000 : false,
  })
  const proxy = useQuery({ queryKey: ['proxy', 'info'], queryFn: api.getProxyInfo })
  const [selectedVulnerabilityId, setSelectedVulnerabilityId] = useState('')

  useEffect(() => { if (project.data) setTarget(project.data.target) }, [project.data])
  useEffect(() => { if (scopeQuery.data) setScope(scopeQuery.data) }, [scopeQuery.data])
  useEffect(() => { if (notesQuery.data) { setNotes(notesQuery.data.content); setNotesLoaded(true) } }, [notesQuery.data])

  const saveTarget = useMutation({ mutationFn: () => api.updateProject(projectId, { target: target.trim() }), onSuccess: (data) => queryClient.setQueryData(['projects', projectId], data) })
  const saveScope = useMutation({ mutationFn: (next: ScopeConfig) => api.updateScope(projectId, next), onSuccess: (data) => { setScope(data); queryClient.setQueryData(['projects', projectId, 'scope'], data) } })
  const saveNotes = useMutation({ mutationFn: () => api.saveNotes(projectId, notes), onSuccess: (data) => queryClient.setQueryData(['projects', projectId, 'notes'], data) })
  const methodologyDetail = useQuery({ queryKey: ['projects', projectId, 'methodology', selectedVulnerabilityId], queryFn: () => api.getMethodologyDetail(projectId, selectedVulnerabilityId), enabled: Boolean(selectedVulnerabilityId) })
  const updateMethodology = useMutation({ mutationFn: (data: { status: MethodologyStatus; notes: string }) => api.updateMethodology(projectId, selectedVulnerabilityId, data), onSuccess: (updated) => { queryClient.setQueryData(['projects', projectId, 'methodology', selectedVulnerabilityId], updated); void queryClient.invalidateQueries({ queryKey: ['projects', projectId, 'methodology'] }) } })
  const saveSession = useMutation({
    mutationFn: () => selectedSessionId ? api.updateAuthSession(projectId, selectedSessionId, sessionDraft) : api.createAuthSession(projectId, sessionDraft),
    onSuccess: (saved) => { setSelectedSessionId(saved.id); setSessionDraft(saved); void queryClient.invalidateQueries({ queryKey: ['projects', projectId, 'auth-sessions'] }) },
  })
  const deleteSession = useMutation({ mutationFn: (id: string) => api.deleteAuthSession(projectId, id), onSuccess: () => { setSelectedSessionId(''); setSessionDraft(emptySession()); void queryClient.invalidateQueries({ queryKey: ['projects', projectId, 'auth-sessions'] }) } })

  const orderedTraffic = useMemo(() => [...(traffic.data ?? [])].sort((a, b) => Date.parse(b.timestamp) - Date.parse(a.timestamp)), [traffic.data])
  const activeRun = runs.data?.find((run) => ['queued', 'running', 'stopping'].includes(run.status))
  const hostCount = new Set(orderedTraffic.map((item) => item.host).filter(Boolean)).size
  const endpointCount = new Set(orderedTraffic.map((item) => `${item.host}${item.path}`)).size
  const selectedSession = authSessions.data?.find((item) => item.id === selectedSessionId)

  function addEntry(event: FormEvent) {
    event.preventDefault()
    const value = entryValue.trim()
    if (!value) return
    const next = { ...scope, entries: [...scope.entries, { value, entry_type: entryType, in_scope: entryDirection === 'in' }] }
    setScope(next); setEntryValue(''); saveScope.mutate(next)
  }

  function selectAuthSession(id: string) {
    const next = authSessions.data?.find((item) => item.id === id)
    if (!next) return
    setSelectedSessionId(id); setSessionDraft({ name: next.name, headers: next.headers, params: next.params })
  }

  if (project.isPending || scopeQuery.isPending) return <main className="page"><p className="muted">Loading target workbench…</p></main>
  if (project.isError || scopeQuery.isError) return <main className="page"><p className="error">Could not load this project.</p></main>

  return <main className="page target-workspace">
    <Link className="back-link" to="/projects">← All projects</Link>
    <header className="page-header workspace-header target-workspace-header">
      <div><p className="eyebrow">Target window</p><h1>{project.data.name}</h1><p className="target-address"><span className="target-online" /> {project.data.target || 'Target not configured'} <small>· {displayHost(project.data.target)}</small></p></div>
      <div className="target-header-status"><span className="status"><i /> Workspace ready</span><small>{proxy.data ? `Proxy ${proxy.data.host}:${proxy.data.port}` : 'Proxy status unavailable'}</small></div>
    </header>

    <nav className="target-workbench-tabs" aria-label="Target window sections">
      {([['target', 'Target', '⌂'], ['scope', 'Scope', '◎'], ['sessions', 'Sessions', '⚿'], ['flow', 'Testing Flow', '⚡'], ['notes', 'Notes', '▤']] as [WorkbenchTab, string, string][]).map(([key, label, glyph]) => <button className={tab === key ? 'selected' : ''} onClick={() => setTab(key)} key={key}><span>{glyph}</span>{label}{key === 'sessions' && authSessions.data?.length ? <em>{authSessions.data.length}</em> : null}</button>)}
    </nav>

    {tab === 'target' && <section className="target-tab">
      <section className="target-stat-grid">
        <article className="panel target-stat"><span>Hosts observed</span><strong>{hostCount}</strong><small>Across scoped proxy traffic</small></article>
        <article className="panel target-stat"><span>Endpoints</span><strong>{endpointCount}</strong><small>Unique host and path pairs</small></article>
        <article className="panel target-stat"><span>Pipeline results</span><strong>{results.data?.length ?? 0}</strong><small>Deduplicated project records</small></article>
        <article className="panel target-stat"><span>Pipeline runs</span><strong>{sessions.data?.length ?? 0}</strong><small>{activeRun ? `${activeRun.status} now` : 'No active run'}</small></article>
      </section>
      <section className="target-overview-grid">
        <article className="panel target-focus-card"><header><div><p className="eyebrow">Primary target</p><h2>Keep the target window close</h2><p className="muted">The web target workspace now brings the desktop target, scope, session profiles, testing flow, and notes into one place.</p></div><span className={activeRun ? 'live-dot active' : 'live-dot'}>{activeRun ? `${activeRun.status} · ${activeRun.progress_completed}/${activeRun.progress_total}` : 'Idle'}</span></header><form onSubmit={(event) => { event.preventDefault(); saveTarget.mutate() }}><label>Target<input value={target} onChange={(event) => setTarget(event.target.value)} placeholder="https://example.com" /></label><button disabled={saveTarget.isPending}>{saveTarget.isPending ? 'Saving…' : 'Save target'}</button></form>{saveTarget.isError && <p className="error">{saveTarget.error.message}</p>}</article>
        <aside className="panel target-quick-actions"><header><p className="eyebrow">Workbenches</p><h2>Open a tool</h2></header><div>{[['/browser', 'Browser', 'Browse the target through the proxy.'], ['/sitemap', 'Site Map', 'Explore captured hosts and paths.'], ['/history', 'HTTP History', 'Inspect full request and response pairs.'], ['/network', 'Network', 'Map hosts, technologies, and relationships.'], ['/results', 'Results', 'Review pipeline and proxy-derived findings.'], ['/repeater', 'Repeater', 'Replay a request with the desktop-style editor.']].map(([path, label, detail]) => <Link to={`/projects/${projectId}${path}`} key={label}><b>{label}</b><span>{detail}</span><i>›</i></Link>)}</div></aside>
      </section>
      <section className="panel target-capture-panel"><header><div><p className="eyebrow">Live attack surface</p><h2>Recent captured requests</h2></div><div className="target-panel-actions"><button className="subtle-button" onClick={() => void traffic.refetch()}>↻ Refresh</button><Link className="button-link subtle" to={`/projects/${projectId}/sitemap`}>Open Site Map</Link></div></header>{traffic.isError ? <p className="error">Traffic could not be loaded.</p> : orderedTraffic.length === 0 ? <div className="empty compact">No captured endpoints match this target yet. Proxy traffic from another device will appear here when its host is in scope.</div> : <div className="target-capture-list">{orderedTraffic.slice(0, 10).map((entry) => <article key={entry.id}><span className="method-badge">{entry.method}</span><div><b>{entry.host}</b><code>{entry.path || '/'}</code><small>{formatDate(entry.timestamp)} · {entry.status_code || '—'}</small></div><button onClick={() => navigate(`/projects/${projectId}/repeater`, { state: { request: { method: entry.method, url: displayUrl(entry), headers: requestHeaders(entry), body: requestBody(entry) } } })}>Send to Repeater</button></article>)}</div>}</section>
    </section>}

    {tab === 'scope' && <section className="target-scope-tab"><div className="panel scope-editor"><div className="scope-heading"><div><p className="eyebrow">Boundaries</p><h2>Project scope</h2><p className="muted">These rules drive Site Map, History, Network, WebSockets, and the external-device proxy captures.</p></div><label className="toggle"><input type="checkbox" checked={scope.include_subdomains} onChange={() => { const next = { ...scope, include_subdomains: !scope.include_subdomains }; setScope(next); saveScope.mutate(next) }} /> Include subdomains</label></div><form className="scope-form" onSubmit={addEntry}><select value={entryDirection} onChange={(event) => setEntryDirection(event.target.value as 'in' | 'out')}><option value="in">In scope</option><option value="out">Excluded</option></select><select value={entryType} onChange={(event) => setEntryType(event.target.value as ScopeEntryType)}><option value="domain">domain</option><option value="wildcard">wildcard</option><option value="url">url</option><option value="regex">regex</option></select><input value={entryValue} onChange={(event) => setEntryValue(event.target.value)} placeholder="example.com" /><button>Add rule</button></form><div className="scope-list">{scope.entries.length === 0 && <div className="empty compact">No restrictions. All targets are currently in scope.</div>}{scope.entries.map((entry, index) => <div className={`scope-row ${entry.in_scope ? 'scope-in' : 'scope-out'}`} key={`${entry.value}-${index}`}><span className="rule-direction">{entry.in_scope ? 'IN' : 'OUT'}</span><span className="rule-type">{entry.entry_type}</span><code>{entry.value}</code><button onClick={() => { const next = { ...scope, entries: scope.entries.filter((_, itemIndex) => itemIndex !== index) }; setScope(next); saveScope.mutate(next) }}>Remove</button></div>)}</div>{saveScope.isError && <p className="error">Scope could not be saved. Reload before making more changes.</p>}</div><aside className="panel scope-help"><p className="eyebrow">How matching works</p><h2>Exclusions always win</h2><p>Out-of-scope rules override matching inclusions. Domain rules include child hosts when the subdomain option is enabled.</p><dl><dt>domain</dt><dd>Exact host or its subdomains</dd><dt>wildcard</dt><dd>Apex and every child host</dd><dt>url</dt><dd>Host and path prefix</dd><dt>regex</dt><dd>Advanced host expression</dd></dl></aside></section>}

    {tab === 'sessions' && <section className="target-sessions-tab"><aside className="panel target-session-list"><header><div><p className="eyebrow">Session factory</p><h2>Named profiles</h2></div><button onClick={() => { setSelectedSessionId(''); setSessionDraft(emptySession()) }}>＋ New</button></header>{authSessions.data?.map((item) => <button className={item.id === selectedSessionId ? 'selected' : ''} onClick={() => selectAuthSession(item.id)} key={item.id}><b>{item.name}</b><span>{item.headers.length} headers · {item.params.length} params</span></button>)}{!authSessions.data?.length && <div className="empty compact">No saved auth profiles yet.</div>}</aside><section className="panel target-session-editor"><header><div><p className="eyebrow">Reusable request context</p><h2>{selectedSession ? selectedSession.name : 'New session profile'}</h2><p className="muted">Save headers and URL parameters for use in Repeater and Intruder.</p></div>{selectedSessionId && <button className="danger" onClick={() => { if (confirm('Delete this session profile?')) deleteSession.mutate(selectedSessionId) }}>Delete</button>}</header><label>Name<input value={sessionDraft.name} onChange={(event) => setSessionDraft({ ...sessionDraft, name: event.target.value })} /></label><div className="target-session-section"><header><b>Headers</b><small>{sessionDraft.headers.length} rows</small></header><SessionRows rows={sessionDraft.headers} onChange={(headers) => setSessionDraft({ ...sessionDraft, headers })} /></div><div className="target-session-section"><header><b>URL parameters</b><small>{sessionDraft.params.length} rows</small></header><SessionRows rows={sessionDraft.params} onChange={(params) => setSessionDraft({ ...sessionDraft, params })} /></div><footer><button onClick={() => saveSession.mutate()} disabled={saveSession.isPending || !sessionDraft.name.trim()}>{saveSession.isPending ? 'Saving…' : 'Save session'}</button>{saveSession.isError && <p className="error">{saveSession.error.message}</p>}</footer></section></section>}

    {tab === 'flow' && <section className="target-flow-tab methodology-tab"><header className="target-flow-header"><div><p className="eyebrow">Testing methodology</p><h2>Testing Flow</h2><p className="muted">Track coverage from the same vulnerability checklist used by the desktop Target Window. Change a check’s status, attach notes, and open its testing guidance.</p></div><span className="methodology-summary">{methodology.data?.reduce((total, category) => total + category.vulnerabilities.length, 0) ?? 0} checks</span></header><div className="methodology-workbench"><aside className="panel methodology-checklist">{methodology.data?.map((category) => { const tested = category.vulnerabilities.filter((item) => item.status === 'tested_clean' || item.status === 'vulnerable').length; return <details key={category.id} open><summary><span style={{ color: category.accent }}>{category.icon}</span><b>{category.name}</b><small>{tested}/{category.vulnerabilities.length} tested</small></summary><div>{category.vulnerabilities.map((item) => <button className={item.id === selectedVulnerabilityId ? 'selected' : ''} onClick={() => setSelectedVulnerabilityId(item.id)} key={item.id}><span>{methodologyStatusLabels[item.status]}</span><b>{item.name}</b></button>)}</div></details> })}{methodology.isPending && <div className="empty compact">Loading testing checklist…</div>}{methodology.isError && <p className="error">The testing methodology could not be loaded.</p>}</aside><article className="panel methodology-detail">{!selectedVulnerabilityId ? <div className="methodology-placeholder"><strong>Select a check</strong><span>Choose a vulnerability from the checklist to review its guidance and record coverage.</span></div> : methodologyDetail.isPending ? <div className="empty">Loading check…</div> : methodologyDetail.isError ? <p className="error">This methodology check could not be loaded.</p> : methodologyDetail.data && <><header><div><p className="eyebrow">{methodologyDetail.data.category_name}</p><h2>{methodologyDetail.data.name}</h2></div><select value={methodologyDetail.data.status} onChange={(event) => updateMethodology.mutate({ status: event.target.value as MethodologyStatus, notes: methodologyDetail.data?.notes ?? '' })}>{methodologyStatuses.map((status) => <option value={status} key={status}>{methodologyStatusLabels[status]}</option>)}</select></header><div className="methodology-description"><div className="markdown-content" dangerouslySetInnerHTML={{ __html: renderMarkdown(methodologyDetail.data.description || 'No testing guidance is available for this check yet.') }} /></div><label>Check notes<textarea value={methodologyDetail.data.notes} onChange={(event) => queryClient.setQueryData(['projects', projectId, 'methodology', selectedVulnerabilityId], { ...methodologyDetail.data, notes: event.target.value })} placeholder="Record evidence, endpoints, payloads, and conclusions…" /></label><footer><button disabled={updateMethodology.isPending} onClick={() => updateMethodology.mutate({ status: methodologyDetail.data!.status, notes: methodologyDetail.data!.notes })}>{updateMethodology.isPending ? 'Saving…' : 'Save check'}</button>{updateMethodology.isError && <p className="error">{updateMethodology.error.message}</p>}</footer></>}</article></div></section>}

    {tab === 'notes' && <section className="panel target-notes-tab"><header><div><p className="eyebrow">Project notebook</p><h2>Target notes</h2><p className="muted">Saved to the project workspace as <code>notes.md</code>, matching the desktop Target window.</p></div><span className={saveNotes.isPending ? 'live-dot active' : 'status'}>{saveNotes.isPending ? 'Saving…' : notesLoaded ? 'Saved remotely' : 'Loading…'}</span></header><textarea className="target-notes-editor" value={notes} onChange={(event) => setNotes(event.target.value)} placeholder={`Notes for ${displayHost(project.data.target)}…`} /><footer><button onClick={() => saveNotes.mutate()} disabled={!notesLoaded || saveNotes.isPending}>{saveNotes.isPending ? 'Saving…' : 'Save notes'}</button>{saveNotes.isError && <p className="error">{saveNotes.error.message}</p>}</footer></section>}
  </main>
}
