import { useEffect, useMemo, useRef, useState } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { Link, useParams, useSearchParams } from 'react-router-dom'

import { api, type StoredResult } from '../../api/client'
import { SubdomainImportPanel } from './SubdomainImportPanel'

const categories = [
  ['subdomain', 'Subdomain Enum'],
  ['dns', 'DNS Records'],
  ['portscan', 'Port Scan'],
  ['http', 'Live HTTP Hosts'],
  ['crawl', 'Endpoints / Crawl'],
  ['params', 'Parameters'],
  ['fuzz', 'Directory Fuzz'],
  ['vuln', 'Vulnerabilities'],
  ['osint', 'OSINT / Cloud'],
] as const

type Category = typeof categories[number][0]
type Column = { label: string; fields: string[] }

const schemas: Partial<Record<Category, Column[]>> = {
  subdomain: [{ label: 'Domain', fields: ['domain'] }, { label: 'IP Address(es)', fields: ['ip_addresses', 'ip'] }],
  dns: [{ label: 'Name', fields: ['name'] }, { label: 'Type', fields: ['record_type', 'type'] }, { label: 'Value', fields: ['value'] }],
  portscan: [{ label: 'Host', fields: ['host'] }, { label: 'Port', fields: ['port'] }, { label: 'Protocol', fields: ['protocol'] }, { label: 'Service', fields: ['service'] }, { label: 'Version', fields: ['version'] }, { label: 'State', fields: ['state'] }],
  http: [{ label: 'URL', fields: ['url'] }, { label: 'Status', fields: ['status_code', 'status'] }, { label: 'Title', fields: ['title'] }, { label: 'Technologies', fields: ['technologies', 'tech'] }],
  crawl: [{ label: 'URL', fields: ['url'] }, { label: 'Method', fields: ['method'] }, { label: 'Status', fields: ['status_code', 'status'] }, { label: 'Parameters', fields: ['parameters', 'params'] }],
  params: [{ label: 'Parameter', fields: ['name'] }, { label: 'Endpoint', fields: ['endpoint', 'url'] }, { label: 'Method', fields: ['method'] }, { label: 'Type', fields: ['param_type', 'type'] }, { label: 'Example', fields: ['example_value', 'value'] }],
  fuzz: [{ label: 'Base URL', fields: ['url'] }, { label: 'Path', fields: ['path'] }, { label: 'Status', fields: ['status_code', 'status'] }, { label: 'Length', fields: ['content_length', 'length'] }, { label: 'Words', fields: ['words'] }, { label: 'Lines', fields: ['lines'] }, { label: 'Redirect', fields: ['redirect_url'] }],
  vuln: [{ label: 'Severity', fields: ['severity'] }, { label: 'Name', fields: ['name'] }, { label: 'URL', fields: ['url'] }, { label: 'Template', fields: ['template_id'] }, { label: 'Tags', fields: ['tags'] }],
  osint: [{ label: 'Type', fields: ['result_type', 'type'] }, { label: 'Value', fields: ['value'] }, { label: 'Provider', fields: ['provider'] }, { label: 'Extra', fields: ['extra'] }],
}

const staticAsset = /\.(?:css|js|mjs|map|png|jpe?g|gif|svg|ico|webp|woff2?|ttf|eot|mp[34]|webm)(?:[?#]|$)/i

function displayValue(value: unknown): string {
  if (value === null || value === undefined || value === '') return '—'
  if (Array.isArray(value)) return value.map(displayValue).join(', ')
  if (typeof value === 'object') return JSON.stringify(value)
  return String(value)
}

function fieldValue(result: StoredResult, fields: string[]): string {
  for (const field of fields) {
    if (result.data[field] !== undefined && result.data[field] !== '') return displayValue(result.data[field])
  }
  return '—'
}

function csvCell(value: string): string {
  return `"${value.replaceAll('"', '""')}"`
}

export function ResultsPage() {
  const { projectId = '' } = useParams()
  const [searchParams] = useSearchParams()
  const queryClient = useQueryClient()
  const [category, setCategory] = useState<Category>('subdomain')
  const [sessionId, setSessionId] = useState(searchParams.get('session') || 'all')
  const [source, setSource] = useState('combined')
  const [search, setSearch] = useState('')
  const [hideStatic, setHideStatic] = useState(true)
  const selectedInitialCategory = useRef(false)

  const sessions = useQuery({
    queryKey: ['projects', projectId, 'sessions'],
    queryFn: () => api.listSessions(projectId),
    enabled: Boolean(projectId),
  })
  const results = useQuery({
    queryKey: ['projects', projectId, 'results', sessionId],
    queryFn: () => sessionId === 'all' ? api.listProjectResults(projectId) : api.listResults(projectId, sessionId),
    enabled: Boolean(projectId),
  })

  const counts = useMemo(() => Object.fromEntries(categories.map(([key]) => [key, results.data?.filter((item) => item.category === key).length ?? 0])), [results.data])
  useEffect(() => {
    if (selectedInitialCategory.current || !results.data) return
    const first = categories.find(([key]) => counts[key] > 0)
    if (first) setCategory(first[0])
    selectedInitialCategory.current = true
  }, [counts, results.data])
  useEffect(() => { setSource('combined') }, [category, sessionId])

  const categoryResults = useMemo(() => results.data?.filter((item) => item.category === category) ?? [], [category, results.data])
  const sources = useMemo(() => {
    const sourceCounts = new Map<string, number>()
    categoryResults.forEach((item) => item.sources.forEach((itemSource) => sourceCounts.set(itemSource, (sourceCounts.get(itemSource) ?? 0) + 1)))
    return [...sourceCounts.entries()].sort((a, b) => b[1] - a[1])
  }, [categoryResults])
  const filtered = useMemo(() => {
    const query = search.trim().toLowerCase()
    return categoryResults.filter((item) => {
      if (source !== 'combined' && !item.sources.includes(source)) return false
      if (hideStatic && (category === 'crawl' || category === 'params')) {
        const assetTarget = displayValue(item.data.url ?? item.data.endpoint ?? '')
        if (staticAsset.test(assetTarget)) return false
      }
      return !query || `${item.result_key} ${JSON.stringify(item.data)} ${item.sources.join(' ')}`.toLowerCase().includes(query)
    })
  }, [category, categoryResults, hideStatic, search, source])
  const columns = schemas[category] ?? [{ label: 'Result', fields: [] }]

  function exportCsv() {
    const header = [...columns.map((column) => column.label), 'Sources']
    const rows = filtered.map((item) => [...columns.map((column) => column.fields.length ? fieldValue(item, column.fields) : item.result_key), item.sources.join(', ')])
    const csv = [header, ...rows].map((row) => row.map((cell) => csvCell(cell)).join(',')).join('\n')
    const url = URL.createObjectURL(new Blob([csv], { type: 'text/csv;charset=utf-8' }))
    const link = document.createElement('a')
    link.href = url
    link.download = `awe-${category}-results.csv`
    link.click()
    URL.revokeObjectURL(url)
  }

  return <main className="page results-page">
    
    <header className="page-header results-header"><div><p className="eyebrow">Project intelligence</p><h1>Results</h1><p className="muted">Merged, de-duplicated findings from pipeline runs and proxy traffic.</p></div><span className="result-total">{results.data?.length ?? 0} unique</span></header>
    <div className="results-toolbar panel">
      <select aria-label="Result session" value={sessionId} onChange={(event) => setSessionId(event.target.value)}><option value="all">All sessions + proxy traffic</option>{sessions.data?.map((session) => <option value={session.id} key={session.id}>{session.pipeline_name} · {new Date(session.started_at).toLocaleString()}</option>)}</select>
      <input aria-label="Search results" value={search} onChange={(event) => setSearch(event.target.value)} placeholder="Search the current category…" />
      {(category === 'crawl' || category === 'params') && <label className="result-toggle"><input type="checkbox" checked={hideStatic} onChange={(event) => setHideStatic(event.target.checked)} /> Hide static assets</label>}
      <button className="secondary-button" onClick={() => void queryClient.invalidateQueries({ queryKey: ['projects', projectId, 'results'] })}>Refresh</button>
      <button onClick={exportCsv} disabled={!filtered.length}>Export CSV</button>
    </div>
    <SubdomainImportPanel projectId={projectId} />
    {results.isError && <p className="error">Results could not be loaded. Check the backend and MongoDB connection.</p>}
    <section className="results-browser">
      <aside className="panel result-categories"><b>Categories</b>{categories.map(([key, label]) => <button className={category === key ? 'selected' : ''} onClick={() => setCategory(key)} key={key}><span>{label}</span><em>{counts[key]}</em></button>)}</aside>
      <div className="panel result-content">
        <div className="result-source-tabs"><button className={source === 'combined' ? 'selected' : ''} onClick={() => setSource('combined')}>Combined <span>{categoryResults.length}</span></button>{sources.map(([itemSource, count]) => <button className={source === itemSource ? 'selected' : ''} onClick={() => setSource(itemSource)} key={itemSource}>{itemSource.replaceAll('_', ' ')} <span>{count}</span></button>)}</div>
        <div className="result-stats"><strong>{filtered.length}</strong> shown · {categoryResults.length} unique · {sources.length} sources</div>
        {results.isFetching && <div className="empty compact">Loading results…</div>}
        {!results.isFetching && filtered.length === 0 && <div className="empty">No results match this view.</div>}
        {filtered.length > 0 && <div className="result-data-table"><table><thead><tr>{columns.map((column) => <th key={column.label}>{column.label}</th>)}<th>Sources</th></tr></thead><tbody>{filtered.map((item) => <tr key={`${item.category}-${item.result_key}`} title={item.result_key}>{columns.map((column) => <td key={column.label}><code className={category === 'vuln' && column.label === 'Severity' ? `severity-${fieldValue(item, column.fields).toLowerCase()}` : ''}>{column.fields.length ? fieldValue(item, column.fields) : item.result_key}</code></td>)}<td>{item.sources.join(', ') || '—'}</td></tr>)}</tbody></table></div>}
      </div>
    </section>
  </main>
}
