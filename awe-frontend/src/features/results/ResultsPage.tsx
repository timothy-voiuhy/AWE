import { useEffect, useMemo, useRef, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useNavigate, useParams, useSearchParams } from 'react-router-dom'

import { api, type StoredResult } from '../../api/client'
import { OptionsMenu } from '../../components/OptionsMenu'
import { Spinner } from '../../components/Spinner'
import { SubdomainImportPanel } from './SubdomainImportPanel'

const knownCategories: Array<[string, string]> = [
  ['subdomain', 'Subdomain Enum'],
  ['dns', 'DNS Records'],
  ['portscan', 'Port Scan'],
  ['http', 'Live HTTP Hosts'],
  ['crawl', 'Endpoints / Crawl'],
  ['params', 'Parameters'],
  ['fuzz', 'Directory Fuzz'],
  ['vuln', 'Vulnerabilities'],
  ['osint', 'OSINT / Cloud'],
]

type Category = string
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

function resultUrl(result: StoredResult): string | null {
  const data = result.data
  let candidate = String(data.url ?? data.endpoint ?? '').trim()
  if (result.category === 'fuzz' && candidate && data.path) {
    try { candidate = new URL(String(data.path), candidate).toString() } catch { /* keep the base URL */ }
  }
  if (!candidate && result.category === 'portscan') {
    const host = String(data.host ?? '').trim()
    const port = String(data.port ?? '').trim()
    if (host) candidate = `${['443', '8443'].includes(port) ? 'https' : 'http'}://${host}${port ? `:${port}` : ''}`
  }
  if (!candidate && ['subdomain', 'dns'].includes(result.category)) {
    candidate = String(data.domain ?? data.name ?? result.result_key).trim()
  }
  if (!candidate) return null
  if (!/^https?:\/\//i.test(candidate)) candidate = `https://${candidate}`
  try {
    const parsed = new URL(candidate)
    return ['http:', 'https:'].includes(parsed.protocol) ? parsed.toString() : null
  } catch {
    return null
  }
}

export function ResultsPage() {
  const { projectId = '' } = useParams()
  const navigate = useNavigate()
  const [searchParams] = useSearchParams()
  const queryClient = useQueryClient()
  const [category, setCategory] = useState<Category>('subdomain')
  const [sessionId, setSessionId] = useState(searchParams.get('session') || 'all')
  const [source, setSource] = useState('combined')
  const [search, setSearch] = useState('')
  const [hideStatic, setHideStatic] = useState(true)
  const selectedInitialCategory = useRef(false)
  const importDialog = useRef<HTMLDialogElement>(null)
  const resultActionsDialog = useRef<HTMLDialogElement>(null)
  const [activeResult, setActiveResult] = useState<StoredResult | null>(null)
  const [actionNotice, setActionNotice] = useState('')

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
  const updateCachedResult = (item: StoredResult, transform: (row: StoredResult) => StoredResult | null) => {
    queryClient.setQueriesData<StoredResult[]>({ queryKey: ['projects', projectId, 'results'] }, current => current?.flatMap(row => {
      if (row.category !== item.category || row.result_key !== item.result_key) return [row]
      const next = transform(row)
      return next ? [next] : []
    }))
  }
  const reviewResult = useMutation({
    mutationFn: ({ item, reviewed }: { item: StoredResult; reviewed: boolean }) => api.setResultReviewed(projectId, { category: item.category, result_key: item.result_key, reviewed }),
    onSuccess: (response, { item }) => {
      updateCachedResult(item, row => ({ ...row, reviewed: response.reviewed }))
      setActiveResult(current => current && current.category === item.category && current.result_key === item.result_key ? { ...current, reviewed: response.reviewed } : current)
      setActionNotice(response.reviewed ? 'Result marked as reviewed.' : 'Result marked as not reviewed.')
    },
  })
  const removeResult = useMutation({
    mutationFn: (item: StoredResult) => api.deleteResult(projectId, { category: item.category, result_key: item.result_key, ...(sessionId === 'all' ? {} : { session_id: sessionId }) }),
    onSuccess: (_, item) => {
      updateCachedResult(item, () => null)
      resultActionsDialog.current?.close()
      setActionNotice('Result removed.')
    },
  })
  const openInAwe = useMutation({
    mutationFn: async (item: StoredResult) => {
      const url = resultUrl(item)
      if (!url) throw new Error('This result does not contain a web address.')
      const session = await api.createBrowserSession(projectId)
      try {
        await api.navigateBrowser(projectId, session.id, url)
        return session
      } catch (error) {
        await api.closeBrowserSession(projectId, session.id).catch(() => undefined)
        throw error
      }
    },
    onSuccess: session => {
      resultActionsDialog.current?.close()
      navigate(`/projects/${projectId}/browser?session=${encodeURIComponent(session.id)}`)
    },
  })

  function showResultActions(item: StoredResult) {
    setActiveResult(item)
    setActionNotice('')
    requestAnimationFrame(() => resultActionsDialog.current?.showModal())
  }

  const categories = useMemo(() => {
    const known = new Set(knownCategories.map(([key]) => key))
    const extra = [...new Set(results.data?.map((item) => item.category) ?? [])]
      .filter((key) => !known.has(key))
      .sort()
      .map((key): [string, string] => [key, key.replaceAll('_', ' ').replace(/\b\w/g, (letter) => letter.toUpperCase())])
    return [...knownCategories, ...extra]
  }, [results.data])

  const counts = useMemo(() => Object.fromEntries(categories.map(([key]) => [key, results.data?.filter((item) => item.category === key).length ?? 0])), [categories, results.data])
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
    <div className="results-toolbar panel">
      <select aria-label="Result session" value={sessionId} onChange={(event) => setSessionId(event.target.value)}><option value="all">All results</option>{sessions.data?.map((session) => <option value={session.id} key={session.id}>{session.pipeline_name} · {new Date(session.started_at).toLocaleString()}</option>)}</select>
      <input aria-label="Search results" value={search} onChange={(event) => setSearch(event.target.value)} placeholder="Search the current category…" />
      {(category === 'crawl' || category === 'params') && <label className="result-toggle"><input type="checkbox" checked={hideStatic} onChange={(event) => setHideStatic(event.target.checked)} /> Hide static assets</label>}
      <div className="results-header-actions"><span className="result-total">{results.data?.length ?? 0} unique</span><OptionsMenu label="Results options"><button type="button" onClick={() => importDialog.current?.showModal()}>Import subdomains</button><button type="button" onClick={exportCsv} disabled={!filtered.length}>Export CSV</button><button type="button" onClick={() => void queryClient.invalidateQueries({ queryKey: ['projects', projectId, 'results'] })}>Refresh results</button></OptionsMenu></div>
    </div>
    <dialog ref={importDialog} className="results-import-dialog" aria-labelledby="results-import-title" onClick={event => { if (event.target === event.currentTarget) importDialog.current?.close() }}>
      <SubdomainImportPanel projectId={projectId} compact headingId="results-import-title" onClose={() => importDialog.current?.close()} />
    </dialog>
    <dialog ref={resultActionsDialog} className="result-actions-dialog" aria-labelledby="result-actions-title" onClose={() => setActiveResult(null)} onClick={event => { if (event.target === event.currentTarget) resultActionsDialog.current?.close() }}>
      {activeResult && <div className="result-actions-content"><header><div><b id="result-actions-title">Result actions</b><code>{activeResult.result_key}</code></div><button type="button" aria-label="Close result actions" onClick={() => resultActionsDialog.current?.close()}>×</button></header><div className="result-open-actions"><a className={!resultUrl(activeResult) ? 'disabled' : ''} href={resultUrl(activeResult) || undefined} target="_blank" rel="noopener noreferrer" aria-disabled={!resultUrl(activeResult)} onClick={event => { if (!resultUrl(activeResult)) event.preventDefault(); else resultActionsDialog.current?.close() }}><b>Open in this browser</b><span>Use a new tab in your current browser</span></a><button type="button" disabled={!resultUrl(activeResult) || openInAwe.isPending} onClick={() => openInAwe.mutate(activeResult)}><b>{openInAwe.isPending ? 'Starting AWE Browser…' : 'Open in AWE Browser'}</b><span>Use the proxied interactive browser</span></button></div><footer><button type="button" disabled={reviewResult.isPending} onClick={() => reviewResult.mutate({ item: activeResult, reviewed: !activeResult.reviewed })}>{activeResult.reviewed ? 'Mark as not reviewed' : 'Mark as reviewed'}</button><button type="button" className="danger" disabled={removeResult.isPending} onClick={() => { if (confirm('Remove this result? This cannot be undone.')) removeResult.mutate(activeResult) }}>{removeResult.isPending ? 'Removing…' : 'Remove result'}</button></footer>{(openInAwe.isError || reviewResult.isError || removeResult.isError) && <p className="error">{String((openInAwe.error || reviewResult.error || removeResult.error)?.message)}</p>}</div>}
    </dialog>
    {actionNotice && <p className="success result-action-notice">{actionNotice}</p>}
    {results.isError && <p className="error">Results could not be loaded. Check the backend and MongoDB connection.</p>}
    <section className="results-browser">
      <aside className="panel result-categories"><b>Categories</b>{categories.map(([key, label]) => <button className={category === key ? 'selected' : ''} onClick={() => setCategory(key)} key={key}><span>{label}</span><em>{counts[key]}</em></button>)}</aside>
      <div className="panel result-content">
        <div className="result-source-tabs"><button className={source === 'combined' ? 'selected' : ''} onClick={() => setSource('combined')}>Combined <span>{categoryResults.length}</span></button>{sources.map(([itemSource, count]) => <button className={source === itemSource ? 'selected' : ''} onClick={() => setSource(itemSource)} key={itemSource}>{itemSource.replaceAll('_', ' ')} <span>{count}</span></button>)}</div>
        <div className="result-stats"><strong>{filtered.length}</strong> shown · {categoryResults.length} unique · {sources.length} sources</div>
        {results.isFetching && <div className="empty compact"><Spinner size="small" label="Loading results…" /></div>}
        {!results.isFetching && filtered.length === 0 && <div className="empty">No results match this view.</div>}
        {filtered.length > 0 && <div className="result-data-table"><table><thead><tr>{columns.map((column) => <th key={column.label}>{column.label}</th>)}<th>Sources</th><th className="result-actions-column">Actions</th></tr></thead><tbody>{filtered.map((item) => <tr className={item.reviewed ? 'result-reviewed' : ''} key={`${item.category}-${item.result_key}`} title={item.result_key}>{columns.map((column) => <td key={column.label}><code className={category === 'vuln' && column.label === 'Severity' ? `severity-${fieldValue(item, column.fields).toLowerCase()}` : ''}>{column.fields.length ? fieldValue(item, column.fields) : item.result_key}</code></td>)}<td>{item.sources.join(', ') || '—'}</td><td className="result-row-actions">{item.reviewed && <span title="Reviewed">✓</span>}<button type="button" aria-label={`Actions for ${item.result_key}`} title="Result actions" onClick={() => showResultActions(item)}>⋮</button></td></tr>)}</tbody></table></div>}
      </div>
    </section>
  </main>
}
