import { useMemo, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Link, useParams } from 'react-router-dom'

import { api, TrafficEntry } from '../../api/client'

function statusClass(status: number) { return status >= 500 ? 'status-5' : status >= 400 ? 'status-4' : status >= 300 ? 'status-3' : 'status-2' }
function pretty(value: unknown) { return typeof value === 'string' ? value : JSON.stringify(value ?? {}, null, 2) }

export function HttpHistoryPage() {
  const { projectId = '' } = useParams(); const [selected, setSelected] = useState<TrafficEntry | null>(null); const [query, setQuery] = useState('')
  const traffic = useQuery({ queryKey: ['projects', projectId, 'traffic'], queryFn: () => api.listTraffic(projectId), refetchInterval: 3000 })
  const rows = traffic.data?.filter((item) => `${item.method} ${item.host}${item.path} ${item.status_code}`.toLowerCase().includes(query.toLowerCase())) ?? []
  return <main className="page feature-page"><PageHead projectId={projectId} eyebrow="Proxy" title="HTTP History" detail="Chronological requests captured by AWE's proxy." /><section className="panel traffic-toolbar"><input value={query} onChange={(e) => setQuery(e.target.value)} placeholder="Filter method, host, path, or status…"/><span>{rows.length} requests</span></section><section className="traffic-split"><div className="panel traffic-list">{rows.map((item) => <button className={selected?.id === item.id ? 'selected' : ''} onClick={() => setSelected(item)} key={item.id}><b>{item.method}</b><span>{item.host}<small>{item.path}</small></span><i className={statusClass(item.status_code)}>{item.status_code}</i></button>)}</div><TrafficDetail item={selected ?? rows[0]} /></section></main>
}

export function SiteMapPage() {
  const { projectId = '' } = useParams(); const traffic = useQuery({ queryKey: ['projects', projectId, 'traffic'], queryFn: () => api.listTraffic(projectId) })
  const hosts = useMemo(() => Object.entries((traffic.data ?? []).reduce<Record<string, TrafficEntry[]>>((acc, item) => { (acc[item.host] ??= []).push(item); return acc }, {})), [traffic.data])
  return <main className="page feature-page"><PageHead projectId={projectId} eyebrow="Attack surface" title="Site Map" detail="Unique hosts and paths observed through proxy traffic." /><section className="sitemap-grid">{hosts.map(([host, entries]) => <article className="panel site-host" key={host}><header><strong>{host}</strong><span>{entries.length}</span></header>{Array.from(new Map(entries.map((entry) => [`${entry.method}:${entry.path}`, entry])).values()).map((entry) => <div key={`${entry.method}:${entry.path}`}><b>{entry.method}</b><code>{entry.path}</code><i className={statusClass(entry.status_code)}>{entry.status_code}</i></div>)}</article>)}</section>{hosts.length === 0 && <div className="panel empty">No captured hosts yet.</div>}</main>
}

export function NetworkPage() {
  const { projectId = '' } = useParams(); const traffic = useQuery({ queryKey: ['projects', projectId, 'traffic'], queryFn: () => api.listTraffic(projectId) })
  const nodes = useMemo(() => Object.entries((traffic.data ?? []).reduce<Record<string, { count: number; statuses: Set<number> }>>((acc, item) => { const node = acc[item.host] ??= { count: 0, statuses: new Set() }; node.count++; node.statuses.add(item.status_code); return acc }, {})), [traffic.data])
  return <main className="page feature-page"><PageHead projectId={projectId} eyebrow="Topology" title="Network" detail="A responsive host graph derived from captured requests." /><section className="network-canvas panel"><div className="target-node"><b>Target</b><span>{nodes.length} observed hosts</span></div><div className="host-nodes">{nodes.map(([host, data]) => <article key={host}><span className="node-line"/><b>{host}</b><small>{data.count} requests</small><div>{[...data.statuses].slice(0, 4).map((status) => <i className={statusClass(status)} key={status}>{status}</i>)}</div></article>)}</div></section></main>
}

function PageHead({ projectId, eyebrow, title, detail }: { projectId: string; eyebrow: string; title: string; detail: string }) { return <><Link className="back-link" to={`/projects/${projectId}`}>← Project workspace</Link><header className="page-header"><div><p className="eyebrow">{eyebrow}</p><h1>{title}</h1><p className="muted">{detail}</p></div></header></> }
function TrafficDetail({ item }: { item?: TrafficEntry }) { if (!item) return <div className="panel empty">Select a request to inspect it.</div>; return <section className="panel traffic-detail"><header><b>{item.method} {item.host}{item.path}</b><i className={statusClass(item.status_code)}>{item.status_code}</i></header><div><article><span>Request</span><pre>{pretty(item.request)}</pre></article><article><span>Response</span><pre>{pretty(item.response)}</pre></article></div></section> }
