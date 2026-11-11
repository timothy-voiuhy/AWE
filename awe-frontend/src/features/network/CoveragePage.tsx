import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Link, useParams } from 'react-router-dom'
import { getTransformCoverage, type CoverageLevel } from '../../api/coverage'
import { OptionsMenu } from '../../components/OptionsMenu'
import './coverage.css'

const labels: Record<CoverageLevel, string> = { fixture_verified: 'Fixture tested', adapter_only: 'Adapter only', manual_required: 'Manual / partial' }

export function CoveragePage() {
  const { projectId = '' } = useParams()
  const coverage = useQuery({ queryKey: ['transform-coverage'], queryFn: getTransformCoverage })
  const [search, setSearch] = useState('')
  const [level, setLevel] = useState('all')
  const [family, setFamily] = useState('all')
  const rows = coverage.data?.rows || []
  const visible = rows.filter(row => (level === 'all' || row.verification === level) && (family === 'all' || row.family === family) && `${row.area} ${row.family} ${row.tool_keys.join(' ')} ${row.cwe.join(' ')} ${row.inputs.join(' ')} ${row.limitations}`.toLowerCase().includes(search.toLowerCase()))
  return <main className="page feature-page coverage-page">
    <header className="panel coverage-header"><div><b>Vulnerability coverage</b><span>{coverage.data?.native_transform_count ?? '—'} native validation transforms · suite {coverage.data?.suite_version || '—'}</span></div><OptionsMenu label="Coverage options"><Link to={`/projects/${projectId}/network/transforms`}>Transforms</Link><Link to={`/projects/${projectId}/network/docs?doc=validation-transforms`}>Validation guide</Link><Link to={`/projects/${projectId}/network/docs?doc=vulnerability-coverage`}>Coverage document</Link></OptionsMenu></header>
    <p className="coverage-note">Fixture tested means the detector was exercised against controlled vulnerable and protected responses. It does not guarantee coverage of every application or confirm every finding. Registered adapters still require their images, prerequisites, and target-specific verification.</p>
    <nav className="coverage-levels" aria-label="Coverage evidence filters"><button aria-pressed={level === 'all'} onClick={() => setLevel('all')}>All areas <b>{rows.length}</b></button>{(Object.keys(labels) as CoverageLevel[]).map(value => <button key={value} aria-pressed={level === value} onClick={() => setLevel(value)}>{labels[value]} <b>{rows.filter(row => row.verification === value).length}</b></button>)}</nav>
    <div className="panel coverage-filters"><input aria-label="Search coverage" placeholder="Search a vulnerability, CWE, tool, or prerequisite…" value={search} onChange={event => setSearch(event.target.value)} /><select aria-label="Coverage family" value={family} onChange={event => setFamily(event.target.value)}><option value="all">All families</option>{[...new Set(rows.map(row => row.family))].sort().map(value => <option key={value}>{value}</option>)}</select><span role="status">{visible.length} areas</span></div>
    {coverage.isError && <p className="error" role="alert">{coverage.error.message}</p>}
    {coverage.isPending ? <p className="muted">Loading coverage matrix…</p> : <section className="panel coverage-table-wrap"><table className="coverage-table"><thead><tr><th>Vulnerability / behavior</th><th>Detector evidence</th><th>Transforms</th><th>Prerequisites and limits</th></tr></thead><tbody>{visible.map(row => <tr key={row.id}><td><b>{row.area}</b><small>{row.family}{row.cwe.length ? ` · ${row.cwe.join(', ')}` : ''}</small></td><td><span className={`coverage-status coverage-${row.verification}`}>{labels[row.verification]}</span></td><td>{row.tool_keys.length ? row.tool_keys.map(key => row.registered_tool_keys.includes(key) ? <Link key={key} to={`/projects/${projectId}/network/transforms?find=${encodeURIComponent(key)}`}>{key}</Link> : <span className="muted" key={key}>{key} · not registered</span>) : <span className="muted">No dedicated transform</span>}</td><td><p>{row.inputs.join(' · ')}</p><span>{row.limitations}</span></td></tr>)}</tbody></table>{!visible.length && <div className="empty compact">No coverage areas match these filters.</div>}</section>}
  </main>
}
