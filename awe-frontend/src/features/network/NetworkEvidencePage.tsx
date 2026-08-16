import { useMemo, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Link, useParams } from 'react-router-dom'

import { api, type EvidenceInput, type EvidenceKind, type EvidenceRecord } from '../../api/client'

const emptyEvidence: EvidenceInput = {
  title: '',
  summary: '',
  kind: 'note',
  source_type: 'manual',
  source_id: '',
  investigation_id: '',
  entity_ids: [],
  relationship_ids: [],
  tags: [],
  data: {},
}

function formatDate(value: string) {
  const date = new Date(value)
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString()
}

function splitValues(value: string) {
  return value.split(',').map(item => item.trim()).filter(Boolean)
}

function EvidenceCard({ record, selected, onSelect, onDelete }: { record: EvidenceRecord; selected: boolean; onSelect: () => void; onDelete: () => void }) {
  return <article className={`evidence-card ${selected ? 'selected' : ''}`}>
    <button type="button" onClick={onSelect}>
      <header><b>{record.title}</b><span>{record.kind} · {formatDate(record.created_at)}</span></header>
      <p>{record.summary || `${record.source_type}${record.source_id ? ` · ${record.source_id}` : ''}`}</p>
      <footer>{record.tags.slice(0, 5).map(tag => <em key={tag}>{tag}</em>)}</footer>
    </button>
    <button className="danger evidence-delete" type="button" onClick={onDelete}>Delete</button>
  </article>
}

export function NetworkEvidencePage() {
  const { projectId = '' } = useParams()
  const qc = useQueryClient()
  const [query, setQuery] = useState('')
  const [kind, setKind] = useState('')
  const [selectedId, setSelectedId] = useState('')
  const [draft, setDraft] = useState<EvidenceInput>(emptyEvidence)
  const [tags, setTags] = useState('')
  const [entities, setEntities] = useState('')
  const [dataJson, setDataJson] = useState('{}')
  const [notice, setNotice] = useState('')

  const evidence = useQuery({ queryKey: ['projects', projectId, 'evidence'], queryFn: () => api.listEvidence(projectId), refetchInterval: 5000 })
  const create = useMutation({
    mutationFn: () => api.createEvidence(projectId, { ...draft, tags: splitValues(tags), entity_ids: splitValues(entities), data: JSON.parse(dataJson) as Record<string, unknown> }),
    onSuccess: item => {
      setNotice(`Saved evidence ${item.title}.`)
      setDraft(emptyEvidence); setTags(''); setEntities(''); setDataJson('{}'); setSelectedId(item.id)
      void qc.invalidateQueries({ queryKey: ['projects', projectId, 'evidence'] })
    },
    onError: error => setNotice((error as Error).message),
  })
  const remove = useMutation({
    mutationFn: (id: string) => api.deleteEvidence(projectId, id),
    onSuccess: () => { setSelectedId(''); void qc.invalidateQueries({ queryKey: ['projects', projectId, 'evidence'] }) },
  })

  const rows = useMemo(() => (evidence.data || []).filter(item => {
    const haystack = `${item.title} ${item.summary} ${item.kind} ${item.source_type} ${item.source_id} ${item.tags.join(' ')} ${JSON.stringify(item.data)}`.toLowerCase()
    return (!kind || item.kind === kind) && (!query || haystack.includes(query.toLowerCase()))
  }), [evidence.data, kind, query])
  const selected = rows.find(item => item.id === selectedId) || rows[0]

  function saveManual() {
    try {
      JSON.parse(dataJson)
      create.mutate()
    } catch {
      setNotice('Evidence data JSON is invalid.')
    }
  }

  return <main className="page feature-page network-evidence-page">
    
    <header className="page-header network-evidence-header"><div><p className="eyebrow">Network</p><h1>Evidence</h1><p className="muted">Durable project evidence from transforms, Docker tools, HTTP captures, findings, screenshots, files, and analyst notes.</p></div><Link className="button-link" to={`/projects/${projectId}/network/logs`}>Transform logs</Link></header>
    {notice && <p className={notice.includes('invalid') || notice.includes('failed') ? 'error' : 'success'}>{notice}</p>}
    {(evidence.isError || remove.isError) && <p className="error">{String((evidence.error || remove.error)?.message)}</p>}
    <section className="panel evidence-toolbar"><div><strong>{rows.length}</strong><span>evidence records</span></div><input value={query} onChange={event => setQuery(event.target.value)} placeholder="Search evidence..." /><select value={kind} onChange={event => setKind(event.target.value)}><option value="">All kinds</option>{(['tool_output','http','screenshot','note','finding','file','manual'] as EvidenceKind[]).map(item => <option value={item} key={item}>{item}</option>)}</select><button onClick={() => void evidence.refetch()}>Refresh</button></section>
    <section className="evidence-workbench">
      <section className="panel evidence-list">
        {rows.map(item => <EvidenceCard key={item.id} record={item} selected={selected?.id === item.id} onSelect={() => setSelectedId(item.id)} onDelete={() => { if (confirm('Delete this evidence record?')) remove.mutate(item.id) }} />)}
        {!evidence.isPending && !rows.length && <div className="empty">No evidence records match this view.</div>}
        {evidence.isPending && !evidence.data && <div className="empty">Loading evidence...</div>}
      </section>
      <section className="panel evidence-detail">{selected ? <><header><div><b>{selected.title}</b><span>{selected.source_type} · {selected.source_id || 'manual'} · {formatDate(selected.created_at)}</span></div><em>{selected.kind}</em></header><p>{selected.summary || 'No summary recorded.'}</p><dl><dt>Investigation</dt><dd>{selected.investigation_id || 'Not linked'}</dd><dt>Entities</dt><dd>{selected.entity_ids.join(', ') || 'None'}</dd><dt>Relationships</dt><dd>{selected.relationship_ids.join(', ') || 'None'}</dd><dt>Tags</dt><dd>{selected.tags.join(', ') || 'None'}</dd></dl><pre>{JSON.stringify(selected.data, null, 2)}</pre></> : <div className="empty">Select evidence to inspect it.</div>}</section>
      <section className="panel evidence-create"><header><div><b>Add evidence</b><span>Manual evidence can link to investigations and graph entity IDs.</span></div></header><label>Title<input value={draft.title} onChange={event => setDraft(current => ({ ...current, title: event.target.value }))} /></label><label>Kind<select value={draft.kind} onChange={event => setDraft(current => ({ ...current, kind: event.target.value as EvidenceKind }))}>{(['note','manual','finding','file','screenshot','http','tool_output'] as EvidenceKind[]).map(item => <option value={item} key={item}>{item}</option>)}</select></label><label>Summary<textarea value={draft.summary} onChange={event => setDraft(current => ({ ...current, summary: event.target.value }))} /></label><label>Source<input value={draft.source_type} onChange={event => setDraft(current => ({ ...current, source_type: event.target.value }))} /></label><label>Source ID<input value={draft.source_id} onChange={event => setDraft(current => ({ ...current, source_id: event.target.value }))} /></label><label>Investigation ID<input value={draft.investigation_id} onChange={event => setDraft(current => ({ ...current, investigation_id: event.target.value }))} /></label><label>Entity IDs<input value={entities} onChange={event => setEntities(event.target.value)} placeholder="id1, id2" /></label><label>Tags<input value={tags} onChange={event => setTags(event.target.value)} placeholder="login, xss, high" /></label><label>Data JSON<textarea value={dataJson} onChange={event => setDataJson(event.target.value)} /></label><button onClick={saveManual} disabled={create.isPending || !draft.title.trim()}>{create.isPending ? 'Saving...' : 'Save evidence'}</button></section>
    </section>
  </main>
}
