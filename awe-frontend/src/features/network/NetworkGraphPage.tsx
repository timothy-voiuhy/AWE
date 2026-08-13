import { useEffect, useMemo, useRef, useState } from 'react'
import cytoscape, { type Core } from 'cytoscape'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Link, useParams } from 'react-router-dom'

import { api, type GraphEntity, type GraphRelationship } from '../../api/client'

const palette: Record<string, string> = {
  target: '#89b4fa', domain: '#74c7ec', subdomain: '#74c7ec', url: '#a6e3a1', endpoint: '#a6e3a1',
  ip: '#cba6f7', port: '#cba6f7', technology: '#f9e2af', tech: '#f9e2af', vulnerability: '#f38ba8', vuln: '#f38ba8',
  parameter: '#fab387', param: '#fab387', osint: '#f5c2e7', custom: '#bac2de',
}
const MAX_RENDER_NODES = 350

function color(kind: string) { return palette[kind] || '#bac2de' }

export function NetworkGraphPage() {
  const { projectId = '' } = useParams()
  const queryClient = useQueryClient()
  const cyRef = useRef<Core | null>(null)
  const hostRef = useRef<HTMLDivElement>(null)
  const [investigationId, setInvestigationId] = useState('')
  const [selectedId, setSelectedId] = useState('')
  const [focusId, setFocusId] = useState('')
  const [focusDepth, setFocusDepth] = useState(1)
  const [graphExpanded, setGraphExpanded] = useState(false)
  const [query, setQuery] = useState('')
  const [kind, setKind] = useState('')
  const [selectedTransform, setSelectedTransform] = useState('')
  const [transformParameters, setTransformParameters] = useState<Record<string, string>>({})
  const [transformJobId, setTransformJobId] = useState('')
  const [notice, setNotice] = useState('')
  const [entityDraft, setEntityDraft] = useState({ kind: 'custom', label: '', value: '' })
  const [relationshipDraft, setRelationshipDraft] = useState({ source_id: '', target_id: '', kind: 'linked_to', label: '' })

  const investigations = useQuery({ queryKey: ['projects', projectId, 'investigations'], queryFn: () => api.listInvestigations(projectId) })
  useEffect(() => {
    if (!investigationId && investigations.data?.[0]) setInvestigationId(investigations.data[0].id)
  }, [investigations.data, investigationId])
  const graph = useQuery({ queryKey: ['projects', projectId, 'investigation-graph', investigationId, focusId, focusDepth], queryFn: () => api.getInvestigationGraph(projectId, investigationId, { focus_id: focusId || undefined, depth: focusDepth, limit: focusId ? 500 : undefined }), enabled: !!investigationId, refetchInterval: 5000 })
  const transforms = useQuery({ queryKey: ['projects', projectId, 'transforms'], queryFn: () => api.listGraphTransforms(projectId) })
  const activeTransform = transforms.data?.find(item => item.id === selectedTransform)
  const transformJob = useQuery({ queryKey: ['projects', projectId, 'transform-job', transformJobId], queryFn: () => api.getGraphTransform(projectId, transformJobId), enabled: !!transformJobId, refetchInterval: query => ['queued', 'running'].includes(query.state.data?.status || '') ? 1000 : false })
  const selected = graph.data?.entities.find(item => item.id === selectedId) || graph.data?.entities[0]
  const filteredEntities = useMemo(() => (graph.data?.entities || []).filter(item => {
    const haystack = `${item.label} ${item.value} ${item.kind} ${JSON.stringify(item.data)}`.toLowerCase()
    return (!query || haystack.includes(query.toLowerCase())) && (!kind || item.kind === kind)
  }), [graph.data?.entities, query, kind])
  const visibleEntities = useMemo(() => {
    if (filteredEntities.length <= MAX_RENDER_NODES) return filteredEntities
    const root = filteredEntities.find(item => item.kind === 'target')
    const selected = selectedId ? filteredEntities.find(item => item.id === selectedId) : undefined
    const prioritized = [root, selected, ...filteredEntities].filter((item): item is GraphEntity => Boolean(item))
    return [...new Map(prioritized.map(item => [item.id, item])).values()].slice(0, MAX_RENDER_NODES)
  }, [filteredEntities, selectedId])
  const renderSignature = useMemo(() => visibleEntities.map(item => `${item.id}:${item.label}:${item.kind}`).join('|'), [visibleEntities])
  const relationshipSignature = useMemo(() => {
    const allowed = new Set(visibleEntities.map(item => item.id))
    return (graph.data?.relationships || []).filter(edge => allowed.has(edge.source_id) && allowed.has(edge.target_id)).map(edge => `${edge.id}:${edge.source_id}:${edge.target_id}:${edge.label || edge.kind}`).join('|')
  }, [graph.data?.relationships, renderSignature, visibleEntities])

  useEffect(() => {
    if (!hostRef.current || !graph.data) return
    cyRef.current?.destroy()
    const allowed = new Set(visibleEntities.map(item => item.id))
    const elements: cytoscape.ElementDefinition[] = [
      ...visibleEntities.map(entity => ({ data: { id: entity.id, label: entity.label, kind: entity.kind, color: color(entity.kind), source: entity.source }, position: { x: entity.x || 0, y: entity.y || 0 } })),
      ...graph.data.relationships.filter(edge => allowed.has(edge.source_id) && allowed.has(edge.target_id)).map(edge => ({ data: { id: edge.id, source: edge.source_id, target: edge.target_id, label: edge.label || edge.kind } })),
    ]
    const cy = cytoscape({ container: hostRef.current, elements, style: [
      { selector: 'node', style: { 'background-color': 'data(color)', label: 'data(label)', color: '#cdd6f4', 'font-size': '10px', 'text-wrap': 'ellipsis', 'text-max-width': '120px', 'text-valign': 'bottom', 'text-margin-y': '8px', width: 34, height: 34, 'border-width': 2, 'border-color': '#313244' } as unknown as cytoscape.Css.Node },
      { selector: 'node:selected', style: { 'border-color': '#f9e2af', 'border-width': 4, 'overlay-color': '#f9e2af', 'overlay-opacity': 0.12 } as unknown as cytoscape.Css.Node },
      { selector: 'edge', style: { width: 1.5, 'line-color': '#585b70', 'target-arrow-color': '#7f849c', 'target-arrow-shape': 'triangle', label: 'data(label)', color: '#7f849c', 'font-size': '8px', 'curve-style': 'bezier', 'text-rotation': 'autorotate' } as unknown as cytoscape.Css.Edge },
    ], layout: visibleEntities.length > 120
      ? { name: 'grid', animate: false, padding: 40, avoidOverlap: true }
      : { name: 'cose', animate: false, padding: 40, numIter: 250 } })
    cy.on('tap', 'node', event => { setSelectedId(event.target.id()) })
    cy.on('dragfree', 'node', () => {
      const positions: Record<string, { x: number; y: number }> = {}
      cy.nodes().forEach(node => { positions[node.id()] = node.position() })
      if (graph.data) void api.saveGraphPreferences(projectId, graph.data.investigation.id, { preferences: { ...(graph.data.investigation.preferences || {}), positions }, revision: graph.data.investigation.revision })
    })
    cyRef.current = cy
    return () => { cy.destroy(); cyRef.current = null }
  }, [projectId, renderSignature, relationshipSignature])

  const createInvestigation = useMutation({ mutationFn: () => api.createInvestigation(projectId, 'New investigation'), onSuccess: item => { setInvestigationId(item.id); void queryClient.invalidateQueries({ queryKey: ['projects', projectId, 'investigations'] }) } })
  const createEntity = useMutation({ mutationFn: () => api.createGraphEntity(projectId, investigationId, { ...entityDraft, data: {}, confidence: 1, severity: '', scope: 'unknown', x: 0, y: 0 }), onSuccess: () => { setEntityDraft({ kind: 'custom', label: '', value: '' }); void queryClient.invalidateQueries({ queryKey: ['projects', projectId, 'investigation-graph', investigationId] }) } })
  const createRelationship = useMutation({ mutationFn: () => api.createGraphRelationship(projectId, investigationId, { ...relationshipDraft, data: {}, confidence: 1 }), onSuccess: () => { setRelationshipDraft({ source_id: '', target_id: '', kind: 'linked_to', label: '' }); void queryClient.invalidateQueries({ queryKey: ['projects', projectId, 'investigation-graph', investigationId] }) } })
  const deleteEntity = useMutation({ mutationFn: (id: string) => api.deleteGraphEntity(projectId, investigationId, id), onSuccess: () => { setSelectedId(''); void queryClient.invalidateQueries({ queryKey: ['projects', projectId, 'investigation-graph', investigationId] }) } })
  const transform = useMutation({ mutationFn: () => api.startGraphTransform(projectId, { transform_id: selectedTransform, entity_ids: selected ? [selected.id] : [], parameters: transformParameters, investigation_id: investigationId, approved: activeTransform?.requires_approval === true }), onSuccess: job => { setTransformJobId(job.id); setNotice(`Transform queued: ${activeTransform?.display_name || job.transform_id}.`); setSelectedTransform(''); setTransformParameters({}) } })

  useEffect(() => {
    if (!graphExpanded) return
    const closeOnEscape = (event: KeyboardEvent) => { if (event.key === 'Escape') setGraphExpanded(false) }
    document.addEventListener('keydown', closeOnEscape)
    return () => document.removeEventListener('keydown', closeOnEscape)
  }, [graphExpanded])

  const kinds = [...new Set((graph.data?.entities || []).map(item => item.kind))].sort()
  const selectedRelationships = (graph.data?.relationships || []).filter(item => item.source_id === selected?.id || item.target_id === selected?.id)
  const exportGraph = () => {
    if (!graph.data) return
    const safeName = graph.data.investigation.name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '') || 'investigation'
    const blob = new Blob([JSON.stringify(graph.data, null, 2)], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const anchor = document.createElement('a')
    anchor.href = url
    anchor.download = `awe-${safeName}.json`
    document.body.appendChild(anchor)
    anchor.click()
    anchor.remove()
    URL.revokeObjectURL(url)
  }

  return <main className={`page feature-page network-page${graphExpanded ? ' network-expanded' : ''}`}>
    <Link className="back-link" to={`/projects/${projectId}`}>← Project workspace</Link>
    <header className="page-header"><div><p className="eyebrow">Investigation workbench</p><h1>Network Graph</h1><p className="muted">Explore derived attack-surface data, analyst entities, evidence, and Docker-backed transforms.</p></div><button onClick={() => createInvestigation.mutate()} disabled={createInvestigation.isPending}>＋ New investigation</button></header>
    <section className="panel graph-toolbar"><select value={investigationId} onChange={event => { setInvestigationId(event.target.value); setSelectedId(''); setFocusId('') }}>{investigations.data?.map(item => <option value={item.id} key={item.id}>{item.name}</option>)}</select><input value={query} onChange={event => setQuery(event.target.value)} placeholder="Search entities…"/><select value={kind} onChange={event => setKind(event.target.value)}><option value="">All entity types</option>{kinds.map(item => <option value={item} key={item}>{item}</option>)}</select><button onClick={() => cyRef.current?.fit(undefined, 40)}>Fit</button><button onClick={() => cyRef.current?.layout({ name: 'cose', animate: true, padding: 40 }).run()}>Auto layout</button><select aria-label="Focus depth" value={focusDepth} onChange={event => setFocusDepth(Number(event.target.value))}><option value={1}>Depth 1</option><option value={2}>Depth 2</option><option value={3}>Depth 3</option></select><button onClick={() => selected && setFocusId(selected.id)} disabled={!selected}>Focus selected</button>{focusId && <button onClick={() => setFocusId('')}>Overview</button>}<button onClick={exportGraph} disabled={!graph.data}>Export JSON</button><button onClick={() => setGraphExpanded(value => !value)}>{graphExpanded ? 'Exit full workspace' : 'View graph full workspace'}</button><span className="graph-count">{visibleEntities.length} entities · {graph.data?.relationships.length || 0} links</span></section>
    {notice && <p className="success">{notice}</p>}{graph.isError && <p className="error">Could not load the investigation graph.</p>}{transformJob.data && <p className={transformJob.data.status === 'failed' ? 'error' : 'success'}>Transform {transformJob.data.status}{transformJob.data.message ? ` — ${transformJob.data.message}` : ''}</p>}{focusId && <p className="graph-focus-notice">Focused on <code>{focusId}</code> through depth {focusDepth}. <button onClick={() => setFocusId('')}>Return to overview</button></p>}{filteredEntities.length > MAX_RENDER_NODES && <p className="graph-limit-notice">Large graph detected: showing {MAX_RENDER_NODES} of {filteredEntities.length} matching entities for responsive rendering. Use search or type filters to narrow the view.</p>}
    <section className="graph-workbench"><section className="panel graph-canvas"><div ref={hostRef} className="cytoscape-host" />{graph.isPending && !graph.data && <div className="graph-overlay">Loading graph…</div>}{!visibleEntities.length && !graph.isPending && <div className="graph-overlay">No entities match the active filters.</div>}</section>
      <aside className="panel graph-inspector">{selected ? <><header><div><b>{selected.label}</b><span>{selected.kind} · {selected.source}</span></div><button className="danger" onClick={() => { if (selected.source === 'manual' && confirm('Delete this analyst entity?')) deleteEntity.mutate(selected.id) }}>Delete</button></header><dl className="graph-properties"><dt>Value</dt><dd><code>{selected.value || selected.label}</code></dd><dt>Confidence</dt><dd>{Math.round(selected.confidence * 100)}%</dd><dt>Relationships</dt><dd>{selectedRelationships.length}</dd></dl><div className="graph-actions"><select value={selectedTransform} onChange={event => { setSelectedTransform(event.target.value); setTransformParameters({}) }}><option value="">Run transform…</option>{transforms.data?.filter(item => item.input_types.includes(selected.kind)).map(item => <option value={item.id} key={item.id}>{item.display_name}{item.requires_approval ? ' · approval' : ''}</option>)}</select><button disabled={!selectedTransform || transform.isPending} onClick={() => transform.mutate()}>Run</button></div>{activeTransform && <div className="transform-parameters"><small>{activeTransform.description || 'Transform parameters'}</small>{activeTransform.parameters.map(parameter => { const key = String(parameter.key || ''); return <label key={key}>{String(parameter.label || key)}<input value={transformParameters[key] || String(parameter.default || '')} onChange={event => setTransformParameters({ ...transformParameters, [key]: event.target.value })} placeholder={key} /></label> })}<span className={`transform-risk risk-${activeTransform.mode}`}>{activeTransform.mode}{activeTransform.requires_approval ? ' · approval required' : ''}</span></div>}<div className="graph-relationships"><b>Relationships</b>{selectedRelationships.map(edge => <span key={edge.id}>{edge.kind}: {edge.source_id === selected.id ? edge.target_id : edge.source_id}</span>)}</div><div className="graph-provenance"><b>Provenance</b>{selected.provenance.length ? selected.provenance.map((item, index) => <span key={`${String(item.source || item.tool_key || 'source')}-${index}`}>{String(item.source || item.tool_key || 'source')}{item.tool_key ? ` · ${String(item.tool_key)}` : ''}{item.transform_job_id ? ` · job ${String(item.transform_job_id)}` : ''}</span>) : <small>No source metadata recorded.</small>}</div><details><summary>Properties</summary><pre>{JSON.stringify(selected.data, null, 2)}</pre></details></> : <div className="empty">Select an entity to inspect it.</div>}
        <form className="graph-form" onSubmit={event => { event.preventDefault(); if (entityDraft.label.trim()) createEntity.mutate() }}><b>Add analyst entity</b><input value={entityDraft.kind} onChange={event => setEntityDraft({ ...entityDraft, kind: event.target.value })} placeholder="Type"/><input value={entityDraft.label} onChange={event => setEntityDraft({ ...entityDraft, label: event.target.value })} placeholder="Label"/><input value={entityDraft.value} onChange={event => setEntityDraft({ ...entityDraft, value: event.target.value })} placeholder="Canonical value"/><button>Add entity</button></form>
        <form className="graph-form" onSubmit={event => { event.preventDefault(); if (relationshipDraft.source_id && relationshipDraft.target_id) createRelationship.mutate() }}><b>Add relationship</b><input value={relationshipDraft.source_id} onChange={event => setRelationshipDraft({ ...relationshipDraft, source_id: event.target.value })} placeholder="Source entity ID"/><input value={relationshipDraft.target_id} onChange={event => setRelationshipDraft({ ...relationshipDraft, target_id: event.target.value })} placeholder="Target entity ID"/><input value={relationshipDraft.kind} onChange={event => setRelationshipDraft({ ...relationshipDraft, kind: event.target.value })} placeholder="Relationship type"/><button>Add link</button></form>
      </aside></section>
  </main>
}
