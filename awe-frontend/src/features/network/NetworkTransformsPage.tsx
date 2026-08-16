import { useEffect, useMemo, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Link, useParams } from 'react-router-dom'

import { api, type DockerTool, type ToolParamSpec, type TransformDefinitionInput, type TransformManifest, type TransformStage } from '../../api/client'

function valueFor(spec: ToolParamSpec, values: Record<string, unknown>) {
  if (values[spec.key] !== undefined) return values[spec.key]
  if (spec.type === 'secret' || spec.default === 'secret') return ''
  return spec.default ?? (spec.type === 'check' ? false : '')
}

function ParameterFields({ specs, values, onChange }: { specs: Array<Record<string, unknown>>; values: Record<string, unknown>; onChange: (key: string, value: unknown) => void }) {
  return <div className="graph-tool-params">{specs.map(raw => {
    const spec = raw as unknown as ToolParamSpec
    const current = valueFor(spec, values)
    if (spec.type === 'check') return <label key={spec.key} className="graph-tool-check"><input type="checkbox" checked={Boolean(current)} onChange={event => onChange(spec.key, event.target.checked)} />{spec.label || spec.key}</label>
    if (spec.type === 'combo') return <label key={spec.key}>{spec.label || spec.key}<select value={String(current)} onChange={event => onChange(spec.key, event.target.value)}>{(spec.options || []).map(option => <option key={option}>{option}</option>)}</select></label>
    return <label key={spec.key}>{spec.label || spec.key}<input type={spec.type === 'secret' || spec.default === 'secret' ? 'password' : 'text'} value={String(current)} onChange={event => onChange(spec.key, event.target.value)} placeholder={spec.type === 'secret' ? 'Stored only for this run' : spec.key} /></label>
  })}</div>
}

const emptyComposite: TransformDefinitionInput = {
  id: '', display_name: 'Enumerate live subdomains', description: 'Run multiple subdomain tools, tunnel results into live probing, and ingest only the final graph-ready output.',
  input_types: ['target', 'domain', 'subdomain'], output_types: ['subdomain'], relationship_types: ['has_subdomain'],
  mode: 'safe_active', requires_approval: false, scope_required: true, parameters: [
    { key: 'domain', label: 'Target domain', type: 'text', default: '' },
    { key: 'flags', label: 'httpx extra flags', type: 'text', default: '' },
  ],
  stages: [
    { name: 'Enumerate', tool_keys: ['subfinder', 'assetfinder', 'amass', 'ctl'], input_source: 'seed', parameters: {} },
    { name: 'Live probe', tool_keys: ['httpx'], input_source: 'previous', parameters: {} },
  ],
}

function csv(value: string) {
  return value.split(',').map(item => item.trim()).filter(Boolean)
}

function TransformCatalog({ transforms, selectedId, onSelect, onDelete }: { transforms: TransformManifest[]; selectedId: string; onSelect: (id: string) => void; onDelete: (id: string) => void }) {
  return <section className="panel transform-catalog"><header><div><b>Transform catalog</b><span>{transforms.length} available graph transforms</span></div></header>
    <div>{transforms.map(item => <article className={item.id === selectedId ? 'selected' : ''} key={item.id}>
      <header><div><b>{item.display_name}</b><span>{item.mode}{item.requires_approval ? ' · approval required' : ''}{item.stages?.length ? ` · ${item.stages.length} stages` : ' · single tool'}</span></div><button type="button" onClick={() => onSelect(item.id)}>Select</button></header>
      <p>{item.description || 'No transform description provided.'}</p>
      <dl><dt>Tool</dt><dd><code>{item.tool_key}</code></dd><dt>Inputs</dt><dd>{item.input_types.join(', ') || 'None declared'}</dd><dt>Outputs</dt><dd>{item.output_types.join(', ') || 'None declared'}</dd><dt>Relationships</dt><dd>{item.relationship_types.join(', ') || 'None declared'}</dd></dl>
      {item.stages?.length ? <ol className="transform-stage-list">{item.stages.map((stage, index) => <li key={`${item.id}-${index}`}><b>{stage.name || `Stage ${index + 1}`}</b><span>{stage.tool_keys.join(', ')} · input: {stage.input_source}</span></li>)}</ol> : null}
      {item.id.startsWith('custom:') && <button type="button" className="subtle" onClick={() => onDelete(item.id)}>Delete custom transform</button>}
    </article>)}</div>
  </section>
}

function CompositeBuilder({ tools, value, onChange, onSave, saving }: { tools: DockerTool[]; value: TransformDefinitionInput; onChange: (value: TransformDefinitionInput) => void; onSave: () => void; saving: boolean }) {
  const graphTools = tools.filter(tool => tool.graph_enabled)
  const updateStage = (index: number, patch: Partial<TransformStage>) => onChange({ ...value, stages: value.stages.map((stage, i) => i === index ? { ...stage, ...patch } : stage) })
  return <section className="panel graph-tool-create"><header><div><b>Create composite transform</b><span>Define staged tooling and tunnel previous stage output through tools that accept an input file.</span></div></header>
    <div className="graph-tool-editor-grid">
      <label>Id<input value={value.id || ''} onChange={event => onChange({ ...value, id: event.target.value })} placeholder="custom:live-subdomains" /></label>
      <label>Display name<input value={value.display_name} onChange={event => onChange({ ...value, display_name: event.target.value })} /></label>
      <label>Mode<select value={value.mode} onChange={event => onChange({ ...value, mode: event.target.value as TransformDefinitionInput['mode'] })}><option value="passive">Passive</option><option value="safe_active">Safe active</option><option value="active">Active</option><option value="high_risk">High risk</option></select></label>
      <label className="wide">Description<input value={value.description} onChange={event => onChange({ ...value, description: event.target.value })} /></label>
      <label>Input types<input value={value.input_types.join(', ')} onChange={event => onChange({ ...value, input_types: csv(event.target.value) })} /></label>
      <label>Output types<input value={value.output_types.join(', ')} onChange={event => onChange({ ...value, output_types: csv(event.target.value) })} /></label>
      <label>Relationships<input value={value.relationship_types.join(', ')} onChange={event => onChange({ ...value, relationship_types: csv(event.target.value) })} /></label>
    </div>
    <div className="transform-builder-stages">{value.stages.map((stage, index) => <article key={index}>
      <header><b>Stage {index + 1}</b><button type="button" disabled={value.stages.length < 2} onClick={() => onChange({ ...value, stages: value.stages.filter((_, i) => i !== index) })}>Remove</button></header>
      <label>Name<input value={stage.name} onChange={event => updateStage(index, { name: event.target.value })} /></label>
      <label>Tools<input list="graph-tool-keys" value={stage.tool_keys.join(', ')} onChange={event => updateStage(index, { tool_keys: csv(event.target.value) })} placeholder="subfinder, assetfinder" /></label>
      <label>Input<select value={stage.input_source} onChange={event => updateStage(index, { input_source: event.target.value as TransformStage['input_source'] })}><option value="seed">Seed entity/parameters</option><option value="previous">Previous stage output</option></select></label>
    </article>)}</div>
    <datalist id="graph-tool-keys">{graphTools.map(tool => <option key={tool.key} value={tool.key}>{tool.display_name}</option>)}</datalist>
    <footer className="network-transform-actions"><button type="button" onClick={() => onChange({ ...value, stages: [...value.stages, { name: `Stage ${value.stages.length + 1}`, tool_keys: [], input_source: 'previous', parameters: {} }] })}>Add stage</button><button type="button" onClick={onSave} disabled={saving || !value.display_name || value.stages.some(stage => !stage.tool_keys.length)}>{saving ? 'Saving...' : 'Save composite transform'}</button></footer>
  </section>
}

export function NetworkTransformsPage() {
  const { projectId = '' } = useParams()
  const qc = useQueryClient()
  const [investigationId, setInvestigationId] = useState('')
  const [transformId, setTransformId] = useState('')
  const [entityId, setEntityId] = useState('')
  const [parameters, setParameters] = useState<Record<string, unknown>>({})
  const [composite, setComposite] = useState<TransformDefinitionInput>(emptyComposite)
  const [jobId, setJobId] = useState('')
  const [notice, setNotice] = useState('')

  const investigations = useQuery({ queryKey: ['projects', projectId, 'investigations'], queryFn: () => api.listInvestigations(projectId) })
  const transforms = useQuery({ queryKey: ['projects', projectId, 'transforms'], queryFn: () => api.listGraphTransforms(projectId) })
  const tools = useQuery({ queryKey: ['docker', 'tools'], queryFn: api.listDockerTools })
  const graph = useQuery({ queryKey: ['projects', projectId, 'investigation-graph', investigationId], queryFn: () => api.getInvestigationGraph(projectId, investigationId, { limit: 5000 }), enabled: !!investigationId })
  const job = useQuery({ queryKey: ['projects', projectId, 'transform-job', jobId], queryFn: () => api.getGraphTransform(projectId, jobId), enabled: !!jobId, refetchInterval: query => ['queued', 'running'].includes(query.state.data?.status || '') ? 1000 : false })
  useEffect(() => { if (!investigationId && investigations.data?.[0]) setInvestigationId(investigations.data[0].id) }, [investigationId, investigations.data])
  useEffect(() => { if (!transformId && transforms.data?.[0]) setTransformId(transforms.data[0].id) }, [transformId, transforms.data])
  const selected = transforms.data?.find(item => item.id === transformId)
  const compatibleEntities = useMemo(() => graph.data?.entities.filter(entity => selected?.input_types.includes(entity.kind)) || [], [graph.data, selected])
  useEffect(() => { if (compatibleEntities.length && !compatibleEntities.some(entity => entity.id === entityId)) setEntityId(compatibleEntities[0].id || '') }, [compatibleEntities, entityId])
  useEffect(() => { setParameters({}) }, [transformId])

  const run = useMutation({
    mutationFn: async () => {
      if (!selected || !entityId) throw new Error('Choose a compatible graph entity first.')
      if (selected.requires_approval && !window.confirm(`Run ${selected.display_name} in ${selected.mode} mode? This may actively interact with the target.`)) throw new Error('Execution cancelled.')
      return api.startGraphTransform(projectId, { transform_id: selected.id, entity_ids: [entityId], parameters, investigation_id: investigationId, approved: selected.requires_approval })
    },
    onSuccess: item => { setJobId(item.id); setNotice(`Queued ${selected?.display_name || item.transform_id}.`); void qc.invalidateQueries({ queryKey: ['projects', projectId, 'investigation-graph', investigationId] }); void qc.invalidateQueries({ queryKey: ['projects', projectId, 'transform-jobs'] }) },
  })
  const saveComposite = useMutation({
    mutationFn: () => api.createTransformDefinition(projectId, composite),
    onSuccess: item => { setNotice(`Saved composite transform ${item.display_name}.`); setTransformId(item.id); setComposite(emptyComposite); void qc.invalidateQueries({ queryKey: ['projects', projectId, 'transforms'] }) },
  })
  const deleteComposite = useMutation({
    mutationFn: (id: string) => api.deleteTransformDefinition(projectId, id),
    onSuccess: () => { setNotice('Deleted custom transform.'); void qc.invalidateQueries({ queryKey: ['projects', projectId, 'transforms'] }) },
  })

  return <main className="page feature-page network-transforms-page">
    
    <header className="page-header graph-tools-header"><div><p className="eyebrow">Network</p><h1>Transforms</h1><p className="muted">Run graph-capable Docker tools against selected investigation entities.</p></div><div className="network-transform-actions"><Link className="button-link subtle" to={`/projects/${projectId}/network/tools`}>Tool catalog</Link><Link className="button-link" to={`/projects/${projectId}/network/logs`}>Live logs</Link></div></header>
    {notice && <p className="success">{notice}</p>}{(run.isError || job.isError || transforms.isError || graph.isError || saveComposite.isError || deleteComposite.isError) && <p className="error">{String((run.error || job.error || transforms.error || graph.error || saveComposite.error || deleteComposite.error)?.message)}</p>}
    <section className="network-transforms-workbench">
      <section className="panel graph-tool-runner"><header><div><b>Run graph transform</b><span>Outputs are parsed and attached to the selected investigation.</span></div><span className={`transform-risk risk-${selected?.mode || 'passive'}`}>{selected?.mode || 'passive'}</span></header><label>Investigation<select value={investigationId} onChange={event => setInvestigationId(event.target.value)}>{investigations.data?.map(item => <option value={item.id} key={item.id}>{item.name}</option>)}</select></label><label>Transform<select value={transformId} onChange={event => setTransformId(event.target.value)}>{transforms.data?.map(item => <option value={item.id} key={item.id}>{item.display_name} · {item.mode}</option>)}</select></label><label>Input entity<select value={entityId} onChange={event => setEntityId(event.target.value)}>{compatibleEntities.map(entity => <option value={entity.id} key={entity.id}>{entity.label} · {entity.kind}</option>)}</select></label>{selected && <><p className="muted">{selected.description}</p><small>Accepts: {selected.input_types.join(', ')} · Produces: {selected.output_types.join(', ')} · Relationships: {selected.relationship_types.join(', ')}</small><ParameterFields specs={selected.parameters} values={parameters} onChange={(key, value) => setParameters(current => ({ ...current, [key]: value }))} /><button onClick={() => run.mutate()} disabled={!selected || !entityId || run.isPending}>{run.isPending ? 'Starting...' : 'Run transform'}</button></>}</section>
      <section className="panel graph-tool-status"><header><b>Execution status</b><span>{job.data?.status || 'No graph run selected'}</span></header>{job.data ? <><p>{job.data.message || 'Waiting for operation output...'}</p><div className="transform-progress-track"><span style={{ width: `${job.data.progress_total ? Math.round(((job.data.progress_completed || 0) / job.data.progress_total) * 100) : job.data.status === 'completed' ? 100 : 18}%` }} /></div><pre>{job.data.logs?.slice(-30).join('\n') || 'No logs yet.'}</pre><Link className="button-link subtle" to={`/projects/${projectId}/network/logs`}>Open full logs</Link></> : <p className="muted">Run a transform to monitor parsing, approval, and graph ingestion.</p>}</section>
    </section>
    <CompositeBuilder tools={tools.data || []} value={composite} onChange={setComposite} onSave={() => saveComposite.mutate()} saving={saveComposite.isPending} />
    {transforms.data?.length ? <TransformCatalog transforms={transforms.data} selectedId={transformId} onSelect={setTransformId} onDelete={id => deleteComposite.mutate(id)} /> : null}
  </main>
}
