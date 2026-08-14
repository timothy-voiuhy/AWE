import { useEffect, useMemo, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Link, useParams } from 'react-router-dom'

import { api, type DockerToolInput, type ToolParamSpec } from '../../api/client'

const emptyTool: DockerToolInput = {
  key: '', display_name: '', category: 'architecture', image: '', description: '',
  command_template: '', param_specs: [], dockerfile: 'FROM alpine:3.19\nRUN mkdir -p /output\n',
  parser: 'def parse(output_dir: str) -> list:\n    return []\n', input_types: ['domain'],
  output_types: ['component'], relationship_types: ['has_component'], execution_mode: 'safe_active',
  credential_fields: [],
}

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

export function GraphToolsPage() {
  const { projectId = '' } = useParams()
  const qc = useQueryClient()
  const [investigationId, setInvestigationId] = useState('')
  const [transformId, setTransformId] = useState('')
  const [entityId, setEntityId] = useState('')
  const [parameters, setParameters] = useState<Record<string, unknown>>({})
  const [jobId, setJobId] = useState('')
  const [custom, setCustom] = useState<DockerToolInput>(emptyTool)
  const [paramJson, setParamJson] = useState('[]')
  const [notice, setNotice] = useState('')

  const investigations = useQuery({ queryKey: ['projects', projectId, 'investigations'], queryFn: () => api.listInvestigations(projectId) })
  const transforms = useQuery({ queryKey: ['projects', projectId, 'transforms'], queryFn: () => api.listGraphTransforms(projectId) })
  const tools = useQuery({ queryKey: ['docker', 'tools'], queryFn: api.listDockerTools })
  const graph = useQuery({ queryKey: ['projects', projectId, 'investigation-graph', investigationId], queryFn: () => api.getInvestigationGraph(projectId, investigationId, { limit: 5000 }), enabled: !!investigationId })
  const job = useQuery({ queryKey: ['projects', projectId, 'transform-job', jobId], queryFn: () => api.getGraphTransform(projectId, jobId), enabled: !!jobId, refetchInterval: query => ['queued', 'running'].includes(query.state.data?.status || '') ? 1000 : false })
  useEffect(() => { if (!investigationId && investigations.data?.[0]) setInvestigationId(investigations.data[0].id) }, [investigationId, investigations.data])
  const selected = transforms.data?.find(item => item.id === transformId)
  const compatibleEntities = useMemo(() => graph.data?.entities.filter(entity => selected?.input_types.includes(entity.kind)) || [], [graph.data, selected])
  useEffect(() => { if (!transformId && transforms.data?.[0]) setTransformId(transforms.data[0].id) }, [transformId, transforms.data])
  useEffect(() => { if (compatibleEntities.length && !compatibleEntities.some(entity => entity.id === entityId)) setEntityId(compatibleEntities[0].id || '') }, [compatibleEntities, entityId])
  useEffect(() => { setParameters({}) }, [transformId])

  const run = useMutation({
    mutationFn: async () => {
      if (!selected || !entityId) throw new Error('Choose a compatible graph entity first.')
      if (selected.requires_approval && !window.confirm(`Run ${selected.display_name} in ${selected.mode} mode? This may actively interact with the target.`)) throw new Error('Execution cancelled.')
      return api.startGraphTransform(projectId, { transform_id: selected.id, entity_ids: [entityId], parameters, investigation_id: investigationId, approved: selected.requires_approval })
    },
    onSuccess: item => { setJobId(item.id); setNotice(`Queued ${selected?.display_name || item.transform_id}.`); void qc.invalidateQueries({ queryKey: ['projects', projectId, 'investigation-graph', investigationId] }) },
  })
  const create = useMutation({
    mutationFn: () => api.createDockerTool({ ...custom, param_specs: JSON.parse(paramJson) }),
    onSuccess: item => { setNotice(`Created ${item.display_name} as a graph tool.`); setCustom(emptyTool); setParamJson('[]'); void qc.invalidateQueries({ queryKey: ['projects', projectId, 'transforms'] }); void qc.invalidateQueries({ queryKey: ['docker', 'tools'] }) },
  })
  const update = (key: string, value: unknown) => setCustom(current => ({ ...current, [key]: value } as DockerToolInput))
  return <main className="page feature-page graph-tools-page">
    <Link className="back-link" to={`/projects/${projectId}/network`}>← Network graph</Link>
    <header className="page-header"><div><p className="eyebrow">Graph automation</p><h1>Graph Tools</h1><p className="muted">Configure built-in and custom Docker transforms, run them against graph entities, and ingest typed results into an investigation.</p></div><Link className="button-link" to={`/projects/${projectId}/docker`}>Docker manager</Link></header>
    {notice && <p className="success">{notice}</p>}{(run.isError || create.isError || job.isError) && <p className="error">{String((run.error || create.error || job.error)?.message)}</p>}
    <section className="graph-tools-grid">
      <section className="panel graph-tool-runner"><header><div><b>Run graph transform</b><span>Outputs are parsed and attached to the selected investigation.</span></div><span className={`transform-risk risk-${selected?.mode || 'passive'}`}>{selected?.mode || 'passive'}</span></header><label>Investigation<select value={investigationId} onChange={event => setInvestigationId(event.target.value)}>{investigations.data?.map(item => <option value={item.id} key={item.id}>{item.name}</option>)}</select></label><label>Transform<select value={transformId} onChange={event => setTransformId(event.target.value)}>{transforms.data?.map(item => <option value={item.id} key={item.id}>{item.display_name} · {item.mode}</option>)}</select></label><label>Input entity<select value={entityId} onChange={event => setEntityId(event.target.value)}>{compatibleEntities.map(entity => <option value={entity.id} key={entity.id}>{entity.label} · {entity.kind}</option>)}</select></label>{selected && <><p className="muted">{selected.description}</p><small>Accepts: {selected.input_types.join(', ')} · Produces: {selected.output_types.join(', ')} · Relationships: {selected.relationship_types.join(', ')}</small><ParameterFields specs={selected.parameters} values={parameters} onChange={(key, value) => setParameters(current => ({ ...current, [key]: value }))} /><button onClick={() => run.mutate()} disabled={!selected || !entityId || run.isPending}>{run.isPending ? 'Starting…' : 'Run transform'}</button></>}</section>
      <section className="panel graph-tool-status"><header><b>Execution status</b><span>{job.data?.status || 'No graph run selected'}</span></header>{job.data ? <><p>{job.data.message || 'Waiting for operation output…'}</p><div className="transform-progress-track"><span style={{ width: `${job.data.progress_total ? Math.round(((job.data.progress_completed || 0) / job.data.progress_total) * 100) : job.data.status === 'completed' ? 100 : 18}%` }} /></div><pre>{job.data.logs?.slice(-20).join('\n') || 'No logs yet.'}</pre></> : <p className="muted">Run a transform to monitor parsing, approval, and graph ingestion.</p>}{tools.data?.filter(item => item.graph_enabled).length ? <div><b>Graph-enabled catalog</b>{tools.data.filter(item => item.graph_enabled).map(item => <span className="graph-tool-catalog-row" key={item.key}>{item.display_name}<small>{item.execution_mode} · {item.output_types.join(', ')}</small></span>)}</div> : null}</section>
    </section>
    <section className="panel graph-tool-create"><header><div><b>Create custom graph tool</b><span>Define the Docker command, parser, graph contract, and safety mode in one place.</span></div></header><div className="graph-tool-editor-grid"><label>Key<input value={custom.key} onChange={event => update('key', event.target.value)} placeholder="my_scanner" /></label><label>Display name<input value={custom.display_name} onChange={event => update('display_name', event.target.value)} /></label><label>Image<input value={custom.image} onChange={event => update('image', event.target.value || `awe/custom_${custom.key}`)} /></label><label>Category<input value={custom.category} onChange={event => update('category', event.target.value)} /></label><label className="wide">Description<input value={custom.description} onChange={event => update('description', event.target.value)} /></label><label className="wide">Command template<input value={custom.command_template} onChange={event => update('command_template', event.target.value)} placeholder="scanner -u {url} -o /output/results.json" /></label><label>Input types<input value={custom.input_types.join(', ')} onChange={event => update('input_types', event.target.value.split(',').map(v => v.trim()).filter(Boolean))} /></label><label>Output types<input value={custom.output_types.join(', ')} onChange={event => update('output_types', event.target.value.split(',').map(v => v.trim()).filter(Boolean))} /></label><label>Relationships<input value={custom.relationship_types.join(', ')} onChange={event => update('relationship_types', event.target.value.split(',').map(v => v.trim()).filter(Boolean))} /></label><label>Execution mode<select value={custom.execution_mode} onChange={event => update('execution_mode', event.target.value)}><option value="passive">Passive</option><option value="safe_active">Safe active</option><option value="active">Active</option><option value="high_risk">High risk</option></select></label><label>Credential fields<input value={custom.credential_fields.join(', ')} onChange={event => update('credential_fields', event.target.value.split(',').map(v => v.trim()).filter(Boolean))} /></label><label className="wide">Parameters JSON<textarea value={paramJson} onChange={event => setParamJson(event.target.value)} placeholder='[{"key":"url","label":"Target URL","type":"text"}]' /></label><label className="wide">Dockerfile<textarea value={custom.dockerfile} onChange={event => update('dockerfile', event.target.value)} /></label><label className="wide">parser.py<textarea value={custom.parser} onChange={event => update('parser', event.target.value)} /></label></div><button onClick={() => { try { JSON.parse(paramJson); create.mutate() } catch { setNotice('Parameters JSON is invalid.') } }} disabled={create.isPending || !custom.key || !custom.display_name || !custom.image || !custom.command_template}>{create.isPending ? 'Saving…' : 'Create graph tool'}</button></section>
  </main>
}
