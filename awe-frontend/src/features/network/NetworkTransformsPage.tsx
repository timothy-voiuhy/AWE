import { useEffect, useMemo, useRef, useState, type ReactNode } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Link, useParams } from 'react-router-dom'

import { api, type DockerTool, type ToolParamSpec, type TransformDefinitionInput, type TransformJob, type TransformManifest, type TransformStage } from '../../api/client'
import { CategoryGroup, groupByCategory } from '../../components/CategoryGroup'
import { OptionsMenu } from '../../components/OptionsMenu'

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
  id: '', display_name: 'Enumerate live subdomains', category: 'subdomain', description: 'Run multiple subdomain tools, tunnel results into live probing, and ingest only the final graph-ready output.',
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

const activeJobStatuses = new Set<TransformJob['status']>(['queued', 'running', 'approval_required'])

function TransformRunRow({ job, manifest, onResume, onCancel, busy }: { job: TransformJob; manifest?: TransformManifest; onResume: (job: TransformJob, parameters: Record<string, unknown>, manifest?: TransformManifest) => void; onCancel: (id: string) => void; busy: boolean }) {
  const [secrets, setSecrets] = useState<Record<string, string>>({})
  const secretSpecs = (manifest?.parameters || []).map(spec => spec as unknown as ToolParamSpec).filter(spec => spec.type === 'secret' || spec.default === 'secret')
  const name = manifest?.display_name || job.transform_id
  const progress = job.progress_total
    ? Math.min(100, Math.round(((job.progress_completed || 0) / job.progress_total) * 100))
    : job.status === 'completed' ? 100 : activeJobStatuses.has(job.status) ? 18 : 100
  return <article className={`transform-run-row run-${job.status}`}>
    <div className="transform-run-heading"><div><b>{name}</b><small>{new Date(job.created_at).toLocaleString()}</small></div><span className="transform-run-status">{job.status.replace('_', ' ')}</span></div>
    <p>{job.message || (activeJobStatuses.has(job.status) ? 'Waiting for operation output…' : 'No status details available.')}</p>
    <div className="transform-progress-track" role="progressbar" aria-label={`${name} progress`} aria-valuenow={progress} aria-valuemin={0} aria-valuemax={100}><span style={{ width: `${progress}%` }} /></div>
    {job.progress_total ? <small>{job.progress_completed || 0} of {job.progress_total} steps</small> : null}
    {job.logs?.length ? <details><summary>Latest output ({job.logs.length} lines)</summary><pre>{job.logs.slice(-30).join('\n')}</pre></details> : null}
    {activeJobStatuses.has(job.status) ? <div className="transform-run-actions"><button type="button" className="subtle" onClick={() => onCancel(job.id)} disabled={busy}>Cancel run</button></div> : null}
    {['failed', 'cancelled'].includes(job.status) ? <div className="transform-run-actions">{secretSpecs.length ? <details className="transform-resume-secrets"><summary>Resume run</summary><div>{secretSpecs.map(spec => <label key={spec.key}>{spec.label || spec.key}<input type="password" autoComplete="off" value={secrets[spec.key] || ''} onChange={event => setSecrets(current => ({ ...current, [spec.key]: event.target.value }))} placeholder="Re-enter after a backend restart if needed" /></label>)}<button type="button" onClick={() => onResume(job, secrets, manifest)} disabled={busy}>{busy ? 'Resuming…' : 'Resume transform'}</button></div></details> : <button type="button" onClick={() => onResume(job, {}, manifest)} disabled={busy}>{busy ? 'Resuming…' : 'Resume transform'}</button>}</div> : null}
  </article>
}

function TransformCatalog({ transforms, onRun, onDelete, actions }: { transforms: TransformManifest[]; onRun: (id: string) => void; onDelete: (id: string) => void; actions: ReactNode }) {
  const groups = groupByCategory(transforms)
  return <section className="panel transform-catalog"><header><div><b>Transform catalog</b><span>{transforms.length} available graph transforms</span></div>{actions}</header>
    <div className="catalog-groups">{groups.map(group => <CategoryGroup key={group.category} name={group.category} count={group.entries.length}><div className="transform-catalog-grid">{group.entries.map(item => <article key={item.id}>
      <header><div><b>{item.display_name}</b><span>{item.mode}{item.requires_approval ? ' · approval required' : ''}{item.stages?.length ? ` · ${item.stages.length} stages` : ' · single tool'}</span></div><button type="button" onClick={() => onRun(item.id)}>Run</button></header>
      <p>{item.description || 'No transform description provided.'}</p>
      <dl><dt>Tool</dt><dd><code>{item.tool_key}</code></dd><dt>Execution</dt><dd>{item.execution_kind || 'batch'}</dd><dt>Outputs</dt><dd>{(item.output_channels || ['logs', 'structured']).join(', ')}</dd><dt>Inputs</dt><dd>{item.input_types.join(', ') || 'None declared'}</dd><dt>Entities</dt><dd>{item.output_types.join(', ') || 'Researcher-reviewed output'}</dd><dt>Relationships</dt><dd>{item.relationship_types.join(', ') || 'None declared'}</dd></dl>
      {item.stages?.length ? <ol className="transform-stage-list">{item.stages.map((stage, index) => <li key={`${item.id}-${index}`}><b>{stage.name || `Stage ${index + 1}`}</b><span>{stage.tool_keys.join(', ')} · input: {stage.input_source}</span></li>)}</ol> : null}
      {item.id.startsWith('custom:') && <button type="button" className="subtle" onClick={() => onDelete(item.id)}>Delete custom transform</button>}
    </article>)}</div></CategoryGroup>)}</div>
  </section>
}

function CompositeBuilder({ tools, value, onChange, onSave, onClose, saving, error }: { tools: DockerTool[]; value: TransformDefinitionInput; onChange: (value: TransformDefinitionInput) => void; onSave: () => void; onClose: () => void; saving: boolean; error?: string }) {
  const graphTools = tools.filter(tool => tool.graph_enabled)
  const updateStage = (index: number, patch: Partial<TransformStage>) => onChange({ ...value, stages: value.stages.map((stage, i) => i === index ? { ...stage, ...patch } : stage) })
  return <section className="panel graph-tool-create"><header><div><b id="composite-dialog-title">Create composite transform</b><span>Define staged tooling and tunnel previous stage output through tools that accept an input file.</span></div><button type="button" className="subtle transform-dialog-close" aria-label="Close dialog" onClick={onClose}>×</button></header>
    <div className="graph-tool-editor-grid">
      <label>Id<input value={value.id || ''} onChange={event => onChange({ ...value, id: event.target.value })} placeholder="custom:live-subdomains" /></label>
      <label>Display name<input value={value.display_name} onChange={event => onChange({ ...value, display_name: event.target.value })} /></label>
      <label>Category<input value={value.category} onChange={event => onChange({ ...value, category: event.target.value })} placeholder="Subdomain" required /></label>
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
    {error && <p className="error" role="alert">{error}</p>}
    <footer className="network-transform-actions"><button type="button" onClick={() => onChange({ ...value, stages: [...value.stages, { name: `Stage ${value.stages.length + 1}`, tool_keys: [], input_source: 'previous', parameters: {} }] })}>Add stage</button><button type="button" className="subtle" onClick={onClose}>Cancel</button><button type="button" onClick={onSave} disabled={saving || !value.display_name.trim() || !value.category.trim() || value.stages.some(stage => !stage.tool_keys.length)}>{saving ? 'Saving...' : 'Save composite transform'}</button></footer>
  </section>
}

export function NetworkTransformsPage() {
  const { projectId = '' } = useParams()
  const qc = useQueryClient()
  const [investigationId, setInvestigationId] = useState('')
  const [transformId, setTransformId] = useState('')
  const [parameters, setParameters] = useState<Record<string, unknown>>({})
  const [composite, setComposite] = useState<TransformDefinitionInput>(emptyComposite)
  const [compositeOpen, setCompositeOpen] = useState(false)
  const compositeDialog = useRef<HTMLDialogElement>(null)
  const [runsOpen, setRunsOpen] = useState(false)
  const runsDialog = useRef<HTMLDialogElement>(null)
  const [runOpen, setRunOpen] = useState(false)
  const runDialog = useRef<HTMLDialogElement>(null)
  const [inputSelection, setInputSelection] = useState('')
  const [jobId, setJobId] = useState('')
  const [notice, setNotice] = useState('')
  useEffect(() => {
    if (compositeOpen && !compositeDialog.current?.open) compositeDialog.current?.showModal()
    if (!compositeOpen && compositeDialog.current?.open) compositeDialog.current.close()
  }, [compositeOpen])
  useEffect(() => {
    if (runsOpen && !runsDialog.current?.open) runsDialog.current?.showModal()
    if (!runsOpen && runsDialog.current?.open) runsDialog.current.close()
  }, [runsOpen])
  useEffect(() => {
    if (runOpen && !runDialog.current?.open) runDialog.current?.showModal()
    if (!runOpen && runDialog.current?.open) runDialog.current.close()
  }, [runOpen])

  const investigations = useQuery({ queryKey: ['projects', projectId, 'investigations'], queryFn: () => api.listInvestigations(projectId) })
  const transforms = useQuery({ queryKey: ['projects', projectId, 'transforms'], queryFn: () => api.listGraphTransforms(projectId) })
  const tools = useQuery({ queryKey: ['docker', 'tools'], queryFn: api.listDockerTools })
  const graph = useQuery({ queryKey: ['projects', projectId, 'investigation-graph', investigationId], queryFn: () => api.getInvestigationGraph(projectId, investigationId, { limit: 5000 }), enabled: !!investigationId })
  const job = useQuery({ queryKey: ['projects', projectId, 'transform-job', jobId], queryFn: () => api.getGraphTransform(projectId, jobId), enabled: !!jobId, refetchInterval: query => ['queued', 'running'].includes(query.state.data?.status || '') ? 1000 : false })
  const jobs = useQuery({ queryKey: ['projects', projectId, 'transform-jobs'], queryFn: () => api.listGraphTransformJobs(projectId), enabled: runsOpen || runOpen, refetchInterval: query => query.state.data?.some(item => activeJobStatuses.has(item.status)) ? 1000 : 4000 })
  useEffect(() => { if (!investigationId && investigations.data?.[0]) setInvestigationId(investigations.data[0].id) }, [investigationId, investigations.data])
  useEffect(() => { if (!transformId && transforms.data?.[0]) setTransformId(transforms.data[0].id) }, [transformId, transforms.data])
  const selected = transforms.data?.find(item => item.id === transformId)
  const transformNames = useMemo(() => new Map((transforms.data || []).map(item => [item.id, item.display_name])), [transforms.data])
  const activeJobs = jobs.data?.filter(item => activeJobStatuses.has(item.status)) || []
  const unfinishedJobs = jobs.data?.filter(item => ['failed', 'cancelled'].includes(item.status)) || []
  const recentJobs = jobs.data?.filter(item => item.status === 'completed').slice(0, 8) || []
  const compatibleEntities = useMemo(() => graph.data?.entities.filter(entity => selected?.input_types.includes(entity.kind)) || [], [graph.data, selected])
  const compatibleOutputs = useMemo(() => (jobs.data || []).filter(item => item.status === 'completed' && item.investigation_id === investigationId).map(item => {
    const entities = compatibleEntities.filter(entity => entity.provenance.some(source => source.transform_job_id === item.id))
    return { job: item, entities, manifest: transforms.data?.find(manifest => manifest.id === item.transform_id) }
  }).filter(item => item.entities.length), [compatibleEntities, investigationId, jobs.data, transforms.data])
  const selectedInput = useMemo(() => {
    if (inputSelection.startsWith('job:')) {
      const output = compatibleOutputs.find(item => item.job.id === inputSelection.slice(4))
      return output ? { entityIds: output.entities.map(entity => entity.id), sourceJobId: output.job.id } : null
    }
    const entity = compatibleEntities.find(item => item.id === inputSelection.slice(7))
    return entity ? { entityIds: [entity.id], sourceJobId: '' } : null
  }, [compatibleEntities, compatibleOutputs, inputSelection])
  useEffect(() => {
    if (!runOpen || inputSelection || jobs.isPending || graph.isPending) return
    if (compatibleOutputs[0]) setInputSelection(`job:${compatibleOutputs[0].job.id}`)
    else if (compatibleEntities[0]) setInputSelection(`entity:${compatibleEntities[0].id}`)
  }, [compatibleEntities, compatibleOutputs, graph.isPending, inputSelection, jobs.isPending, runOpen])
  useEffect(() => { setParameters({}) }, [transformId])

  const run = useMutation({
    mutationFn: async () => {
      if (!selected || !selectedInput?.entityIds.length) throw new Error('Choose a compatible graph entity or transform output first.')
      if (selected.requires_approval && !window.confirm(`Run ${selected.display_name} in ${selected.mode} mode? This may actively interact with the target.`)) throw new Error('Execution cancelled.')
      return api.startGraphTransform(projectId, { transform_id: selected.id, entity_ids: selectedInput.entityIds, source_job_id: selectedInput.sourceJobId, parameters, investigation_id: investigationId, approved: selected.requires_approval })
    },
    onSuccess: item => { setJobId(item.id); setNotice(`Queued ${selected?.display_name || item.transform_id}.`); void qc.invalidateQueries({ queryKey: ['projects', projectId, 'investigation-graph', investigationId] }); void qc.invalidateQueries({ queryKey: ['projects', projectId, 'transform-jobs'] }) },
  })
  const saveComposite = useMutation({
    mutationFn: () => api.createTransformDefinition(projectId, composite),
    onSuccess: item => { setNotice(`Saved composite transform ${item.display_name}.`); setTransformId(item.id); setComposite(emptyComposite); setCompositeOpen(false); void qc.invalidateQueries({ queryKey: ['projects', projectId, 'transforms'] }) },
  })
  const deleteComposite = useMutation({
    mutationFn: (id: string) => api.deleteTransformDefinition(projectId, id),
    onSuccess: () => { setNotice('Deleted custom transform.'); void qc.invalidateQueries({ queryKey: ['projects', projectId, 'transforms'] }) },
  })
  const resume = useMutation({
    mutationFn: ({ id, parameters, approved }: { id: string; parameters: Record<string, unknown>; approved: boolean }) => api.resumeGraphTransform(projectId, id, { parameters, approved }),
    onSuccess: item => { setJobId(item.id); setNotice(`Resuming ${transformNames.get(item.transform_id) || item.transform_id}.`); void qc.invalidateQueries({ queryKey: ['projects', projectId, 'transform-jobs'] }) },
  })
  const cancelRun = useMutation({
    mutationFn: (id: string) => api.cancelGraphTransform(projectId, id),
    onSuccess: () => void qc.invalidateQueries({ queryKey: ['projects', projectId, 'transform-jobs'] }),
  })
  const resumeRun = (item: TransformJob, secrets: Record<string, unknown>, manifest?: TransformManifest) => {
    if (manifest?.requires_approval && !window.confirm(`Resume ${manifest.display_name} in ${manifest.mode} mode? This may actively interact with the target.`)) return
    resume.mutate({ id: item.id, parameters: secrets, approved: manifest?.requires_approval === true })
  }
  const closeComposite = () => { setCompositeOpen(false); setComposite(emptyComposite); saveComposite.reset() }
  const openRunner = (id: string) => { setTransformId(id); setInputSelection(''); setJobId(''); setNotice(''); run.reset(); setRunOpen(true) }
  useEffect(() => {
    if (job.data?.status === 'completed') {
      void qc.invalidateQueries({ queryKey: ['projects', projectId, 'investigation-graph', investigationId] })
      void qc.invalidateQueries({ queryKey: ['projects', projectId, 'transform-jobs'] })
    }
  }, [investigationId, job.data?.status, projectId, qc])

  return <main className="page feature-page network-transforms-page">
    
    {notice && <p className="success">{notice}</p>}{(run.isError || job.isError || transforms.isError || graph.isError || deleteComposite.isError) && <p className="error">{String((run.error || job.error || transforms.error || graph.error || deleteComposite.error)?.message)}</p>}
    {transforms.data?.length ? <TransformCatalog transforms={transforms.data} onRun={openRunner} onDelete={id => deleteComposite.mutate(id)} actions={<OptionsMenu label="Transform options"><button type="button" onClick={() => { resume.reset(); cancelRun.reset(); setRunsOpen(true) }}>View running transforms</button><button type="button" onClick={() => { saveComposite.reset(); setCompositeOpen(true) }}>Create composite transform</button><Link to={`/projects/${projectId}/network/tools`}>Tool catalog</Link><Link to={`/projects/${projectId}/network/logs`}>Live logs</Link></OptionsMenu>} /> : null}
    <dialog ref={runDialog} className="transform-dialog transform-run-dialog" aria-labelledby="transform-run-title" onClose={() => setRunOpen(false)}>
      <header><div><b id="transform-run-title">{selected ? `Run ${selected.display_name}` : 'Run graph transform'}</b><span>Choose one graph entity or all compatible output from a previous transform.</span></div><button type="button" className="transform-dialog-close" aria-label="Close run dialog" onClick={() => setRunOpen(false)}>×</button></header>
      <div className="transform-run-workbench"><section className="graph-tool-runner"><header><div><b>Run graph transform</b><span>Outputs are parsed and attached to the selected investigation.</span></div><span className={`transform-risk risk-${selected?.mode || 'passive'}`}>{selected?.mode || 'passive'}</span></header><label>Investigation<select value={investigationId} onChange={event => { setInvestigationId(event.target.value); setInputSelection('') }}>{investigations.data?.map(item => <option value={item.id} key={item.id}>{item.name}</option>)}</select></label><label>Input source<select aria-label="Transform input source" value={inputSelection} onChange={event => setInputSelection(event.target.value)}>{compatibleOutputs.length ? <optgroup label="Previous transform output">{compatibleOutputs.map(item => <option value={`job:${item.job.id}`} key={item.job.id}>{item.manifest?.display_name || item.job.transform_id} · {item.entities.length} compatible {item.entities.length === 1 ? 'entity' : 'entities'}</option>)}</optgroup> : null}<optgroup label="Individual graph entity">{compatibleEntities.map(entity => <option value={`entity:${entity.id}`} key={entity.id}>{entity.label} · {entity.kind}</option>)}</optgroup></select></label>{selected && <><p className="muted">{selected.description}</p><small>Accepts: {selected.input_types.join(', ')} · Produces: {selected.output_types.join(', ')} · Relationships: {selected.relationship_types.join(', ')}</small><ParameterFields specs={selected.parameters} values={parameters} onChange={(key, value) => setParameters(current => ({ ...current, [key]: value }))} /><button onClick={() => run.mutate()} disabled={!selectedInput || run.isPending}>{run.isPending ? 'Starting...' : `Run with ${selectedInput?.entityIds.length || 0} input${selectedInput?.entityIds.length === 1 ? '' : 's'}`}</button></>}</section><section className="graph-tool-status"><header><b>Execution status</b><span>{job.data?.status || 'Ready to run'}</span></header>{job.data ? <><p>{job.data.message || 'Waiting for operation output...'}</p><div className="transform-progress-track"><span style={{ width: `${job.data.progress_total ? Math.round(((job.data.progress_completed || 0) / job.data.progress_total) * 100) : job.data.status === 'completed' ? 100 : 18}%` }} /></div><pre>{job.data.logs?.slice(-30).join('\n') || 'No logs yet.'}</pre><Link className="button-link subtle" to={`/projects/${projectId}/network/logs`}>Open full logs</Link></> : <p className="muted">Execution progress and recent output will appear here after the run starts.</p>}</section></div>
    </dialog>
    <dialog ref={compositeDialog} className="transform-dialog" aria-labelledby="composite-dialog-title" onClose={closeComposite}>
      <CompositeBuilder tools={tools.data || []} value={composite} onChange={setComposite} onSave={() => saveComposite.mutate()} onClose={closeComposite} saving={saveComposite.isPending} error={saveComposite.error?.message} />
    </dialog>
    <dialog ref={runsDialog} className="transform-dialog transform-runs-dialog" aria-labelledby="transform-runs-title" onClose={() => setRunsOpen(false)}>
      <header><div><b id="transform-runs-title">Transform runs</b><span>Statuses and output refresh while this dialog is open.</span></div><button type="button" className="transform-dialog-close" aria-label="Close dialog" onClick={() => setRunsOpen(false)}>×</button></header>
      <div className="transform-runs-content">
        {jobs.isPending && !jobs.data ? <p className="muted">Loading transform runs…</p> : null}
        {jobs.isError ? <p className="error" role="alert">{jobs.error.message}</p> : null}
        {(resume.isError || cancelRun.isError) ? <p className="error" role="alert">{(resume.error || cancelRun.error)?.message}</p> : null}
        <section><h2>Active <span>{activeJobs.length}</span></h2>{activeJobs.length ? <div className="transform-runs-list">{activeJobs.map(item => <TransformRunRow key={item.id} job={item} manifest={transforms.data?.find(manifest => manifest.id === item.transform_id)} onResume={resumeRun} onCancel={id => cancelRun.mutate(id)} busy={(resume.isPending && resume.variables?.id === item.id) || (cancelRun.isPending && cancelRun.variables === item.id)} />)}</div> : !jobs.isPending ? <p className="muted">No transforms are running.</p> : null}</section>
        {unfinishedJobs.length ? <section><h2>Unfinished <span>{unfinishedJobs.length}</span></h2><div className="transform-runs-list">{unfinishedJobs.map(item => <TransformRunRow key={item.id} job={item} manifest={transforms.data?.find(manifest => manifest.id === item.transform_id)} onResume={resumeRun} onCancel={id => cancelRun.mutate(id)} busy={(resume.isPending && resume.variables?.id === item.id) || (cancelRun.isPending && cancelRun.variables === item.id)} />)}</div></section> : null}
        {recentJobs.length ? <section><h2>Recent results</h2><div className="transform-runs-list">{recentJobs.map(item => <TransformRunRow key={item.id} job={item} manifest={transforms.data?.find(manifest => manifest.id === item.transform_id)} onResume={resumeRun} onCancel={id => cancelRun.mutate(id)} busy={(resume.isPending && resume.variables?.id === item.id) || (cancelRun.isPending && cancelRun.variables === item.id)} />)}</div></section> : null}
        <Link className="button-link subtle" to={`/projects/${projectId}/network/logs`} onClick={() => setRunsOpen(false)}>Open full logs</Link>
      </div>
    </dialog>
  </main>
}
