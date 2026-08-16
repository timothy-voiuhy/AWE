import { useMemo, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Link, useParams } from 'react-router-dom'

import { api, type DockerTool, type DockerToolInput } from '../../api/client'

const emptyTool: DockerToolInput = {
  key: '', display_name: '', category: 'architecture', image: '', description: '',
  command_template: '', param_specs: [], dockerfile: 'FROM alpine:3.19\nRUN mkdir -p /output\n',
  parser: 'def parse(output_dir: str) -> list:\n    return []\n', input_types: ['domain'],
  output_types: ['component'], relationship_types: ['has_component'], execution_mode: 'safe_active',
  credential_fields: [],
}

function graphToolGaps(tool: DockerTool) {
  const gaps: string[] = []
  if (!tool.input_types.length) gaps.push('No graph input types')
  if (!tool.output_types.length) gaps.push('No graph output types')
  if (!tool.relationship_types.length) gaps.push('No graph relationships')
  if (tool.status !== 'ok') gaps.push('No parser')
  return gaps
}

function GraphToolCatalog({ tools, projectId }: { tools: DockerTool[]; projectId: string }) {
  return <section className="panel graph-tool-catalog"><header><div><b>Tool catalog</b><span>{tools.length} Docker tools · {tools.filter(item => item.graph_enabled).length} graph enabled</span></div></header>
    <div>{tools.map(tool => {
      const gaps = graphToolGaps(tool)
      return <article className={tool.graph_enabled ? 'graph-catalog-row enabled' : 'graph-catalog-row disabled'} key={tool.key}>
        <div><b>{tool.display_name}</b><span>{tool.category} · {tool.execution_mode} · {tool.source}</span><code>{tool.image}</code></div>
        <strong>{tool.graph_enabled ? 'Graph enabled' : 'Not graph enabled'}</strong>
        <p>{tool.graph_enabled ? `Accepts ${tool.input_types.join(', ')} and produces ${tool.output_types.join(', ')} via ${tool.relationship_types.join(', ')}.` : gaps.join(' · ')}</p>
        {tool.graph_enabled && <Link className="button-link subtle" to={`/projects/${projectId}/network/transforms`}>Run transform</Link>}
      </article>
    })}</div>
  </section>
}

export function GraphToolsPage() {
  const { projectId = '' } = useParams()
  const qc = useQueryClient()
  const [custom, setCustom] = useState<DockerToolInput>(emptyTool)
  const [paramJson, setParamJson] = useState('[]')
  const [notice, setNotice] = useState('')

  const tools = useQuery({ queryKey: ['docker', 'tools'], queryFn: api.listDockerTools })
  const sortedTools = useMemo(() => [...(tools.data || [])].sort((a, b) => Number(b.graph_enabled) - Number(a.graph_enabled) || a.display_name.localeCompare(b.display_name)), [tools.data])
  const create = useMutation({
    mutationFn: () => api.createDockerTool({ ...custom, param_specs: JSON.parse(paramJson) }),
    onSuccess: item => { setNotice(`Created ${item.display_name} as a graph tool.`); setCustom(emptyTool); setParamJson('[]'); void qc.invalidateQueries({ queryKey: ['projects', projectId, 'transforms'] }); void qc.invalidateQueries({ queryKey: ['docker', 'tools'] }) },
  })
  const update = (key: string, value: unknown) => setCustom(current => ({ ...current, [key]: value } as DockerToolInput))

  return <main className="page feature-page graph-tools-page">
    
    <header className="page-header graph-tools-header"><div><p className="eyebrow">Graph automation</p><h1>Graph Tools</h1><p className="muted">Review Docker graph compatibility and create custom graph-capable tools.</p></div><Link className="button-link" to={`/projects/${projectId}/network/transforms`}>Transforms</Link></header>
    {notice && <p className="success">{notice}</p>}{(create.isError || tools.isError) && <p className="error">{String((create.error || tools.error)?.message)}</p>}
    <section className="graph-tools-workbench">
      {sortedTools.length > 0 ? <GraphToolCatalog tools={sortedTools} projectId={projectId} /> : <section className="panel empty">No Docker tools are registered.</section>}
      <section className="panel graph-tool-create"><header><div><b>Create custom graph tool</b><span>Define the Docker command, parser, graph contract, and safety mode in one place.</span></div></header><div className="graph-tool-editor-grid"><label>Key<input value={custom.key} onChange={event => update('key', event.target.value)} placeholder="my_scanner" /></label><label>Display name<input value={custom.display_name} onChange={event => update('display_name', event.target.value)} /></label><label>Image<input value={custom.image} onChange={event => update('image', event.target.value || `awe/custom_${custom.key}`)} /></label><label>Category<input value={custom.category} onChange={event => update('category', event.target.value)} /></label><label className="wide">Description<input value={custom.description} onChange={event => update('description', event.target.value)} /></label><label className="wide">Command template<input value={custom.command_template} onChange={event => update('command_template', event.target.value)} placeholder="scanner -u {url} -o /output/results.json" /></label><label>Input types<input value={custom.input_types.join(', ')} onChange={event => update('input_types', event.target.value.split(',').map(v => v.trim()).filter(Boolean))} /></label><label>Output types<input value={custom.output_types.join(', ')} onChange={event => update('output_types', event.target.value.split(',').map(v => v.trim()).filter(Boolean))} /></label><label>Relationships<input value={custom.relationship_types.join(', ')} onChange={event => update('relationship_types', event.target.value.split(',').map(v => v.trim()).filter(Boolean))} /></label><label>Execution mode<select value={custom.execution_mode} onChange={event => update('execution_mode', event.target.value)}><option value="passive">Passive</option><option value="safe_active">Safe active</option><option value="active">Active</option><option value="high_risk">High risk</option></select></label><label>Credential fields<input value={custom.credential_fields.join(', ')} onChange={event => update('credential_fields', event.target.value.split(',').map(v => v.trim()).filter(Boolean))} /></label><label className="wide">Parameters JSON<textarea value={paramJson} onChange={event => setParamJson(event.target.value)} placeholder='[{"key":"url","label":"Target URL","type":"text"}]' /></label><label className="wide">Dockerfile<textarea value={custom.dockerfile} onChange={event => update('dockerfile', event.target.value)} /></label><label className="wide">parser.py<textarea value={custom.parser} onChange={event => update('parser', event.target.value)} /></label></div><button onClick={() => { try { JSON.parse(paramJson); create.mutate() } catch { setNotice('Parameters JSON is invalid.') } }} disabled={create.isPending || !custom.key || !custom.display_name || !custom.image || !custom.command_template}>{create.isPending ? 'Saving...' : 'Create graph tool'}</button></section>
    </section>
  </main>
}
