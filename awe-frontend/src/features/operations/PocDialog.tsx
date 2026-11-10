import { useState, type RefObject } from 'react'
import { useMutation } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import { runtime, type ExecutionOptions } from '../../api/runtime'
import { ExecutionFields } from './ExecutionFields'

export function PocDialog({ projectId, dialog }: { projectId: string; dialog: RefObject<HTMLDialogElement> }) {
  const [source, setSource] = useState('git')
  const [key, setKey] = useState('')
  const [name, setName] = useState('')
  const [repository, setRepository] = useState('')
  const [revision, setRevision] = useState('')
  const [archive, setArchive] = useState<File>()
  const [command, setCommand] = useState('python /poc/poc.py')
  const [dockerfile, setDockerfile] = useState('FROM python:3.12-slim\nWORKDIR /poc\nCOPY . /poc\nRUN mkdir -p /output\n')
  const [parameters, setParameters] = useState('[]')
  const [parser, setParser] = useState('def parse(output_dir: str) -> list:\n    return []\n')
  const [execution, setExecution] = useState<ExecutionOptions>({ execution_kind: 'batch', output_channels: ['logs', 'artifacts'], artifact_paths: ['**/*'] })
  const build = useMutation({ mutationFn: async () => runtime.poc(projectId, { key, display_name: name, repository: source === 'git' ? repository : '', revision, command_template: command, dockerfile, category: 'vuln', execution_mode: 'high_risk', input_types: ['target', 'domain', 'subdomain', 'url'], output_types: [], relationship_types: [], param_specs: JSON.parse(parameters), parser: execution.output_channels?.includes('structured') ? parser : '', ...execution }, source === 'archive' ? archive : undefined) })
  return <dialog ref={dialog} className="graph-tool-dialog" aria-labelledby="poc-title"><section className="panel runtime-evidence"><header className="runtime-toolbar"><b id="poc-title">Register a PoC</b><button onClick={() => dialog.current?.close()}>Close</button></header><label>Tool key<input value={key} onChange={e => setKey(e.target.value)} placeholder="my_poc" /></label><label>Display name<input value={name} onChange={e => setName(e.target.value)} /></label><label>Source<select value={source} onChange={e => setSource(e.target.value)}><option value="git">Public Git repository</option><option value="archive">Source archive</option></select></label>{source === 'git' ? <><label>Repository URL<input value={repository} onChange={e => setRepository(e.target.value)} placeholder="https://..." /></label><label>Revision<input value={revision} onChange={e => setRevision(e.target.value)} placeholder="Commit, tag, or branch resolved to a commit" /></label></> : <label>Source archive<input type="file" accept=".zip,.tar,.gz,.tgz" onChange={e => setArchive(e.target.files?.[0])} /></label>}<label>Command<input value={command} onChange={e => setCommand(e.target.value)} /></label><label>Dockerfile<textarea value={dockerfile} onChange={e => setDockerfile(e.target.value)} /></label><label>Parameters JSON<textarea value={parameters} onChange={e => setParameters(e.target.value)} /></label><ExecutionFields value={execution} onChange={setExecution} />{execution.output_channels?.includes('structured') && <label>parser.py<textarea value={parser} onChange={e => setParser(e.target.value)} /></label>}<button disabled={!key || !name || !command || build.isPending} onClick={() => build.mutate()}>{build.isPending ? 'Submitting…' : 'Build and register PoC'}</button>{build.error && <p className="error">{build.error.message}</p>}{build.data && <Link to={`/projects/${projectId}/runs/${build.data.id}`} onClick={() => dialog.current?.close()}>Open build logs and status</Link>}</section></dialog>
}
