import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import { api, type PreflightReport } from '../../api/client'
import './image-filters.css'

export function useExecutionPreflight(projectId: string, transformId: string, toolKey: string, enabled = true) {
  return useQuery({ queryKey: ['execution-preflight', projectId, transformId, toolKey], queryFn: () => transformId ? api.transformPreflight(projectId, transformId) : api.toolPreflight(toolKey), enabled: enabled && Boolean(transformId || toolKey), staleTime: 0, retry: false })
}

export function ExecutionPreflight({ projectId, report, pending, error, onRecheck }: { projectId: string; report?: PreflightReport; pending: boolean; error?: Error | null; onRecheck: () => void }) {
  const [operationId, setOperationId] = useState('')
  const qc = useQueryClient()
  const action = useMutation({ mutationFn: ({ key, operation }: { key: string; operation: 'build' | 'pull' }) => api.operateOneToolImage(key, operation), onSuccess: item => setOperationId(item.id) })
  const operation = useQuery({ queryKey: ['docker', 'operation', operationId], queryFn: async () => {
    const item = await api.dockerOperation(operationId)
    if (['completed', 'failed', 'cancelled'].includes(item.status)) {
      void qc.invalidateQueries({ queryKey: ['execution-preflight'] })
      void qc.invalidateQueries({ queryKey: ['docker', 'tools'] })
      void qc.invalidateQueries({ queryKey: ['docker', 'images'] })
    }
    return item
  }, enabled: Boolean(operationId), refetchInterval: query => query.state.data && ['completed', 'failed', 'cancelled'].includes(query.state.data.status) ? false : 750 })
  const busy = action.isPending || Boolean(operationId && (!operation.data || ['queued', 'running'].includes(operation.data.status)))
  return <section className="tool-preflight" aria-label="Execution prerequisites">
    <header><b>{pending ? 'Checking prerequisites…' : report?.ready && !error ? 'Ready to run' : 'Prerequisites need attention'}</b><button type="button" className="subtle" disabled={pending || busy} onClick={onRecheck}>Recheck</button></header>
    {error && <p className="error" role="alert">{error.message}</p>}
    {report?.tools.map(tool => <article key={tool.tool_key}><code>{tool.tool_key}{tool.image ? ` · ${tool.image}` : ''}</code>{tool.issues.length ? tool.issues.map((issue, index) => <div key={index}><p className={issue.warning ? 'muted' : 'error'}>{issue.message}</p><nav>{['build', 'pull'].includes(issue.action) && <button type="button" disabled={busy} onClick={() => action.mutate({ key: tool.tool_key, operation: issue.action as 'build' | 'pull' })}>{issue.action === 'build' ? 'Build image' : 'Pull image'}</button>}{issue.action === 'edit' && <Link to={`/projects/${projectId}/docker`}>Manage tool definition</Link>}</nav></div>) : <p className="muted">Required image installed; output parser {tool.image ? 'ready or not required' : 'checked'}.</p>}</article>)}
    {(action.isError || operation.isError) && <p className="error" role="alert">{(action.error || operation.error)?.message}</p>}
    {operation.data && <details open><summary>Image setup · {operation.data.status}</summary><pre>{operation.data.logs.join('\n') || operation.data.message || 'Waiting for image setup…'}</pre></details>}
  </section>
}
