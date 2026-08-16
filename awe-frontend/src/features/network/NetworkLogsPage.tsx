import { useMemo } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Link, useParams } from 'react-router-dom'

import { api, type TransformJob, type TransformManifest } from '../../api/client'

const activeStatuses = new Set(['queued', 'running', 'approval_required'])

async function copyText(value: string) {
  try {
    if (navigator.clipboard?.writeText) {
      await navigator.clipboard.writeText(value)
      return
    }
  } catch {}
  const area = document.createElement('textarea')
  area.value = value
  area.setAttribute('readonly', '')
  area.style.position = 'fixed'
  area.style.opacity = '0'
  document.body.appendChild(area)
  area.select()
  document.execCommand('copy')
  area.remove()
}

function formatDate(value: string) {
  const date = new Date(value)
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString()
}

function progress(job: TransformJob) {
  if (job.progress_total) return Math.min(100, Math.round(((job.progress_completed || 0) / job.progress_total) * 100))
  return job.status === 'completed' ? 100 : activeStatuses.has(job.status) ? 18 : 100
}

function TransformLogCard({ job, manifest, onCancel }: { job: TransformJob; manifest?: TransformManifest; onCancel: (id: string) => void }) {
  const logs = job.logs || []
  const title = manifest?.display_name || job.transform_id
  return <article className={`panel network-log-card log-${job.status}`}>
    <header><div><b>{title}</b><span>{job.status} · {formatDate(job.created_at)}</span></div><em>{manifest?.mode || 'transform'}</em></header>
    <div className="network-log-meta"><span>Job <code>{job.id}</code></span><span>Operation <code>{job.operation_id || 'pending'}</code></span></div>
    <div className="transform-progress-track"><span style={{ width: `${progress(job)}%` }} /></div>
    {job.message && <p className={job.status === 'failed' ? 'error' : 'muted'}>{job.message}</p>}
    <details className="docker-card-logs" open>
      <summary><span>{activeStatuses.has(job.status) ? 'Live logs' : 'Logs'}</span><em>{logs.length} lines</em></summary>
      <div className="docker-card-log-actions"><button type="button" onClick={() => void copyText(logs.join('\n'))}>Copy</button>{activeStatuses.has(job.status) && <button type="button" onClick={() => onCancel(job.id)}>Cancel</button>}</div>
      <pre>{logs.join('\n') || 'Waiting for Docker output...'}</pre>
    </details>
  </article>
}

export function NetworkLogsPage() {
  const { projectId = '' } = useParams()
  const qc = useQueryClient()
  const transforms = useQuery({ queryKey: ['projects', projectId, 'transforms'], queryFn: () => api.listGraphTransforms(projectId) })
  const jobs = useQuery({
    queryKey: ['projects', projectId, 'transform-jobs'],
    queryFn: () => api.listGraphTransformJobs(projectId),
    refetchInterval: query => query.state.data?.some(job => activeStatuses.has(job.status)) ? 1000 : 4000,
  })
  const cancel = useMutation({
    mutationFn: (id: string) => api.cancelGraphTransform(projectId, id),
    onSuccess: () => void qc.invalidateQueries({ queryKey: ['projects', projectId, 'transform-jobs'] }),
  })
  const manifestById = useMemo(() => new Map((transforms.data || []).map(item => [item.id, item])), [transforms.data])
  const activeCount = jobs.data?.filter(job => activeStatuses.has(job.status)).length || 0

  return <main className="page feature-page network-logs-page">
    
    <header className="page-header network-logs-header"><div><p className="eyebrow">Network</p><h1>Transform Logs</h1><p className="muted">Live Docker output for graph transforms running from the Network workspace.</p></div><Link className="button-link" to={`/projects/${projectId}/network/tools`}>Graph Tools</Link></header>
    {(jobs.isError || transforms.isError || cancel.isError) && <p className="error">{String((jobs.error || transforms.error || cancel.error)?.message)}</p>}
    <section className="panel network-log-summary"><div><strong>{jobs.data?.length || 0}</strong><span>Transform jobs</span></div><div><strong>{activeCount}</strong><span>Running now</span></div><button onClick={() => void jobs.refetch()}>Refresh</button></section>
    <section className="network-log-grid">
      {jobs.data?.map(job => <TransformLogCard key={job.id} job={job} manifest={manifestById.get(job.transform_id)} onCancel={id => cancel.mutate(id)} />)}
      {!jobs.isPending && !jobs.data?.length && <div className="panel empty">No graph transform logs yet. Run a transform from Network or Graph Tools to see live Docker output here.</div>}
      {jobs.isPending && !jobs.data && <div className="panel empty">Loading transform logs...</div>}
    </section>
  </main>
}
