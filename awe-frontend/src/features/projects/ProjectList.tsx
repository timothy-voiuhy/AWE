import { FormEvent, useRef, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Link } from 'react-router-dom'

import { api } from '../../api/client'
import { OptionsMenu } from '../../components/OptionsMenu'
import { Spinner } from '../../components/Spinner'

function activityLabel(value: string) {
  const elapsed = Math.max(0, Date.now() - new Date(value).getTime())
  const minutes = Math.floor(elapsed / 60_000)
  if (minutes < 1) return 'Just now'
  if (minutes < 60) return `${minutes}m ago`
  const hours = Math.floor(minutes / 60)
  if (hours < 24) return `${hours}h ago`
  const days = Math.floor(hours / 24)
  if (days < 7) return `${days}d ago`
  return new Date(value).toLocaleDateString()
}

function targetLabel(value: string) {
  if (!value) return 'Target not configured'
  try { return new URL(value.includes('://') ? value : `https://${value}`).host || value }
  catch { return value }
}

export function ProjectList() {
  const queryClient = useQueryClient()
  const createDialog = useRef<HTMLDialogElement>(null)
  const [name, setName] = useState('')
  const [target, setTarget] = useState('')
  const [notice, setNotice] = useState('')
  const dashboard = useQuery({ queryKey: ['dashboard'], queryFn: api.getDashboard, refetchInterval: 15_000 })
  const createProject = useMutation({
    mutationFn: api.createProject,
    onSuccess: (project) => {
      setName('')
      setTarget('')
      setNotice(`Created ${project.name}.`)
      createDialog.current?.close()
      void queryClient.invalidateQueries({ queryKey: ['dashboard'] })
      void queryClient.invalidateQueries({ queryKey: ['projects'] })
    },
  })

  function submit(event: FormEvent) {
    event.preventDefault()
    if (name.trim()) createProject.mutate({ name: name.trim(), target: target.trim() })
  }

  function openCreate() {
    createProject.reset()
    setNotice('')
    createDialog.current?.showModal()
  }

  function closeCreate() {
    createDialog.current?.close()
    createProject.reset()
  }

  const data = dashboard.data
  const projects = data?.projects || []
  const reviewCoverage = data?.total_results ? Math.min(100, Math.round((data.reviewed_results / data.total_results) * 100)) : 0
  const targetCoverage = data?.total_projects ? Math.round((data.configured_targets / data.total_projects) * 100) : 0

  return (
    <main className="page projects-dashboard-page">
      <header className="projects-dashboard-header">
        <h1>AWE Dashboard</h1>
        <div className="projects-dashboard-actions"><span className="live-dot active">Workspace online</span><OptionsMenu label="Dashboard options"><button type="button" onClick={openCreate}>New project</button><button type="button" onClick={() => void dashboard.refetch()}>Refresh dashboard</button><Link to="/vault">Open vault</Link><Link to="/database">Database health</Link></OptionsMenu></div>
      </header>

      {notice && <p className="success dashboard-notice">{notice}</p>}
      {dashboard.isError && <p className="error">Could not load the dashboard: {dashboard.error.message}</p>}

      <section className="dashboard-metrics" aria-label="Workspace metrics">
        <article><span>Engagements</span><strong>{dashboard.isPending ? '—' : data?.total_projects || 0}</strong><small>{data?.recent_projects || 0} active this week</small></article>
        <article><span>Active runs</span><strong>{dashboard.isPending ? '—' : data?.active_runs || 0}</strong><small>{data?.total_sessions || 0} scan sessions</small></article>
        <article><span>Observations</span><strong>{dashboard.isPending ? '—' : (data?.total_results || 0).toLocaleString()}</strong><small>Across all engagements</small></article>
        <article><span>Review coverage</span><strong>{dashboard.isPending ? '—' : `${reviewCoverage}%`}</strong><small>{data?.reviewed_results || 0} reviewed results</small></article>
      </section>

      <section className="dashboard-workbench">
        <section className="dashboard-portfolio" aria-labelledby="portfolio-title">
          <header><div><h2 id="portfolio-title">Engagement portfolio</h2><span>{projects.length} workspaces</span></div><small>Last activity</small></header>
          {dashboard.isPending && <Spinner label="Loading dashboard…" />}
          {!dashboard.isPending && !projects.length && <div className="dashboard-empty"><b>No engagements yet</b><span>Use Dashboard options to create the first project.</span></div>}
          <div className="dashboard-project-list" aria-label="Projects">
            {projects.map((project) => {
              const state = project.active_runs ? 'Running' : project.target ? 'Ready' : 'Needs target'
              return <Link className="dashboard-project-row" to={`/projects/${project.id}`} key={project.id}>
                <span className="dashboard-project-mark">{project.name.slice(0, 1).toUpperCase()}</span>
                <span className="dashboard-project-identity"><b>{project.name}</b><small>{targetLabel(project.target)}</small></span>
                <span className={`dashboard-project-state state-${state.toLowerCase().replace(' ', '-')}`}>{state}</span>
                <span className="dashboard-project-stat"><b>{project.result_count.toLocaleString()}</b><small>observations</small></span>
                <span className="dashboard-project-stat"><b>{project.session_count}</b><small>sessions</small></span>
                <time dateTime={project.last_activity}>{activityLabel(project.last_activity)}</time>
                <span className="dashboard-project-arrow" aria-hidden="true">→</span>
              </Link>
            })}
          </div>
        </section>

        <aside className="dashboard-sidebar">
          <section className="dashboard-posture"><header><h2>Workspace posture</h2><span>{targetCoverage}% ready</span></header><div className="dashboard-progress"><span style={{ width: `${targetCoverage}%` }} /></div><dl><div><dt>Configured targets</dt><dd>{data?.configured_targets || 0}/{data?.total_projects || 0}</dd></div><div><dt>Needs a target</dt><dd>{Math.max(0, (data?.total_projects || 0) - (data?.configured_targets || 0))}</dd></div><div><dt>Unreviewed results</dt><dd>{Math.max(0, (data?.total_results || 0) - (data?.reviewed_results || 0)).toLocaleString()}</dd></div></dl></section>
          <section className="dashboard-activity"><header><h2>Recent activity</h2><span>Latest updates</span></header>{projects.slice(0, 5).map(project => <Link to={`/projects/${project.id}`} key={project.id}><span className={project.active_runs ? 'activity-indicator active' : 'activity-indicator'} /><span><b>{project.name}</b><small>{project.active_runs ? `${project.active_runs} active run${project.active_runs === 1 ? '' : 's'}` : targetLabel(project.target)}</small></span><time>{activityLabel(project.last_activity)}</time></Link>)}{!projects.length && <p>No project activity yet.</p>}</section>
        </aside>
      </section>

      <dialog ref={createDialog} className="project-create-dialog" aria-labelledby="project-create-title" onClose={() => createProject.reset()}>
        <form onSubmit={submit}>
          <header><div><p className="eyebrow">New workspace</p><h2 id="project-create-title">Create an engagement</h2><span>Start with a name and optional initial target. Scope can be refined inside the workspace.</span></div><button type="button" aria-label="Close project creation" onClick={closeCreate}>×</button></header>
          <label>Project name<input value={name} onChange={(event) => setName(event.target.value)} placeholder="Acme external assessment" autoFocus required /></label>
          <label>Initial target <small>Optional</small><input value={target} onChange={(event) => setTarget(event.target.value)} placeholder="https://example.com" /></label>
          {createProject.isError && <p className="error">{createProject.error.message}</p>}
          <footer><button type="button" className="subtle" onClick={closeCreate}>Cancel</button><button disabled={createProject.isPending || !name.trim()}>{createProject.isPending ? 'Creating…' : 'Create project'}</button></footer>
        </form>
      </dialog>
    </main>
  )
}
