import { FormEvent, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Link } from 'react-router-dom'

import { api } from '../../api/client'

export function ProjectList() {
  const queryClient = useQueryClient()
  const [name, setName] = useState('')
  const [target, setTarget] = useState('')
  const projects = useQuery({ queryKey: ['projects'], queryFn: api.listProjects })
  const createProject = useMutation({
    mutationFn: api.createProject,
    onSuccess: () => {
      setName('')
      setTarget('')
      void queryClient.invalidateQueries({ queryKey: ['projects'] })
    },
  })

  function submit(event: FormEvent) {
    event.preventDefault()
    if (name.trim()) createProject.mutate({ name: name.trim(), target: target.trim() })
  }

  return (
    <main className="page">
      <header className="page-header">
        <div>
          <p className="eyebrow">Workspace</p>
          <h1>Projects</h1>
          <p className="muted">Choose a target workspace or start a new engagement.</p>
        </div>
      </header>

      <section className="panel create-panel">
        <div>
          <p className="eyebrow">New project</p>
          <h2>Start an engagement</h2>
        </div>
        <form onSubmit={submit}>
          <label>
            Name
            <input value={name} onChange={(event) => setName(event.target.value)} placeholder="Acme audit" required />
          </label>
          <label>
            Initial target
            <input value={target} onChange={(event) => setTarget(event.target.value)} placeholder="https://example.com" />
          </label>
          <button disabled={createProject.isPending}>{createProject.isPending ? 'Creating…' : 'Create project'}</button>
        </form>
        {createProject.isError && <p className="error">{createProject.error.message}</p>}
      </section>

      <section className="project-section">
        <div className="section-title"><h2>Recent projects</h2><span>{projects.data?.length ?? 0}</span></div>
        {projects.isPending && <p className="muted">Loading projects…</p>}
        {projects.isError && <p className="error">Could not load projects: {projects.error.message}</p>}
        {projects.data?.length === 0 && <div className="empty">No projects yet. Create the first one above.</div>}
        <div className="project-grid">
          {projects.data?.map((project) => (
            <Link className="project-card" to={`/projects/${project.id}`} key={project.id}>
              <span className="project-mark">A</span>
              <div><h3>{project.name}</h3><p>{project.target || 'No target configured'}</p></div>
              <time>{new Date(project.updated_at).toLocaleDateString()}</time>
            </Link>
          ))}
        </div>
      </section>
    </main>
  )
}
