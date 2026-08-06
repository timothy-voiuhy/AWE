import { Navigate, Route, Routes } from 'react-router-dom'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'

import { api } from './api/client'
import { LoginPage } from './features/auth/LoginPage'
import { ProjectList } from './features/projects/ProjectList'
import { ProjectWorkspace } from './features/projects/ProjectWorkspace'

export function App() {
  const queryClient = useQueryClient()
  const session = useQuery({ queryKey: ['auth', 'session'], queryFn: api.getSession, retry: false })
  const logout = useMutation({
    mutationFn: api.logout,
    onSettled: () => {
      queryClient.clear()
      void queryClient.invalidateQueries({ queryKey: ['auth', 'session'] })
    },
  })

  if (session.isPending) return <main className="login-page"><p className="muted">Checking session…</p></main>
  if (session.isError) return <LoginPage />

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand"><span>AW</span><strong>AWE</strong></div>
        <nav><a className="active" href="/projects">Projects</a></nav>
        <button className="logout-button" onClick={() => logout.mutate()}>Sign out</button>
        <small>Attack Workspace Environment</small>
      </aside>
      <Routes>
        <Route path="/projects" element={<ProjectList />} />
        <Route path="/projects/:projectId" element={<ProjectWorkspace />} />
        <Route path="*" element={<Navigate to="/projects" replace />} />
      </Routes>
    </div>
  )
}
