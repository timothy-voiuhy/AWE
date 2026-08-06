import { Navigate, NavLink, Route, Routes, useLocation } from 'react-router-dom'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useState } from 'react'

import { api } from './api/client'
import { LoginPage } from './features/auth/LoginPage'
import { SetupPage } from './features/auth/SetupPage'
import { ProjectList } from './features/projects/ProjectList'
import { ProjectWorkspace } from './features/projects/ProjectWorkspace'
import { ComparerPage } from './features/utilities/ComparerPage'
import { GraphqlPage } from './features/utilities/GraphqlPage'
import { DecoderPage } from './features/utilities/DecoderPage'
import { JwtPage } from './features/utilities/JwtPage'
import { HttpHistoryPage, NetworkPage, SiteMapPage } from './features/proxy/TrafficPages'
import { RepeaterPage } from './features/testing/RepeaterPage'
import { DockerPage, SettingsPage } from './features/operations/OperationsPages'
import { InterceptPage, IntruderPage, WebSocketsPage } from './features/testing/SecurityTestingPages'
import { BrowserPage } from './features/browser/BrowserPage'
import { GlobalVaultPage } from './features/operations/GlobalVaultPage'

const workspaceNav = [
  { path: '', label: 'Overview', glyph: '⌂' },
  { path: '/browser', label: 'Browser', glyph: '◉' },
  { path: '/history', label: 'History', glyph: '⊟' },
  { path: '/sitemap', label: 'Site Map', glyph: '◫' },
  { path: '/network', label: 'Network', glyph: '⊗' },
  { path: '/repeater', label: 'Repeater', glyph: '↻' },
  { path: '/intruder', label: 'Intruder', glyph: '⚡' },
  { path: '/intercept', label: 'Intercept', glyph: '⏸' },
  { path: '/websockets', label: 'WebSockets', glyph: '⇆' },
  { path: '/decoder', label: 'Decoder', glyph: '⊞' },
  { path: '/comparer', label: 'Comparer', glyph: '⇌' },
  { path: '/jwt', label: 'JWT', glyph: '⚿' },
  { path: '/graphql', label: 'GraphQL', glyph: '⬡' },
  { path: '/docker', label: 'Docker', glyph: '⬡' },
  { path: '/vault', label: 'Vault', glyph: '⛁' },
  { path: '/settings', label: 'Settings', glyph: '⚙' },
]

export function App() {
  const [sidebarOpen, setSidebarOpen] = useState(false)
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false)
  const queryClient = useQueryClient()
  const location = useLocation()
  const projectId = location.pathname.match(/^\/projects\/([^/]+)/)?.[1]
  const setupStatus = useQuery({ queryKey: ['auth', 'setup-status'], queryFn: api.getSetupStatus, retry: false })
  const session = useQuery({ queryKey: ['auth', 'session'], queryFn: api.getSession, retry: false })
  const logout = useMutation({
    mutationFn: api.logout,
    onSettled: () => {
      queryClient.clear()
      void queryClient.invalidateQueries({ queryKey: ['auth', 'session'] })
    },
  })

  if (setupStatus.isPending || session.isPending) return <main className="login-page"><p className="muted">Checking session…</p></main>
  if (setupStatus.data && !setupStatus.data.configured) return <SetupPage />
  if (session.isError) return <LoginPage />

  return (
    <div className={`app-shell ${sidebarCollapsed ? 'shell-collapsed' : ''}`}>
      <button className="mobile-menu-button" onClick={() => setSidebarOpen(true)}>☰</button>
      {sidebarOpen && <button className="sidebar-scrim" onClick={() => setSidebarOpen(false)} />}
      <aside className={`sidebar ${sidebarOpen ? 'sidebar-open' : ''} ${sidebarCollapsed ? 'sidebar-collapsed' : ''}`}>
        <div className="brand"><span>AW</span><strong>AWE</strong><button className="sidebar-toggle" onClick={() => setSidebarCollapsed((value) => !value)}>{sidebarCollapsed ? '›' : '‹'}</button><button className="mobile-close" onClick={() => setSidebarOpen(false)}>×</button></div>
        <nav className="primary-nav">
          <NavLink onClick={() => setSidebarOpen(false)} title="Projects" className={({ isActive }) => isActive && !projectId ? 'active' : ''} to="/projects"><span>◫</span><em>Projects</em></NavLink>
          <NavLink onClick={() => setSidebarOpen(false)} title="Vault" className={({ isActive }) => isActive ? 'active' : ''} to="/vault"><span>⛁</span><em>Vault</em></NavLink>
          {projectId && <div className="workspace-nav"><small>Workspace</small>{workspaceNav.map((item) => <NavLink onClick={() => setSidebarOpen(false)} title={item.label} end={!item.path} className={({ isActive }) => isActive ? 'active' : ''} to={`/projects/${projectId}${item.path}`} key={item.label}><span>{item.glyph}</span><em>{item.label}</em></NavLink>)}</div>}
        </nav>
        <button className="logout-button" title="Sign out" onClick={() => logout.mutate()}><span>⇥</span><em>Sign out</em></button>
        <small>Attack Workspace Environment</small>
      </aside>
      <Routes>
        <Route path="/projects" element={<ProjectList />} />
        <Route path="/projects/:projectId" element={<ProjectWorkspace />} />
        <Route path="/projects/:projectId/browser" element={<BrowserPage />} />
        <Route path="/projects/:projectId/decoder" element={<DecoderPage />} />
        <Route path="/projects/:projectId/comparer" element={<ComparerPage />} />
        <Route path="/projects/:projectId/jwt" element={<JwtPage />} />
        <Route path="/projects/:projectId/graphql" element={<GraphqlPage />} />
        <Route path="/projects/:projectId/history" element={<HttpHistoryPage />} />
        <Route path="/projects/:projectId/sitemap" element={<SiteMapPage />} />
        <Route path="/projects/:projectId/network" element={<NetworkPage />} />
        <Route path="/projects/:projectId/repeater" element={<RepeaterPage />} />
        <Route path="/projects/:projectId/intruder" element={<IntruderPage />} />
        <Route path="/projects/:projectId/intercept" element={<InterceptPage />} />
        <Route path="/projects/:projectId/websockets" element={<WebSocketsPage />} />
        <Route path="/projects/:projectId/docker" element={<DockerPage />} />
        <Route path="/projects/:projectId/vault" element={<GlobalVaultPage />} />
        <Route path="/vault" element={<GlobalVaultPage />} />
        <Route path="/projects/:projectId/settings" element={<SettingsPage />} />
        <Route path="*" element={<Navigate to="/projects" replace />} />
      </Routes>
    </div>
  )
}
