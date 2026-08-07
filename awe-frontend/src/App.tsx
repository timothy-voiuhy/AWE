import { Navigate, NavLink, Route, Routes, useLocation } from 'react-router-dom'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useRef, useState, type TouchEvent } from 'react'

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
import { InterceptPage, WebSocketsPage } from './features/testing/SecurityTestingPages'
import { IntruderPage } from './features/testing/IntruderPage'
import { BrowserPage } from './features/browser/BrowserPage'
import { GlobalVaultPage } from './features/operations/GlobalVaultPage'
import { AIPage } from './features/ai/AIPage'
import { StreamingAIPage } from './features/ai/StreamingAIPage'
import { TerminalPage } from './features/terminal/TerminalPage'
import { ResultsPage } from './features/results/ResultsPage'
import { TerminalConfigPage } from './features/terminal/TerminalConfigPage'
import { DockerManagerPage } from './features/operations/DockerManagerPage'
import { PipelinePage } from './features/pipeline/PipelinePage'

const workspaceNav = [
  { path: '', label: 'Overview', glyph: '⌂', icon: '/assets/icons/target.png' },
  { path: '/browser', label: 'Browser', glyph: '◉', icon: '/assets/icons/browser.png' },
  { path: '/pipeline', label: 'Pipeline', glyph: '⚡', icon: '/assets/icons/pipeline.png' },
  { path: '/ai', label: 'AI Chat', glyph: '✦' },
  { path: '/terminal', label: 'Terminal', glyph: '>_' },
  { path: '/results', label: 'Results', glyph: '◈', icon: '/assets/icons/results.png' },
  { path: '/history', label: 'History', glyph: '⊟', icon: '/assets/icons/http.png' },
  { path: '/sitemap', label: 'Site Map', glyph: '◫', icon: '/assets/icons/sitemap.png' },
  { path: '/network', label: 'Network', glyph: '⊗', icon: '/assets/icons/network.png' },
  { path: '/repeater', label: 'Repeater', glyph: '↻', icon: '/assets/icons/repeater.png' },
  { path: '/intruder', label: 'Intruder', glyph: '⚡', icon: '/assets/icons/intruder.png' },
  { path: '/intercept', label: 'Intercept', glyph: '⏸', icon: '/assets/icons/intercept.png' },
  { path: '/websockets', label: 'WebSockets', glyph: '⇆', icon: '/assets/icons/websocket.png' },
  { path: '/decoder', label: 'Decoder', glyph: '⊞', icon: '/assets/icons/encoding.png' },
  { path: '/comparer', label: 'Comparer', glyph: '⇌', icon: '/assets/icons/comparer.png' },
  { path: '/jwt', label: 'JWT', glyph: '⚿', icon: '/assets/icons/jwt.png' },
  { path: '/graphql', label: 'GraphQL', glyph: '⬡', icon: '/assets/icons/graphql.png' },
  { path: '/docker', label: 'Docker', glyph: '⬡', icon: '/assets/icons/docker.png' },
  { path: '/vault', label: 'Vault', glyph: '⛁', icon: '/assets/icons/notes.png' },
  { path: '/settings', label: 'Settings', glyph: '⚙', icon: '/assets/icons/settings-512.png' },
]

export function App() {
  const [sidebarOpen, setSidebarOpen] = useState(false)
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false)
  const swipeStart = useRef<{ x: number; y: number } | null>(null)
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

  function startSidebarSwipe(event: TouchEvent<HTMLDivElement>) {
    const touch = event.touches[0]
    if (!sidebarOpen && touch) {
      swipeStart.current = { x: touch.clientX, y: touch.clientY }
    }
  }

  function continueSidebarSwipe(event: TouchEvent<HTMLDivElement>) {
    const start = swipeStart.current
    const touch = event.touches[0]
    if (!start || !touch) return

    const horizontalDistance = touch.clientX - start.x
    const verticalDistance = Math.abs(touch.clientY - start.y)
    if (horizontalDistance >= 45 && horizontalDistance > verticalDistance * 1.25) {
      event.preventDefault()
      swipeStart.current = null
      setSidebarOpen(true)
    }
  }

  if (setupStatus.isPending || session.isPending) return <main className="login-page"><p className="muted">Checking session…</p></main>
  if (setupStatus.data && !setupStatus.data.configured) return <SetupPage />
  if (session.isError) return <LoginPage />

  return (
    <div className={`app-shell ${sidebarCollapsed ? 'shell-collapsed' : ''}`}>
      {!sidebarOpen && <div
        className="sidebar-swipe-zone"
        aria-hidden="true"
        onTouchStart={startSidebarSwipe}
        onTouchMove={continueSidebarSwipe}
        onTouchEnd={() => { swipeStart.current = null }}
        onTouchCancel={() => { swipeStart.current = null }}
      />}
      {sidebarOpen && <button className="sidebar-scrim" onClick={() => setSidebarOpen(false)} />}
      <aside className={`sidebar ${sidebarOpen ? 'sidebar-open' : ''} ${sidebarCollapsed ? 'sidebar-collapsed' : ''}`}>
        <div className="brand"><span>AW</span><strong>AWE</strong><button className="sidebar-toggle" onClick={() => setSidebarCollapsed((value) => !value)}>{sidebarCollapsed ? '›' : '‹'}</button><button className="mobile-close" onClick={() => setSidebarOpen(false)}>×</button></div>
        <nav className="primary-nav">
          <NavLink onClick={() => setSidebarOpen(false)} title="Projects" className={({ isActive }) => isActive && !projectId ? 'active' : ''} to="/projects"><img src="/assets/icons/target.png" alt="" /><em>Projects</em></NavLink>
          <NavLink onClick={() => setSidebarOpen(false)} title="Vault" className={({ isActive }) => isActive ? 'active' : ''} to="/vault"><img src="/assets/icons/notes.png" alt="" /><em>Vault</em></NavLink>
          {projectId && <div className="workspace-nav"><small>Workspace</small>{workspaceNav.map((item) => <NavLink onClick={() => setSidebarOpen(false)} title={item.label} end={!item.path} className={({ isActive }) => isActive ? 'active' : ''} to={`/projects/${projectId}${item.path}`} key={item.label}>{item.icon ? <img src={item.icon} alt="" /> : <span>{item.glyph}</span>}<em>{item.label}</em></NavLink>)}</div>}
        </nav>
        <button className="logout-button" title="Sign out" onClick={() => logout.mutate()}><span>⇥</span><em>Sign out</em></button>
        <small>Attack Workspace Environment</small>
      </aside>
      <Routes>
        <Route path="/projects" element={<ProjectList />} />
        <Route path="/projects/:projectId" element={<ProjectWorkspace />} />
        <Route path="/projects/:projectId/browser" element={<BrowserPage />} />
        <Route path="/projects/:projectId/pipeline" element={<PipelinePage />} />
        <Route path="/projects/:projectId/ai" element={<StreamingAIPage />} />
        <Route path="/projects/:projectId/terminal" element={<TerminalPage />} />
        <Route path="/projects/:projectId/results" element={<ResultsPage />} />
        <Route path="/projects/:projectId/terminal/config" element={<TerminalConfigPage />} />
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
        <Route path="/projects/:projectId/docker" element={<DockerManagerPage />} />
        <Route path="/projects/:projectId/vault" element={<GlobalVaultPage />} />
        <Route path="/vault" element={<GlobalVaultPage />} />
        <Route path="/projects/:projectId/settings" element={<SettingsPage />} />
        <Route path="*" element={<Navigate to="/projects" replace />} />
      </Routes>
    </div>
  )
}
