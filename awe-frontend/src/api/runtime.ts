import { request } from './client'

export interface ExecutionOptions {
  execution_kind?: 'batch' | 'interactive'
  output_channels?: Array<'logs' | 'structured' | 'artifacts' | 'session'>
  artifact_paths?: string[]
  execution_timeout?: number
  session_idle_timeout?: number
  source_metadata?: Record<string, unknown>
}
export interface RunEvent { sequence: number; timestamp: string; stream: string; stage: string; data: string }
export interface RunArtifact { id: string; name: string; size: number; mime_type: string; sha256: string }
export interface ToolRun { id: string; kind: string; created_at: string; status: string; message?: string; session_id?: string; exit_code?: number; parsing_status?: string; parser_error?: string; logs_truncated?: boolean; artifacts_truncated?: boolean; result?: Record<string, unknown> }
export interface ManagedSession { id: string; project_id: string; kind: string; run_id: string; status: string; label: string; host?: string; port?: number; capabilities: string[]; message?: string }
const base = (project: string) => `/projects/${project}`
export const runtime = {
  runs: (p: string) => request<ToolRun[]>(`${base(p)}/runs`),
  run: (p: string, id: string) => request<ToolRun>(`${base(p)}/runs/${id}`),
  events: (p: string, id: string, after = 0, search = '') => request<{ events: RunEvent[]; cursor: number; truncated: boolean }>(`${base(p)}/runs/${id}/events?after=${after}&search=${encodeURIComponent(search)}`),
  artifacts: (p: string, id: string) => request<RunArtifact[]>(`${base(p)}/runs/${id}/artifacts`),
  refreshArtifacts: (p: string, id: string) => request<RunArtifact[]>(`${base(p)}/runs/${id}/artifacts/refresh`, { method: 'POST' }),
  evidence: (p: string, id: string, payload: object) => request(`${base(p)}/runs/${id}/evidence`, { method: 'POST', body: JSON.stringify(payload) }),
  sessions: (p: string) => request<ManagedSession[]>(`${base(p)}/sessions/interactive`),
  createSession: (p: string, payload: object) => request<ManagedSession>(`${base(p)}/sessions/interactive`, { method: 'POST', body: JSON.stringify(payload) }),
  terminate: (p: string, id: string) => request<ManagedSession>(`${base(p)}/sessions/interactive/${id}`, { method: 'DELETE' }),
  poc: (p: string, definition: object, archive?: File) => {
    const data = new FormData(); data.append('definition', JSON.stringify(definition)); if (archive) data.append('archive', archive)
    return request<ToolRun>(`${base(p)}/pocs`, { method: 'POST', body: data })
  },
}
