export interface Project {
  id: string
  name: string
  target: string
  created_at: string
  updated_at: string
}

export interface CreateProjectInput {
  name: string
  target: string
}

export type ScopeEntryType = 'domain' | 'wildcard' | 'url' | 'regex'

export interface ScopeEntry {
  value: string
  entry_type: ScopeEntryType
  in_scope: boolean
}

export interface ScopeConfig {
  entries: ScopeEntry[]
  include_subdomains: boolean
}

export interface PipelineTemplate {
  key: string
  name: string
  description: string
  category: string
  steps: Array<{
    tool_key: string
    stage: number
    condition: string
    input_category: string | null
    extra_params: Record<string, unknown>
  }>
}

export type PipelineJobStatus = 'queued' | 'running' | 'completed' | 'failed' | 'stopping' | 'stopped'

export interface PipelineEvent {
  sequence: number
  type: string
  timestamp: string
  data: Record<string, unknown>
}

export interface PipelineJob {
  id: string
  project_id: string
  pipeline_key: string
  status: PipelineJobStatus
  created_at: string
  started_at: string | null
  completed_at: string | null
  session_id: string
  progress_completed: number
  progress_total: number
  message: string
  events: PipelineEvent[]
}

export interface ScanSession {
  id: string
  pipeline_key: string
  pipeline_name: string
  target: string
  status: string
  started_at: string
  completed_at: string | null
}

export interface StoredResult {
  id: string
  session_id: string
  tool_run_id: string
  category: string
  result_key: string
  data: Record<string, unknown>
  sources: string[]
  created_at: string
}

class ApiError extends Error {
  constructor(
    message: string,
    readonly status: number,
  ) {
    super(message)
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const csrf = document.cookie.split('; ').find((item) => item.startsWith('awe_csrf='))?.split('=')[1]
  const response = await fetch(`/api/v1${path}`, {
    ...init,
    credentials: 'include',
    headers: {
      'Content-Type': 'application/json',
      ...(csrf ? { 'X-AWE-CSRF': decodeURIComponent(csrf) } : {}),
      ...init?.headers,
    },
  })
  if (!response.ok) {
    const body = (await response.json().catch(() => null)) as { detail?: string } | null
    throw new ApiError(body?.detail ?? 'AWE backend request failed', response.status)
  }
  if (response.status === 204) return undefined as T
  return response.json() as Promise<T>
}

export const api = {
  getSession: () => request<{ username: string; csrf_token: string }>('/auth/session'),
  login: (username: string, password: string) =>
    request<{ username: string; csrf_token: string }>('/auth/login', {
      method: 'POST',
      body: JSON.stringify({ username, password }),
    }),
  logout: () => request<void>('/auth/logout', { method: 'POST' }),
  listProjects: () => request<Project[]>('/projects'),
  getProject: (projectId: string) => request<Project>(`/projects/${projectId}`),
  createProject: (input: CreateProjectInput) =>
    request<Project>('/projects', {
      method: 'POST',
      body: JSON.stringify(input),
    }),
  updateProject: (projectId: string, input: Partial<CreateProjectInput>) =>
    request<Project>(`/projects/${projectId}`, {
      method: 'PATCH',
      body: JSON.stringify(input),
    }),
  getScope: (projectId: string) => request<ScopeConfig>(`/projects/${projectId}/scope`),
  updateScope: (projectId: string, scope: ScopeConfig) =>
    request<ScopeConfig>(`/projects/${projectId}/scope`, {
      method: 'PUT',
      body: JSON.stringify(scope),
    }),
  listPipelines: () => request<PipelineTemplate[]>('/pipelines'),
  listPipelineRuns: (projectId: string) => request<PipelineJob[]>(`/projects/${projectId}/pipeline-runs`),
  startPipelineRun: (projectId: string, pipelineKey: string) =>
    request<PipelineJob>(`/projects/${projectId}/pipeline-runs`, {
      method: 'POST',
      body: JSON.stringify({ pipeline_key: pipelineKey, params: {} }),
    }),
  cancelPipelineRun: (projectId: string, jobId: string) =>
    request<PipelineJob>(`/projects/${projectId}/pipeline-runs/${jobId}/cancel`, { method: 'POST' }),
  listSessions: (projectId: string) => request<ScanSession[]>(`/projects/${projectId}/sessions`),
  listResults: (projectId: string, sessionId: string) =>
    request<StoredResult[]>(`/projects/${projectId}/sessions/${sessionId}/results`),
}
