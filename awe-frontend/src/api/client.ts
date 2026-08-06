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

export interface TrafficEntry {
  id: string
  host: string
  path: string
  method: string
  status_code: number
  timestamp: string
  tool_source: string | null
  request: Record<string, unknown>
  response: Record<string, unknown>
}

export interface RepeaterResponse { status_code: number; reason: string; headers: Record<string, string>; body: string; elapsed_ms: number; body_truncated: boolean }
export interface ProjectSettings { default_threads:number;default_rate_limit:number;default_concurrency:number;proxy_port:number;upstream_proxy:string }
export interface DockerContainer { id:string;name:string;image:string;status:string;created:string }
export interface VaultItem { id:string;name:string;value:string;kind:'credential'|'api_key'|'token'|'note';created_at:string }
export interface VaultCategory { id:string;name:string;accent:string;created_at:string;order:number }
export interface VaultItemRecord { id:string;category_id:string;type:'image'|'pdf'|'file'|'link'|'note';title:string;created_at:string;url?:string;text?:string;lang?:string;filename?:string }
export interface IntruderResult { sequence:number;payload:string;status_code:number;length:number;elapsed_ms:number;error:string }
export interface WebSocketConnection { id:string;host:string;path:string;opened_at:string;closed_at:string|null;frame_count:number }
export interface WebSocketFrame { id:string;conn_id:string;direction:string;opcode_name:string;payload_text:string;payload_len:number;timestamp:string }
export interface InterceptRequest { id:string;host:string;method:string;url:string;headers:string[][];body_b64:string }
export interface BrowserSession { id:string;project_id:string;url:string;title:string;viewport_width:number;viewport_height:number;created_at:string;updated_at:string }

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
  getSetupStatus: () => request<{ configured: boolean }>('/auth/setup-status'),
  setupAccount: (username: string, password: string) =>
    request<{ username: string; csrf_token: string }>('/auth/setup', {
      method: 'POST',
      body: JSON.stringify({ username, password }),
    }),
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
  listTraffic: (projectId: string) => request<TrafficEntry[]>(`/projects/${projectId}/traffic`),
  sendRepeater: (projectId: string, payload: { method: string; url: string; headers: Record<string, string>; body: string }) => request<RepeaterResponse>(`/projects/${projectId}/repeater/send`, { method: 'POST', body: JSON.stringify(payload) }),
  getSettings:(id:string)=>request<ProjectSettings>(`/projects/${id}/settings`),
  saveSettings:(id:string,data:ProjectSettings)=>request<ProjectSettings>(`/projects/${id}/settings`,{method:'PUT',body:JSON.stringify(data)}),
  listContainers:()=>request<DockerContainer[]>('/docker/containers'),
  stopContainer:(id:string)=>request<void>(`/docker/containers/${id}/stop`,{method:'POST'}),
  removeContainer:(id:string)=>request<void>(`/docker/containers/${id}`,{method:'DELETE'}),
  listVault:(id:string)=>request<VaultItem[]>(`/projects/${id}/vault`),
  createVault:(id:string,data:Omit<VaultItem,'id'|'created_at'>)=>request<VaultItem>(`/projects/${id}/vault`,{method:'POST',body:JSON.stringify(data)}),
  deleteVault:(id:string,item:string)=>request<void>(`/projects/${id}/vault/${item}`,{method:'DELETE'}),
  listVaultCategories:()=>request<VaultCategory[]>('/vault/categories'),
  createVaultCategory:(data:{name:string;accent:string})=>request<VaultCategory>('/vault/categories',{method:'POST',body:JSON.stringify(data)}),
  deleteVaultCategory:(id:string)=>request<void>(`/vault/categories/${id}`,{method:'DELETE'}),
  listVaultItems:(category:string)=>request<VaultItemRecord[]>(`/vault/categories/${category}/items`),
  createVaultLink:(category:string,data:{type:'link';title:string;url:string})=>request<VaultItemRecord>(`/vault/categories/${category}/items`,{method:'POST',body:JSON.stringify(data)}),
  createVaultNote:(category:string,data:{type:'note';title:string;text:string;lang:string})=>request<VaultItemRecord>(`/vault/categories/${category}/items`,{method:'POST',body:JSON.stringify(data)}),
  deleteVaultItem:(id:string)=>request<void>(`/vault/items/${id}`,{method:'DELETE'}),
  runIntruder:(id:string,data:{method:string;url:string;headers:Record<string,string>;body:string;payloads:string[];placeholder:string})=>request<IntruderResult[]>(`/projects/${id}/intruder/runs`,{method:'POST',body:JSON.stringify(data)}),
  listWebSockets:(id:string)=>request<WebSocketConnection[]>(`/projects/${id}/websockets`),
  listWebSocketFrames:(id:string,connection:string)=>request<WebSocketFrame[]>(`/projects/${id}/websockets/${connection}/frames`),
  sendWebSocket:(id:string,url:string,message:string)=>request<{reply:string}>(`/projects/${id}/websockets/send`,{method:'POST',body:JSON.stringify({url,message})}),
  setIntercept:(id:string,enabled:boolean,patterns:string[])=>request<void>(`/projects/${id}/intercept`,{method:'PUT',body:JSON.stringify({enabled,patterns})}),
  listPendingIntercepts:(id:string)=>request<InterceptRequest[]>(`/projects/${id}/intercept/pending`),
  resolveIntercept:(id:string,requestId:string,data:{decision:'forward'|'drop';headers:string[][];body_b64:string})=>request<void>(`/projects/${id}/intercept/${requestId}/resolve`,{method:'POST',body:JSON.stringify(data)}),
  listBrowserSessions:(id:string)=>request<BrowserSession[]>(`/projects/${id}/browser/sessions`),
  createBrowserSession:(id:string,data?:{width:number;height:number})=>request<BrowserSession>(`/projects/${id}/browser/sessions`,{method:'POST',body:JSON.stringify(data??{width:1280,height:800})}),
  navigateBrowser:(id:string,session:string,url:string)=>request<BrowserSession>(`/projects/${id}/browser/sessions/${session}/navigate`,{method:'POST',body:JSON.stringify({url})}),
  closeBrowserSession:(id:string,session:string)=>request<void>(`/projects/${id}/browser/sessions/${session}`,{method:'DELETE'}),
  browserScreenshotUrl:(id:string,session:string)=>`/api/v1/projects/${id}/browser/sessions/${session}/screenshot`,
}
