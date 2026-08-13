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

export interface ProjectNotes { content: string }
export interface AuthSessionEntry { id:string; name:string; headers:string[][]; params:string[][] }
export type MethodologyStatus = 'not_tested'|'in_progress'|'tested_clean'|'vulnerable'|'na'
export interface MethodologyVulnerability { id:string; name:string; description_file:string; status:MethodologyStatus; notes:string }
export interface MethodologyCategory { id:string; name:string; accent:string; icon:string; vulnerabilities:MethodologyVulnerability[] }
export interface MethodologyDetail extends MethodologyVulnerability { category_id:string; category_name:string; description:string }

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
  params: Record<string, unknown>
  in_scope: string[]
  out_of_scope: string[]
}

export interface PipelineToolRun { id:string;session_id:string;tool_key:string;display_name:string;stage:number;status:string;started_at:string;completed_at:string|null;result_count:number;error_msg:string|null;log_lines:string[] }

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
export interface DatabaseCollectionStats { name:string; documents:number; storage_bytes:number; index_bytes:number }
export interface DatabaseStats { name:string; documents:number; storage_bytes:number; index_bytes:number; collections:DatabaseCollectionStats[] }
export interface DatabaseOverview { databases:DatabaseStats[]; traffic_database:string }
export interface DatabaseCleanupResult { database:string; collection:string; deleted_documents:number; reclaimed_storage_bytes:number }
export interface NetworkNode { id:string; kind:string; label:string; data:Record<string,unknown> }
export interface NetworkEdge { source_id:string; target_id:string; kind:string; label:string }
export interface NetworkGraph { nodes:NetworkNode[]; edges:NetworkEdge[] }

export interface RepeaterResponse { status_code: number; reason: string; headers: Record<string, string>; body: string; elapsed_ms: number; body_truncated: boolean }
export interface ProjectSettings { default_threads:number;default_rate_limit:number;default_concurrency:number;proxy_port:number;upstream_proxy:string }
export interface ProxyInfo { host:string;port:number;certificate_url:string;scheme:string;username:string;password_configured:boolean }
export interface DockerContainer { id:string;name:string;image:string;status:string;created:string;is_service:boolean }
export interface DockerImage { id:string;tags:string[];size_mb:number }
export interface DockerTool { key:string;display_name:string;category:string;image:string;description:string;param_specs:Array<{key:string;label?:string;type?:'text'|'check'|'combo';default?:unknown;options?:string[]}>;source:'build'|'hub';image_present:boolean;is_custom:boolean;status:string;command_template:string;dockerfile:string;parser:string }
export interface DockerOperation { id:string;kind:string;status:'queued'|'running'|'completed'|'failed'|'cancelling'|'cancelled';progress_completed:number;progress_total:number;message:string;logs:string[];result:Record<string,unknown> }
export interface DockerToolInput { key:string;display_name:string;category:string;image:string;description:string;command_template:string;param_specs:DockerTool['param_specs'];dockerfile:string;parser:string }
export interface VaultItem { id:string;name:string;value:string;kind:'credential'|'api_key'|'token'|'note';created_at:string }
export interface VaultCategory { id:string;name:string;accent:string;created_at:string;order:number }
export interface VaultItemRecord { id:string;category_id:string;type:'image'|'pdf'|'file'|'link'|'note';title:string;created_at:string;url?:string;text?:string;lang?:string;filename?:string }
export interface JwtScanResult { output:string }
export interface IntruderResult { sequence:number;payload:string;status_code:number;length:number;elapsed_ms:number;error:string;request_url:string;request_body:string;response_headers:Record<string,string>;response_body:string }
export interface IntruderJob { id:string;project_id:string;status:'queued'|'running'|'cancelling'|'cancelled'|'completed'|'failed';created_at:string;completed_at:string|null;total:number;completed:number;error:string;results:IntruderResult[] }
export interface WebSocketConnection { id:string;host:string;path:string;opened_at:string;closed_at:string|null;frame_count:number }
export interface WebSocketFrame { id:string;conn_id:string;direction:string;opcode_name:string;payload_text:string;payload_len:number;timestamp:string }
export interface InterceptRequest { id:string;host:string;method:string;url:string;headers:string[][];body_b64:string }
export interface BrowserSession { id:string;project_id:string;url:string;title:string;viewport_width:number;viewport_height:number;created_at:string;updated_at:string }
export interface AIConversation { id:string;title:string;updated_at:string }
export interface AIMessage { role:'user'|'assistant'|'system';content:string;created_at:string }
export interface AIConversationDetail extends AIConversation { messages:AIMessage[] }
export interface AISettings { provider:'openai'|'anthropic'|'ollama';model:string;base_url:string;api_key:string;api_key_configured:boolean }
export interface AIApproval { id:string;conversation_id:string;tool_name:string;arguments:Record<string,unknown>;risk:'low'|'medium'|'high';status:'pending'|'approved'|'rejected'|'expired';created_at:string;resolved_at:string|null }
export interface TerminalSessionInfo { id:string;project_id:string;host:string;port:number;username:string }
export interface TerminalProfile { id:string;name:string;host:string;port:number;username:string }

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
  const isMultipart = typeof FormData !== 'undefined' && init?.body instanceof FormData
  const response = await fetch(`/api/v1${path}`, {
    ...init,
    credentials: 'include',
    headers: {
      ...(isMultipart ? {} : { 'Content-Type': 'application/json' }),
      ...(csrf ? { 'X-AWE-CSRF': decodeURIComponent(csrf) } : {}),
      ...init?.headers,
    },
  })
  if (!response.ok) {
    const body = (await response.json().catch(() => null)) as { detail?: string | Array<{ msg?: string }> } | null
    const detail = Array.isArray(body?.detail)
      ? body.detail.map((item) => item.msg).filter(Boolean).join('; ')
      : body?.detail
    throw new ApiError(detail || 'AWE backend request failed', response.status)
  }
  if (response.status === 204) return undefined as T
  return response.json() as Promise<T>
}

export const api = {
  getProxyInfo:()=>request<ProxyInfo>('/proxy/info'),
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
  getNotes: (projectId:string) => request<ProjectNotes>(`/projects/${projectId}/notes`),
  saveNotes: (projectId:string, content:string) => request<ProjectNotes>(`/projects/${projectId}/notes`,{method:'PUT',body:JSON.stringify({content})}),
  listAuthSessions: (projectId:string) => request<AuthSessionEntry[]>(`/projects/${projectId}/auth-sessions`),
  createAuthSession: (projectId:string, data:Omit<AuthSessionEntry,'id'>) => request<AuthSessionEntry>(`/projects/${projectId}/auth-sessions`,{method:'POST',body:JSON.stringify(data)}),
  updateAuthSession: (projectId:string, id:string, data:Omit<AuthSessionEntry,'id'>) => request<AuthSessionEntry>(`/projects/${projectId}/auth-sessions/${id}`,{method:'PUT',body:JSON.stringify(data)}),
  deleteAuthSession: (projectId:string, id:string) => request<void>(`/projects/${projectId}/auth-sessions/${id}`,{method:'DELETE'}),
  listMethodology: (projectId:string) => request<MethodologyCategory[]>(`/projects/${projectId}/methodology`),
  getMethodologyDetail: (projectId:string, vulnId:string) => request<MethodologyDetail>(`/projects/${projectId}/methodology/${encodeURIComponent(vulnId)}`),
  updateMethodology: (projectId:string, vulnId:string, data:{status:MethodologyStatus;notes:string}) => request<MethodologyDetail>(`/projects/${projectId}/methodology/${encodeURIComponent(vulnId)}`,{method:'PUT',body:JSON.stringify(data)}),
  listPipelines: () => request<PipelineTemplate[]>('/pipelines'),
  listPipelineRuns: (projectId: string) => request<PipelineJob[]>(`/projects/${projectId}/pipeline-runs`),
  startPipelineRun: (projectId: string, pipelineKey: string, options: { session_id?: string; tool_keys?: string[] } = {}) =>
    request<PipelineJob>(`/projects/${projectId}/pipeline-runs`, {
      method: 'POST',
      body: JSON.stringify({ pipeline_key: pipelineKey, params: {}, ...options }),
    }),
  cancelPipelineRun: (projectId: string, jobId: string) =>
    request<PipelineJob>(`/projects/${projectId}/pipeline-runs/${jobId}/cancel`, { method: 'POST' }),
  listSessions: (projectId: string) => request<ScanSession[]>(`/projects/${projectId}/sessions`),
  listSessionToolRuns: (projectId:string,sessionId:string)=>request<PipelineToolRun[]>(`/projects/${projectId}/sessions/${sessionId}/tool-runs`),
  deleteSession: (projectId:string,sessionId:string)=>request<void>(`/projects/${projectId}/sessions/${sessionId}`,{method:'DELETE'}),
  listProjectResults: (projectId: string) => request<StoredResult[]>(`/projects/${projectId}/results`),
  listResults: (projectId: string, sessionId: string) =>
    request<StoredResult[]>(`/projects/${projectId}/sessions/${sessionId}/results`),
  listTraffic: (projectId: string) => request<TrafficEntry[]>(`/projects/${projectId}/traffic`),
  getDatabaseOverview: () => request<DatabaseOverview>('/database/overview'),
  clearAllProxyTraffic: () => request<DatabaseCleanupResult>('/database/traffic',{method:'DELETE'}),
  getNetworkGraph:(projectId:string)=>request<NetworkGraph>(`/projects/${projectId}/network`),
  addNetworkManual:(projectId:string,data:{kind:string;label:string;parent_id?:string;data?:Record<string,unknown>})=>request<NetworkNode>(`/projects/${projectId}/network/manual`,{method:'POST',body:JSON.stringify(data)}),
  getTraffic: (projectId:string,trafficId:string)=>request<TrafficEntry>(`/projects/${projectId}/traffic/${trafficId}`),
  deleteTraffic: (projectId:string,trafficId:string)=>request<void>(`/projects/${projectId}/traffic/${trafficId}`,{method:'DELETE'}),
  deleteTrafficSubtree:(projectId:string,host:string,pathPrefix='')=>request<void>(`/projects/${projectId}/traffic?host=${encodeURIComponent(host)}&path_prefix=${encodeURIComponent(pathPrefix)}`,{method:'DELETE'}),
  syncTrafficResults:(projectId:string)=>request<{session_id:string;written_by_category:Record<string,number>;extracted_counts:Record<string,number>}>(`/projects/${projectId}/traffic/sync-results`,{method:'POST'}),
  sendRepeater: (projectId: string, payload: { method: string; url: string; headers: Record<string, string>; body: string }) => request<RepeaterResponse>(`/projects/${projectId}/repeater/send`, { method: 'POST', body: JSON.stringify(payload) }),
  getSettings:(id:string)=>request<ProjectSettings>(`/projects/${id}/settings`),
  saveSettings:(id:string,data:ProjectSettings)=>request<ProjectSettings>(`/projects/${id}/settings`,{method:'PUT',body:JSON.stringify(data)}),
  listContainers:()=>request<DockerContainer[]>('/docker/containers'),
  stopContainer:(id:string)=>request<void>(`/docker/containers/${id}/stop`,{method:'POST'}),
  startContainer:(id:string)=>request<void>(`/docker/containers/${id}/start`,{method:'POST'}),
  removeContainer:(id:string)=>request<void>(`/docker/containers/${id}`,{method:'DELETE'}),
  listImages:()=>request<DockerImage[]>('/docker/images'),
  removeImage:(id:string)=>request<void>(`/docker/images/${encodeURIComponent(id)}`,{method:'DELETE'}),
  pullImage:(image:string)=>request<{id:string;tags:string[]}>('/docker/images/pull',{method:'POST',body:JSON.stringify({image})}),
  buildImage:(tag:string,dockerfile:string)=>request<{id:string;tags:string[];logs:string[]}>('/docker/images/build',{method:'POST',body:JSON.stringify({tag,dockerfile})}),
  createDockerTool:(payload:DockerToolInput)=>request<DockerTool>('/docker/tools',{method:'POST',body:JSON.stringify(payload)}),
  updateDockerTool:(key:string,payload:DockerToolInput)=>request<DockerTool>(`/docker/tools/${encodeURIComponent(key)}`,{method:'PUT',body:JSON.stringify(payload)}),
  deleteDockerTool:(key:string)=>request<void>(`/docker/tools/${encodeURIComponent(key)}`,{method:'DELETE'}),
  operateToolImages:(operation:'build'|'pull'|'setup')=>request<DockerOperation>(`/docker/tools/images/${operation}`,{method:'POST'}),
  operateOneToolImage:(key:string,operation:'build'|'pull')=>request<DockerOperation>(`/docker/tools/${encodeURIComponent(key)}/image/${operation}`,{method:'POST'}),
  pruneDocker:()=>request<{removed:number}>('/docker/prune',{method:'POST'}),
  containerLogs:(id:string)=>request<string[]>(`/docker/containers/${id}/logs`),
  listDockerTools:()=>request<DockerTool[]>('/docker/tools'),
  dockerStatus:()=>request<{available:boolean;version:string;message:string}>('/docker/status'),
  dockerOperation:(id:string)=>request<DockerOperation>(`/docker/operations/${id}`),
  cancelDockerOperation:(id:string)=>request<DockerOperation>(`/docker/operations/${id}/cancel`,{method:'POST'}),
  runDockerTool:(projectId:string,key:string,params:Record<string,unknown>,output_subdir:string)=>request<DockerOperation>(`/projects/${projectId}/docker/tools/${encodeURIComponent(key)}/runs`,{method:'POST',body:JSON.stringify({params,output_subdir})}),
  listVault:(id:string)=>request<VaultItem[]>(`/projects/${id}/vault`),
  createVault:(id:string,data:Omit<VaultItem,'id'|'created_at'>)=>request<VaultItem>(`/projects/${id}/vault`,{method:'POST',body:JSON.stringify(data)}),
  deleteVault:(id:string,item:string)=>request<void>(`/projects/${id}/vault/${item}`,{method:'DELETE'}),
  listVaultCategories:()=>request<VaultCategory[]>('/vault/categories'),
  createVaultCategory:(data:{name:string;accent:string})=>request<VaultCategory>('/vault/categories',{method:'POST',body:JSON.stringify(data)}),
  deleteVaultCategory:(id:string)=>request<void>(`/vault/categories/${id}`,{method:'DELETE'}),
  updateVaultCategory:(id:string,data:{name:string;accent:string})=>request<VaultCategory>(`/vault/categories/${id}`,{method:'PATCH',body:JSON.stringify(data)}),
  listVaultItems:(category:string)=>request<VaultItemRecord[]>(`/vault/categories/${category}/items`),
  createVaultLink:(category:string,data:{type:'link';title:string;url:string})=>request<VaultItemRecord>(`/vault/categories/${category}/items`,{method:'POST',body:JSON.stringify(data)}),
  createVaultNote:(category:string,data:{type:'note';title:string;text:string;lang:string})=>request<VaultItemRecord>(`/vault/categories/${category}/items`,{method:'POST',body:JSON.stringify(data)}),
  uploadVaultFile:async(category:string,file:File)=>{const data=new FormData();data.append('upload',file);return request<VaultItemRecord>(`/vault/categories/${category}/files`,{method:'POST',body:data})},
  updateVaultItem:(id:string,data:{type:'link'|'note';title?:string;url?:string;text?:string;lang?:string})=>request<VaultItemRecord>(`/vault/items/${id}`,{method:'PATCH',body:JSON.stringify(data)}),
  deleteVaultItem:(id:string)=>request<void>(`/vault/items/${id}`,{method:'DELETE'}),
  scanJwt:(data:{token:string;url?:string;cookie?:string;header?:string;mode?:string})=>request<JwtScanResult>('/jwt/scan',{method:'POST',body:JSON.stringify(data)}),
  runIntruder:async(id:string,data:{method:string;url:string;headers:Record<string,string>;body:string;payloads:string[];payload_sets?:string[][];attack_mode?:string;placeholder:string;concurrency?:number;timeout_seconds?:number;follow_redirects?:boolean})=>{let job=await request<IntruderJob>(`/projects/${id}/intruder/jobs`,{method:'POST',body:JSON.stringify(data)});while(['queued','running','cancelling'].includes(job.status)){await new Promise(resolve=>setTimeout(resolve,350));job=await request<IntruderJob>(`/projects/${id}/intruder/jobs/${job.id}`)}if(job.status==='failed')throw new Error(job.error||'Intruder job failed');return job.results},
  startIntruderJob:(id:string,data:{method:string;url:string;headers:Record<string,string>;body:string;payloads:string[];payload_sets?:string[][];attack_mode?:string;placeholder:string;concurrency?:number;timeout_seconds?:number;follow_redirects?:boolean})=>request<IntruderJob>(`/projects/${id}/intruder/jobs`,{method:'POST',body:JSON.stringify(data)}),
  listIntruderJobs:(id:string)=>request<IntruderJob[]>(`/projects/${id}/intruder/jobs`),
  getIntruderJob:(id:string,job:string)=>request<IntruderJob>(`/projects/${id}/intruder/jobs/${job}`),
  cancelIntruderJob:(id:string,job:string)=>request<IntruderJob>(`/projects/${id}/intruder/jobs/${job}/cancel`,{method:'POST'}),
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
  getAISettings:(id:string)=>request<AISettings>(`/projects/${id}/ai/settings`),
  saveAISettings:(id:string,data:AISettings)=>request<AISettings>(`/projects/${id}/ai/settings`,{method:'PUT',body:JSON.stringify(data)}),
  listAIConversations:(id:string)=>request<AIConversation[]>(`/projects/${id}/ai/conversations`),
  createAIConversation:(id:string)=>request<AIConversationDetail>(`/projects/${id}/ai/conversations`,{method:'POST'}),
  getAIConversation:(id:string,cid:string)=>request<AIConversationDetail>(`/projects/${id}/ai/conversations/${cid}`),
  sendAIMessage:(id:string,cid:string,content:string)=>request<AIConversationDetail>(`/projects/${id}/ai/conversations/${cid}/messages`,{method:'POST',body:JSON.stringify({content})}),
  listAIApprovals:(id:string)=>request<AIApproval[]>(`/projects/${id}/ai/approvals`),
  resolveAIApproval:(id:string,approval:string,decision:'approve'|'reject')=>request<AIApproval>(`/projects/${id}/ai/approvals/${approval}`,{method:'POST',body:JSON.stringify({decision})}),
  createTerminalSession:(id:string,data:{host:string;port:number;username:string;password:string;private_key?:string;key_passphrase?:string;trust_host_key?:boolean})=>request<TerminalSessionInfo>(`/projects/${id}/terminal/sessions`,{method:'POST',body:JSON.stringify(data)}),
  listTerminalProfiles:(id:string)=>request<TerminalProfile[]>(`/projects/${id}/terminal/profiles`),
  createTerminalProfile:(id:string,data:{name:string;host:string;port:number;username:string})=>request<TerminalProfile>(`/projects/${id}/terminal/profiles`,{method:'POST',body:JSON.stringify(data)}),
  updateTerminalProfile:(id:string,profile:string,data:{name:string;host:string;port:number;username:string})=>request<TerminalProfile>(`/projects/${id}/terminal/profiles/${profile}`,{method:'PUT',body:JSON.stringify(data)}),
  deleteTerminalProfile:(id:string,profile:string)=>request<void>(`/projects/${id}/terminal/profiles/${profile}`,{method:'DELETE'}),
}
