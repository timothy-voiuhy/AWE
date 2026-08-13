from datetime import datetime

from typing import Literal

from pydantic import BaseModel, Field, field_validator, model_validator


class HealthResponse(BaseModel):
    status: str
    service: str
    version: str


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=100)
    password: str = Field(min_length=1, max_length=1000)


class SetupRequest(BaseModel):
    username: str = Field(min_length=1, max_length=100)
    password: str = Field(min_length=12, max_length=1000)


class SetupStatus(BaseModel):
    configured: bool


class AuthSession(BaseModel):
    username: str
    csrf_token: str


class ProjectCreate(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    target: str = Field(default="", max_length=2048)


class ProjectUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=100)
    target: str | None = Field(default=None, max_length=2048)


class Project(BaseModel):
    id: str
    name: str
    target: str
    created_at: datetime
    updated_at: datetime


class ScopeEntry(BaseModel):
    value: str = Field(min_length=1, max_length=2048)
    entry_type: Literal["domain", "wildcard", "url", "regex"] = "domain"
    in_scope: bool = True

    @field_validator("value")
    @classmethod
    def normalize_value(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("Scope value cannot be blank")
        return value


class ScopeConfig(BaseModel):
    entries: list[ScopeEntry] = Field(default_factory=list, max_length=1000)
    include_subdomains: bool = True


class ProjectNotes(BaseModel):
    content: str = Field(default="", max_length=500_000)


class AuthSessionInput(BaseModel):
    name: str = Field(default="Unnamed", min_length=1, max_length=200)
    headers: list[list[str]] = Field(default_factory=list, max_length=500)
    params: list[list[str]] = Field(default_factory=list, max_length=500)


class AuthSessionEntry(AuthSessionInput):
    id: str


class MethodologyStateInput(BaseModel):
    status: Literal["not_tested", "in_progress", "tested_clean", "vulnerable", "na"] = "not_tested"
    notes: str = Field(default="", max_length=50_000)


class MethodologyVulnerability(BaseModel):
    id: str
    name: str
    description_file: str = ""
    status: str = "not_tested"
    notes: str = ""


class MethodologyCategory(BaseModel):
    id: str
    name: str
    accent: str = "#9399B2"
    icon: str = "◉"
    vulnerabilities: list[MethodologyVulnerability] = Field(default_factory=list)


class MethodologyDetail(MethodologyVulnerability):
    category_id: str
    category_name: str
    description: str = ""


class PipelineStep(BaseModel):
    tool_key: str
    stage: int
    condition: str
    input_category: str | None
    extra_params: dict = Field(default_factory=dict)


class PipelineTemplate(BaseModel):
    key: str
    name: str
    description: str
    category: str
    steps: list[PipelineStep]


class PipelineRunCreate(BaseModel):
    pipeline_key: str = Field(min_length=1, max_length=100)
    params: dict = Field(default_factory=dict)
    session_id: str = Field(default="", max_length=100)
    tool_keys: list[str] = Field(default_factory=list, max_length=200)


class PipelineEvent(BaseModel):
    sequence: int
    type: str
    timestamp: datetime
    data: dict = Field(default_factory=dict)


class PipelineJob(BaseModel):
    id: str
    project_id: str
    pipeline_key: str
    status: Literal["queued", "running", "completed", "failed", "stopping", "stopped"]
    created_at: datetime
    started_at: datetime | None = None
    completed_at: datetime | None = None
    session_id: str = ""
    progress_completed: int = 0
    progress_total: int = 0
    message: str = ""
    events: list[PipelineEvent] = Field(default_factory=list)


class ScanSession(BaseModel):
    id: str
    pipeline_key: str
    pipeline_name: str
    target: str
    status: str
    started_at: str
    completed_at: str | None = None
    params: dict = Field(default_factory=dict)
    in_scope: list[str] = Field(default_factory=list)
    out_of_scope: list[str] = Field(default_factory=list)


class PipelineToolRun(BaseModel):
    id: str
    session_id: str
    tool_key: str
    display_name: str = ""
    stage: int = 0
    status: str
    started_at: str = ""
    completed_at: str | None = None
    result_count: int = 0
    error_msg: str | None = None
    log_lines: list[str] = Field(default_factory=list)


class StoredResult(BaseModel):
    id: str
    session_id: str
    tool_run_id: str
    category: str
    result_key: str
    data: dict = Field(default_factory=dict)
    sources: list[str] = Field(default_factory=list)
    created_at: str = ""


class TrafficEntry(BaseModel):
    id: str
    host: str
    path: str
    method: str
    status_code: int
    timestamp: str
    tool_source: str | None = None
    request: dict = Field(default_factory=dict)
    response: dict = Field(default_factory=dict)


class DatabaseCollectionStats(BaseModel):
    name: str
    documents: int = 0
    storage_bytes: int = 0
    index_bytes: int = 0


class DatabaseStats(BaseModel):
    name: str
    documents: int = 0
    storage_bytes: int = 0
    index_bytes: int = 0
    collections: list[DatabaseCollectionStats] = Field(default_factory=list)


class DatabaseOverview(BaseModel):
    databases: list[DatabaseStats] = Field(default_factory=list)
    traffic_database: str = "awe_proxy_traffic"


class DatabaseCleanupResult(BaseModel):
    database: str
    collection: str
    deleted_documents: int = 0
    reclaimed_storage_bytes: int = 0


class NetworkNode(BaseModel):
    id: str
    kind: str
    label: str
    data: dict = Field(default_factory=dict)


class NetworkEdge(BaseModel):
    source_id: str
    target_id: str
    kind: str
    label: str = ""


class NetworkGraph(BaseModel):
    nodes: list[NetworkNode] = Field(default_factory=list)
    edges: list[NetworkEdge] = Field(default_factory=list)


class GraphEntity(BaseModel):
    id: str
    kind: str
    label: str
    value: str = ""
    data: dict = Field(default_factory=dict)
    source: Literal["derived", "manual", "imported", "transform"] = "derived"
    confidence: float = Field(default=1.0, ge=0, le=1)
    severity: str = ""
    scope: Literal["in", "out", "unknown"] = "unknown"
    pinned: bool = False
    bookmarked: bool = False
    x: float = 0
    y: float = 0
    provenance: list[dict] = Field(default_factory=list)


class GraphRelationship(BaseModel):
    id: str
    source_id: str
    target_id: str
    kind: str
    label: str = ""
    data: dict = Field(default_factory=dict)
    source: Literal["derived", "manual", "imported", "transform"] = "derived"
    confidence: float = Field(default=1.0, ge=0, le=1)
    provenance: list[dict] = Field(default_factory=list)


class GraphInvestigation(BaseModel):
    id: str
    project_id: str
    name: str
    revision: int = 1
    created_at: datetime
    updated_at: datetime
    root_ids: list[str] = Field(default_factory=list)
    entity_ids: list[str] = Field(default_factory=list)
    relationship_ids: list[str] = Field(default_factory=list)
    preferences: dict = Field(default_factory=dict)


class GraphBundle(BaseModel):
    investigation: GraphInvestigation
    entities: list[GraphEntity] = Field(default_factory=list)
    relationships: list[GraphRelationship] = Field(default_factory=list)
    revision: int = 1


class InvestigationCreate(BaseModel):
    name: str = Field(default="Untitled investigation", min_length=1, max_length=200)


class GraphEntityInput(BaseModel):
    kind: str = Field(min_length=1, max_length=80)
    label: str = Field(min_length=1, max_length=500)
    value: str = Field(default="", max_length=4096)
    data: dict = Field(default_factory=dict)
    confidence: float = Field(default=1.0, ge=0, le=1)
    severity: str = Field(default="", max_length=30)
    scope: Literal["in", "out", "unknown"] = "unknown"
    x: float = 0
    y: float = 0


class GraphRelationshipInput(BaseModel):
    source_id: str = Field(min_length=1, max_length=200)
    target_id: str = Field(min_length=1, max_length=200)
    kind: str = Field(min_length=1, max_length=100)
    label: str = Field(default="", max_length=500)
    data: dict = Field(default_factory=dict)
    confidence: float = Field(default=1.0, ge=0, le=1)


class GraphPreferencesInput(BaseModel):
    preferences: dict = Field(default_factory=dict)
    revision: int = Field(default=1, ge=1)


class TransformManifest(BaseModel):
    id: str
    tool_key: str
    display_name: str
    description: str = ""
    input_types: list[str] = Field(default_factory=list)
    output_types: list[str] = Field(default_factory=list)
    relationship_types: list[str] = Field(default_factory=list)
    mode: Literal["passive", "safe_active", "active", "high_risk"] = "passive"
    requires_approval: bool = False
    scope_required: bool = True
    parameters: list[dict] = Field(default_factory=list)


class TransformStart(BaseModel):
    transform_id: str
    entity_ids: list[str] = Field(default_factory=list, min_length=1, max_length=100)
    parameters: dict = Field(default_factory=dict)
    investigation_id: str = ""
    approved: bool = False


class TransformJob(BaseModel):
    id: str
    project_id: str
    investigation_id: str
    transform_id: str
    status: Literal["queued", "running", "completed", "failed", "cancelled", "approval_required"]
    entity_ids: list[str] = Field(default_factory=list)
    operation_id: str = ""
    parameters: dict = Field(default_factory=dict)
    message: str = ""
    created_at: datetime
    completed_at: datetime | None = None
    outputs_ingested: bool = False
    progress_completed: int = 0
    progress_total: int = 0
    logs: list[str] = Field(default_factory=list)


class NetworkManualNode(BaseModel):
    kind: Literal["subdomain", "ip", "port", "tech", "vuln", "osint", "endpoint", "cdn", "custom"]
    label: str = Field(min_length=1, max_length=500)
    parent_id: str = ""
    data: dict = Field(default_factory=dict)


class RepeaterRequest(BaseModel):
    method: Literal["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"] = "GET"
    url: str = Field(min_length=1, max_length=4096)
    headers: dict[str, str] = Field(default_factory=dict)
    body: str = Field(default="", max_length=2_000_000)
    timeout_seconds: float = Field(default=20, ge=1, le=60)


class RepeaterResponse(BaseModel):
    status_code: int
    reason: str
    headers: dict[str, str]
    body: str
    elapsed_ms: int
    body_truncated: bool = False


class ProjectSettings(BaseModel):
    default_threads: int = Field(default=10, ge=1, le=500)
    default_rate_limit: int = Field(default=150, ge=1, le=10000)
    default_concurrency: int = Field(default=25, ge=1, le=500)
    proxy_port: int = Field(default=8080, ge=1, le=65535)
    upstream_proxy: str = Field(default="", max_length=2048)


class DockerContainer(BaseModel):
    id: str
    name: str
    image: str
    status: str
    created: str = ""
    is_service: bool = False


class DockerImage(BaseModel):
    id: str
    tags: list[str]
    size_mb: float


class DockerTool(BaseModel):
    key: str
    display_name: str
    category: str
    image: str
    description: str = ""
    param_specs: list[dict] = Field(default_factory=list)
    source: str = "hub"
    image_present: bool = False
    is_custom: bool = False
    status: str = "ok"
    command_template: str = ""
    dockerfile: str = ""
    parser: str = ""


class DockerImagePull(BaseModel):
    image: str = Field(min_length=1, max_length=256, pattern=r"^[a-zA-Z0-9._:/-]+$")

class DockerImageBuild(BaseModel):
    tag: str = Field(min_length=1, max_length=256, pattern=r"^[a-zA-Z0-9._:/-]+$")
    dockerfile: str = Field(min_length=1, max_length=200_000)

class DockerToolCreate(BaseModel):
    key: str = Field(pattern=r"^[a-z0-9_]+$", min_length=1, max_length=64)
    display_name: str = Field(min_length=1, max_length=120)
    category: str = Field(min_length=1, max_length=80)
    image: str = Field(min_length=1, max_length=256)
    command_template: str = Field(min_length=1, max_length=2000)
    description: str = ""
    param_specs: list[dict] = Field(default_factory=list)
    dockerfile: str = Field(min_length=1, max_length=200_000)
    parser: str = Field(min_length=1, max_length=500_000)


class DockerToolRun(BaseModel):
    params: dict[str, object] = Field(default_factory=dict)
    output_subdir: str = Field(default="docker-output", max_length=200)


class DockerOperation(BaseModel):
    id: str
    kind: str
    status: Literal["queued", "running", "completed", "failed", "cancelling", "cancelled"]
    progress_completed: int = 0
    progress_total: int = 0
    message: str = ""
    logs: list[str] = Field(default_factory=list)
    result: dict = Field(default_factory=dict)


class VaultItemInput(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    value: str = Field(min_length=1, max_length=100_000)
    kind: Literal["credential", "api_key", "token", "note"] = "credential"


class VaultItem(VaultItemInput):
    id: str
    created_at: str


class VaultCategory(BaseModel):
    id: str
    name: str
    accent: str
    created_at: str
    order: int = 0


class VaultItemRecord(BaseModel):
    id: str
    category_id: str
    type: Literal["image", "pdf", "file", "link", "note"]
    title: str
    created_at: str
    url: str | None = None
    text: str | None = None
    lang: str | None = None
    filename: str | None = None


class VaultCategoryInput(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    accent: str = Field(default="#89b4fa", max_length=32)


class VaultItemRecordInput(BaseModel):
    type: Literal["link", "note"]
    title: str = Field(default="", max_length=240)
    url: str | None = Field(default=None, max_length=4096)
    text: str | None = Field(default=None, max_length=1_000_000)
    lang: str = Field(default="txt", max_length=32)


class JwtScanRequest(BaseModel):
    token: str = Field(min_length=10, max_length=20000)
    url: str = Field(default="", max_length=4096)
    cookie: str = Field(default="jwt", max_length=200)
    header: str = Field(default="Authorization: Bearer", max_length=300)
    mode: Literal["decode", "pb", "at", "er", "as", "rs", "ki"] = "decode"


class IntruderRequest(BaseModel):
    method: Literal["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"] = "GET"
    url: str = Field(min_length=1, max_length=4096)
    headers: dict[str, str] = Field(default_factory=dict)
    body: str = Field(default="", max_length=2_000_000)
    payloads: list[str] = Field(min_length=1, max_length=500)
    payload_sets: list[list[str]] = Field(default_factory=list, max_length=25)
    attack_mode: Literal["sniper", "battering_ram", "pitchfork", "cluster_bomb"] = "sniper"
    placeholder: str = Field(default="§payload§", min_length=1, max_length=50)
    concurrency: int = Field(default=5, ge=1, le=25)
    timeout_seconds: float = Field(default=20, ge=1, le=120)
    follow_redirects: bool = False


class IntruderResult(BaseModel):
    sequence: int
    payload: str
    status_code: int
    length: int
    elapsed_ms: int
    error: str = ""
    request_url: str = ""
    request_body: str = ""
    response_headers: dict[str, str] = Field(default_factory=dict)
    response_body: str = ""

class IntruderJob(BaseModel):
    id: str
    project_id: str
    status: Literal["queued", "running", "cancelling", "cancelled", "completed", "failed"]
    created_at: datetime
    completed_at: datetime | None = None
    total: int = 0
    completed: int = 0
    error: str = ""
    results: list[IntruderResult] = Field(default_factory=list)


class WebSocketConnection(BaseModel):
    id: str
    host: str
    path: str
    opened_at: str
    closed_at: str | None = None
    frame_count: int = 0


class WebSocketFrame(BaseModel):
    id: str
    conn_id: str
    direction: str
    opcode_name: str
    payload_text: str
    payload_len: int
    timestamp: str


class WebSocketSendRequest(BaseModel):
    url: str = Field(min_length=1, max_length=4096)
    message: str = Field(max_length=1_000_000)


class WebSocketSendResponse(BaseModel):
    reply: str = ""


class InterceptConfig(BaseModel):
    enabled: bool
    patterns: list[str] = Field(default_factory=list, max_length=100)


class InterceptRequest(BaseModel):
    id: str
    host: str
    method: str
    url: str
    headers: list[list[str]] = Field(default_factory=list)
    body_b64: str = ""


class InterceptDecision(BaseModel):
    decision: Literal["forward", "drop"]
    headers: list[list[str]] = Field(default_factory=list)
    body_b64: str = ""


class BrowserSession(BaseModel):
    id: str
    project_id: str
    url: str
    title: str = ""
    viewport_width: int
    viewport_height: int
    created_at: datetime
    updated_at: datetime


class BrowserNavigate(BaseModel):
    url: str = Field(min_length=1, max_length=4096)


class BrowserViewport(BaseModel):
    width: int = Field(default=1280, ge=320, le=2560)
    height: int = Field(default=800, ge=240, le=1600)


class AIConversation(BaseModel):
    id: str
    title: str
    updated_at: str


class AIMessage(BaseModel):
    role: Literal["user", "assistant", "system"]
    content: str
    created_at: str


class AIConversationDetail(AIConversation):
    messages: list[AIMessage] = Field(default_factory=list)


class AIChatRequest(BaseModel):
    content: str = Field(min_length=1, max_length=100_000)


class AISettings(BaseModel):
    provider: Literal["openai", "anthropic", "ollama"] = "openai"
    model: str = Field(default="gpt-4o-mini", max_length=200)
    base_url: str = Field(default="", max_length=2048)
    api_key: str = Field(default="", max_length=1000)
    api_key_configured: bool = False


class AIApproval(BaseModel):
    id: str
    conversation_id: str
    tool_name: str
    arguments: dict = Field(default_factory=dict)
    risk: Literal["low", "medium", "high"] = "medium"
    status: Literal["pending", "approved", "rejected", "expired"] = "pending"
    created_at: str
    resolved_at: str | None = None


class AIApprovalDecision(BaseModel):
    decision: Literal["approve", "reject"]


class TerminalConnectRequest(BaseModel):
    host: str = Field(min_length=1, max_length=255)
    port: int = Field(default=22, ge=1, le=65535)
    username: str = Field(min_length=1, max_length=120)
    password: str = Field(default="", max_length=1000)
    private_key: str = Field(default="", max_length=100_000)
    key_passphrase: str = Field(default="", max_length=1000)
    trust_host_key: bool = False

    @model_validator(mode="after")
    def require_credentials(self):
        if not self.password and not self.private_key:
            raise ValueError("A password or private key is required")
        return self


class TerminalSessionInfo(BaseModel):
    id: str
    project_id: str
    host: str
    port: int
    username: str


class TerminalProfileInput(BaseModel):
    name: str = Field(default="", max_length=120)
    host: str = Field(min_length=1, max_length=255)
    port: int = Field(default=22, ge=1, le=65535)
    username: str = Field(min_length=1, max_length=120)


class TerminalProfile(TerminalProfileInput):
    id: str
