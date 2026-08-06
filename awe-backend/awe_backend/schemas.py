from datetime import datetime

from typing import Literal

from pydantic import BaseModel, Field, field_validator


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


class IntruderRequest(BaseModel):
    method: Literal["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"] = "GET"
    url: str = Field(min_length=1, max_length=4096)
    headers: dict[str, str] = Field(default_factory=dict)
    body: str = Field(default="", max_length=2_000_000)
    payloads: list[str] = Field(min_length=1, max_length=100)
    placeholder: str = Field(default="§payload§", min_length=1, max_length=50)


class IntruderResult(BaseModel):
    sequence: int
    payload: str
    status_code: int
    length: int
    elapsed_ms: int
    error: str = ""


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
