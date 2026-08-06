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
