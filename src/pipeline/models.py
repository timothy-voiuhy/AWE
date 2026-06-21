"""
Pipeline data model.

PipelineStep  — a single tool execution within a pipeline, with stage grouping
                and optional inter-tool data passing.
PipelineTemplate — an ordered collection of steps with metadata.

Stage semantics:
  - Steps with the same stage number run in parallel.
  - Stage N+1 only starts after all steps in stage N have completed (or been skipped).
  - A skipped step still allows the next stage to run.

input_category semantics:
  - If set, the executor writes a combined input file from that category's
    DB results (from the current session) and mounts it as /input/<category>.txt
    in the container.  The tool's build_command must accept input_file= kwarg.
  - None means the tool uses its own direct target param (domain/url/host).
"""
from dataclasses import dataclass, field


@dataclass
class PipelineStep:
    tool_key: str
    stage: int = 0
    condition: str = "always"
    # "always"              — always run
    # "if:<category>"       — only run if the session has ≥1 result in <category>
    input_category: str | None = None
    # category whose combined values feed this tool as an input file list
    extra_params: dict = field(default_factory=dict)
    # overrides merged on top of the session-level params at execution time


@dataclass
class PipelineTemplate:
    key: str
    name: str
    description: str
    steps: list[PipelineStep]
    category: str = "general"
    # "quick" | "recon" | "content" | "vuln" | "osint" | "full"
