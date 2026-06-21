"""
Built-in pipeline templates.

Data flow between stages:

  Stage 0 — Subdomain enum (amass, subfinder, assetfinder, ctl) — parallel
              output → subdomain category in DB
  Stage 1 — DNS resolution (dnsx) — reads combined subdomains as input list
              output → dns category
  Stage 2 — Live host probe (httpx) — reads combined subdomains as input list
              output → http category
  Stage 3 — URL discovery (gospider, katana, waybackurls, gau) — parallel
              reads combined http (live URLs) as input list
              output → crawl category
  Stage 4 — Parameter discovery (arjun, x8) — parallel
              reads combined http (live URLs)
              output → params category
  Stage 5 — Directory fuzzing (ffuf) — reads combined http
              output → fuzz category
  Stage 6 — Vuln scan (nuclei) — reads combined http (live URLs)
              output → vuln category
  Stage 7 — OSINT (github_recon, cloud_enum) — parallel, domain-level, no input file
              output → osint category

All templates are registered in PIPELINE_REGISTRY keyed by template.key.
"""
from pipeline.models import PipelineStep, PipelineTemplate

# ── Helpers ───────────────────────────────────────────────────────────────────

def _subdomain_tools(stage: int = 0) -> list[PipelineStep]:
    return [
        PipelineStep("amass",       stage=stage),
        PipelineStep("subfinder",   stage=stage),
        PipelineStep("assetfinder", stage=stage),
        PipelineStep("ctl",         stage=stage),
    ]

def _dns_step(stage: int = 1) -> PipelineStep:
    return PipelineStep("dnsx", stage=stage, condition="if:subdomain",
                        input_category="subdomain")

def _httpx_step(stage: int = 2) -> PipelineStep:
    return PipelineStep("httpx", stage=stage, condition="if:subdomain",
                        input_category="subdomain")

def _crawl_tools(stage: int = 3) -> list[PipelineStep]:
    return [
        PipelineStep("gospider",    stage=stage, condition="if:http", input_category="http"),
        PipelineStep("katana",      stage=stage, condition="if:http", input_category="http"),
        PipelineStep("waybackurls", stage=stage, input_category=None),  # takes domain directly
        PipelineStep("gau",         stage=stage, input_category=None),  # takes domain directly
    ]

def _param_tools(stage: int = 4) -> list[PipelineStep]:
    return [
        PipelineStep("arjun", stage=stage, condition="if:http", input_category="http"),
        PipelineStep("x8",    stage=stage, condition="if:http", input_category="http"),
    ]

def _fuzz_step(stage: int = 5) -> PipelineStep:
    return PipelineStep("ffuf", stage=stage, condition="if:http", input_category="http")

def _nuclei_step(stage: int = 6) -> PipelineStep:
    return PipelineStep("nuclei", stage=stage, condition="if:http", input_category="http")

def _osint_tools(stage: int = 7) -> list[PipelineStep]:
    return [
        PipelineStep("github_recon", stage=stage),
        PipelineStep("cloud_enum",   stage=stage),
    ]


# ── Templates ─────────────────────────────────────────────────────────────────

QUICK_RECON = PipelineTemplate(
    key="quick_recon",
    name="Quick Recon",
    description="Fast passive subdomain enum → live host probe → nuclei info scan",
    category="quick",
    steps=[
        PipelineStep("subfinder",   stage=0),
        PipelineStep("assetfinder", stage=0),
        PipelineStep("ctl",         stage=0),
        _httpx_step(stage=1),
        PipelineStep("nuclei", stage=2, condition="if:http", input_category="http",
                     extra_params={"severity": "high,critical"}),
    ],
)

FULL_SUBDOMAIN = PipelineTemplate(
    key="full_subdomain",
    name="Full Subdomain Enumeration",
    description="All subdomain tools in parallel → DNS resolution → live host detection",
    category="recon",
    steps=[
        *_subdomain_tools(stage=0),
        PipelineStep("shuffledns", stage=0),
        PipelineStep("sublist3r",  stage=0),
        _dns_step(stage=1),
        _httpx_step(stage=2),
    ],
)

CONTENT_DISCOVERY = PipelineTemplate(
    key="content_discovery",
    name="Content Discovery",
    description="Subdomain enum → live hosts → crawl all URLs → find parameters → fuzz directories",
    category="content",
    steps=[
        PipelineStep("subfinder",   stage=0),
        PipelineStep("assetfinder", stage=0),
        _httpx_step(stage=1),
        *_crawl_tools(stage=2),
        *_param_tools(stage=3),
        _fuzz_step(stage=4),
    ],
)

VULN_SCAN = PipelineTemplate(
    key="vuln_scan",
    name="Vulnerability Scan",
    description="Subdomain enum → live hosts → nuclei full scan",
    category="vuln",
    steps=[
        PipelineStep("subfinder",   stage=0),
        PipelineStep("assetfinder", stage=0),
        _httpx_step(stage=1),
        _nuclei_step(stage=2),
    ],
)

OSINT_ONLY = PipelineTemplate(
    key="osint",
    name="OSINT",
    description="GitHub recon + cloud bucket enumeration",
    category="osint",
    steps=_osint_tools(stage=0),
)

FULL_PIPELINE = PipelineTemplate(
    key="full",
    name="Full Pipeline",
    description="Complete recon: subdomain enum → DNS → HTTP → crawl → params → fuzz → nuclei → OSINT",
    category="full",
    steps=[
        *_subdomain_tools(stage=0),
        PipelineStep("shuffledns", stage=0),
        PipelineStep("sublist3r",  stage=0),
        _dns_step(stage=1),
        _httpx_step(stage=2),
        *_crawl_tools(stage=3),
        *_param_tools(stage=4),
        _fuzz_step(stage=5),
        _nuclei_step(stage=6),
        *_osint_tools(stage=7),
    ],
)

PIPELINE_REGISTRY: dict[str, PipelineTemplate] = {
    t.key: t for t in [
        QUICK_RECON,
        FULL_SUBDOMAIN,
        CONTENT_DISCOVERY,
        VULN_SCAN,
        OSINT_ONLY,
        FULL_PIPELINE,
    ]
}
