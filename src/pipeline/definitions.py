"""
Built-in pipeline templates.

Data flow between stages:

  Stage 0 — Subdomain enum (amass, subfinder, assetfinder, ctl) — parallel
              output → subdomain category in DB
  Stage 1 — DNS resolution (dnsx) — reads combined subdomains as input list
              output → dns category
  Stage 2 — Live host probe (httpx) — reads combined subdomains as input list
              output → http category
  Stage 3 — URL discovery (gospider, katana) — parallel, reads http list (-S / -list)
             URL discovery (waybackurls, gau) — parallel, reads subdomain list (stdin)
              output → crawl category
  Stage 4 — Parameter discovery (arjun, x8) — parallel, reads http list (-i / -u filename)
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
        PipelineStep("waybackurls", stage=stage, input_category="subdomain"),
        PipelineStep("gau",         stage=stage, input_category="subdomain"),
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

# ── Vulnerability pipeline helpers ────────────────────────────────────────────

def _xss_tools(stage: int) -> list[PipelineStep]:
    return [
        PipelineStep("kxss",   stage=stage, condition="if:crawl", input_category="crawl"),
        PipelineStep("gxss",   stage=stage, condition="if:crawl", input_category="crawl"),
    ]

def _recon_plus_tools(stage: int) -> list[PipelineStep]:
    return [
        PipelineStep("gowitness", stage=stage, condition="if:http", input_category="http"),
        PipelineStep("subzy",     stage=stage, condition="if:subdomain", input_category="subdomain"),
        PipelineStep("wafw00f",   stage=stage, condition="if:http", input_category="http"),
    ]


# ── XSS Detection Pipeline ────────────────────────────────────────────────────

XSS_SCAN = PipelineTemplate(
    key="xss_scan",
    name="XSS Detection",
    description=(
        "Subdomain enum → live hosts → full crawl → "
        "reflection check (kxss + gxss) → XSS confirmation (dalfox)"
    ),
    category="vuln",
    steps=[
        PipelineStep("subfinder",   stage=0),
        PipelineStep("assetfinder", stage=0),
        _httpx_step(stage=1),
        *_crawl_tools(stage=2),
        *_xss_tools(stage=3),
        PipelineStep("dalfox", stage=4, condition="if:crawl", input_category="crawl"),
    ],
)


# ── SQL Injection Pipeline ────────────────────────────────────────────────────

SQLI_SCAN = PipelineTemplate(
    key="sqli_scan",
    name="SQL Injection Hunt",
    description=(
        "Subdomain enum → live hosts → crawl all URLs → "
        "parameter discovery → sqlmap on parameterised URLs"
    ),
    category="vuln",
    steps=[
        PipelineStep("subfinder",   stage=0),
        PipelineStep("assetfinder", stage=0),
        _httpx_step(stage=1),
        PipelineStep("gospider",    stage=2, condition="if:http", input_category="http"),
        PipelineStep("katana",      stage=2, condition="if:http", input_category="http"),
        PipelineStep("waybackurls", stage=2, input_category="subdomain"),
        PipelineStep("gau",         stage=2, input_category="subdomain"),
        PipelineStep("arjun",       stage=3, condition="if:http", input_category="http"),
        PipelineStep("x8",          stage=3, condition="if:http", input_category="http"),
        PipelineStep("sqlmap",      stage=4, condition="if:crawl", input_category="crawl"),
    ],
)


# ── Deep Recon Pipeline ───────────────────────────────────────────────────────

RECON_PLUS = PipelineTemplate(
    key="recon_plus",
    name="Deep Recon",
    description=(
        "Full subdomain enum → live hosts → "
        "screenshots + subdomain takeover check + WAF fingerprinting in parallel"
    ),
    category="recon",
    steps=[
        *_subdomain_tools(stage=0),
        PipelineStep("shuffledns", stage=0),
        _httpx_step(stage=1),
        *_recon_plus_tools(stage=2),
    ],
)


# ── API Attack Surface Pipeline ───────────────────────────────────────────────

API_SCAN = PipelineTemplate(
    key="api_scan",
    name="API Attack Surface",
    description=(
        "Subdomain enum → live hosts → "
        "JS crawl + kiterunner API brute-force in parallel → nuclei API templates"
    ),
    category="content",
    steps=[
        PipelineStep("subfinder",   stage=0),
        PipelineStep("assetfinder", stage=0),
        _httpx_step(stage=1),
        PipelineStep("katana",      stage=2, condition="if:http", input_category="http"),
        PipelineStep("kiterunner",  stage=2, condition="if:http", input_category="http"),
        PipelineStep("nuclei",      stage=3, condition="if:http", input_category="http",
                     extra_params={"tags": "api,graphql,swagger,openapi"}),
    ],
)


# ── CORS Misconfiguration Pipeline ────────────────────────────────────────────

CORS_SCAN = PipelineTemplate(
    key="cors_scan",
    name="CORS Misconfiguration Scan",
    description=(
        "Subdomain enum → live hosts → "
        "corsy + nuclei CORS templates in parallel"
    ),
    category="vuln",
    steps=[
        PipelineStep("subfinder",   stage=0),
        PipelineStep("assetfinder", stage=0),
        _httpx_step(stage=1),
        PipelineStep("corsy",  stage=2, condition="if:http", input_category="http"),
        PipelineStep("nuclei", stage=2, condition="if:http", input_category="http",
                     extra_params={"tags": "cors,misconfig"}),
    ],
)


# ── Secrets & Exposure Pipeline ───────────────────────────────────────────────

SECRETS_SCAN = PipelineTemplate(
    key="secrets_scan",
    name="Secrets & Credential Exposure",
    description=(
        "Subdomain enum → live hosts → "
        "JS crawl → SecretFinder + nuclei token/secrets templates in parallel"
    ),
    category="vuln",
    steps=[
        PipelineStep("subfinder",   stage=0),
        PipelineStep("assetfinder", stage=0),
        _httpx_step(stage=1),
        PipelineStep("gospider", stage=2, condition="if:http", input_category="http"),
        PipelineStep("katana",   stage=2, condition="if:http", input_category="http"),
        PipelineStep("secretfinder", stage=3),
        PipelineStep("nuclei",       stage=3, condition="if:http", input_category="http",
                     extra_params={"tags": "token,exposure,secrets,api-key"}),
    ],
)


# ── Full Vulnerability Assessment ─────────────────────────────────────────────

FULL_VULN_SCAN = PipelineTemplate(
    key="full_vuln",
    name="Full Vulnerability Assessment",
    description=(
        "Complete attack chain: subdomain enum → recon+ (screenshots, takeover, WAF) → "
        "deep crawl → param discovery → XSS reflection → "
        "dalfox + sqlmap + CORS + secrets in parallel → "
        "kiterunner API scan + nuclei full sweep → OSINT"
    ),
    category="full",
    steps=[
        # Stage 0 — Subdomain enumeration
        *_subdomain_tools(stage=0),
        PipelineStep("shuffledns", stage=0),
        # Stage 1 — DNS + live host detection
        _dns_step(stage=1),
        _httpx_step(stage=1),
        # Stage 2 — Recon+ (screenshots, takeover, WAF) — parallel
        *_recon_plus_tools(stage=2),
        # Stage 3 — Full crawl + URL discovery — parallel
        PipelineStep("gospider",    stage=3, condition="if:http",      input_category="http"),
        PipelineStep("katana",      stage=3, condition="if:http",      input_category="http"),
        PipelineStep("waybackurls", stage=3, input_category="subdomain"),
        PipelineStep("gau",         stage=3, input_category="subdomain"),
        # Stage 4 — Parameter discovery — parallel
        PipelineStep("arjun", stage=4, condition="if:http", input_category="http"),
        PipelineStep("x8",    stage=4, condition="if:http", input_category="http"),
        # Stage 5 — Reflection detection — parallel
        *_xss_tools(stage=5),
        # Stage 6 — Active vuln testing — parallel, different input categories
        PipelineStep("dalfox",       stage=6, condition="if:crawl", input_category="crawl"),
        PipelineStep("sqlmap",       stage=6, condition="if:crawl", input_category="crawl"),
        PipelineStep("corsy",        stage=6, condition="if:http",  input_category="http"),
        PipelineStep("secretfinder", stage=6),
        # Stage 7 — API surface + broad vuln sweep — parallel
        PipelineStep("kiterunner", stage=7, condition="if:http", input_category="http"),
        _nuclei_step(stage=7),
        # Stage 8 — OSINT
        *_osint_tools(stage=8),
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
        # vulnerability pipelines
        XSS_SCAN,
        SQLI_SCAN,
        RECON_PLUS,
        API_SCAN,
        CORS_SCAN,
        SECRETS_SCAN,
        FULL_VULN_SCAN,
    ]
}
