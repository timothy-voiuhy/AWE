"""
Registry of every security tool AWE can run in Docker containers.

Tools map 1-to-1 with the ars0n-framework-v2 tool stack plus AWE's own tools.
Each ToolConfig defines:
  - image:       Docker Hub image (pulled automatically)
  - dockerfile:  Path to local Dockerfile (built on first run if image missing)
  - param_spec:  List of form field descriptors used to auto-generate the UI
  - build_command(**kwargs) → str: command string passed to docker run
  - get_volumes(output_dir) → dict: volume mounts
"""
import os
import shlex
import time
from dataclasses import dataclass, field
from typing import Optional

from config.config import RUNDIR

_DF = RUNDIR + "dockerfiles/"   # Dockerfile directory


# ── Base class ────────────────────────────────────────────────────────────────

@dataclass
class ToolConfig:
    key: str
    display_name: str
    image: str
    description: str = ""
    category: str = "misc"
    dockerfile: Optional[str] = None
    # Graph contracts consumed by the web graph transform adapter. These are
    # deliberately descriptive: parsers remain responsible for producing the
    # typed result objects, while the graph layer uses these values to label
    # the transform's expected output and relationship families.
    output_types: tuple[str, ...] = ()
    relationship_types: tuple[str, ...] = ()
    input_types: tuple[str, ...] = ()
    execution_mode: str = "passive"
    credential_fields: tuple[str, ...] = ()

    def container_name(self) -> str:
        return f"awe_{self.key}_{int(time.time())}"

    def get_volumes(self, output_dir: str, input_dir: str | None = None) -> dict:
        os.makedirs(output_dir, exist_ok=True)
        vols = {output_dir: {"bind": "/output", "mode": "rw"}}
        if input_dir:
            vols[input_dir] = {"bind": "/input", "mode": "ro"}
        return vols

    def build_command(self, **kwargs) -> str:
        raise NotImplementedError

    def build_environment(self, **kwargs) -> dict[str, str]:
        """Return secret-bearing environment variables without putting them in commands/logs."""
        return {}

    def param_spec(self) -> list[dict]:
        """
        List of UI field descriptors.
        Each dict: {key, label, type: "text"|"check"|"combo", default, options}
        """
        return []


# ── Subdomain enumeration ─────────────────────────────────────────────────────

@dataclass
class _Amass(ToolConfig):
    key: str = "amass"
    display_name: str = "Amass"
    image: str = "caffix/amass"
    description: str = "In-depth attack surface mapping via DNS and scraping"
    category: str = "subdomain"

    def get_volumes(self, output_dir: str, input_dir: str | None = None) -> dict:
        os.makedirs(output_dir, exist_ok=True)
        # Mount output dir as /output (amass writes to /output/amass_results.txt via -o)
        # Also expose it as /.config/amass so amass can persist its graph DB between runs
        vols = {
            output_dir: {"bind": "/output", "mode": "rw"},
        }
        if input_dir:
            vols[input_dir] = {"bind": "/input", "mode": "ro"}
        return vols

    def build_command(self, domain: str = "", mode: str = "passive",
                      wordlist: str = "", **_) -> str:
        # amass v4: enum subcommand requires an explicit mode flag.
        # -passive  = OSINT/data-source lookups only, no direct DNS probing
        # -active   = enables direct DNS queries, zone transfers, cert grabs
        # -brute    = DNS brute-force (requires -w <wordlist>)
        cmd = f"amass enum -d {domain} -o /output/amass_results.txt"
        if mode == "active":
            cmd += " -active"
            if wordlist:
                cmd += f" -brute -w {wordlist} -min-for-recursive 2"
        else:
            # passive is the safe default — works without any API keys
            cmd += " -passive"
        return cmd

    def param_spec(self):
        return [
            {"key": "domain",   "label": "Target domain", "type": "text",  "default": ""},
            {"key": "mode",     "label": "Mode",          "type": "combo",
             "options": ["passive", "active"],            "default": "passive"},
            {"key": "wordlist", "label": "Brute-force wordlist (active mode only)",
             "type": "text", "default": ""},
        ]


@dataclass
class _Assetfinder(ToolConfig):
    key: str = "assetfinder"
    display_name: str = "Assetfinder"
    image: str = "awe/assetfinder"
    description: str = "Find assets/subdomains related to a domain using passive sources"
    category: str = "subdomain"
    dockerfile: str = _DF + "Dockerfile.assetfinder"

    def build_command(self, domain: str = "", subs_only: bool = True, **_) -> str:
        flag = "--subs-only" if subs_only else ""
        return f"assetfinder {flag} {domain} | tee /output/assetfinder_results.txt"

    def param_spec(self):
        return [
            {"key": "domain",    "label": "Target domain",   "type": "text",  "default": ""},
            {"key": "subs_only", "label": "Subdomains only", "type": "check", "default": True},
        ]


@dataclass
class _Subfinder(ToolConfig):
    key: str = "subfinder"
    display_name: str = "Subfinder"
    image: str = "projectdiscovery/subfinder:latest"
    description: str = "Fast passive subdomain enumeration from multiple sources"
    category: str = "subdomain"

    def build_command(self, domain: str = "", all_sources: bool = False,
                      silent: bool = True, **_) -> str:
        cmd = f"subfinder -d {domain} -o /output/subfinder_results.txt"
        if all_sources:
            cmd += " -all"
        if silent:
            cmd += " -silent"
        return cmd

    def param_spec(self):
        return [
            {"key": "domain",      "label": "Target domain", "type": "text",  "default": ""},
            {"key": "all_sources", "label": "All sources",   "type": "check", "default": False},
            {"key": "silent",      "label": "Silent output", "type": "check", "default": True},
        ]


@dataclass
class _Sublist3r(ToolConfig):
    key: str = "sublist3r"
    display_name: str = "Sublist3r"
    image: str = "awe/sublist3r"
    description: str = "Subdomain enumeration via search engines and OSINT sources"
    category: str = "subdomain"
    dockerfile: str = _DF + "Dockerfile.sublist3r"

    def build_command(self, domain: str = "", bruteforce: bool = False,
                      threads: str = "10", engines: str = "", **_) -> str:
        cmd = f"sublist3r -d {domain} -o /output/sublist3r_results.txt -t {threads} -v"
        if bruteforce:
            cmd += " -b"
        if engines:
            cmd += f" -e {engines}"
        return cmd

    def param_spec(self):
        return [
            {"key": "domain",     "label": "Target domain",   "type": "text",  "default": ""},
            {"key": "threads",    "label": "Threads",         "type": "text",  "default": "10"},
            {"key": "bruteforce", "label": "Bruteforce",      "type": "check", "default": False},
            {"key": "engines",    "label": "Engines (csv)",   "type": "text",  "default": ""},
        ]


@dataclass
class _SubDomainizer(ToolConfig):
    key: str = "subdomainizer"
    display_name: str = "SubDomainizer"
    image: str = "awe/subdomainizer"
    description: str = "Subdomain + secret discovery from JavaScript files"
    category: str = "subdomain"
    dockerfile: str = _DF + "Dockerfile.subdomainizer"

    def build_command(self, url: str = "", cookies: str = "", **_) -> str:
        cmd = f"python SubDomainizer.py -u {url} -o /output/subdomainizer_results.txt -k"
        if cookies:
            cmd += f" -c '{cookies}'"
        return cmd

    def param_spec(self):
        return [
            {"key": "url",     "label": "Target URL",         "type": "text", "default": ""},
            {"key": "cookies", "label": "Cookies (optional)", "type": "text", "default": ""},
        ]


@dataclass
class _ShuffleDNS(ToolConfig):
    key: str = "shuffledns"
    display_name: str = "ShuffleDNS"
    image: str = "awe/shuffledns"
    description: str = "Mass DNS brute-forcing with wildcard filtering via massdns"
    category: str = "subdomain"
    dockerfile: str = _DF + "Dockerfile.shuffledns"

    def get_volumes(self, output_dir: str, input_dir: str | None = None) -> dict:
        os.makedirs(output_dir, exist_ok=True)
        wordlists_dir = os.path.join(RUNDIR, "resources", "wordlists")
        vols = {
            output_dir:   {"bind": "/output",    "mode": "rw"},
            wordlists_dir: {"bind": "/wordlists", "mode": "ro"},
        }
        if input_dir:
            vols[input_dir] = {"bind": "/input", "mode": "ro"}
        return vols

    def build_command(self, domain: str = "", wordlist: str = "/wordlists/dns-common.txt",
                      resolvers: str = "/wordlists/resolvers.txt",
                      threads: str = "10000", **_) -> str:
        return (
            f"shuffledns -d {domain} -w {wordlist} -r {resolvers}"
            f" -t {threads} -mode bruteforce -o /output/shuffledns_results.txt -silent"
        )

    def param_spec(self):
        return [
            {"key": "domain",    "label": "Target domain",              "type": "text",
             "default": ""},
            {"key": "wordlist",  "label": "Wordlist (container path)",  "type": "text",
             "default": "/wordlists/dns-common.txt"},
            {"key": "resolvers", "label": "Resolvers (container path)", "type": "text",
             "default": "/wordlists/resolvers.txt"},
            {"key": "threads",   "label": "Concurrent resolves",        "type": "text",
             "default": "10000"},
        ]


@dataclass
class _CTL(ToolConfig):
    key: str = "ctl"
    display_name: str = "CTL"
    image: str = "awe/ctl"
    description: str = "Certificate Transparency Log search for subdomain discovery"
    category: str = "subdomain"
    dockerfile: str = _DF + "Dockerfile.ctl"

    def build_command(self, domain: str = "", **_) -> str:
        # Dockerfile entrypoint is ["subfinder", "-s", "crtsh"] — bypassed by sh -c,
        # so we call subfinder directly with the crtsh source flag.
        return f"subfinder -d {domain} -s crtsh -o /output/ctl_results.txt -silent"

    def param_spec(self):
        return [
            {"key": "domain", "label": "Target domain", "type": "text", "default": ""},
        ]


# ── DNS ───────────────────────────────────────────────────────────────────────

@dataclass
class _DNSx(ToolConfig):
    key: str = "dnsx"
    display_name: str = "DNSx"
    image: str = "projectdiscovery/dnsx:latest"
    description: str = "Fast DNS toolkit for bulk DNS resolution and enumeration"
    category: str = "dns"

    def build_command(self, domain: str = "", record_types: str = "A,CNAME,MX",
                      silent: bool = True, input_file: str = "", **_) -> str:
        src = f"-l {input_file}" if input_file else f"-d {domain}"
        cmd = f"dnsx {src} -resp -o /output/dnsx_results.txt"
        for rt in record_types.split(","):
            cmd += f" -{rt.strip().lower()}"
        if silent:
            cmd += " -silent"
        return cmd

    def param_spec(self):
        return [
            {"key": "domain",       "label": "Domain / list",      "type": "text",  "default": ""},
            {"key": "record_types", "label": "Record types (csv)",  "type": "text",  "default": "A,CNAME,MX"},
            {"key": "silent",       "label": "Silent",             "type": "check", "default": True},
        ]


@dataclass
class _Metabigor(ToolConfig):
    key: str = "metabigor"
    display_name: str = "Metabigor"
    image: str = "awe/metabigor"
    description: str = "OSINT tool for network intelligence — ASN, netblock, IP enumeration"
    category: str = "dns"
    dockerfile: str = _DF + "Dockerfile.metabigor"

    def build_command(self, query: str = "", mode: str = "net --org", **_) -> str:
        return f"metabigor {mode} -i '{query}' | tee /output/metabigor_results.txt"

    def param_spec(self):
        return [
            {"key": "query", "label": "Organisation / ASN / IP", "type": "text", "default": ""},
            {"key": "mode",  "label": "Mode",                    "type": "combo",
             "options": ["net --org", "netd --org", "net --asn", "ip -open"],
             "default": "net --org"},
        ]


# ── Port scanning ─────────────────────────────────────────────────────────────

@dataclass
class _Nmap(ToolConfig):
    key: str = "nmap"
    display_name: str = "Nmap"
    image: str = "instrumentisto/nmap"
    description: str = "Network exploration and security port scanning"
    category: str = "portscan"

    def build_command(self, target: str = "", ports: str = "",
                      flags: str = "-sV -T4", **_) -> str:
        cmd = f"nmap {flags} {target} -oN /output/nmap_results.txt"
        if ports:
            cmd += f" -p {ports}"
        return cmd

    def param_spec(self):
        return [
            {"key": "target", "label": "Target host / CIDR",  "type": "text", "default": ""},
            {"key": "ports",  "label": "Ports (e.g. 80,443)", "type": "text", "default": ""},
            {"key": "flags",  "label": "Nmap flags",          "type": "text", "default": "-sV -T4"},
        ]


@dataclass
class _Naabu(ToolConfig):
    key: str = "naabu"
    display_name: str = "Naabu"
    image: str = "projectdiscovery/naabu:latest"
    description: str = "Fast port scanner with SYN/CONNECT scan support"
    category: str = "portscan"

    def build_command(self, host: str = "", ports: str = "top-100",
                      rate: str = "1000", input_file: str = "", **_) -> str:
        src = f"-list {input_file}" if input_file else f"-host {host}"
        return f"naabu {src} -p {ports} -rate {rate} -o /output/naabu_results.txt -silent"

    def param_spec(self):
        return [
            {"key": "host",  "label": "Target host", "type": "text", "default": ""},
            {"key": "ports", "label": "Port range",  "type": "text", "default": "top-100"},
            {"key": "rate",  "label": "Rate (pps)",  "type": "text", "default": "1000"},
        ]


# ── HTTP probing ──────────────────────────────────────────────────────────────

@dataclass
class _Httpx(ToolConfig):
    key: str = "httpx"
    display_name: str = "httpx"
    image: str = "projectdiscovery/httpx:latest"
    description: str = "Fast HTTP toolkit — live host detection, status, title, technology"
    category: str = "http"

    def build_command(self, target: str = "", flags: str = "",
                      input_file: str = "", **_) -> str:
        base = "-status-code -title -tech-detect -silent -json"
        if flags:
            base += f" {flags}"
        src = f"-l {input_file}" if input_file else f"-u {target}"
        return f"httpx {src} -o /output/httpx_results.txt {base}"

    def param_spec(self):
        return [
            {"key": "target", "label": "Target URL / IP", "type": "text", "default": ""},
            {"key": "flags",  "label": "Extra flags",     "type": "text", "default": ""},
        ]


# ── Crawling & URL discovery ──────────────────────────────────────────────────

@dataclass
class _GoSpider(ToolConfig):
    key: str = "gospider"
    display_name: str = "GoSpider"
    image: str = "awe/gospider"
    description: str = "Fast web spider — crawls URLs, extracts subdomains and JS endpoints"
    category: str = "crawl"
    dockerfile: str = _DF + "Dockerfile.gospider"

    def build_command(self, url: str = "", depth: str = "3",
                      concurrent: str = "10", timeout: str = "300",
                      input_file: str = "", **_) -> str:
        site = f"-S {input_file}" if input_file else f"-s {url}"
        return (
            f"gospider {site} -c {concurrent} -d {depth} -t 3"
            f" -m {timeout} --js --sitemap --robots -a -w -r"
            f" --blacklist '.(jpg|jpeg|gif|png|css|woff|woff2|ico|svg|ttf|eot)'"
            f" -o /output/gospider_results.txt"
        )

    def param_spec(self):
        return [
            {"key": "url",        "label": "Target URL",  "type": "text", "default": ""},
            {"key": "depth",      "label": "Depth",       "type": "text", "default": "3"},
            {"key": "concurrent", "label": "Concurrency", "type": "text", "default": "10"},
            {"key": "timeout",    "label": "Timeout (s)", "type": "text", "default": "300"},
        ]


@dataclass
class _Katana(ToolConfig):
    key: str = "katana"
    display_name: str = "Katana"
    image: str = "projectdiscovery/katana:latest"
    description: str = "Next-gen web crawler for hidden endpoints and attack surface discovery"
    category: str = "crawl"

    def build_command(self, url: str = "", depth: str = "3",
                      concurrency: str = "25", input_file: str = "", **_) -> str:
        src = f"-list {input_file}" if input_file else f"-u {url}"
        return (
            f"katana {src} -d {depth} -jc -j -silent"
            f" -c {concurrency} -p {concurrency} -retry 3 -rd 1 -rl 10"
            f" -timeout 120 -o /output/katana_results.txt"
        )

    def param_spec(self):
        return [
            {"key": "url",         "label": "Target URL",  "type": "text", "default": ""},
            {"key": "depth",       "label": "Depth",       "type": "text", "default": "3"},
            {"key": "concurrency", "label": "Concurrency", "type": "text", "default": "25"},
        ]


@dataclass
class _WaybackURLs(ToolConfig):
    key: str = "waybackurls"
    display_name: str = "WaybackURLs"
    image: str = "awe/waybackurls"
    description: str = "Fetch URLs from Wayback Machine and Common Crawl archives"
    category: str = "crawl"
    dockerfile: str = _DF + "Dockerfile.waybackurls"

    def build_command(self, domain: str = "", dates: bool = False,
                      input_file: str = "", **_) -> str:
        flags = "--dates" if dates else ""
        src = f"cat {input_file}" if input_file else f"echo {domain}"
        return f"{src} | waybackurls {flags} | tee /output/waybackurls_results.txt"

    def param_spec(self):
        return [
            {"key": "domain", "label": "Target domain", "type": "text",  "default": ""},
            {"key": "dates",  "label": "Include dates", "type": "check", "default": False},
        ]


@dataclass
class _GAU(ToolConfig):
    key: str = "gau"
    display_name: str = "GAU"
    image: str = "awe/gau"
    description: str = "Get All URLs from AlienVault OTX, Wayback Machine and Common Crawl"
    category: str = "crawl"
    dockerfile: str = _DF + "Dockerfile.gau"

    def build_command(self, domain: str = "", providers: str = "",
                      threads: str = "1", input_file: str = "", **_) -> str:
        if input_file:
            cmd = f"cat {input_file} | gau --threads {threads} --o /output/gau_results.txt"
        else:
            cmd = f"gau --threads {threads} --o /output/gau_results.txt {domain}"
        if providers:
            cmd += f" --providers {providers}"
        return cmd

    def param_spec(self):
        return [
            {"key": "domain",    "label": "Target domain",          "type": "text", "default": ""},
            {"key": "threads",   "label": "Threads",                "type": "text", "default": "1"},
            {"key": "providers", "label": "Providers (optional)",   "type": "text", "default": ""},
        ]


@dataclass
class _LinkFinder(ToolConfig):
    key: str = "linkfinder"
    display_name: str = "LinkFinder"
    image: str = "awe/linkfinder"
    description: str = "Extract URLs and endpoints from JavaScript files"
    category: str = "crawl"
    dockerfile: str = _DF + "Dockerfile.linkfinder"

    def build_command(self, url: str = "", domain_crawl: bool = True,
                      cookies: str = "", **_) -> str:
        cmd = f"python3 linkfinder.py -i {url} -o cli"
        if domain_crawl:
            cmd += " -d"
        if cookies:
            cmd += f" -c '{cookies}'"
        cmd += " | tee /output/linkfinder_results.txt"
        return cmd

    def param_spec(self):
        return [
            {"key": "url",          "label": "Target URL",   "type": "text",  "default": ""},
            {"key": "domain_crawl", "label": "Domain crawl", "type": "check", "default": True},
            {"key": "cookies",      "label": "Cookies",      "type": "text",  "default": ""},
        ]



@dataclass
class _XnLinkFinder(ToolConfig):
    key: str = "xnlinkfinder"
    display_name: str = "xnLinkFinder"
    image: str = "awe/xnlinkfinder"
    description: str = "Deep link/endpoint discovery from URLs, JS files, and Burp output"
    category: str = "crawl"
    dockerfile: str = _DF + "Dockerfile.xnlinkfinder"

    def build_command(self, url: str = "", depth: str = "2",
                      scope: str = "", cookies: str = "", **_) -> str:
        cmd = f"xnLinkFinder -i {url} -o /output/xnlinkfinder_results.txt -d {depth} --no-banner"
        if scope:
            cmd += f" -sf {scope}"
        if cookies:
            cmd += f" -c {cookies}"
        return cmd

    def param_spec(self):
        return [
            {"key": "url",     "label": "Target URL",          "type": "text",  "default": ""},
            {"key": "depth",   "label": "Crawl depth",         "type": "text",  "default": "2"},
            {"key": "scope",   "label": "Scope filter (domain)","type": "text",  "default": ""},
            {"key": "cookies", "label": "Cookies",             "type": "text",  "default": ""},
        ]


# ── Fuzzing & directory brute-forcing ─────────────────────────────────────────

@dataclass
class _FFuf(ToolConfig):
    key: str = "ffuf"
    display_name: str = "FFuf"
    image: str = "awe/ffuf"
    description: str = "Fast web fuzzer — directory brute-forcing, vhost/parameter fuzzing"
    category: str = "fuzz"
    dockerfile: str = _DF + "Dockerfile.ffuf"

    def build_command(self, url: str = "", wordlist: str = "/wordlists/common.txt",
                      threads: str = "40", extensions: str = "",
                      filter_code: str = "404", **_) -> str:
        cmd = (
            f"ffuf -u {url}/FUZZ -w {wordlist} -t {threads}"
            f" -fc {filter_code} -o /output/ffuf_results.json -of json -silent"
        )
        if extensions:
            cmd += f" -e {extensions}"
        return cmd

    def param_spec(self):
        return [
            {"key": "url",         "label": "Target URL",           "type": "text",
             "default": ""},
            {"key": "wordlist",    "label": "Wordlist (container)",  "type": "text",
             "default": "/wordlists/common.txt"},
            {"key": "threads",     "label": "Threads",              "type": "text",
             "default": "40"},
            {"key": "extensions",  "label": "Extensions (.php,.html)", "type": "text",
             "default": ""},
            {"key": "filter_code", "label": "Filter HTTP codes",    "type": "text",
             "default": "404"},
        ]


@dataclass
class _CeWL(ToolConfig):
    key: str = "cewl"
    display_name: str = "CeWL"
    image: str = "awe/cewl"
    description: str = "Custom wordlist generator by spidering a target website"
    category: str = "fuzz"
    dockerfile: str = _DF + "Dockerfile.cewl"

    def build_command(self, url: str = "", depth: str = "2",
                      min_word_length: str = "5", **_) -> str:
        return (
            f"cewl -d {depth} -m {min_word_length}"
            f" -w /output/cewl_wordlist.txt {url}"
        )

    def param_spec(self):
        return [
            {"key": "url",             "label": "Target URL",       "type": "text",
             "default": ""},
            {"key": "depth",           "label": "Spider depth",     "type": "text",
             "default": "2"},
            {"key": "min_word_length", "label": "Min word length",  "type": "text",
             "default": "5"},
        ]


# ── Parameter discovery ───────────────────────────────────────────────────────

@dataclass
class _Arjun(ToolConfig):
    key: str = "arjun"
    display_name: str = "Arjun"
    image: str = "awe/arjun"
    description: str = "HTTP parameter discovery — finds hidden GET/POST parameters"
    category: str = "params"
    dockerfile: str = _DF + "Dockerfile.arjun"

    def build_command(self, url: str = "", method: str = "GET",
                      threads: str = "5", delay: str = "0",
                      input_file: str = "", **_) -> str:
        src = f"-i {input_file}" if input_file else f"-u {url}"
        return (
            f"arjun {src} -m {method} -t {threads}"
            f" -d {delay} --stable -o /output/arjun_results.json"
        )

    def param_spec(self):
        return [
            {"key": "url",     "label": "Target URL", "type": "text",  "default": ""},
            {"key": "method",  "label": "Method",     "type": "combo",
             "options": ["GET", "POST", "XML", "JSON"], "default": "GET"},
            {"key": "threads", "label": "Threads",    "type": "text",  "default": "5"},
            {"key": "delay",   "label": "Delay (s)",  "type": "text",  "default": "0"},
        ]


@dataclass
class _Parameth(ToolConfig):
    key: str = "parameth"
    display_name: str = "Parameth"
    image: str = "awe/parameth"
    description: str = "Parameter discovery through testing and mutation"
    category: str = "params"
    dockerfile: str = _DF + "Dockerfile.parameth"

    def build_command(self, url: str = "", method: str = "GET",
                      wordlist: str = "", **_) -> str:
        cmd = f"python3 parameth.py -u {url} -m {method} -o /output/parameth_results.txt"
        if wordlist:
            cmd += f" -p {wordlist}"
        return cmd

    def param_spec(self):
        return [
            {"key": "url",      "label": "Target URL",          "type": "text",  "default": ""},
            {"key": "method",   "label": "Method",              "type": "combo",
             "options": ["GET", "POST"],                        "default": "GET"},
            {"key": "wordlist", "label": "Wordlist (optional)", "type": "text",  "default": ""},
        ]


@dataclass
class _X8(ToolConfig):
    key: str = "x8"
    display_name: str = "X8"
    image: str = "awe/x8"
    description: str = "Parameter discovery focused on reflected/hidden params and XSS"
    category: str = "params"
    dockerfile: str = _DF + "Dockerfile.x8"

    def build_command(self, url: str = "", method: str = "GET",
                      workers: str = "10", body_type: str = "urlencode",
                      input_file: str = "", **_) -> str:
        src = input_file if input_file else url
        cmd = (
            f"x8 -u {src} -o /output/x8_results.txt"
            f" -W {workers} -X {method}"
            f" --learn-requests 9 --verify"
        )
        if method.upper() != "GET":
            cmd += f" -t {body_type}"
        return cmd

    def param_spec(self):
        return [
            {"key": "url",       "label": "Target URL", "type": "text",  "default": ""},
            {"key": "method",    "label": "Method",     "type": "combo",
             "options": ["GET", "POST"],               "default": "GET"},
            {"key": "workers",   "label": "Workers",    "type": "text",  "default": "10"},
            {"key": "body_type", "label": "Body type",  "type": "combo",
             "options": ["urlencode", "json"],          "default": "urlencode"},
        ]


# ── Vulnerability scanning ────────────────────────────────────────────────────

@dataclass
class _Nuclei(ToolConfig):
    key: str = "nuclei"
    display_name: str = "Nuclei"
    image: str = "projectdiscovery/nuclei:latest"
    description: str = "Template-based vulnerability scanner — CVEs, misconfigs, exposures"
    category: str = "vuln"

    def build_command(self, target: str = "", severity: str = "",
                      tags: str = "", concurrency: str = "25",
                      rate_limit: str = "150", input_file: str = "", **_) -> str:
        src = f"-l {input_file}" if input_file else f"-u {target}"
        cmd = (
            f"nuclei {src} -o /output/nuclei_results.jsonl -jsonl -nh"
            f" -c {concurrency} -rl {rate_limit} -timeout 10 -retries 1 -bs 25"
        )
        if severity:
            cmd += f" -severity {severity}"
        if tags:
            cmd += f" -tags {tags}"
        return cmd

    def param_spec(self):
        return [
            {"key": "target",      "label": "Target URL",      "type": "text",  "default": ""},
            {"key": "severity",    "label": "Severity",        "type": "combo",
             "options": ["", "info", "low", "medium", "high", "critical"], "default": ""},
            {"key": "tags",        "label": "Tags (optional)", "type": "text",  "default": ""},
            {"key": "concurrency", "label": "Concurrency",    "type": "text",  "default": "25"},
            {"key": "rate_limit",  "label": "Rate limit",     "type": "text",  "default": "150"},
        ]


# ── OSINT / cloud ─────────────────────────────────────────────────────────────

@dataclass
class _GithubRecon(ToolConfig):
    key: str = "github_recon"
    display_name: str = "GitHub Recon"
    image: str = "awe/github_recon"
    description: str = "Search GitHub for endpoints, secrets and domain mentions"
    category: str = "osint"
    dockerfile: str = _DF + "Dockerfile.github_recon"

    def build_command(self, domain: str = "", api_key: str = "", **_) -> str:
        return (
            f"python3 /app/github-search/github-endpoints.py"
            f" -d {domain} -t {api_key} | tee /output/github_recon_results.txt"
        )

    def param_spec(self):
        return [
            {"key": "domain",  "label": "Target domain",    "type": "text", "default": ""},
            {"key": "api_key", "label": "GitHub API token", "type": "text", "default": ""},
        ]


@dataclass
class _CloudEnum(ToolConfig):
    key: str = "cloud_enum"
    display_name: str = "Cloud Enum"
    image: str = "awe/cloud_enum"
    description: str = "Multi-cloud OSINT — AWS, Azure, GCP bucket and resource enumeration"
    category: str = "osint"
    dockerfile: str = _DF + "Dockerfile.cloud_enum"

    def build_command(self, keywords: str = "", threads: str = "20",
                      disable_azure: bool = False, disable_gcp: bool = False, **_) -> str:
        kw_flags = " ".join(f"-k {k.strip()}" for k in keywords.split(",") if k.strip())
        cmd = f"python3 cloud_enum.py {kw_flags} -t {threads} --logfile /output/cloud_enum_results.txt"
        if disable_azure:
            cmd += " --disable-azure"
        if disable_gcp:
            cmd += " --disable-gcp"
        return cmd

    def param_spec(self):
        return [
            {"key": "keywords",      "label": "Keywords (csv)", "type": "text",  "default": ""},
            {"key": "threads",       "label": "Threads",        "type": "text",  "default": "20"},
            {"key": "disable_azure", "label": "Skip Azure",     "type": "check", "default": False},
            {"key": "disable_gcp",   "label": "Skip GCP",       "type": "check", "default": False},
        ]


# ── Network ownership / certificates ─────────────────────────────────────────

@dataclass
class _Asnmap(ToolConfig):
    key: str = "asnmap"
    display_name: str = "ASNMap"
    image: str = "awe/asnmap"
    description: str = "Map domains, organisations, ASNs, and IPs to announced network ranges"
    category: str = "osint"
    dockerfile: str = _DF + "Dockerfile.asnmap"
    output_types: tuple[str, ...] = ("asn", "netblock")
    relationship_types: tuple[str, ...] = ("owned_by", "announces", "contains")

    def build_command(self, target: str = "", target_type: str = "domain",
                      input_file: str = "", **_) -> str:
        if input_file:
            source = f"-f {input_file}"
        else:
            flag = {"domain": "-d", "asn": "-a", "ip": "-i", "org": "-org"}.get(target_type, "-d")
            source = f"{flag} '{target}'"
        return f"asnmap {source} -json -silent -o /output/asnmap_results.jsonl"

    def param_spec(self):
        return [
            {"key": "target",      "label": "Domain / ASN / IP / organisation", "type": "text",  "default": ""},
            {"key": "target_type", "label": "Input type",                       "type": "combo",
             "options": ["domain", "asn", "ip", "org"],                         "default": "domain"},
        ]


@dataclass
class _Tlsx(ToolConfig):
    key: str = "tlsx"
    display_name: str = "tlsx"
    image: str = "awe/tlsx"
    description: str = "TLS certificate, protocol, cipher, and fingerprint collection"
    category: str = "osint"
    dockerfile: str = _DF + "Dockerfile.tlsx"
    output_types: tuple[str, ...] = ("certificate", "tls_finding")
    relationship_types: tuple[str, ...] = ("has_certificate", "has_tls_finding")

    def build_command(self, target: str = "", input_file: str = "", ports: str = "443",
                      concurrency: str = "25", **_) -> str:
        source = f"-list {input_file}" if input_file else f"-host '{target}'"
        return (
            f"tlsx {source} -port {ports} -json -san -cn -so -tls-version"
            f" -cipher -hash sha256 -jarm -ja3 -serial -probe-status"
            f" -expired -self-signed -mismatched -untrusted"
            f" -c {concurrency} -timeout 8 -o /output/tlsx_results.jsonl"
        )

    def param_spec(self):
        return [
            {"key": "target",      "label": "Target host",       "type": "text", "default": ""},
            {"key": "ports",       "label": "TLS ports",          "type": "text", "default": "443"},
            {"key": "concurrency", "label": "Concurrency",        "type": "text", "default": "25"},
        ]


# ── TLS assessment ───────────────────────────────────────────────────────────

@dataclass
class _Testssl(ToolConfig):
    key: str = "testssl"
    display_name: str = "testssl.sh"
    image: str = "awe/testssl"
    description: str = "Detailed TLS protocol, cipher, certificate, and cryptographic weakness assessment"
    category: str = "vuln"
    dockerfile: str = _DF + "Dockerfile.testssl"
    output_types: tuple[str, ...] = ("tls_finding",)
    relationship_types: tuple[str, ...] = ("has_tls_finding",)

    def build_command(self, target: str = "", **_) -> str:
        return (
            f"testssl.sh --quiet --warnings batch --jsonfile /output/testssl_results.json"
            f" '{target}'"
        )

    def param_spec(self):
        return [
            {"key": "target", "label": "TLS host or URL", "type": "text", "default": ""},
        ]


# ── Architecture-specific adapters ──────────────────────────────────────────

@dataclass
class _Wpscan(ToolConfig):
    key: str = "wpscan"
    display_name: str = "WPScan"
    image: str = "awe/wpscan"
    description: str = "WordPress core, plugin, theme, user, and vulnerability enumeration"
    category: str = "architecture"
    dockerfile: str = _DF + "Dockerfile.wpscan"
    output_types: tuple[str, ...] = ("platform", "component", "identity", "misconfiguration", "vulnerability")
    relationship_types: tuple[str, ...] = ("runs", "has_component", "has_finding")
    input_types: tuple[str, ...] = ("url", "domain", "subdomain", "technology")
    execution_mode: str = "safe_active"
    credential_fields: tuple[str, ...] = ("api_token",)

    def build_command(self, url: str = "", enumerate: str = "vp,vt,u", **_) -> str:
        return (f"wpscan --url {shlex.quote(url)} --format json "
                f"--output /output/wpscan_results.json --enumerate {shlex.quote(enumerate)} --no-update")

    def build_environment(self, api_token: str = "", **_) -> dict[str, str]:
        return {"WPSCAN_API_TOKEN": api_token} if api_token else {}

    def param_spec(self):
        return [
            {"key": "url", "label": "WordPress URL", "type": "text", "default": ""},
            {"key": "enumerate", "label": "Enumeration (vp,vt,u)", "type": "text", "default": "vp,vt,u"},
            {"key": "api_token", "label": "WPScan API token (optional)", "type": "text", "default": "secret"},
        ]


@dataclass
class _Droopescan(ToolConfig):
    key: str = "droopescan"
    display_name: str = "Droopescan"
    image: str = "awe/droopescan"
    description: str = "Drupal version, module, theme, and endpoint discovery"
    category: str = "architecture"
    dockerfile: str = _DF + "Dockerfile.droopescan"
    output_types: tuple[str, ...] = ("platform", "component", "endpoint", "misconfiguration")
    relationship_types: tuple[str, ...] = ("runs", "has_component", "has_finding")
    input_types: tuple[str, ...] = ("url", "domain", "subdomain", "technology")
    execution_mode: str = "safe_active"

    def build_command(self, url: str = "", **_) -> str:
        return (f"droopescan scan drupal -u {shlex.quote(url)} "
                "-o json > /output/droopescan_results.json")

    def param_spec(self):
        return [{"key": "url", "label": "Drupal URL", "type": "text", "default": ""}]


@dataclass
class _Prowler(ToolConfig):
    key: str = "prowler"
    display_name: str = "Prowler"
    image: str = "awe/prowler"
    description: str = "Authenticated read-only posture assessment for cloud, Kubernetes, GitHub, and identity providers"
    category: str = "architecture"
    dockerfile: str = _DF + "Dockerfile.prowler"
    output_types: tuple[str, ...] = ("cloud_account", "cloud_resource", "component", "misconfiguration", "vulnerability")
    relationship_types: tuple[str, ...] = ("contains", "has_resource", "has_finding", "uses_component")
    input_types: tuple[str, ...] = ("cloud_asset", "cluster", "repository", "identity_provider")
    execution_mode: str = "active"
    credential_fields: tuple[str, ...] = ("access_key", "secret_key", "session_token", "api_token")

    def build_command(self, provider: str = "aws", profile: str = "", region: str = "", **_) -> str:
        flags = "-M json-ocsf --output-directory /output --no-banner"
        if profile:
            flags += f" --profile {shlex.quote(profile)}"
        if region:
            flags += f" --region {shlex.quote(region)}"
        return f"prowler {shlex.quote(provider)} {flags}"

    def build_environment(self, access_key: str = "", secret_key: str = "",
                          session_token: str = "", api_token: str = "", **_) -> dict[str, str]:
        env = {}
        if access_key: env["AWS_ACCESS_KEY_ID"] = access_key
        if secret_key: env["AWS_SECRET_ACCESS_KEY"] = secret_key
        if session_token: env["AWS_SESSION_TOKEN"] = session_token
        if api_token: env["PROWLER_API_TOKEN"] = api_token
        return env

    def param_spec(self):
        return [
            {"key": "provider", "label": "Provider", "type": "combo", "default": "aws", "options": ["aws", "azure", "gcp", "kubernetes", "github", "cloudflare", "okta", "iac"]},
            {"key": "profile", "label": "Cloud profile (optional)", "type": "text", "default": ""},
            {"key": "region", "label": "Region (optional)", "type": "text", "default": ""},
            {"key": "access_key", "label": "AWS access key (optional)", "type": "text", "default": "secret"},
            {"key": "secret_key", "label": "AWS secret key (optional)", "type": "text", "default": "secret"},
            {"key": "session_token", "label": "AWS session token (optional)", "type": "text", "default": "secret"},
            {"key": "api_token", "label": "Provider API token (optional)", "type": "secret", "default": "secret"},
        ]


@dataclass
class _Kubescape(ToolConfig):
    key: str = "kubescape"
    display_name: str = "Kubescape"
    image: str = "awe/kubescape"
    description: str = "Kubernetes cluster, manifest, Helm, and image security posture scanning"
    category: str = "architecture"
    dockerfile: str = _DF + "Dockerfile.kubescape"
    output_types: tuple[str, ...] = ("cluster", "workload", "container_image", "misconfiguration", "vulnerability")
    relationship_types: tuple[str, ...] = ("contains", "runs", "uses_image", "has_finding")
    input_types: tuple[str, ...] = ("cluster", "workload", "container_image", "file")
    execution_mode: str = "active"

    def build_command(self, target: str = "", target_type: str = "cluster", framework: str = "nsa", **_) -> str:
        source = "" if target_type == "cluster" else shlex.quote(target)
        command = f"scan {source}".strip()
        if target_type == "cluster" and framework:
            command = f"scan framework {shlex.quote(framework)}"
        return f"{command} --format json --output /output/kubescape_results.json"

    def param_spec(self):
        return [
            {"key": "target", "label": "Manifest directory / image", "type": "text", "default": ""},
            {"key": "target_type", "label": "Target type", "type": "combo", "default": "cluster", "options": ["cluster", "manifest", "image"]},
            {"key": "framework", "label": "Framework", "type": "combo", "default": "nsa", "options": ["nsa", "mitre", "cis-v1.23-t1.0.1"]},
        ]


@dataclass
class _Trivy(ToolConfig):
    key: str = "trivy"
    display_name: str = "Trivy"
    image: str = "awe/trivy"
    description: str = "Container image, filesystem, repository, and IaC vulnerability/configuration scanning"
    category: str = "architecture"
    dockerfile: str = _DF + "Dockerfile.trivy"
    output_types: tuple[str, ...] = ("container_image", "component", "misconfiguration", "vulnerability", "secret")
    relationship_types: tuple[str, ...] = ("contains", "has_component", "has_finding", "contains_secret")
    input_types: tuple[str, ...] = ("container_image", "repository", "file")
    execution_mode: str = "safe_active"

    def build_command(self, target: str = "", target_type: str = "image", **_) -> str:
        return (f"{shlex.quote(target_type)} {shlex.quote(target)} --format json "
                "--output /output/trivy_results.json --scanners vuln,misconfig,secret --no-progress")

    def param_spec(self):
        return [
            {"key": "target", "label": "Image / path / repository", "type": "text", "default": ""},
            {"key": "target_type", "label": "Scan type", "type": "combo", "default": "image", "options": ["image", "fs", "repo", "config"]},
        ]


@dataclass
class _CloudflareAudit(ToolConfig):
    key: str = "cloudflare_audit"
    display_name: str = "Cloudflare Inventory"
    image: str = "awe/cloudflare_audit"
    description: str = "Read-only Cloudflare zone, DNS, proxy, plan, and account inventory"
    category: str = "architecture"
    dockerfile: str = _DF + "Dockerfile.cloudflare_audit"
    output_types: tuple[str, ...] = ("cloudflare_zone", "dns_record", "cloud_resource", "misconfiguration")
    relationship_types: tuple[str, ...] = ("contains", "has_dns", "proxied_by", "has_finding")
    input_types: tuple[str, ...] = ("domain", "cloud_asset")
    execution_mode: str = "active"
    credential_fields: tuple[str, ...] = ("api_token",)

    def build_command(self, zone: str = "", **_) -> str:
        command = f"--zone {shlex.quote(zone)}" if zone else ""
        return f"{command} --output /output/cloudflare_results.json".strip()

    def build_environment(self, api_token: str = "", **_) -> dict[str, str]:
        return {"CLOUDFLARE_API_TOKEN": api_token} if api_token else {}

    def param_spec(self):
        return [
            {"key": "zone", "label": "Zone (optional)", "type": "text", "default": ""},
            {"key": "api_token", "label": "Cloudflare API token", "type": "text", "default": "secret"},
        ]


@dataclass
class _OidcProbe(ToolConfig):
    key: str = "oidc_probe"
    display_name: str = "OIDC Discovery Probe"
    image: str = "awe/oidc_probe"
    description: str = "Safe OpenID Connect issuer metadata and identity-provider discovery"
    category: str = "architecture"
    dockerfile: str = _DF + "Dockerfile.oidc_probe"
    output_types: tuple[str, ...] = ("identity_provider", "oidc_endpoint", "component")
    relationship_types: tuple[str, ...] = ("exposes", "uses_endpoint", "has_component")
    input_types: tuple[str, ...] = ("url", "identity_provider", "domain")
    execution_mode: str = "safe_active"

    def build_command(self, issuer: str = "", **_) -> str:
        return f"{shlex.quote(issuer)} --output /output/oidc_results.json"

    def param_spec(self):
        return [{"key": "issuer", "label": "OIDC issuer URL", "type": "text", "default": ""}]


# ── Email / person OSINT ──────────────────────────────────────────────────────

@dataclass
class _TheHarvester(ToolConfig):
    key: str = "theharvester"
    display_name: str = "theHarvester"
    image: str = "awe/theharvester"
    description: str = "Passive OSINT collection for emails, names, IPs, subdomains, and URLs"
    category: str = "osint"
    dockerfile: str = _DF + "Dockerfile.theharvester"
    output_types: tuple[str, ...] = ("email", "person", "ip", "subdomain", "url")
    relationship_types: tuple[str, ...] = ("has_email", "mentions", "discovers", "resolves_to")

    def build_command(self, domain: str = "", sources: str = "all", **_) -> str:
        return f"theHarvester -d '{domain}' -b '{sources}' -f /output/theharvester_results"

    def param_spec(self):
        return [
            {"key": "domain",  "label": "Target domain",       "type": "text", "default": ""},
            {"key": "sources", "label": "Data sources",        "type": "text", "default": "all"},
        ]


# ── Repository / file secrets ─────────────────────────────────────────────────

@dataclass
class _Gitleaks(ToolConfig):
    key: str = "gitleaks"
    display_name: str = "Gitleaks"
    image: str = "awe/gitleaks"
    description: str = "Detect exposed secrets in repositories, files, and commit history"
    category: str = "osint"
    dockerfile: str = _DF + "Dockerfile.gitleaks"
    output_types: tuple[str, ...] = ("secret", "repository")
    relationship_types: tuple[str, ...] = ("contains_secret", "found_in")

    def build_command(self, source: str = "/input", **_) -> str:
        return (
            f"gitleaks dir --source '{source}' --report-format json"
            f" --report-path /output/gitleaks_results.json --no-banner"
        )

    def param_spec(self):
        return [
            {"key": "source", "label": "Repository path (container path)", "type": "text", "default": "/input"},
        ]


# ── Technology fingerprinting ────────────────────────────────────────────────

@dataclass
class _Whatweb(ToolConfig):
    key: str = "whatweb"
    display_name: str = "WhatWeb"
    image: str = "awe/whatweb"
    description: str = "Web technology and version fingerprinting across CMS, frameworks, servers, and libraries"
    category: str = "http"
    dockerfile: str = _DF + "Dockerfile.whatweb"
    output_types: tuple[str, ...] = ("url", "technology")
    relationship_types: tuple[str, ...] = ("uses_technology", "fingerprints")

    def build_command(self, target: str = "", aggression: str = "1",
                      threads: str = "10", **_) -> str:
        return (
            f"whatweb --log-json=/output/whatweb_results.json --no-errors"
            f" --color=never --aggression={aggression} --max-threads={threads} '{target}'"
        )

    def param_spec(self):
        return [
            {"key": "target",     "label": "Target URL",  "type": "text",  "default": ""},
            {"key": "aggression", "label": "Aggression",  "type": "combo", "options": ["1", "3", "4"], "default": "1"},
            {"key": "threads",    "label": "Threads",     "type": "text",  "default": "10"},
        ]


# ── Cloud bucket exposure ─────────────────────────────────────────────────────

@dataclass
class _S3Scanner(ToolConfig):
    key: str = "s3scanner"
    display_name: str = "S3Scanner"
    image: str = "awe/s3scanner"
    description: str = "Check S3-compatible bucket permissions across AWS and other storage providers"
    category: str = "osint"
    dockerfile: str = _DF + "Dockerfile.s3scanner"
    output_types: tuple[str, ...] = ("cloud_bucket", "cloud_finding")
    relationship_types: tuple[str, ...] = ("has_cloud_asset", "has_cloud_finding")

    def build_command(self, bucket: str = "", provider: str = "aws",
                      threads: str = "4", enumerate_objects: bool = False,
                      input_file: str = "", **_) -> str:
        source = f"-bucket-file '{input_file}'" if input_file else f"-bucket '{bucket}'"
        enum_flag = " -enumerate" if enumerate_objects else ""
        return f"s3scanner {source} -provider {provider} -threads {threads} -json{enum_flag} > /output/s3scanner_results.jsonl"

    def param_spec(self):
        return [
            {"key": "bucket",            "label": "Bucket name",       "type": "text",  "default": ""},
            {"key": "provider",          "label": "Provider",           "type": "combo",
             "options": ["aws", "gcp", "digitalocean", "linode", "scaleway", "custom"], "default": "aws"},
            {"key": "threads",           "label": "Threads",            "type": "text",  "default": "4"},
            {"key": "enumerate_objects", "label": "Enumerate objects",   "type": "check", "default": False},
        ]


# ── JWT Analysis ─────────────────────────────────────────────────────────────

@dataclass
class _JwtTool(ToolConfig):
    key: str = "jwt_tool"
    display_name: str = "JWT Tool"
    image: str = "awe/jwt_tool"
    description: str = "JWT vulnerability scanner — algorithm confusion, alg:none, brute-force"
    category: str = "vuln"
    dockerfile: str = _DF + "Dockerfile.jwt_tool"

    def build_command(self, token: str = "", mode: str = "pb", **_) -> str:
        safe_token = token.strip().replace("'", "")
        return (
            f"python3 jwt_tool.py '{safe_token}' -M {mode} 2>&1"
            f" | tee /output/jwt_tool_output.txt"
        )

    def param_spec(self):
        return [
            {"key": "token", "label": "JWT Token",       "type": "text",  "default": ""},
            {"key": "mode",  "label": "Attack Mode (-M)", "type": "combo",
             "options": ["pb", "at", "as", "rs", "ki"], "default": "pb"},
        ]


# ── XSS / Reflection ─────────────────────────────────────────────────────────

@dataclass
class _Kxss(ToolConfig):
    key: str = "kxss"
    display_name: str = "kxss"
    image: str = "awe/kxss"
    description: str = "Probe URL parameters for reflection and which special characters survive unescaped"
    category: str = "xss"
    dockerfile: str = _DF + "Dockerfile.kxss"

    def build_command(self, input_file: str = "", **_) -> str:
        src = f"cat {input_file}" if input_file else "cat /input/urls.txt"
        return f"{src} | kxss | tee /output/kxss_results.txt"

    def param_spec(self):
        return [
            {"key": "input_file", "label": "URL list (container path)", "type": "text",
             "default": "/input/urls.txt"},
        ]


@dataclass
class _Gxss(ToolConfig):
    key: str = "gxss"
    display_name: str = "Gxss"
    image: str = "awe/gxss"
    description: str = "Concurrent GET parameter reflection checker — find which params echo input back"
    category: str = "xss"
    dockerfile: str = _DF + "Dockerfile.gxss"

    def build_command(self, input_file: str = "", concurrency: str = "30",
                      cookie: str = "", **_) -> str:
        src = input_file if input_file else "/input/urls.txt"
        cmd = f"gxss -i {src} -c {concurrency} | tee /output/gxss_results.txt"
        if cookie:
            cmd = f"gxss -i {src} -c {concurrency} -H 'Cookie: {cookie}' | tee /output/gxss_results.txt"
        return cmd

    def param_spec(self):
        return [
            {"key": "input_file",  "label": "URL list (container path)", "type": "text",
             "default": "/input/urls.txt"},
            {"key": "concurrency", "label": "Concurrency",               "type": "text",
             "default": "30"},
            {"key": "cookie",      "label": "Cookie header (optional)",  "type": "text",
             "default": ""},
        ]


@dataclass
class _Dalfox(ToolConfig):
    key: str = "dalfox"
    display_name: str = "Dalfox"
    image: str = "hahwul/dalfox:latest"
    description: str = "XSS scanner — detects reflection context, generates and verifies payloads"
    category: str = "xss"

    def build_command(self, url: str = "", mode: str = "url",
                      cookie: str = "", headers: str = "",
                      data: str = "", worker: str = "10",
                      timeout: str = "10", blind: str = "",
                      input_file: str = "", **_) -> str:
        if input_file:
            cmd = f"dalfox file {input_file} -o /output/dalfox_results.txt --format json -w {worker} --timeout {timeout}"
        elif mode == "pipe":
            cmd = f"dalfox pipe -o /output/dalfox_results.txt --format json -w {worker} --timeout {timeout}"
        else:
            cmd = f"dalfox url {url} -o /output/dalfox_results.txt --format json -w {worker} --timeout {timeout}"
        if cookie:
            cmd += f" --cookie '{cookie}'"
        if headers:
            for h in headers.split(";;"):
                cmd += f" --header '{h.strip()}'"
        if data:
            cmd += f" --data '{data}'"
        if blind:
            cmd += f" --blind {blind}"
        return cmd

    def param_spec(self):
        return [
            {"key": "url",     "label": "Target URL",              "type": "text",  "default": ""},
            {"key": "mode",    "label": "Mode",                    "type": "combo",
             "options": ["url", "pipe", "sxss"],                   "default": "url"},
            {"key": "worker",  "label": "Workers",                 "type": "text",  "default": "10"},
            {"key": "timeout", "label": "Timeout (s)",             "type": "text",  "default": "10"},
            {"key": "cookie",  "label": "Cookie",                  "type": "text",  "default": ""},
            {"key": "headers", "label": "Headers (;; separated)",  "type": "text",  "default": ""},
            {"key": "data",    "label": "POST body",               "type": "text",  "default": ""},
            {"key": "blind",   "label": "Blind XSS callback URL",  "type": "text",  "default": ""},
        ]


# ── GraphQL Analysis ─────────────────────────────────────────────────────────

@dataclass
class _GraphQLTools(ToolConfig):
    key: str = "graphql_tools"
    display_name: str = "GraphQL Tools"
    image: str = "awe/graphql_tools"
    description: str = "GraphQL engine fingerprinting (graphw00f) + hidden field discovery (clairvoyance)"
    category: str = "vuln"
    dockerfile: str = _DF + "Dockerfile.graphql_tools"

    def build_command(self, endpoint: str = "", **_) -> str:
        safe = endpoint.strip().replace("'", "").replace('"', "")
        return (
            f"graphw00f -d -t '{safe}' 2>&1 | tee /output/fingerprint.txt && "
            f"clairvoyance '{safe}' "
            f"-o /output/schema.json 2>&1 | tee -a /output/fingerprint.txt"
        )

    def param_spec(self):
        return [
            {"key": "endpoint", "label": "GraphQL Endpoint URL", "type": "text", "default": ""},
        ]


# ── Screenshot ────────────────────────────────────────────────────────────────

@dataclass
class _Gowitness(ToolConfig):
    key: str = "gowitness"
    display_name: str = "Gowitness"
    image: str = "awe/gowitness"
    description: str = "Screenshot live HTTP hosts — visual triage of large attack surfaces"
    category: str = "screenshot"
    dockerfile: str = _DF + "Dockerfile.gowitness"

    def get_volumes(self, output_dir: str, input_dir: str | None = None) -> dict:
        os.makedirs(output_dir, exist_ok=True)
        os.makedirs(os.path.join(output_dir, "screenshots"), exist_ok=True)
        vols = {output_dir: {"bind": "/output", "mode": "rw"}}
        if input_dir:
            vols[input_dir] = {"bind": "/input", "mode": "ro"}
        return vols

    def build_command(self, input_file: str = "", url: str = "",
                      timeout: str = "10", **_) -> str:
        src = f"-f {input_file}" if input_file else f"-f /dev/stdin"
        return (
            f"gowitness scan file {src}"
            f" -s /output/screenshots/ --write-jsonl"
            f" --timeout {timeout} --log-scan-errors"
        )

    def param_spec(self):
        return [
            {"key": "timeout", "label": "Per-URL timeout (s)", "type": "text", "default": "10"},
        ]


# ── Subdomain takeover ────────────────────────────────────────────────────────

@dataclass
class _Subzy(ToolConfig):
    key: str = "subzy"
    display_name: str = "Subzy"
    image: str = "awe/subzy"
    description: str = "Subdomain takeover checker — finds unclaimed cloud/SaaS resources"
    category: str = "vuln"
    dockerfile: str = _DF + "Dockerfile.subzy"

    def build_command(self, input_file: str = "", domain: str = "",
                      timeout: str = "10", concurrency: str = "10", **_) -> str:
        targets = f"--targets {input_file}" if input_file else f"--target {domain}"
        return (
            f"subzy run {targets} --timeout {timeout}"
            f" --concurrency {concurrency} --hide_fails"
            f" --output /output/subzy_results.json"
        )

    def param_spec(self):
        return [
            {"key": "timeout",     "label": "Timeout (s)",   "type": "text", "default": "10"},
            {"key": "concurrency", "label": "Concurrency",   "type": "text", "default": "10"},
        ]


# ── WAF detection ─────────────────────────────────────────────────────────────

@dataclass
class _Wafw00f(ToolConfig):
    key: str = "wafw00f"
    display_name: str = "wafw00f"
    image: str = "awe/wafw00f"
    description: str = "WAF fingerprinting — detect and identify web application firewalls"
    category: str = "vuln"
    dockerfile: str = _DF + "Dockerfile.wafw00f"

    def build_command(self, input_file: str = "", url: str = "", **_) -> str:
        src = f"-i {input_file}" if input_file else url
        return f"wafw00f {src} -f json -o /output/wafw00f_results.json"

    def param_spec(self):
        return [
            {"key": "url", "label": "Target URL (single)", "type": "text", "default": ""},
        ]


# ── SQL injection ─────────────────────────────────────────────────────────────

@dataclass
class _Sqlmap(ToolConfig):
    key: str = "sqlmap"
    display_name: str = "sqlmap"
    image: str = "awe/sqlmap"
    description: str = "Automated SQL injection detection and exploitation"
    category: str = "vuln"
    dockerfile: str = _DF + "Dockerfile.sqlmap"

    def build_command(self, input_file: str = "", url: str = "",
                      level: str = "1", risk: str = "1",
                      threads: str = "5", dbms: str = "", **_) -> str:
        src = f"-m {input_file}" if input_file else f"-u {url}"
        cmd = (
            f"python3 sqlmap.py {src} --batch --level {level} --risk {risk}"
            f" -t {threads} --output-dir /output/"
        )
        if dbms:
            cmd += f" --dbms {dbms}"
        return cmd

    def param_spec(self):
        return [
            {"key": "url",     "label": "Target URL",     "type": "text",  "default": ""},
            {"key": "level",   "label": "Level (1-5)",    "type": "combo",
             "options": ["1", "2", "3", "4", "5"],        "default": "1"},
            {"key": "risk",    "label": "Risk (1-3)",     "type": "combo",
             "options": ["1", "2", "3"],                  "default": "1"},
            {"key": "threads", "label": "Threads",        "type": "text",  "default": "5"},
            {"key": "dbms",    "label": "DBMS (optional)","type": "text",  "default": ""},
        ]


# ── API discovery ─────────────────────────────────────────────────────────────

@dataclass
class _Kiterunner(ToolConfig):
    key: str = "kiterunner"
    display_name: str = "Kiterunner"
    image: str = "awe/kiterunner"
    description: str = "API route discovery using assetnote wordlists — finds hidden REST/GraphQL endpoints"
    category: str = "crawl"
    dockerfile: str = _DF + "Dockerfile.kiterunner"

    def build_command(self, input_file: str = "", url: str = "",
                      wordlist: str = "apiroutes-210228:20000",
                      workers: str = "20", fail_codes: str = "404", **_) -> str:
        target = input_file if input_file else url
        return (
            f"kr scan {target} -A={wordlist}"
            f" -x {workers} --fail-status-codes {fail_codes}"
            f" -o /output/kiterunner_results.txt"
        )

    def param_spec(self):
        return [
            {"key": "url",        "label": "Target URL",             "type": "text",
             "default": ""},
            {"key": "wordlist",   "label": "Assetnote wordlist",     "type": "text",
             "default": "apiroutes-210228:20000"},
            {"key": "workers",    "label": "Workers",                "type": "text",
             "default": "20"},
            {"key": "fail_codes", "label": "Fail status codes",      "type": "text",
             "default": "404"},
        ]


# ── CORS misconfiguration ─────────────────────────────────────────────────────

@dataclass
class _Corsy(ToolConfig):
    key: str = "corsy"
    display_name: str = "Corsy"
    image: str = "awe/corsy"
    description: str = "CORS misconfiguration scanner — wildcard origins, credential leakage"
    category: str = "vuln"
    dockerfile: str = _DF + "Dockerfile.corsy"

    def build_command(self, input_file: str = "", url: str = "",
                      threads: str = "10", headers: str = "", **_) -> str:
        src = f"-i {input_file}" if input_file else f"-u {url}"
        cmd = f"python3 corsy.py {src} -t {threads} -o /output/corsy_results.json"
        if headers:
            cmd += f" --headers '{headers}'"
        return cmd

    def param_spec(self):
        return [
            {"key": "url",     "label": "Target URL (single)", "type": "text",  "default": ""},
            {"key": "threads", "label": "Threads",             "type": "text",  "default": "10"},
            {"key": "headers", "label": "Extra headers",       "type": "text",  "default": ""},
        ]


# ── Secret / credential exposure ──────────────────────────────────────────────

@dataclass
class _SecretFinder(ToolConfig):
    key: str = "secretfinder"
    display_name: str = "SecretFinder"
    image: str = "awe/secretfinder"
    description: str = "Scan JavaScript files for API keys, tokens and credentials"
    category: str = "vuln"
    dockerfile: str = _DF + "Dockerfile.secretfinder"

    def build_command(self, url: str = "", cookies: str = "", **_) -> str:
        cmd = f"python3 SecretFinder.py -i {url} -e -o cli | tee /output/secretfinder_results.txt"
        if cookies:
            cmd = f"python3 SecretFinder.py -i {url} -e -c '{cookies}' -o cli | tee /output/secretfinder_results.txt"
        return cmd

    def param_spec(self):
        return [
            {"key": "url",     "label": "Target URL",         "type": "text", "default": ""},
            {"key": "cookies", "label": "Cookies (optional)", "type": "text", "default": ""},
        ]


# ── Registry ──────────────────────────────────────────────────────────────────

TOOL_REGISTRY: dict[str, ToolConfig] = {
    t.key: t for t in [
        # subdomain enumeration
        _Amass(),
        _Assetfinder(),
        _Subfinder(),
        _Sublist3r(),
        _SubDomainizer(),
        _ShuffleDNS(),
        _CTL(),
        # dns
        _DNSx(),
        _Metabigor(),
        # port scanning
        _Nmap(),
        _Naabu(),
        # http probing
        _Httpx(),
        # crawling & url discovery
        _GoSpider(),
        _Katana(),
        _WaybackURLs(),
        _GAU(),
        _LinkFinder(),
        _XnLinkFinder(),
        # fuzzing
        _FFuf(),
        _CeWL(),
        # parameter discovery
        _Arjun(),
        _Parameth(),
        _X8(),
        # xss / reflection
        _Kxss(),
        _Gxss(),
        _Dalfox(),
        # sqli
        _Sqlmap(),
        # screenshot
        _Gowitness(),
        # takeover / waf
        _Subzy(),
        _Wafw00f(),
        # api discovery
        _Kiterunner(),
        # cors
        _Corsy(),
        # secrets
        _SecretFinder(),
        # vulnerability scanning
        _Nuclei(),
        _JwtTool(),
        _GraphQLTools(),
        # osint
        _GithubRecon(),
        _CloudEnum(),
        _Asnmap(),
        _Tlsx(),
        _TheHarvester(),
        _Gitleaks(),
        _S3Scanner(),
        # technology fingerprinting
        _Whatweb(),
        # TLS assessment
        _Testssl(),
        # architecture-specific platforms and posture
        _Wpscan(),
        _Droopescan(),
        _Prowler(),
        _Kubescape(),
        _Trivy(),
        _CloudflareAudit(),
        _OidcProbe(),
    ]
}

# Tools grouped by category (used by the Docker Manager UI)
TOOL_CATEGORIES: dict[str, list[str]] = {}
for _k, _v in TOOL_REGISTRY.items():
    TOOL_CATEGORIES.setdefault(_v.category, []).append(_k)
