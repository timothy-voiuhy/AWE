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
                      concurrent: str = "10", timeout: str = "300", **_) -> str:
        return (
            f"gospider -s {url} -c {concurrent} -d {depth} -t 3"
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
                      concurrency: str = "20", **_) -> str:
        return (
            f"katana -u {url} -d {depth} -jc -j -silent"
            f" -c {concurrency} -p 20 -retry 3 -rd 1 -rl 10"
            f" -timeout 120 -o /output/katana_results.txt"
        )

    def param_spec(self):
        return [
            {"key": "url",         "label": "Target URL",  "type": "text", "default": ""},
            {"key": "depth",       "label": "Depth",       "type": "text", "default": "3"},
            {"key": "concurrency", "label": "Concurrency", "type": "text", "default": "20"},
        ]


@dataclass
class _WaybackURLs(ToolConfig):
    key: str = "waybackurls"
    display_name: str = "WaybackURLs"
    image: str = "awe/waybackurls"
    description: str = "Fetch URLs from Wayback Machine and Common Crawl archives"
    category: str = "crawl"
    dockerfile: str = _DF + "Dockerfile.waybackurls"

    def build_command(self, domain: str = "", dates: bool = False, **_) -> str:
        flags = "--dates" if dates else ""
        return f"waybackurls {flags} {domain} | tee /output/waybackurls_results.txt"

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
                      threads: str = "1", **_) -> str:
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
                      threads: str = "5", delay: str = "0", **_) -> str:
        return (
            f"arjun -u {url} -m {method} -t {threads}"
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
                      workers: str = "10", body_type: str = "urlencode", **_) -> str:
        return (
            f"x8 -u {url} -o /output/x8_results.txt"
            f" --workers {workers} --method {method}"
            f" --body-type {body_type}"
            f" --learn-requests-count 9 --verify-requests-count 3 --value-size 5"
        )

    def param_spec(self):
        return [
            {"key": "url",       "label": "Target URL", "type": "text",  "default": ""},
            {"key": "method",    "label": "Method",     "type": "combo",
             "options": ["GET", "POST"],               "default": "GET"},
            {"key": "workers",   "label": "Workers",    "type": "text",  "default": "10"},
            {"key": "body_type", "label": "Body type",  "type": "combo",
             "options": ["urlencode", "json", "multipart"], "default": "urlencode"},
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
            f"python3 /app/clairvoyance/clairvoyance/main.py '{safe}' "
            f"-o /output/schema.json 2>&1 | tee -a /output/fingerprint.txt"
        )

    def param_spec(self):
        return [
            {"key": "endpoint", "label": "GraphQL Endpoint URL", "type": "text", "default": ""},
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
        # vulnerability scanning
        _Nuclei(),
        _JwtTool(),
        _GraphQLTools(),
        # osint
        _GithubRecon(),
        _CloudEnum(),
    ]
}

# Tools grouped by category (used by the Docker Manager UI)
TOOL_CATEGORIES: dict[str, list[str]] = {}
for _k, _v in TOOL_REGISTRY.items():
    TOOL_CATEGORIES.setdefault(_v.category, []).append(_k)
