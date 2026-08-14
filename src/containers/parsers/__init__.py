"""
Per-tool output file parsers.

Each parser function:
  parse_<toolname>(output_dir: str) -> list[BaseResult]

Returns an empty list (never raises) if the file is missing or malformed.
All files are expected under output_dir/ with the filenames the Docker tool
configs write to (e.g. amass → /.config/amass/amass_.txt).

Built-in tools each get their own module in this package (one file per tool
key). Custom, user-registered tools have their parser dynamically loaded
elsewhere (see containers.custom_tools) and merged into PARSERS in place.
"""
from containers.parsers.amass import parse_amass
from containers.parsers.assetfinder import parse_assetfinder
from containers.parsers.subfinder import parse_subfinder
from containers.parsers.sublist3r import parse_sublist3r
from containers.parsers.subdomainizer import parse_subdomainizer
from containers.parsers.shuffledns import parse_shuffledns
from containers.parsers.ctl import parse_ctl
from containers.parsers.dnsx import parse_dnsx
from containers.parsers.metabigor import parse_metabigor
from containers.parsers.nmap import parse_nmap
from containers.parsers.naabu import parse_naabu
from containers.parsers.httpx import parse_httpx
from containers.parsers.gospider import parse_gospider
from containers.parsers.katana import parse_katana
from containers.parsers.waybackurls import parse_waybackurls
from containers.parsers.gau import parse_gau
from containers.parsers.linkfinder import parse_linkfinder
from containers.parsers.xnlinkfinder import parse_xnlinkfinder
from containers.parsers.ffuf import parse_ffuf
from containers.parsers.cewl import parse_cewl
from containers.parsers.arjun import parse_arjun
from containers.parsers.parameth import parse_parameth
from containers.parsers.x8 import parse_x8
from containers.parsers.nuclei import parse_nuclei
from containers.parsers.jwt_tool import parse_jwt_tool
from containers.parsers.graphql_tools import parse_graphql_tools
from containers.parsers.kxss import parse_kxss
from containers.parsers.gxss import parse_gxss
from containers.parsers.dalfox import parse_dalfox
from containers.parsers.sqlmap import parse_sqlmap
from containers.parsers.gowitness import parse_gowitness
from containers.parsers.subzy import parse_subzy
from containers.parsers.wafw00f import parse_wafw00f
from containers.parsers.corsy import parse_corsy
from containers.parsers.secretfinder import parse_secretfinder
from containers.parsers.kiterunner import parse_kiterunner
from containers.parsers.github_recon import parse_github_recon
from containers.parsers.cloud_enum import parse_cloud_enum
from containers.parsers.asnmap import parse_asnmap
from containers.parsers.tlsx import parse_tlsx
from containers.parsers.testssl import parse_testssl
from containers.parsers.theharvester import parse_theharvester
from containers.parsers.gitleaks import parse_gitleaks
from containers.parsers.whatweb import parse_whatweb
from containers.parsers.s3scanner import parse_s3scanner
from containers.parsers.architecture import (
    parse_wpscan, parse_droopescan, parse_prowler, parse_kubescape,
    parse_trivy, parse_cloudflare_audit, parse_oidc_probe,
)

# ── Master parser registry ────────────────────────────────────────────────────
# Mutable on purpose — containers.custom_tools adds/removes entries in place
# as the user registers/removes custom tools at runtime.
PARSERS: dict[str, callable] = {
    # subdomain
    "amass":         parse_amass,
    "assetfinder":   parse_assetfinder,
    "subfinder":     parse_subfinder,
    "sublist3r":     parse_sublist3r,
    "subdomainizer": parse_subdomainizer,
    "shuffledns":    parse_shuffledns,
    "ctl":           parse_ctl,
    # dns
    "dnsx":          parse_dnsx,
    "metabigor":     parse_metabigor,
    # portscan
    "nmap":          parse_nmap,
    "naabu":         parse_naabu,
    # http
    "httpx":         parse_httpx,
    # crawl
    "gospider":      parse_gospider,
    "katana":        parse_katana,
    "waybackurls":   parse_waybackurls,
    "gau":           parse_gau,
    "linkfinder":    parse_linkfinder,
    "xnlinkfinder":  parse_xnlinkfinder,
    # fuzz
    "ffuf":          parse_ffuf,
    "cewl":          parse_cewl,
    # params
    "arjun":         parse_arjun,
    "parameth":      parse_parameth,
    "x8":            parse_x8,
    # vuln
    "nuclei":        parse_nuclei,
    "jwt_tool":      parse_jwt_tool,
    "graphql_tools": parse_graphql_tools,
    # xss / reflection
    "kxss":          parse_kxss,
    "gxss":          parse_gxss,
    "dalfox":        parse_dalfox,
    # sqli
    "sqlmap":        parse_sqlmap,
    # screenshot
    "gowitness":     parse_gowitness,
    # takeover
    "subzy":         parse_subzy,
    # waf
    "wafw00f":       parse_wafw00f,
    # cors
    "corsy":         parse_corsy,
    # secrets
    "secretfinder":  parse_secretfinder,
    # api
    "kiterunner":    parse_kiterunner,
    # osint
    "github_recon":  parse_github_recon,
    "cloud_enum":    parse_cloud_enum,
    "asnmap":        parse_asnmap,
    "tlsx":          parse_tlsx,
    "testssl":       parse_testssl,
    "theharvester":  parse_theharvester,
    "gitleaks":      parse_gitleaks,
    "whatweb":       parse_whatweb,
    "s3scanner":     parse_s3scanner,
    "wpscan":        parse_wpscan,
    "droopescan":    parse_droopescan,
    "prowler":       parse_prowler,
    "kubescape":     parse_kubescape,
    "trivy":         parse_trivy,
    "cloudflare_audit": parse_cloudflare_audit,
    "oidc_probe":    parse_oidc_probe,
}
