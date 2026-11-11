"""Disclosure/posture checks with negative controls and body-free evidence."""
import hashlib
import json
import re
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit, urlunsplit
from .transport import origin, safe_url


class Page(HTMLParser):
    def __init__(self, text):
        super().__init__(convert_charrefs=True)
        self.scripts, self.resources, self.forms = [], [], []
        self.current = None
        self.feed(text)

    def handle_starttag(self, tag, attributes):
        attrs = dict(attributes)
        if tag == "script" and attrs.get("src"):
            self.scripts.append(attrs["src"])
        if tag in {"script", "iframe", "img", "source", "audio", "video", "embed"} and attrs.get("src"):
            self.resources.append(attrs["src"])
        if tag == "link" and "stylesheet" in str(attrs.get("rel") or "").lower() and attrs.get("href"):
            self.resources.append(attrs["href"])
        if tag == "form":
            self.current = {"method": str(attrs.get("method") or "GET").upper(), "fields": []}
            self.forms.append(self.current)
        if tag == "input" and self.current is not None:
            self.current["fields"].append(attrs.get("name") or "")

    def handle_endtag(self, tag):
        if tag == "form":
            self.current = None


def directory_listing(scan):
    base = scan.baseline
    if base.status == 200 and re.search(r"<title>\s*(?:Index of|Directory listing for)\s+", base.text, re.I) and re.search(r"(?:Parent Directory|href=[\"'](?:\.\./|\?C=))", base.text, re.I):
        scan.report.finding("directory-index", "A directory listing is exposed", [base], severity="low", verification="verified_behavior")


def debug_errors(scan):
    base = scan.baseline
    signatures = {
        "python-traceback": r'Traceback \(most recent call last\):[\s\S]{0,500}File ["\']',
        "java-stack": r"(?:Exception|Error):[^\n]{1,150}\n\s+at [\w.$]+\([^\n]+\.java:\d+\)",
        "php-stack": r"(?:Fatal error|Uncaught [\w\\]+Exception)[\s\S]{0,300} on line \d+",
        "sqlstate-error": r"SQLSTATE\[[A-Z0-9]{5}\]",
        "dotnet-stack": r"System\.[A-Za-z]+Exception:[\s\S]{0,300}\bat [\w.]+\(",
    }
    matched = [name for name, pattern in signatures.items() if re.search(pattern, base.text)]
    if matched:
        scan.report.finding("detailed-errors", "Detailed application error information is exposed", [base], severity="low", facts={"signature_families": matched})


def git_exposure(scan):
    parsed = urlsplit(scan.url)
    root = urlunsplit((parsed.scheme, parsed.netloc, "/", "", ""))
    control = scan.get(urljoin(root, scan.token + "-not-found"), method="GET", body=b"")
    head = scan.get(urljoin(root, ".git/HEAD"), method="GET", body=b"")
    valid = re.fullmatch(r"(?:ref: refs/(?:heads|tags)/[^\s]+|[0-9a-f]{40,64})\s*", head.text)
    if head.status == 200 and valid and head.text != control.text:
        scan.report.finding("git-head", "Git HEAD metadata is publicly retrievable", [control, head], severity="medium", verification="verified_behavior")


def backup_exposure(scan):
    parsed = urlsplit(scan.url)
    path = parsed.path or "/index"
    target = lambda suffix: urlunsplit((parsed.scheme, parsed.netloc, path + suffix, "", ""))
    control = scan.get(target("." + scan.token), method="GET", body=b"")
    signature = re.compile(r"<\?php\s|-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|\b(?:DATABASE_URL|DB_PASSWORD|SECRET_KEY)\s*[:=]", re.I)
    for suffix in (".bak", ".old", "~"):
        response = scan.get(target(suffix), method="GET", body=b"")
        if response.status == 200 and signature.search(response.text) and not signature.search(control.text) and response.text != control.text:
            scan.report.finding("backup-" + suffix, "A backup filename exposes source or secret-bearing configuration", [control, response], severity="high", facts={"suffix": suffix, "content_saved": False})


def source_maps(scan):
    base = scan.baseline
    candidates = [scan.url] if urlsplit(scan.url).path.endswith(".map") else []
    scripts = [scan.url] if urlsplit(scan.url).path.endswith(".js") else [urljoin(scan.url, value) for value in Page(base.text).scripts[:2]]
    for script in scripts:
        try:
            same_origin = origin(script) == origin(scan.url)
        except ValueError:
            continue
        if not same_origin:
            continue
        parsed = urlsplit(script)
        candidates.append(urlunsplit((parsed.scheme, parsed.netloc, parsed.path + ".map", "", "")))
    for target in dict.fromkeys(candidates):
        response = base if target == scan.url else scan.get(target, method="GET", body=b"")
        try:
            data = json.loads(response.text)
        except ValueError:
            continue
        contents = data.get("sourcesContent") if isinstance(data, dict) else None
        if response.status == 200 and isinstance(contents, list) and any(isinstance(value, str) and value.strip() for value in contents):
            scan.report.finding("published-sources", "A source map includes original source content", [response], severity="low", facts={"source_count": len(contents), "source_content_saved": False})


def csrf_forms(scan):
    base = scan.baseline
    forms = Page(base.text).forms
    suspicious = [index for index, form in enumerate(forms, 1) if form["method"] == "POST" and not any(re.search(r"csrf|xsrf|authenticity|nonce", name, re.I) for name in form["fields"])]
    if suspicious:
        scan.report.finding("form-token-review", "POST forms lack recognizable anti-CSRF fields", [base], severity="low", facts={"form_numbers": suspicious}, detail="Review SameSite, Origin validation, and actual state-changing behavior before confirming CSRF.")


def mixed_content(scan):
    base = scan.baseline
    if urlsplit(scan.url).scheme != "https":
        scan.report.observe("Mixed-content assessment requires an HTTPS page.")
        return
    resources = [value for value in Page(base.text).resources if urlsplit(urljoin(scan.url, value)).scheme == "http"]
    if resources:
        scan.report.finding("http-subresources", "An HTTPS page references HTTP subresources", [base], severity="low", facts={"resource_count": len(resources), "resource_url_hashes": [hashlib.sha256(value.encode()).hexdigest() for value in resources]})


CHECKS = {function.__name__: function for function in (directory_listing, debug_errors, git_exposure, backup_exposure, source_maps, csrf_forms, mixed_content)}
