"""HTTP/browser policy checks and bounded GraphQL probes."""
import json
from http.cookies import SimpleCookie
from urllib.parse import urlsplit


def security_headers(scan):
    base = scan.baseline
    html = "text/html" in base.header("Content-Type").lower()
    required = ["X-Content-Type-Options", "Referrer-Policy"]
    if html:
        required += ["Content-Security-Policy"]
        if not base.header("X-Frame-Options") and "frame-ancestors" not in base.header("Content-Security-Policy").lower():
            required.append("X-Frame-Options")
    if urlsplit(scan.url).scheme == "https":
        required.append("Strict-Transport-Security")
    missing = [name for name in required if not base.header(name)]
    if missing and 200 <= base.status < 300:
        scan.report.finding("missing-headers", "Browser defense headers need review", [base], severity="low", facts={"missing": missing})


def session_cookies(scan):
    base = scan.baseline
    names = {name.strip().casefold() for name in str(scan.config.get("cookie_names", "session,sessionid,sid,PHPSESSID,JSESSIONID")).split(",") if name.strip()}
    seen = 0
    for raw in base.values("Set-Cookie"):
        cookie = SimpleCookie()
        cookie.load(raw)
        for name, morsel in cookie.items():
            if name.casefold() not in names:
                continue
            seen += 1
            missing = [flag for flag in ("secure", "httponly", "samesite") if not morsel[flag]]
            if morsel['samesite'] and morsel['samesite'].lower() not in {'lax', 'strict', 'none'}:
                missing.append('samesite_invalid')
            if missing:
                scan.report.finding(f"cookie-{name}", "Session cookie attributes need review", [base], severity="medium", facts={"cookie_name": name, "missing": missing})
    if not seen:
        scan.report.observe("No configured session cookie was set; existing-cookie policy cannot be inferred.")


def cors(scan):
    base = scan.baseline
    supplied = "https://" + scan.token + ".invalid"
    headers = {key: value for key, value in scan.primary.get("headers", {}).items() if key.lower() != "origin"}
    for value in (supplied, "null"):
        response = scan.get(headers={**headers, "Origin": value})
        allowed = response.values("Access-Control-Allow-Origin")
        credentialed = response.header("Access-Control-Allow-Credentials").strip().lower() == "true"
        if allowed == [value] and credentialed and 200 <= response.status < 300:
            scan.report.finding("credentialed-" + ("null" if value == "null" else "origin"), "Credentialed CORS trusts an untrusted origin", [base, response], verification="verified_behavior", facts={"origin_kind": "null" if value == "null" else "random_external", "credentials_allowed": True})
        elif allowed == ["*"] and credentialed:
            scan.report.observe("Wildcard ACAO with credentials is blocked by browsers; not treated as a credentialed-read finding.")


def open_redirect(scan):
    base = scan.baseline
    hostname = scan.token + ".invalid"
    for value in (f"https://{hostname}/canary", f"//{hostname}/canary"):
        response = scan.get(scan.parameter(value))
        location = response.header("Location")
        if response.status in {301, 302, 303, 307, 308} and urlsplit(location).hostname == hostname:
            scan.report.finding("external-redirect", "A parameter controls an external redirect", [base, response], verification="verified_behavior", facts={"destination": "research_canary.invalid", "followed": False})
            return


def crlf(scan):
    base = scan.baseline
    response = scan.get(scan.parameter(f"{scan.token}\r\nX-AWE-Canary: {scan.token}"))
    if response.values("X-AWE-Canary") == [scan.token]:
        scan.report.finding("header-injection", "Input introduced a response header", [base, response], verification="verified_behavior", facts={"injected_header": "X-AWE-Canary"})


def host_header(scan):
    base = scan.baseline
    hostname = scan.token + ".invalid"
    response = scan.get(host_override=hostname)
    if response.status in {301, 302, 303, 307, 308} and urlsplit(response.header("Location")).hostname == hostname:
        scan.report.finding("host-redirect", "Host header controls a redirect origin", [base, response], verification="verified_behavior", facts={"followed": False})


def http_methods(scan):
    response = scan.get(method="OPTIONS", body=b"")
    advertised = [value.strip().upper() for value in response.header("Allow").split(",") if value.strip()]
    scan.report.observe("Advertised methods are not proof of authorized operation support.", methods=advertised)
    trace = scan.get(method="TRACE", headers={**scan.anonymous_headers(), "X-AWE-Canary": scan.token}, body=b"")
    if trace.status == 200 and scan.token in trace.text:
        scan.report.finding("trace-echo", "TRACE echoes a request canary", [response, trace], severity="low", verification="verified_behavior")


def graphql_introspection(scan):
    response = scan.get(method="POST", body={"query": "query AWEReview { __schema { queryType { name } mutationType { name } } }"}, safe_post=True)
    try:
        data = json.loads(response.text)
    except ValueError:
        return
    schema = (data.get("data") or {}).get("__schema") if isinstance(data, dict) else None
    if response.status == 200 and isinstance(schema, dict) and isinstance(schema.get("queryType"), dict):
        scan.report.finding("schema-introspection", "GraphQL schema introspection is available", [response], severity="info", facts={"schema_returned": True})


def graphql_batching(scan):
    response = scan.get(method="POST", body=[{"query": "query AWEOne { __typename }"}, {"query": "query AWETwo { __typename }"}], safe_post=True)
    try:
        data = json.loads(response.text)
    except ValueError:
        return
    if response.status == 200 and isinstance(data, list) and len(data) == 2 and all(isinstance(item, dict) and (item.get("data") or {}).get("__typename") for item in data):
        scan.report.observe("Two read-only GraphQL queries were accepted as one batch. Rate-limit bypass was not established.", evidence_id=response.evidence_id)


CHECKS = {function.__name__: function for function in (security_headers, session_cookies, cors, open_redirect, crlf, host_header, http_methods, graphql_introspection, graphql_batching)}
