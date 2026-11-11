"""Canary-based checks: no command execution or default system-file retrieval."""
import json
import re
import secrets
import time
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
from .transport import ValidationError, origin


def ssti(scan):
    base = scan.baseline
    for template in ("{{%d*%d}}", "${%d*%d}"):
        responses = []
        for _ in range(2):
            left, right = secrets.randbelow(80) + 21, secrets.randbelow(80) + 21
            prefix = scan.token + secrets.token_hex(3)
            payload = prefix + (template % (left, right)) + prefix
            expected = prefix + str(left * right) + prefix
            response = scan.get(scan.parameter(payload))
            if not 200 <= response.status < 300 or expected not in response.text or payload in response.text or expected in base.text:
                break
            responses.append(response)
        if len(responses) == 2:
            scan.report.finding("arithmetic-evaluation", "Two random arithmetic expressions were evaluated server-side", [base, *responses], severity="high", verification="verified_behavior", facts={"evaluation_count": 2, "command_execution_tested": False})
            return


def canary_traversal(scan):
    marker = scan.marker()
    filename = scan.config.get("canary_file", "")
    if not isinstance(filename, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,79}", filename):
        raise ValidationError("Provide the filename of a researcher-controlled canary")
    base = scan.baseline
    control = scan.get(scan.parameter(scan.token + ".missing"))
    if marker in base.text or marker in control.text:
        raise ValidationError("The private canary marker is already in a control response")
    for depth in (1, 2):
        response = scan.get(scan.parameter("../" * depth + filename))
        if 200 <= response.status < 300 and marker in response.text:
            scan.report.finding("canary-traversal", "A traversal path returned the researcher's canary marker", [base, control, response], severity="high", verification="verified_behavior", facts={"depth": depth, "marker_sha256": scan.report.marker(marker)})
            return


def callback_check(scan, xml=False):
    context = scan.config.get("callback_context", "{}")
    context = json.loads(context or "{}") if isinstance(context, str) else context
    if not isinstance(context, dict) or not context.get("callback_url") or not context.get("monitor_url"):
        raise ValidationError("Provide callback_url and independent monitor_url in callback_context")
    origin(context["callback_url"]); origin(context["monitor_url"])
    poll_delay = float(context.get('poll_delay', 1))
    if not 0 <= poll_delay <= 5:
        raise ValidationError('Callback poll_delay must be between zero and five seconds')
    def keyed(url):
        parts = urlsplit(url)
        query = [(key, value) for key, value in parse_qsl(parts.query, keep_blank_values=True) if key != "awe_probe"]
        return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode([*query, ("awe_probe", scan.token)]), ""))
    callback, monitor = keyed(context["callback_url"]), keyed(context["monitor_url"])
    def observe():
        return scan.transport.request(monitor, context={}, headers=context.get("monitor_headers", {}), external=True)
    before = observe()
    if not 200 <= before.status < 300 or scan.token in before.text:
        raise ValidationError("Callback monitor must not reflect or already contain the fresh token")
    if xml:
        callback = callback.replace('"', '%22').replace("'", '%27')
        body = f'<?xml version="1.0"?><!DOCTYPE root [<!ENTITY awe SYSTEM "{callback}">]><root>&awe;</root>'
        target = scan.get(method="POST", headers={**scan.primary.get("headers", {}), "Content-Type": "application/xml"}, body=body)
    else:
        target = scan.get(scan.parameter(callback))
    monitors = []
    for _ in range(3):
        time.sleep(poll_delay)
        after = observe()
        monitors.append(after)
        if 200 <= after.status < 300 and scan.token in after.text:
            scan.report.finding("xxe-callback" if xml else "ssrf-callback", "The independent monitor recorded the fresh outbound canary", [before, target, *monitors], severity="high", verification="verified_behavior", facts={"token_sha256": scan.report.marker(scan.token), "callback_count_observed": True})
            return
    scan.report.observe("No independently verified callback was observed within the bounded polling window. Delayed callbacks remain inconclusive.")
    scan.report.errors.append({"type": "CallbackNotObserved", "message": "No callback confirmation within three polls; not a clean bill of health."})


CHECKS = {"ssti": ssti, "canary_traversal": canary_traversal, "ssrf_callback": callback_check, "xxe_callback": lambda scan: callback_check(scan, xml=True)}
