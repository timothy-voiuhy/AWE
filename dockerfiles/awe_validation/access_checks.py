"""Differential authorization, logout, JWT and explicit workflow controls."""
import base64
import json
from .transport import ValidationError


def authorization(scan, cache=False):
    marker, base, control = scan.private_controls()
    primary = scan.primary.get("headers", {})
    peer = scan.peer.get("headers", {})
    if not primary or not peer or {key.lower(): value for key, value in primary.items()} == {key.lower(): value for key, value in peer.items()}:
        raise ValidationError("Provide distinct credential contexts for the two identities")
    # The peer is replayed against the SAME object, not a second object URL.
    response = scan.get(context={**scan.peer, "url": scan.url})
    if 200 <= response.status < 300 and marker in response.text:
        scan.report.finding("private-content-boundary", "A second identity received the owner's private marker", [base, control, response], severity="high", verification="verified_behavior" if not cache else "candidate", facts={"private_marker_sha256": scan.report.marker(marker)}, detail="Identity ownership/roles are researcher-supplied. Cache causation is not established." if cache else "Private-marker exposure is verified; assess the intended object/role/tenant policy.")


def anonymous_access(scan):
    marker = scan.marker()
    base = scan.baseline
    primary = scan.primary.get("headers", {})
    if not primary or not 200 <= base.status < 300 or marker not in base.text:
        raise ValidationError("Provide a credentialed baseline containing the private marker")
    headers = scan.anonymous_headers()
    if {key.lower(): value for key, value in primary.items()} == {key.lower(): value for key, value in headers.items()}:
        raise ValidationError("No removable credential headers were supplied")
    response = scan.get(headers=headers)
    # An explicit negative URL is required to distinguish exposed private
    # content from public/login/fallback pages that contain the same marker.
    path = scan.primary.get("negative_control_url")
    if not path:
        raise ValidationError("Provide negative_control_url for anonymous-access verification")
    control = scan.get(path, headers=headers, method="GET", body=b"")
    if marker in control.text:
        raise ValidationError("The negative control contains the private marker")
    if 200 <= response.status < 300 and marker in response.text:
        scan.report.finding("anonymous-private-content", "Anonymous access returns the private response marker", [base, response, control], severity="high", verification="verified_behavior", facts={"private_marker_sha256": scan.report.marker(marker)})


def logout_replay(scan):
    marker, base, control = scan.private_controls()
    logout = scan.primary.get("logout")
    if not isinstance(logout, dict) or not logout.get("url"):
        raise ValidationError("Provide an explicit logout request in request_context.logout")
    response = scan.get(logout["url"], context={"headers": scan.primary.get("headers", {}), **logout})
    if not 200 <= response.status < 400:
        raise ValidationError("Logout did not complete successfully")
    replay = scan.get()
    if 200 <= replay.status < 300 and marker in replay.text:
        scan.report.finding("logout-replay", "The original credential still returns private content after logout", [base, control, response, replay], severity="medium", facts={"private_marker_sha256": scan.report.marker(marker)}, detail="Review the expected logout/revocation policy; stateless-token logout semantics may differ.")


def jwt_check(scan, unsigned=False):
    marker, base, control = scan.private_controls()
    headers = scan.primary.get("headers", {})
    bearer = next((value for key, value in headers.items() if key.lower() == "authorization"), "")
    if not isinstance(bearer, str) or not bearer.lower().startswith("bearer "):
        raise ValidationError("Provide a bearer JWT in the primary request context")
    token = bearer[7:].strip()
    parts = token.split(".")
    if len(parts) != 3 or len(token) > 16384:
        raise ValidationError("Expected a compact three-part JWT")
    decode = lambda value: json.loads(base64.urlsafe_b64decode(value + "=" * (-len(value) % 4)))
    encode = lambda value: base64.urlsafe_b64encode(json.dumps(value, separators=(",", ":")).encode()).decode().rstrip("=")
    header, payload = decode(parts[0]), decode(parts[1])
    if not isinstance(header, dict) or not isinstance(payload, dict) or not parts[2] or str(header.get("alg", "")).lower() == "none":
        raise ValidationError("The baseline must be a signed JWT with object header and payload")
    if unsigned:
        header["alg"] = "none"
        mutant = f"{encode(header)}.{parts[1]}."
    else:
        payload["awe_validation_canary"] = scan.token
        mutant = f"{parts[0]}.{encode(payload)}.{parts[2]}"
    response = scan.get(headers={**scan.anonymous_headers(), "Authorization": "Bearer " + mutant})
    if 200 <= response.status < 300 and marker in response.text:
        scan.report.finding("unsigned-jwt" if unsigned else "modified-jwt", "An altered JWT returns private response content", [base, control, response], severity="high", verification="verified_behavior", facts={"mutation": "alg_none" if unsigned else "payload_without_resigning", "private_marker_sha256": scan.report.marker(marker)})


def workflow_invariants(scan):
    marker = scan.marker()
    valid = scan.primary.get("valid_steps")
    invalid = scan.primary.get("invalid_steps")
    if not isinstance(valid, list) or not isinstance(invalid, list) or not 1 <= len(valid) <= 5 or not 1 <= len(invalid) <= 5:
        raise ValidationError("Provide one to five valid_steps and invalid_steps in request_context")
    if valid == invalid:
        raise ValidationError("Valid and invalid sequences must differ")
    if not scan.peer.get('headers') or scan.peer.get('headers') == scan.primary.get('headers'):
        raise ValidationError("Provide distinct, isolated primary and peer workflow contexts")
    # Each step is explicit; the runner never invents transactions or assumes
    # response cookies should be shared between the two isolated contexts.
    def sequence(steps, context):
        responses = []
        for step in steps:
            if not isinstance(step, dict) or not step.get("url"):
                raise ValidationError("Each workflow step must contain an explicit URL")
            responses.append(scan.get(step["url"], context={**context, **step, "headers": {**context.get("headers", {}), **step.get("headers", {})}}))
        return responses
    normal = sequence(valid, scan.primary)
    if not 200 <= normal[-1].status < 300 or marker not in normal[-1].text:
        raise ValidationError("The valid workflow did not establish the expected success marker")
    mutant = sequence(invalid, scan.peer)
    if 200 <= mutant[-1].status < 300 and marker in mutant[-1].text:
        scan.report.finding("workflow-invariant", "The invalid workflow also reaches the configured success marker", [*normal, *mutant], severity="high", facts={"valid_steps": len(normal), "invalid_steps": len(mutant), "marker_sha256": scan.report.marker(marker)}, detail="Researcher must confirm clean starting state, intended invariant, and business impact.")


CHECKS = {
    "authz_horizontal": authorization, "authz_vertical": authorization, "authz_tenant": authorization,
    "anonymous_access": anonymous_access, "cache_isolation": lambda scan: authorization(scan, cache=True),
    "logout_replay": logout_replay, "jwt_signature": jwt_check, "jwt_none": lambda scan: jwt_check(scan, unsigned=True),
    "workflow_invariants": workflow_invariants,
}
