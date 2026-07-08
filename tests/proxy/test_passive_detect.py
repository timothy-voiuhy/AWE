from proxy.passive_detect import (
    check_cors_misconfig,
    check_security_headers,
    detect_graphql_request,
    extract_cookie_flags,
    find_jwts_in_headers,
    find_secrets_in_text,
)

_JWT = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0In0.abc123signature"


def test_find_jwt_in_authorization_header():
    found = find_jwts_in_headers({"Authorization": f"Bearer {_JWT}"})
    assert len(found) == 1
    assert found[0]["token"] == _JWT
    assert found[0]["header_name"] == "Authorization"


def test_find_jwt_in_cookie_header():
    found = find_jwts_in_headers({"Cookie": f"session={_JWT}; theme=dark"})
    assert len(found) == 1
    assert found[0]["header_name"] == "Cookie:session"


def test_no_jwt_in_plain_cookies():
    assert find_jwts_in_headers({"Cookie": "session=abc123; theme=dark"}) == []


def test_dotted_version_string_is_not_flagged_as_jwt():
    assert find_jwts_in_headers({"Authorization": "v1.2.3-not-a-jwt-at-all"}) == []


def test_no_duplicate_jwt_when_seen_in_multiple_headers():
    found = find_jwts_in_headers({"Authorization": f"Bearer {_JWT}", "Cookie": f"session={_JWT}"})
    assert len(found) == 1  # Authorization wins, cookie occurrence deduped


def test_detect_graphql_from_json_body():
    result = detect_graphql_request("POST", "application/json", '{"query": "{ viewer { id } }"}', "/api/graphql")
    assert result == {"query": "{ viewer { id } }", "variables": {}}


def test_detect_graphql_ignores_get_requests():
    assert detect_graphql_request("GET", "application/json", '{"query": "x"}', "/api/graphql") is None


def test_detect_graphql_from_path_hint_with_text_body():
    result = detect_graphql_request("POST", "text/plain", "query { viewer { id } }", "/graphql")
    assert result["query"] == "query { viewer { id } }"


def test_detect_graphql_returns_none_for_ordinary_json():
    assert detect_graphql_request("POST", "application/json", '{"foo": "bar"}', "/api/users") is None


def test_extract_cookie_flags_parses_all_attributes():
    flags = extract_cookie_flags({"Set-Cookie": ["session=abc; Secure; HttpOnly; SameSite=Strict", "tracking=xyz"]})
    by_name = {f["name"]: f for f in flags}
    assert by_name["session"] == {"name": "session", "secure": True, "httponly": True, "samesite": "Strict"}
    assert by_name["tracking"] == {"name": "tracking", "secure": False, "httponly": False, "samesite": None}


def test_check_security_headers_skips_hsts_over_plain_http():
    issues = check_security_headers({}, is_https=False)
    assert "missing_hsts" not in issues
    assert "missing_csp" in issues


def test_check_security_headers_all_present_yields_no_issues():
    headers = {
        "Strict-Transport-Security": "max-age=1",
        "Content-Security-Policy": "default-src 'self'",
        "X-Frame-Options": "DENY",
        "X-Content-Type-Options": "nosniff",
    }
    assert check_security_headers(headers, is_https=True) == []


def test_cors_wildcard_with_credentials_is_flagged():
    result = check_cors_misconfig({"Access-Control-Allow-Origin": "*", "Access-Control-Allow-Credentials": "true"})
    assert result == "cors_wildcard_with_credentials"


def test_cors_wildcard_without_credentials_is_not_flagged():
    assert check_cors_misconfig({"Access-Control-Allow-Origin": "*"}) is None


def test_cors_reflected_origin_with_credentials_is_flagged():
    result = check_cors_misconfig({
        "Access-Control-Allow-Origin": "https://evil.com",
        "Access-Control-Allow-Credentials": "true",
    })
    assert result == "cors_reflected_origin_with_credentials"


def test_find_secrets_detects_aws_key():
    found = find_secrets_in_text("here is a key AKIAABCDEFGHIJKLMNOP and more text")
    assert any(f["kind"] == "aws_access_key" for f in found)


def test_find_secrets_returns_empty_for_clean_text():
    assert find_secrets_in_text("just a normal response body") == []
