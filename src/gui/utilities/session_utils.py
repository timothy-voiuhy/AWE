from __future__ import annotations

from urllib.parse import urlsplit, urlencode, parse_qs, urlunsplit


def apply_session_to_request(request_text: str, session: dict) -> str:
    """
    Inject session headers (add mode) and URL params into a raw HTTP request.
    session = {"name": str, "headers": [[k, v], …], "params": [[k, v], …]}
    """
    if not request_text.strip():
        return request_text

    lines = request_text.split('\n')
    if not lines:
        return request_text

    req_line = lines[0]
    existing_headers: list[str] = []
    body_idx = len(lines)

    for i, line in enumerate(lines[1:], 1):
        if not line.strip():
            body_idx = i
            break
        existing_headers.append(line)

    body = '\n'.join(lines[body_idx:])

    # ── Merge URL params into request line ────────────────────────────────────
    params = session.get("params") or []
    if params:
        parts = req_line.split(' ', 2)
        if len(parts) >= 2:
            url_part = parts[1]
            is_relative = '://' not in url_part
            parse_src = f'http://x{url_part}' if is_relative else url_part
            parsed = urlsplit(parse_src)
            qs = parse_qs(parsed.query, keep_blank_values=True)
            for item in params:
                if isinstance(item, (list, tuple)) and len(item) >= 2:
                    k, v = str(item[0]), str(item[1])
                elif isinstance(item, dict):
                    k, v = str(item.get("name", item.get("key", ""))), str(item.get("value", ""))
                else:
                    continue
                if k and k not in qs:
                    qs[k] = [v]
            new_query = urlencode({k: vs[0] for k, vs in qs.items()})
            if is_relative:
                path_qs = parsed.path
                if new_query:
                    path_qs += '?' + new_query
                if parsed.fragment:
                    path_qs += '#' + parsed.fragment
                parts[1] = path_qs
            else:
                parts[1] = urlunsplit((
                    parsed.scheme, parsed.netloc, parsed.path,
                    new_query, parsed.fragment,
                ))
            req_line = ' '.join(parts)

    # ── Add session headers (skip names already present) ──────────────────────
    session_headers = session.get("headers") or []
    existing_names = {ln.partition(':')[0].strip().lower() for ln in existing_headers}
    new_headers = list(existing_headers)
    for item in session_headers:
        if isinstance(item, (list, tuple)) and len(item) >= 2:
            name, value = str(item[0]), str(item[1])
        elif isinstance(item, dict):
            name  = str(item.get("name", ""))
            value = str(item.get("value", ""))
        else:
            continue
        if name and name.lower() not in existing_names:
            new_headers.append(f"{name}: {value}")
            existing_names.add(name.lower())

    result_parts = [req_line] + new_headers + ['']
    if body.strip():
        result_parts.append(body)
    return '\n'.join(result_parts)
