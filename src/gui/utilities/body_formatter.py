def format_http_body(text: str, fmt: str) -> str | None:
    """
    Format the body section of an HTTP message (headers + blank line + body).
    *fmt* is one of 'json' | 'xml' | 'html' | 'javascript'.
    Returns the reassembled message with the formatted body, or None on failure.
    """
    idx = text.find('\n\n')
    if idx == -1:
        return None
    headers = text[:idx]
    body    = text[idx + 2:].strip()
    if not body:
        return None

    formatted = None

    if fmt == 'json':
        try:
            import json
            formatted = json.dumps(json.loads(body), indent=2, ensure_ascii=False)
        except Exception:
            pass

    elif fmt == 'xml':
        try:
            import xml.dom.minidom
            pretty = xml.dom.minidom.parseString(body.encode('utf-8')).toprettyxml(indent='  ')
            # Strip auto-added declaration if the original didn't have one
            if not body.lstrip().startswith('<?xml'):
                lines  = pretty.splitlines()
                pretty = '\n'.join(ln for ln in lines[1:] if ln.strip())
            formatted = pretty
        except Exception:
            pass

    elif fmt == 'html':
        try:
            from bs4 import BeautifulSoup
            formatted = BeautifulSoup(body, 'html.parser').prettify()
        except Exception:
            pass

    elif fmt == 'javascript':
        try:
            import jsbeautifier
            formatted = jsbeautifier.beautify(body)
        except Exception:
            pass

    if formatted is None:
        return None
    return headers + '\n\n' + formatted
