"""Controlled vulnerable/protected HTTP endpoints; never contacts public targets."""
import base64
import json
import re
import ssl
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit
from urllib.request import ProxyHandler, build_opener

PRIVATE = "AWE_PRIVATE_RESPONSE_CANARY_93851"
encode = lambda value: base64.urlsafe_b64encode(json.dumps(value).encode()).decode().rstrip('=')
JWT = f'{encode({"alg": "HS256", "typ": "JWT"})}.{encode({"sub": "owner"})}.fixture-signature'


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_GET(self): self.respond()
    def do_POST(self): self.respond()
    def do_OPTIONS(self): self.respond()
    def do_TRACE(self): self.respond()

    def respond(self):
        parts = urlsplit(self.path)
        query = parse_qs(parts.query)
        path = parts.path
        mode = self.headers.get('X-Fixture-Mode', 'safe')
        vulnerable = mode == 'vulnerable'
        length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(length).decode() if length else ''
        self.server.requests.append({'path': path, 'method': self.command, 'headers': dict(self.headers), 'body': body})
        status, headers, content = 200, {'Content-Type': 'text/html'}, '<html><title>Application</title>Normal content</html>'
        slug = path.rsplit('/', 1)[-1]
        if path == '/monitor':
            if self.headers.get('Authorization') != 'Bearer monitor-secret':
                status, content = 401, 'denied'
            else:
                content = json.dumps({'observed': sorted(self.server.callbacks)})
        elif path == '/callback':
            self.server.callbacks.update(query.get('awe_probe', [])); content = 'recorded'
        elif path == '/negative-control':
            status, content = 404, 'not found'
        elif slug in {'authz_horizontal', 'authz_vertical', 'authz_tenant', 'cache_isolation', 'anonymous_access', 'logout_replay', 'jwt_signature', 'jwt_none'}:
            auth = self.headers.get('Authorization', '')
            owner = auth in {'Bearer owner-secret', 'Bearer ' + JWT}
            peer = auth == 'Bearer peer-secret'
            allowed = owner and not (slug == 'logout_replay' and self.server.logged_out)
            if vulnerable and (peer or (slug.startswith('jwt_') and auth.startswith('Bearer ')) or slug == 'anonymous_access'):
                allowed = True
            status, content = (200, PRIVATE) if allowed else (403, 'access denied')
        elif path == '/logout':
            self.server.logged_out = not vulnerable; content = 'logged out'
        elif path.startswith('/workflow/'):
            status, content = (200, PRIVATE) if path.endswith('/allow') or vulnerable else (403, 'workflow blocked')
        elif slug == 'security_headers':
            if not vulnerable:
                headers.update({'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer', 'Content-Security-Policy': "default-src 'self'; frame-ancestors 'none'", 'Strict-Transport-Security': 'max-age=31536000'})
        elif slug == 'session_cookies':
            headers['Set-Cookie'] = 'sid=server-session-secret; Path=/' + ('' if vulnerable else '; Secure; HttpOnly; SameSite=Lax')
        elif slug == 'cors':
            headers.update({'Access-Control-Allow-Origin': self.headers.get('Origin', 'https://trusted.invalid') if vulnerable else 'https://trusted.invalid', 'Access-Control-Allow-Credentials': 'true'})
        elif slug == 'open_redirect':
            status = 302; headers['Location'] = query.get('next', ['/home'])[0] if vulnerable else '/home'
        elif slug == 'crlf':
            match = re.search(r'\r\nX-AWE-Canary: (awe[0-9a-f]+)', query.get('next', [''])[0])
            if vulnerable and match: headers['X-AWE-Canary'] = match[1]
        elif slug == 'host_header':
            status = 302; headers['Location'] = 'https://' + (self.headers['Host'] if vulnerable else 'trusted.invalid') + '/landing'
        elif slug == 'http_methods':
            if self.command == 'OPTIONS': headers['Allow'] = 'GET, HEAD, OPTIONS, TRACE, PUT, DELETE'
            if self.command == 'TRACE': status, content = (200, self.headers.get('X-AWE-Canary', '')) if vulnerable else (405, 'method blocked')
        elif slug == 'directory_listing' and vulnerable:
            content = '<title>Index of /files</title><a href="../">Parent Directory</a>'
        elif slug == 'debug_errors' and vulnerable:
            status, content = 500, 'Traceback (most recent call last):\n File "/app/private.py", line 4\nRuntimeError: response-secret'
        elif path == '/.git/HEAD':
            status, content = (200, 'ref: refs/heads/main\n') if vulnerable else (404, 'not found')
        elif path.endswith('.bak'):
            status, content = (200, '<?php $password="response-secret";') if vulnerable else (404, 'not found')
        elif path.endswith(('.old', '~')) or path.endswith('.missing') or 'not-found' in path or '.awe' in path:
            status, content = 404, 'not found'
        elif slug == 'source_maps':
            content = '<script src="/assets/app.js"></script>'
        elif path == '/assets/app.js.map':
            content = json.dumps({'version': 3, 'sourcesContent': ['private-source-secret'] if vulnerable else []})
        elif slug == 'csrf_forms':
            content = '<form method="POST"><input name="username">' + ('' if vulnerable else '<input name="csrf_token" value="secret-form-token">') + '</form>'
        elif slug == 'mixed_content':
            content = '<script src="' + ('http' if vulnerable else 'https') + '://assets.invalid/a.js"></script>'
        elif slug == 'graphql_introspection':
            content = json.dumps({'data': {'__schema': {'queryType': {'name': 'Query'}}}} if vulnerable else {'errors': [{'message': 'Introspection disabled'}]})
        elif slug == 'graphql_batching':
            status, content = (200, json.dumps([{'data': {'__typename': 'Query'}}, {'data': {'__typename': 'Query'}}])) if vulnerable else (400, '{}')
        elif slug == 'ssti':
            value = query.get('next', [''])[0]
            if vulnerable:
                value = re.sub(r'\{\{(\d+)\*(\d+)\}\}|\$\{(\d+)\*(\d+)\}', lambda match: str(int(match[1] or match[3]) * int(match[2] or match[4])), value)
            content = value
        elif slug == 'canary_traversal':
            value = query.get('next', [''])[0]
            content = PRIVATE if vulnerable and value.startswith('../') and value.endswith('research-canary.txt') else 'no canary'
        elif slug in {'ssrf_callback', 'xxe_callback'}:
            callback = query.get('next', [''])[0]
            if slug == 'xxe_callback':
                match = re.search(r'SYSTEM "([^\"]+)"', body)
                callback = match[1] if match else ''
            # Fixture only: constrain outbound calls to this controlled server.
            parsed = urlsplit(callback)
            if vulnerable and parsed.hostname == '127.0.0.1' and parsed.port == self.server.server_port and parsed.path == '/callback':
                with build_opener(ProxyHandler({})).open(callback, timeout=2) as response: response.read()
        elif slug == 'oversized':
            content = 'x' * 10000
        self.send_response(status)
        for key, value in headers.items(): self.send_header(key, value)
        self.end_headers()
        try: self.wfile.write(content.encode())
        except (BrokenPipeError, ConnectionResetError): pass


def start_server(tls=False, cert=None, key=None):
    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    server.callbacks, server.requests, server.logged_out = set(), [], False
    if tls:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); context.load_cert_chain(cert, key)
        server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
    return server, thread
