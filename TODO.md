# AWE — TODO

Items are grouped by area. ✅ = done this session, 🔴 = high priority, 🟡 = medium, 🟢 = nice-to-have.

---

## Code Quality

### Fixed ✅
- ✅ **Regex recompilation on every request** (`proxy/_rules.py`) — compiled pattern now cached on
  the `Rule` instance via `__dict__` so each regex is compiled exactly once.
- ✅ **Body size cap** (`proxy/_traffic.py`) — request and response bodies are truncated to 512 KB
  before being queued for MongoDB; `body_truncated: true` field added to the response sub-document.
- ✅ **Silent `except: pass` in `scopeEditor.py`** — scope save failure now logged with
  `log.warning(…, exc_info=True)` so the user isn't silently left with an unsaved scope.
- ✅ **Silent `except: pass` in `httpHistory.py`** — filter save/restore failures now logged.
- ✅ **Silent `except: pass` in `targetWindow.py`** — tech-detection display, notes load/save, and
  `project.json` parsing failures now logged.
- ✅ **Silent `except: pass` in `repeater.py`** — auth session load failure now logged.

### Remaining

- ✅ **Nav page indices are magic numbers** — `Page(IntEnum)` added to `targetWindow.py`; all
  `_switch_page(N)` calls replaced with `Page.REPEATER`, `Page.INTRUDER`, etc.

- ✅ **`programState.txt` dead code removed** — load block, `atexit.register`, and
  `saveProgramState()` deleted from `awe.py`; unused `import atexit` removed.

- ✅ **Palette extracted to `src/gui/palette.py`** — all 26 Catppuccin Mocha tokens defined, plus
  shared `SCROLLBAR_V`, `SCROLLBAR_V_THIN`, and `TAB_BAR` stylesheet fragments.
  `targetWindow.py` and `testing_methodology.py` fully migrated; the remaining 34 GUI files can
  be migrated file-by-file as they are touched (two non-standard values, `#EE99A0` and
  `#20203a`, are intentionally kept inline with comments).

- ✅ **CSS re-applied after `setMarkdown()`** (`testing_methodology.py`) — `_MD_CSS` is now also
  set via `document().setDefaultStyleSheet()` immediately after each `setMarkdown()` call,
  because Qt replaces the document on that call and loses the previous stylesheet.

---

## Proxy

### Architecture

- 🔴 **HTTP/2 upstream support**  
  `_upstream.py` uses `httpx.AsyncClient(http2=False)`. Many modern APIs (gRPC-Web, HTTP/2-only
  CDN responses) break or silently downgrade. Enable `http2=True` and add the `h2` extra to
  requirements. Note: httpx streams HTTP/2 transparently; the existing code needs no other change.

- 🟡 **Configurable upstream timeouts**  
  Connect (10 s) and read (30 s) are hardcoded in `_upstream.py`. Expose them in the proxy
  settings panel so testers can raise limits for slow targets.

- 🟡 **CONNECT-tunnel through an upstream/parent proxy**  
  There is no way to chain AWE behind Burp or another proxy. Add an optional upstream SOCKS5/HTTP
  proxy setting routed through httpx's proxy parameter.

- 🟢 **HTTP/2 → HTTP/1.1 downgrade flag**  
  When an H2 client connects, the proxy currently speaks H1 upstream. Add a UI toggle to force H1
  upstream even when the server negotiates H2, which is useful for testing H2-specific issues
  (request smuggling, header injection across the downgrade boundary).

### Interception

- 🔴 **`_pending` dict in `_intercept.py` is unbounded**  
  If the GUI is closed or the operator walks away, queued futures accumulate indefinitely. Add a
  cap (e.g. 500 entries) with a `log.warning` when the limit is hit, and auto-forward the oldest
  entry.

- 🟡 **WebSocket frame-level intercept**  
  `_handler.py` relays WS frames but they bypass the intercept gate. Surface individual frames to
  the GUI the same way HTTP requests are intercepted.

- 🟡 **Intercept queue depth indicator in the UI**  
  The operator has no visibility into how many requests are queued waiting for intercept
  review. Show the count in the Intercept tab header badge.

- 🟢 **Match-and-Replace on status codes**  
  `_rules.py` supports `url`, `*_headers`, `*_body` but not `status_code`. Useful for
  stripping CSP/HSTS headers or changing 301 to 200.

### Traffic Capture

- 🟡 **Binary / hex body viewer**  
  `_traffic.py` base64-encodes non-UTF-8 bodies, but the HTTP History viewer has no hex viewer.
  Add a hex/bytes tab in the response body panel when `body_encoding == "base64"`.

- 🟡 **Traffic deduplication / grouping**  
  Static asset requests (fonts, images, analytics pings) dominate the history list. Add a
  deduplication option that collapses identical `method + URL` entries or allows hide-rules by MIME
  type.

- 🟢 **HSTS / HTTPS-Upgrade stripping**  
  The proxy doesn't strip `Strict-Transport-Security` headers before they reach the browser,
  which can cause the browser to bypass the proxy for subsequent requests. Strip or rewrite HSTS
  max-age to 0 on responses.

- 🟢 **`SSLKEYLOGFILE` export**  
  Export TLS session keys so operators can decrypt captures in Wireshark after the fact.

### TLS / CA

- 🟢 **CA key rotation UI**  
  The CA cert and key are generated once and stored forever. Add a "Rotate CA" button that
  regenerates them and re-exports the cert for browser import.

- 🟢 **gRPC / Protobuf support**  
  gRPC uses HTTP/2 + protobuf framing. After enabling H2 upstream, add optional protobuf
  decoding (via `betterproto` or `grpcio-tools`) so binary frames appear as JSON in the viewer.
