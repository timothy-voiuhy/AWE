import re

from PySide6.QtCore import QRegularExpression
from PySide6.QtGui import QColor, QSyntaxHighlighter, QTextCharFormat, QFont


class SyntaxHighlighter(QSyntaxHighlighter):
    """
    Dual-purpose highlighter: colours HTTP request/response messages AND
    generic JSON / code snippets.

    Rule tuples: (QRegularExpression, QTextCharFormat, group_index)
      group_index 0  → colour the full match
      group_index N  → colour only capture group N (lets you split one pattern
                        across multiple formats, e.g. header name vs value)
    """

    def __init__(self, parent=None):
        super().__init__(parent)

        def _fmt(color, *, bold=False, italic=False) -> QTextCharFormat:
            f = QTextCharFormat()
            f.setForeground(QColor(color))
            if bold:   f.setFontWeight(QFont.Weight.Bold)
            if italic: f.setFontItalic(True)
            return f

        def _re(pattern) -> QRegularExpression:
            return QRegularExpression(pattern)

        R = []   # (QRegularExpression, QTextCharFormat, group_index)

        # ── JSON / code body rules (applied first; HTTP rules override) ────────

        # Quoted strings — Green
        R += [
            (_re(r'"[^"\\]*(?:\\.[^"\\]*)*"'), _fmt("#A6E3A1"), 0),
            (_re(r"'[^'\\]*(?:\\.[^'\\]*)*'"), _fmt("#A6E3A1"), 0),
        ]

        # JSON true / false / null — Peach
        R += [(_re(r"\b(?:true|false|null)\b"), _fmt("#FAB387"), 0)]

        # Numbers — Lavender
        R += [(_re(r"\b\d+(?:\.\d+)?\b"), _fmt("#B4BEFE"), 0)]

        # Brackets / braces — Blue
        bracket_fmt = _fmt("#89B4FA")
        for ch in [r"\{", r"\}", r"\[", r"\]"]:
            R.append((_re(ch), bracket_fmt, 0))

        # Absolute URLs — Peach underlined
        url_fmt = _fmt("#FAB387")
        url_fmt.setFontUnderline(True)
        url_fmt.setUnderlineColor(QColor("#FAB387"))
        R.append((_re(r"https?://[^\s\"\'<>]+"), url_fmt, 0))

        # ── HTTP request / status line ─────────────────────────────────────────

        # Method — bold Blue
        _methods = "GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|CONNECT|TRACE"
        R.append((_re(rf"^({_methods})\b"), _fmt("#89B4FA", bold=True), 0))

        # Relative path on request line (e.g. GET /api/v1 HTTP/1.1)
        R.append((_re(rf"^(?:{_methods})\s+(/[^\s]*)"), _fmt("#FAB387"), 1))

        # HTTP version (start of status line) — dim
        R.append((_re(r"^HTTP/\S+"), _fmt("#585B70"), 0))

        # Status code by class (group 1 = the 3-digit code)
        R += [
            (_re(r"^HTTP/\S+\s+(2\d{2})\b"), _fmt("#A6E3A1", bold=True), 1),  # 2xx green
            (_re(r"^HTTP/\S+\s+(3\d{2})\b"), _fmt("#89B4FA", bold=True), 1),  # 3xx blue
            (_re(r"^HTTP/\S+\s+(4\d{2})\b"), _fmt("#F9E2AF", bold=True), 1),  # 4xx yellow
            (_re(r"^HTTP/\S+\s+(5\d{2})\b"), _fmt("#F38BA8", bold=True), 1),  # 5xx red
        ]

        # Reason phrase after status code — dim
        R.append((_re(r"^HTTP/\S+\s+\d{3}\s+(.+)$"), _fmt("#6C7086"), 1))

        # ── HTTP header lines ──────────────────────────────────────────────────
        # Pattern anchored at line start; only fires on "Name: value" lines.
        # [A-Za-z][A-Za-z0-9\-]+ then literal colon keeps false-positives minimal.

        _hdr = r"^[A-Za-z][A-Za-z0-9\-]+"

        # Header name — bold Mauve
        R.append((_re(rf"{_hdr}(?=:)"), _fmt("#CBA6F7", bold=True), 0))

        # Colon + optional space — dim (group 1)
        R.append((_re(rf"{_hdr}(:\s?)"), _fmt("#585B70"), 1))

        # Header value (everything after the colon) — Teal (group 1)
        R.append((_re(rf"{_hdr}:\s?(.+)$"), _fmt("#89DCEB"), 1))

        # cookie-specific formats (applied after base rules in highlightBlock)
        self._cookie_key_fmt = _fmt("#A6E3A1")           # green  — cookie/attr name
        self._cookie_val_fmt = _fmt("#FAB387")           # peach  — cookie/attr value
        self._cookie_sep_fmt = _fmt("#6C7086", italic=True)  # dim — = ; separators

        self._rules = R   # renamed from highlightRules to avoid external mutation

    # Pattern to detect a Cookie/Set-Cookie header line
    _COOKIE_HDR_RE = re.compile(r'^(?:Set-)?Cookie\s*:\s*', re.IGNORECASE)

    def highlightBlock(self, text: str) -> None:
        for pattern, fmt, group in self._rules:
            it = pattern.globalMatch(text)
            while it.hasNext():
                m = it.next()
                start = m.capturedStart(group)
                length = m.capturedLength(group)
                if start >= 0 and length > 0:
                    self.setFormat(start, length, fmt)

        # Cookie / Set-Cookie line — override the generic header-value teal
        # with per-token colours: key=green  =;=dim  value=peach
        hdr_m = self._COOKIE_HDR_RE.match(text)
        if hdr_m:
            self._apply_cookie_fmt(text, hdr_m.end())

    def _apply_cookie_fmt(self, text: str, value_start: int) -> None:
        """Colour each name=value pair and separator in a Cookie/Set-Cookie value."""
        parts  = text[value_start:].split(';')
        offset = value_start
        for i, part in enumerate(parts):
            if '=' in part:
                eq_idx   = part.index('=')
                key_raw  = part[:eq_idx]
                val_raw  = part[eq_idx + 1:]

                # key (strip leading whitespace, keep inner)
                leading  = len(key_raw) - len(key_raw.lstrip())
                key_body = key_raw.strip()
                if key_body:
                    self.setFormat(offset + leading, len(key_body),
                                   self._cookie_key_fmt)

                # = sign
                self.setFormat(offset + eq_idx, 1, self._cookie_sep_fmt)

                # value
                val_lead = len(val_raw) - len(val_raw.lstrip())
                val_body = val_raw.strip()
                if val_body:
                    self.setFormat(offset + eq_idx + 1 + val_lead,
                                   len(val_body), self._cookie_val_fmt)
            else:
                # bare attribute (HttpOnly, Secure, …)
                attr_raw = part
                leading  = len(attr_raw) - len(attr_raw.lstrip())
                attr     = attr_raw.strip()
                if attr:
                    self.setFormat(offset + leading, len(attr),
                                   self._cookie_key_fmt)

            offset += len(part)
            if i < len(parts) - 1:          # ; separator
                self.setFormat(offset, 1, self._cookie_sep_fmt)
                offset += 1
