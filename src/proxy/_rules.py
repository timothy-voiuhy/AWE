"""
Match & Replace rules engine.

Rules are applied in order to each proxied request and response.
The rule list is swapped atomically when the GUI pushes an update via
the control protocol, so no restart is needed.
"""
from __future__ import annotations

import logging
import re
import threading
from dataclasses import dataclass, field

log = logging.getLogger(__name__)


@dataclass
class Rule:
    id:          str
    enabled:     bool
    match_in:    str   # "url" | "request_headers" | "request_body"
                       # | "response_headers" | "response_body"
    pattern:     str   # regex
    replacement: str   # replacement (supports \1 back-refs)
    comment:     str = ""

    def _compiled(self) -> re.Pattern | None:
        try:
            return re.compile(self.pattern)
        except re.error as exc:
            log.warning("Rule %s has invalid pattern %r: %s", self.id, self.pattern, exc)
            return None


class RulesEngine:
    def __init__(self) -> None:
        self._rules: list[Rule] = []
        self._lock  = threading.Lock()

    def set_rules(self, rules: list[dict]) -> None:
        compiled: list[Rule] = []
        for r in rules:
            try:
                compiled.append(Rule(**r))
            except TypeError as exc:
                log.warning("Skipping malformed rule %r: %s", r, exc)
        with self._lock:
            self._rules = compiled

    def apply_to_request(
        self,
        method:  str,
        url:     str,
        headers: list[tuple[str, str]],
        body:    bytes,
    ) -> tuple[str, str, list[tuple[str, str]], bytes]:
        with self._lock:
            rules = list(self._rules)
        for rule in rules:
            if not rule.enabled:
                continue
            rx = rule._compiled()
            if rx is None:
                continue
            try:
                if rule.match_in == "url":
                    url = rx.sub(rule.replacement, url)
                elif rule.match_in == "request_headers":
                    headers = _sub_headers(rx, rule.replacement, headers)
                elif rule.match_in == "request_body":
                    body_str = body.decode("utf-8", errors="replace")
                    body = rx.sub(rule.replacement, body_str).encode("utf-8")
            except Exception as exc:
                log.warning("Rule %s apply_to_request failed: %s", rule.id, exc)
        return method, url, headers, body

    def apply_to_response(
        self,
        headers: list[tuple[str, str]],
        body:    bytes,
    ) -> tuple[list[tuple[str, str]], bytes]:
        with self._lock:
            rules = list(self._rules)
        for rule in rules:
            if not rule.enabled:
                continue
            rx = rule._compiled()
            if rx is None:
                continue
            try:
                if rule.match_in == "response_headers":
                    headers = _sub_headers(rx, rule.replacement, headers)
                elif rule.match_in == "response_body":
                    body_str = body.decode("utf-8", errors="replace")
                    body = rx.sub(rule.replacement, body_str).encode("utf-8")
            except Exception as exc:
                log.warning("Rule %s apply_to_response failed: %s", rule.id, exc)
        return headers, body

    def to_list(self) -> list[dict]:
        with self._lock:
            return [
                {
                    "id":          r.id,
                    "enabled":     r.enabled,
                    "match_in":    r.match_in,
                    "pattern":     r.pattern,
                    "replacement": r.replacement,
                    "comment":     r.comment,
                }
                for r in self._rules
            ]


def _sub_headers(
    rx:          re.Pattern,
    replacement: str,
    headers:     list[tuple[str, str]],
) -> list[tuple[str, str]]:
    result = []
    for k, v in headers:
        new_v = rx.sub(replacement, v)
        result.append((k, new_v))
    return result
