from __future__ import annotations

import asyncio
import itertools
import re
import sys
import time
from pathlib import Path

import httpx
import websockets

from .schemas import IntruderRequest, IntruderResult


class IntruderService:
    _POSITION_RE = re.compile(r"§([^§]*)§")

    @classmethod
    def generate_requests(cls, request: IntruderRequest) -> list[tuple[list[str], str, str]]:
        marker = "\x00AWE_BODY\x00"
        parts = cls._POSITION_RE.split(f"{request.url}{marker}{request.body}")
        static, originals = parts[0::2], parts[1::2]
        if not originals:
            return [([payload], request.url, request.body) for payload in request.payloads]
        sets = [values for values in (request.payload_sets or [request.payloads]) if values]
        rows: list[list[str]] = []
        if request.attack_mode == "sniper":
            for position in range(len(originals)):
                for payload in sets[0] if sets else []:
                    row = list(originals); row[position] = payload; rows.append(row)
        elif request.attack_mode == "battering_ram":
            for payload in sets[0] if sets else []: rows.append([payload] * len(originals))
        elif request.attack_mode == "pitchfork":
            rows = [list(row) for row in zip(*[sets[i] if i < len(sets) else [] for i in range(len(originals))])]
        else:
            rows = [list(row) for row in itertools.product(*[sets[i] if i < len(sets) else [""] for i in range(len(originals))])]
        generated = []
        for row in rows:
            rebuilt = ''.join(segment + (row[i] if i < len(row) else originals[i]) for i, segment in enumerate(static[:-1])) + static[-1]
            url, _, body = rebuilt.partition(marker)
            generated.append((row, url, body))
        return generated

    async def run(self, request: IntruderRequest, cancel_event=None, progress=None) -> list[IntruderResult]:
        generated = self.generate_requests(request)
        if not generated: raise ValueError("No payload requests could be generated")
        semaphore = asyncio.Semaphore(request.concurrency)
        async with httpx.AsyncClient(follow_redirects=request.follow_redirects, verify=True) as client:
            async def execute(sequence: int, used: list[str], url: str, body: str) -> IntruderResult:
              async with semaphore:
                if cancel_event and cancel_event.is_set(): return None
                started = time.perf_counter()
                payload = " | ".join(str(item) for item in used)
                try:
                    response = await client.request(
                        request.method,
                        url,
                        headers=request.headers,
                        content=body,
                        timeout=request.timeout_seconds,
                    )
                    result=IntruderResult(sequence=sequence, payload=payload, status_code=response.status_code, length=len(response.content), elapsed_ms=int((time.perf_counter() - started) * 1000),request_url=url,request_body=body,response_headers=dict(response.headers),response_body=response.text[:1_000_000]);progress and progress(result);return result
                except httpx.HTTPError as exc:
                    result=IntruderResult(sequence=sequence, payload=payload, status_code=0, length=0, elapsed_ms=int((time.perf_counter() - started) * 1000), error=str(exc)[:300],request_url=url,request_body=body);progress and progress(result);return result
            results = await asyncio.gather(*(execute(sequence, used, url, body) for sequence, (used, url, body) in enumerate(generated, 1)))
        return sorted([item for item in results if item is not None], key=lambda item: item.sequence)


class ProxyControlService:
    def __init__(self, legacy_src_dir: Path, host: str = "127.0.0.1", port: int = 0):
        source = str(legacy_src_dir.resolve())
        if source not in sys.path:
            sys.path.insert(0, source)
        from proxy._control import ControlClient

        if port:
            self._client = ControlClient(port, host=host)
        else:
            control_file = legacy_src_dir.resolve().parent / "tmp" / "proxy_control.txt"
            self._client = ControlClient(int(control_file.read_text().strip()))

    def set_intercept(self, enabled: bool, patterns: list[str]) -> None:
        if not self._client.set_intercept(enabled, patterns):
            raise ConnectionError("AWE proxy is unavailable")

    def pending(self) -> list[dict]:
        return self._client.get_pending_intercept()

    def resolve(self, request_id: str, decision: str, headers: list[list[str]], body_b64: str) -> None:
        if not self._client.resolve_intercept(request_id, decision, headers, body_b64):
            raise ConnectionError("AWE proxy is unavailable or the request expired")


class WebSocketClientService:
    async def send(self, url: str, message: str) -> str:
        async with websockets.connect(url, open_timeout=10, close_timeout=5) as socket:
            await socket.send(message)
            try:
                reply = await asyncio.wait_for(socket.recv(), timeout=10)
            except asyncio.TimeoutError:
                return ""
            return reply.decode(errors="replace") if isinstance(reply, bytes) else reply
