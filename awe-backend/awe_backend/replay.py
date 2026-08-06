import time

import httpx

from .schemas import RepeaterRequest, RepeaterResponse

_MAX_RESPONSE = 2_000_000


class HttpReplayService:
    async def send(self, request: RepeaterRequest) -> RepeaterResponse:
        started = time.perf_counter()
        async with httpx.AsyncClient(follow_redirects=False, verify=True) as client:
            response = await client.request(
                request.method,
                request.url,
                headers=request.headers,
                content=request.body.encode() if request.body else None,
                timeout=request.timeout_seconds,
            )
        raw = response.content
        truncated = len(raw) > _MAX_RESPONSE
        body = raw[:_MAX_RESPONSE].decode(response.encoding or "utf-8", errors="replace")
        return RepeaterResponse(
            status_code=response.status_code,
            reason=response.reason_phrase,
            headers=dict(response.headers),
            body=body,
            elapsed_ms=int((time.perf_counter() - started) * 1000),
            body_truncated=truncated,
        )
