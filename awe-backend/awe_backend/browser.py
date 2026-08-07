from __future__ import annotations

import asyncio
import secrets
import base64
from dataclasses import dataclass
from datetime import datetime, timezone


def _now() -> datetime:
    return datetime.now(timezone.utc)


@dataclass
class BrowserState:
    id: str
    project_id: str
    url: str
    title: str
    viewport_width: int
    viewport_height: int
    created_at: datetime
    updated_at: datetime


@dataclass
class _ManagedBrowser:
    state: BrowserState
    context: object
    page: object


class BrowserUnavailable(RuntimeError):
    pass


class BrowserSessionManager:
    def __init__(self) -> None:
        self._playwright = None
        self._browser = None
        self._sessions: dict[str, _ManagedBrowser] = {}
        self._lock = asyncio.Lock()

    async def _ensure_browser(self, proxy_host: str, proxy_port: int, proxy_enabled: bool = True) -> None:
        if self._browser is not None:
            return
        try:
            from playwright.async_api import async_playwright
            self._playwright = await async_playwright().start()
            options = {"headless": True, "args": ["--disable-gpu", "--no-sandbox"]}
            if proxy_enabled:
                options["proxy"] = {"server": f"http://{proxy_host}:{proxy_port}"}
            self._browser = await self._playwright.chromium.launch(**options)
        except Exception as exc:
            await self.shutdown()
            raise BrowserUnavailable("Managed Chromium is unavailable; run `playwright install chromium`.") from exc

    async def create(self, project_id: str, proxy_host: str, proxy_port: int, width: int, height: int, proxy_enabled: bool = True) -> BrowserState:
        async with self._lock:
            await self._ensure_browser(proxy_host, proxy_port, proxy_enabled)
            context = await self._browser.new_context(
                viewport={"width": width, "height": height},
                ignore_https_errors=True,
                extra_http_headers={"X-AWE-Project-ID": project_id},
            )
            page = await context.new_page()
            now = _now()
            state = BrowserState(secrets.token_urlsafe(18), project_id, "about:blank", "New tab", width, height, now, now)
            self._sessions[state.id] = _ManagedBrowser(state, context, page)
            return state

    def get(self, session_id: str) -> _ManagedBrowser:
        try:
            return self._sessions[session_id]
        except KeyError as exc:
            raise KeyError(session_id) from exc

    def list(self, project_id: str) -> list[BrowserState]:
        return [item.state for item in self._sessions.values() if item.state.project_id == project_id]

    async def navigate(self, session_id: str, url: str) -> BrowserState:
        item = self.get(session_id)
        await item.page.goto(url, wait_until="domcontentloaded", timeout=30_000)
        item.state.url = item.page.url
        item.state.title = await item.page.title()
        item.state.updated_at = _now()
        return item.state

    async def screenshot(self, session_id: str) -> tuple[BrowserState, bytes]:
        item = self.get(session_id)
        image = await item.page.screenshot(type="png", full_page=False)
        item.state.url = item.page.url
        item.state.title = await item.page.title()
        item.state.updated_at = _now()
        return item.state, image

    async def interact(self, session_id: str, action: dict) -> BrowserState:
        item = self.get(session_id)
        kind = action.get("type")
        if kind == "click":
            await item.page.mouse.click(float(action["x"]), float(action["y"]))
        elif kind == "type":
            await item.page.keyboard.insert_text(str(action.get("text", ""))[:10000])
        elif kind == "press":
            await item.page.keyboard.press(str(action.get("key", ""))[:100])
        elif kind == "scroll":
            await item.page.mouse.wheel(float(action.get("x", 0)), float(action.get("y", 0)))
        elif kind == "reload":
            await item.page.reload(wait_until="domcontentloaded", timeout=30_000)
        elif kind == "resize":
            width = max(320, min(2560, int(action.get("width", item.state.viewport_width))))
            height = max(240, min(1600, int(action.get("height", item.state.viewport_height))))
            await item.context.set_default_viewport({"width": width, "height": height})
            item.state.viewport_width, item.state.viewport_height = width, height
        else:
            raise ValueError("Unsupported browser action")
        item.state.url = item.page.url
        item.state.title = await item.page.title()
        item.state.updated_at = _now()
        return item.state

    async def close(self, session_id: str) -> None:
        item = self._sessions.pop(session_id, None)
        if item:
            await item.context.close()

    async def shutdown(self) -> None:
        for session_id in list(self._sessions):
            await self.close(session_id)
        if self._browser:
            await self._browser.close()
            self._browser = None
        if self._playwright:
            await self._playwright.stop()
            self._playwright = None
