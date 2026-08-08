import asyncio
from datetime import datetime, timezone

import pytest

from awe_backend.browser import BrowserSessionManager, BrowserState, _ManagedBrowser


class FakePage:
    def __init__(self) -> None:
        self.url = "about:blank"
        self.events: list[str] = []
        self.screenshot_started = asyncio.Event()
        self.allow_screenshot = asyncio.Event()
        self.goto_started = asyncio.Event()

    async def screenshot(self, **_kwargs):
        self.events.append("screenshot-start")
        self.screenshot_started.set()
        await self.allow_screenshot.wait()
        self.events.append("screenshot-end")
        return b"png"

    async def goto(self, url, **_kwargs):
        self.events.append("goto")
        self.goto_started.set()
        self.url = url

    async def title(self, **_kwargs):
        return "Test page"


@pytest.mark.asyncio
async def test_navigation_waits_for_an_in_progress_screenshot():
    page = FakePage()
    state = BrowserState(
        id="session",
        project_id="project",
        url="about:blank",
        title="New tab",
        viewport_width=1280,
        viewport_height=800,
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )
    manager = BrowserSessionManager()
    manager._sessions[state.id] = _ManagedBrowser(
        state=state,
        context=object(),
        page=page,
        operation_lock=asyncio.Lock(),
    )

    screenshot_task = asyncio.create_task(manager.screenshot(state.id))
    await page.screenshot_started.wait()

    navigate_task = asyncio.create_task(manager.navigate(state.id, "https://example.com"))
    await asyncio.sleep(0)
    assert not page.goto_started.is_set()

    page.allow_screenshot.set()
    await screenshot_task
    await navigate_task

    assert page.events == ["screenshot-start", "screenshot-end", "goto"]
