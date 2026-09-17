from datetime import datetime, timezone

from awe_backend.browser import BrowserSessionManager, BrowserState


def test_browser_sessions_are_vnc_backed_without_screenshot_api():
    manager = BrowserSessionManager()
    assert not hasattr(manager, "screenshot")
    assert not hasattr(manager, "interact")


def test_browser_state_keeps_the_existing_frontend_contract():
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
    assert state.project_id == "project"
    assert state.viewport_width == 1280
