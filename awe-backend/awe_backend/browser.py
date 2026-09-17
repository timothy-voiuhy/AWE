from __future__ import annotations

import asyncio
import json
import os
import secrets
import shutil
import socket
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path


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
    display: int
    vnc_port: int
    runtime_dir: Path
    xvfb: asyncio.subprocess.Process
    vnc: asyncio.subprocess.Process
    browser: asyncio.subprocess.Process
    operation_lock: asyncio.Lock


class BrowserUnavailable(RuntimeError):
    pass


class BrowserSessionManager:
    """Manage visible Chromium sessions whose display is exposed over VNC.

    The browser is intentionally not driven through a DOM automation library.
    Chromium paints into an Xvfb display, x11vnc serves that display, and the
    API's authenticated WebSocket endpoint bridges the VNC bytes to noVNC in
    the frontend.
    """

    def __init__(self) -> None:
        self._sessions: dict[str, _ManagedBrowser] = {}
        self._lock = asyncio.Lock()
        self._next_display = 90

    @staticmethod
    def _binary(name: str, *fallbacks: str) -> str:
        for candidate in (name, *fallbacks):
            path = shutil.which(candidate)
            if path:
                return path
        raise BrowserUnavailable(f"{name} is unavailable in the browser runtime")

    @staticmethod
    def _free_port() -> int:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            probe.bind(("127.0.0.1", 0))
            return int(probe.getsockname()[1])

    async def _wait_for_display(self, display: int, process: asyncio.subprocess.Process) -> None:
        socket_path = Path(f"/tmp/.X11-unix/X{display}")
        for _ in range(50):
            if process.returncode is not None:
                raise BrowserUnavailable("Xvfb exited before the browser display was ready")
            if socket_path.exists():
                return
            await asyncio.sleep(0.05)
        raise BrowserUnavailable("Timed out waiting for the browser display")

    async def _wait_for_vnc(self, port: int, process: asyncio.subprocess.Process) -> None:
        for _ in range(50):
            if process.returncode is not None:
                raise BrowserUnavailable("x11vnc exited before the browser connection was ready")
            try:
                reader, writer = await asyncio.open_connection("127.0.0.1", port)
                del reader
                writer.close()
                await writer.wait_closed()
                return
            except OSError:
                await asyncio.sleep(0.05)
        raise BrowserUnavailable("Timed out waiting for the browser VNC server")

    @staticmethod
    async def _stop_process(process: asyncio.subprocess.Process | None) -> None:
        if process is None or process.returncode is not None:
            return
        process.terminate()
        try:
            await asyncio.wait_for(process.wait(), timeout=3)
        except asyncio.TimeoutError:
            process.kill()
            await process.wait()

    async def _allocate_display(self) -> int:
        # Session creation is serialized, so checking the X socket here avoids
        # collisions while still allowing the manager to coexist with another
        # X server in the container.
        while Path(f"/tmp/.X11-unix/X{self._next_display}").exists():
            self._next_display += 1
        display = self._next_display
        self._next_display += 1
        return display

    @staticmethod
    def _write_browser_extension(runtime_dir: Path, project_id: str, proxy_username: str, proxy_password: str) -> Path:
        """Install a tiny MV3 extension for proxy routing/authentication.

        Chromium's command line has no equivalent of Playwright's extra
        headers/proxy credentials. The extension restores both behaviors while
        keeping the project marker inside the private browser profile.
        """
        extension_dir = runtime_dir / "routing-extension"
        extension_dir.mkdir()
        (extension_dir / "manifest.json").write_text(json.dumps({
            "manifest_version": 3,
            "name": "AWE project routing",
            "version": "1.0.0",
            "permissions": [
                "declarativeNetRequestWithHostAccess",
                "webRequest",
                "webRequestAuthProvider",
            ],
            "host_permissions": ["<all_urls>"],
            "declarative_net_request": {
                "rule_resources": [{"id": "awe-project-header", "enabled": True, "path": "rules.json"}],
            },
            "background": {"service_worker": "background.js"},
        }), encoding="utf-8")
        (extension_dir / "rules.json").write_text(json.dumps([{
            "id": 1,
            "priority": 1,
            "action": {"type": "modifyHeaders", "requestHeaders": [{
                "header": "X-AWE-Project-ID",
                "operation": "set",
                "value": project_id,
            }]},
            "condition": {
                "urlFilter": "*",
                "resourceTypes": [
                    "main_frame", "sub_frame", "stylesheet", "script", "image", "font",
                    "object", "xmlhttprequest", "ping", "media", "websocket", "other",
                ],
            },
        }]), encoding="utf-8")
        (extension_dir / "background.js").write_text(
            "const proxyUsername = " + json.dumps(proxy_username) + ";\n"
            "const proxyPassword = " + json.dumps(proxy_password) + ";\n"
            "if (proxyUsername) {\n"
            "  chrome.webRequest.onAuthRequired.addListener(\n"
            "    details => details.isProxy ? { authCredentials: { username: proxyUsername, password: proxyPassword } } : {},\n"
            "    { urls: ['<all_urls>'] }, ['blocking'],\n"
            "  );\n"
            "}\n",
            encoding="utf-8",
        )
        return extension_dir

    async def create(
        self,
        project_id: str,
        proxy_host: str,
        proxy_port: int,
        width: int,
        height: int,
        proxy_username: str = "",
        proxy_password: str = "",
        proxy_enabled: bool = True,
    ) -> BrowserState:
        async with self._lock:
            session_id = secrets.token_urlsafe(18)
            display = await self._allocate_display()
            vnc_port = self._free_port()
            runtime_dir = Path(tempfile.mkdtemp(prefix=f"awe-browser-{session_id}-"))
            xvfb: asyncio.subprocess.Process | None = None
            vnc: asyncio.subprocess.Process | None = None
            browser: asyncio.subprocess.Process | None = None
            try:
                xvfb_binary = self._binary("Xvfb")
                vnc_binary = self._binary("x11vnc")
                browser_binary = os.environ.get("AWE_BROWSER_BINARY") or self._binary(
                    "chromium", "chromium-browser", "google-chrome"
                )

                xvfb = await asyncio.create_subprocess_exec(
                    xvfb_binary,
                    f":{display}",
                    "-screen",
                    "0",
                    f"{width}x{height}x24",
                    "-ac",
                    "-nolisten",
                    "tcp",
                    stdout=asyncio.subprocess.DEVNULL,
                    stderr=asyncio.subprocess.DEVNULL,
                )
                await self._wait_for_display(display, xvfb)

                vnc = await asyncio.create_subprocess_exec(
                    vnc_binary,
                    "-display",
                    f":{display}",
                    "-rfbport",
                    str(vnc_port),
                    "-localhost",
                    "-forever",
                    "-shared",
                    "-nopw",
                    "-noxdamage",
                    "-quiet",
                    stdout=asyncio.subprocess.DEVNULL,
                    stderr=asyncio.subprocess.DEVNULL,
                )
                await self._wait_for_vnc(vnc_port, vnc)
                extension_dir = self._write_browser_extension(
                    runtime_dir, project_id, proxy_username, proxy_password
                )

                browser_args = [
                    browser_binary,
                    "--no-sandbox",
                    "--disable-gpu",
                    "--disable-dev-shm-usage",
                    "--no-first-run",
                    "--no-default-browser-check",
                    f"--disable-extensions-except={extension_dir}",
                    f"--load-extension={extension_dir}",
                    "--window-position=0,0",
                    f"--window-size={width},{height}",
                    f"--user-data-dir={runtime_dir / 'profile'}",
                ]
                if proxy_enabled:
                    browser_args.append(f"--proxy-server=http://{proxy_host}:{proxy_port}")
                browser_args.append("about:blank")
                browser = await asyncio.create_subprocess_exec(
                    *browser_args,
                    env={**os.environ, "DISPLAY": f":{display}"},
                    stdout=asyncio.subprocess.DEVNULL,
                    stderr=asyncio.subprocess.DEVNULL,
                )
                await asyncio.sleep(0.15)
                if browser.returncode is not None:
                    raise BrowserUnavailable("Chromium exited while starting the browser session")

                now = _now()
                state = BrowserState(
                    session_id,
                    project_id,
                    "about:blank",
                    "New tab",
                    width,
                    height,
                    now,
                    now,
                )
                self._sessions[state.id] = _ManagedBrowser(
                    state, display, vnc_port, runtime_dir, xvfb, vnc, browser, asyncio.Lock()
                )
                return state
            except Exception:
                await self._stop_process(browser)
                await self._stop_process(vnc)
                await self._stop_process(xvfb)
                shutil.rmtree(runtime_dir, ignore_errors=True)
                raise

    def get(self, session_id: str) -> _ManagedBrowser:
        try:
            return self._sessions[session_id]
        except KeyError as exc:
            raise KeyError(session_id) from exc

    def list(self, project_id: str) -> list[BrowserState]:
        return [item.state for item in self._sessions.values() if item.state.project_id == project_id]

    async def navigate(self, session_id: str, url: str) -> BrowserState:
        item = self.get(session_id)
        async with item.operation_lock:
            xdotool = self._binary("xdotool")
            env = {**os.environ, "DISPLAY": f":{item.display}"}
            commands = (
                (xdotool, "key", "--clearmodifiers", "ctrl+l"),
                (xdotool, "type", "--clearmodifiers", "--delay", "1", url),
                (xdotool, "key", "--clearmodifiers", "Return"),
            )
            for command in commands:
                result = await asyncio.create_subprocess_exec(
                    *command,
                    env=env,
                    stdout=asyncio.subprocess.DEVNULL,
                    stderr=asyncio.subprocess.PIPE,
                )
                _, error = await result.communicate()
                if result.returncode:
                    detail = error.decode(errors="replace").strip()
                    raise BrowserUnavailable(f"Could not navigate the VNC browser: {detail}")
            item.state.url = url
            item.state.title = "Loading…"
            item.state.updated_at = _now()
            return item.state

    async def close(self, session_id: str) -> None:
        item = self._sessions.pop(session_id, None)
        if not item:
            return
        async with item.operation_lock:
            await self._stop_process(item.browser)
            await self._stop_process(item.vnc)
            await self._stop_process(item.xvfb)
            shutil.rmtree(item.runtime_dir, ignore_errors=True)

    async def shutdown(self) -> None:
        for session_id in list(self._sessions):
            await self.close(session_id)
