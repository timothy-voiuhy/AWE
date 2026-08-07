from __future__ import annotations

import asyncio
import secrets
import json
from datetime import datetime, timezone
from pathlib import Path
from dataclasses import dataclass


@dataclass
class TerminalSession:
    id: str
    project_id: str
    host: str
    port: int
    username: str
    connection: object
    process: object
    last_activity: float


class TerminalManager:
    def __init__(self, max_per_project: int = 4, idle_seconds: int = 3600): self.sessions: dict[str, TerminalSession] = {}; self.max_per_project=max_per_project; self.idle_seconds=idle_seconds

    async def create(self, project_id: str, host: str, port: int, username: str, password: str, private_key: str = "", key_passphrase: str = "", trust_host_key: bool = False) -> TerminalSession:
        self.expire_idle()
        if sum(1 for item in self.sessions.values() if item.project_id == project_id) >= self.max_per_project: raise RuntimeError("Maximum terminal sessions reached for this project")
        try:
            import asyncssh
            # Omit known_hosts so AsyncSSH uses the user's standard ~/.ssh/known_hosts.
            # Unknown hosts fail closed instead of silently trusting a new key.
            connect_args = {"host":host,"port":port,"username":username}
            if trust_host_key:
                connect_args["known_hosts"] = None
            if private_key:
                connect_args["client_keys"] = [asyncssh.import_private_key(private_key, passphrase=key_passphrase or None)]
            else:
                connect_args["password"] = password
            connection = await asyncssh.connect(**connect_args)
            process = await connection.create_process(term_type="xterm-256color", term_size=(120, 32))
        except Exception as exc:
            raise RuntimeError(f"SSH connection failed: {exc}") from exc
        session = TerminalSession(secrets.token_urlsafe(18), project_id, host, port, username, connection, process, asyncio.get_running_loop().time())
        self.sessions[session.id] = session
        return session

    def get(self, session_id: str) -> TerminalSession:
        if session_id not in self.sessions: raise KeyError(session_id)
        return self.sessions[session_id]

    async def resize(self, session_id: str, cols: int, rows: int):
        session = self.get(session_id); session.last_activity=asyncio.get_running_loop().time(); session.process.change_terminal_size(max(20,min(cols,300)), max(5,min(rows,100)))

    def touch(self, session_id: str): self.get(session_id).last_activity=asyncio.get_running_loop().time()

    def expire_idle(self):
        now=asyncio.get_event_loop().time() if asyncio.get_event_loop().is_running() else 0
        for sid, session in list(self.sessions.items()):
            if now and now-session.last_activity > self.idle_seconds:
                session.process.close(); session.connection.close(); self.sessions.pop(sid,None)

    async def close(self, session_id: str):
        session = self.sessions.pop(session_id, None)
        if session:
            session.process.close(); session.connection.close(); await session.connection.wait_closed()
