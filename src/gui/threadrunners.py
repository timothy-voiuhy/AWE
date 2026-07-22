import logging
import os
import subprocess
import sys
import time
from pathlib import Path
from urllib.parse import urlsplit

from PySide6.QtCore import QThread, QObject, Signal

from config.config import RUNDIR
from containers.docker_manager import manager as _docker_mgr, DockerUnavailableError
from containers.tool_registry import TOOL_REGISTRY
from utilities import OpenProcess, runWhoisOnTarget


def _parent_chain(obj):
    current = obj
    seen = set()
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        yield current
        parent = getattr(current, "parent", None)
        current = parent() if callable(parent) else None


def _monitor_hub(obj):
    for current in _parent_chain(obj):
        if hasattr(current, "ThreadStarted") and hasattr(current, "socketIpc"):
            return current
        top_parent = getattr(current, "topParent", None) or getattr(current, "top_parent", None)
        if top_parent is not None and hasattr(top_parent, "ThreadStarted"):
            return top_parent
    return obj if hasattr(obj, "ThreadStarted") else None


def _thread_owner(obj):
    for current in _parent_chain(obj):
        if hasattr(current, "threads"):
            return current
    hub = _monitor_hub(obj)
    return hub if hub is not None and hasattr(hub, "threads") else None


def register_monitored_thread(thread: QThread, owner, name: str | None = None) -> QThread:
    """Register a QThread with AWE's app-level monitor under its owning window."""
    thread_owner = _thread_owner(owner)
    hub = _monitor_hub(owner)
    if thread_owner is None or hub is None:
        return thread

    base_name = name or thread.objectName() or thread.__class__.__name__
    thread_name = base_name
    sibling_names = {
        t.objectName() for t in getattr(thread_owner, "threads", [])
        if t is not thread
    }
    index = 2
    while thread_name in sibling_names:
        thread_name = f"{base_name} #{index}"
        index += 1
    thread.setObjectName(thread_name)

    if thread not in thread_owner.threads:
        thread_owner.threads.append(thread)

    thread._awe_started_at = time.time()
    thread._awe_thread_owner = thread_owner
    thread._awe_thread_hub = hub
    hub.ThreadStarted.emit(thread_owner, thread.objectName())

    def _finished():
        try:
            hub.socketIpc.processFinishedExecution.emit(thread_owner, thread.objectName())
        except RuntimeError:
            pass

    thread.finished.connect(_finished)
    return thread


# ── Docker-backed tool runner ─────────────────────────────────────────────────

class DockerToolRunner(QThread):
    """
    Generic QThread that runs a registered tool in a Docker container and
    streams its logs line-by-line via the `log` signal.
    Falls back to the native runner if Docker is unavailable.
    """
    log = Signal(str)
    finished_ok = Signal(str)   # tool display name
    finished_err = Signal(str)  # error message

    def __init__(self, tool_key: str, params: dict, output_dir: str):
        super().__init__()
        self._tool_key = tool_key
        self._params = params
        self._output_dir = output_dir

    def run(self):
        ok, reason = _docker_mgr.is_available()
        if not ok:
            self.finished_err.emit(f"Docker unavailable: {reason}")
            return

        tool = TOOL_REGISTRY[self._tool_key]
        try:
            if not _docker_mgr.image_exists(tool.image):
                self.log.emit(f"Image {tool.image} not found locally.")
                if tool.dockerfile:
                    self.log.emit(f"Building from {tool.dockerfile} …")
                    for line in _docker_mgr.build_image(tool.dockerfile, tool.image):
                        self.log.emit(line)
                else:
                    self.log.emit(f"Pulling {tool.image} …")
                    for status in _docker_mgr.pull_image(tool.image):
                        self.log.emit(status)

            command = tool.build_command(**self._params)
            volumes = tool.get_volumes(self._output_dir)
            name = tool.container_name()
            self.log.emit(f"Starting {name} …")
            c = _docker_mgr.run_container(
                image=tool.image,
                command=command,
                name=name,
                volumes=volumes,
            )
            for line in _docker_mgr.stream_logs(c.id):
                self.log.emit(line)
            self.finished_ok.emit(tool.display_name)
        except Exception as exc:
            self.finished_err.emit(str(exc))

class WhoisThreadRunner(QThread):
    def __init__(
        self,
        top_parent=None,
        server_name=None,
        project_dir_path=None,
        thread_owner=None,
    ) -> None:
        super().__init__()
        self.project_dir_path = project_dir_path
        self.whois_results_filename = os.path.join(self.project_dir_path, "whois_results")
        self.server_name = server_name
        self.topParent = top_parent
        self.thread_owner = thread_owner or top_parent
        self.setObjectName("whois runner")
        self.whois_results = ""
        register_monitored_thread(self, self.thread_owner)

    def run(self):
        self.whois_results = runWhoisOnTarget(self.server_name, self.project_dir_path)
        with open(self.whois_results_filename, "wb") as file:
            file.write(self.whois_results)

class AtomProxy(QThread, QObject):
    def __init__(self, proxy_port, top_parent, upstream_proxy: str | None = None):
        super().__init__()
        self.topParent      = top_parent
        self.proxy_port     = proxy_port
        self.upstream_proxy = upstream_proxy
        self.setObjectName("AtomProxy")
        self.process = 0
        self.topParent.threads.append(self)
        self.topParent.ThreadStarted.emit(self.topParent, self.objectName())

    def run(self):
        # shell=False so terminate() hits the Python process directly, not a shell wrapper
        cmd = [sys.executable, "-m", "proxy.server", "-p", str(self.proxy_port)]
        if self.upstream_proxy:
            cmd += ["--upstream-proxy", self.upstream_proxy]
        self.process = OpenProcess(
            process_name="atomProxy", shell=False,
            cwd=RUNDIR + "src/", args=cmd,
        )
        self.process.wait()
        self.topParent.socketIpc.processFinishedExecution.emit(self.topParent, self.objectName())


class SessionHandlerRunner(QThread, QObject):
    def __init__(self, top_parent):
        super().__init__()
        self.top_parent = top_parent
        self.command = f"{sys.executable} {RUNDIR}src/session.py"
        self.setObjectName("SessionHandler")
        self.process = 0
        self.top_parent.threads.append(self)
        self.top_parent.ThreadStarted.emit(self.top_parent, self.objectName())

    def run(self):
        # self.process = subprocess.Popen(self.command, shell=True)
        self.process = OpenProcess(process_name="sessionHandler", shell=True, args=self.command)
        self.process.wait()
        self.top_parent.socketIpc.processFinishedExecution.emit(self.top_parent, self.objectName())
