import logging
import os
import subprocess
import sys
from pathlib import Path
from urllib.parse import urlsplit

from PySide6.QtCore import QThread, QObject, Signal

from config.config import RUNDIR
from containers.docker_manager import manager as _docker_mgr, DockerUnavailableError
from containers.tool_registry import TOOL_REGISTRY
from utiliities import OpenProcess, runWhoisOnTarget


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
    def __init__(self,top_parent= None, server_name = None, project_dir_path = None) -> None:
        super().__init__()
        self.project_dir_path = project_dir_path
        self.whois_results_filename = os.path.join(self.project_dir_path, "whois_results")
        self.server_name = server_name
        self.topParent = top_parent
        self.setObjectName("whois runner")
        self.whois_results = ""
        self.topParent.threads.append(self)
        self.topParent.ThreadStarted.emit(self.topParent, self.objectName())

    def run(self):
        self.whois_results = runWhoisOnTarget(self.server_name, self.project_dir_path)
        with open(self.whois_results_filename, "wb") as file:
            file.write(self.whois_results)
        self.topParent.socketIpc.processFinishedExecution.emit(self.topParent, self.objectName())

class AtomProxy(QThread, QObject):
    def __init__(self, proxy_port, top_parent):
        super().__init__()
        self.topParent = top_parent
        self.proxy_port = proxy_port
        self.setObjectName("AtomProxy")
        self.process = 0
        self.topParent.threads.append(self)
        self.topParent.ThreadStarted.emit(self.topParent, self.objectName())

    def run(self):
        command= f"{sys.executable} {RUNDIR}src/proxyhandlerv3.py -p {self.proxy_port}"
        # self.process = subprocess.Popen(args=command, shell=True, cwd=RUNDIR + "/src/")
        self.process = OpenProcess(process_name="atomProxy", shell=True, cwd=RUNDIR + "/src/", args=command)
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

