import logging
import subprocess
from PySide6.QtCore import QThread, QObject
from config import RUNDIR
from utiliities import AmassSubdProcessor, SubDomainizerRunner, yellow, SublisterRunner, OpenProcess

class AmassThreadRunner(QThread):
    def __init__(self, amassUrlTarget, projectDirPath):
        super().__init__()
        self.setObjectName("AmassThreadRunner")
        self.amassUrlTarget = amassUrlTarget
        self.projectDirPath = projectDirPath

    def amassRun(self):
        amassProcessor = AmassSubdProcessor(
            domain=self.amassUrlTarget, workingDir=self.projectDirPath
        )
        amassProcessor.Run()

    def run(self) -> None:
        self.amassRun()
        # return super().run()


class SubdomainizerThreadRunner(QThread):
    def __init__(self, subDomainizerUrlTarget, projectDirPath):
        super().__init__()
        self.setObjectName("SubdomainizerThreadRunner")
        self.subDomainizerUrlTarget = subDomainizerUrlTarget
        self.projectDirPath = projectDirPath

    def subdomainizerRun(self):
        self.subDomainizerRunner = SubDomainizerRunner(
            self.subDomainizerUrlTarget, self.projectDirPath
        )
        self.subDomainizerRunner.Run()

    def run(self) -> None:
        self.subdomainizerRun()
        logging.info(yellow("Subdomaizer finished running"))


class Sublist3rThreadRunner(QThread):
    def __init__(
            self,
            domain,
            projectDirPath,
            bruteforce: bool = None,
            searchengines: list = None,
            threads: int = None,
            ports: list = None,
    ):
        super().__init__()
        self.setObjectName("Sublist3rThreadRunner")
        self.domain = domain
        self.projectDirPath = projectDirPath
        self.bruteforce = bruteforce
        self.searchengines = searchengines
        self.threads = threads
        self.ports = ports

    def sublist3rRun(self):
        self.sublisterRunner = SublisterRunner(
            self.domain,
            self.projectDirPath,
            bruteforce=self.bruteforce,
            search_engines=self.searchengines,
            threads=self.threads,
            ports=self.ports,
        )
        self.sublisterRunner.RunOnDomain()

    def run(self) -> None:
        self.sublist3rRun()
        print(yellow("Sublister finished running"))


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
        command= f"python {RUNDIR}/src/proxyhandlerv3.py -p {self.proxy_port}"
        self.process = subprocess.Popen(args=command, shell=True, cwd=RUNDIR + "/src/")
        # self.process = OpenProcess(process_name="atomProxy", shell=True, cwd=RUNDIR + "/src/", args=command)
        self.process.wait()
        self.topParent.socketIpc.processFinishedExecution.emit(self.topParent, self.objectName())
        