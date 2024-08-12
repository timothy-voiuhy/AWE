import logging
import os
import subprocess
import sys
from pathlib import Path
from urllib.parse import urlsplit

from PySide6.QtCore import QThread, QObject

from config.config import RUNDIR
from utiliities import AmassSubdProcessor, SubDomainizerRunner, yellow, SublisterRunner, OpenProcess, red, runWhoisOnTarget

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

class AmassThreadRunner(QThread):
    def __init__(self, amassUrlTarget, projectDirPath, main_window, top_parent, only_parse_data = False):
        super().__init__()
        self.only_parse_data = only_parse_data
        self.topParent = top_parent
        self.main_window = main_window
        self.setObjectName("AmassThreadRunner")
        self.amassUrlTarget = amassUrlTarget
        self.projectDirPath = projectDirPath
        self.main_window.threads.append(self)
        self.topParent.ThreadStarted.emit(self.main_window, self.objectName())

    def amassRun(self):
        amassProcessor = AmassSubdProcessor(
            domain=self.amassUrlTarget, workingDir=self.projectDirPath
        )
        if self.only_parse_data is True:
            amassProcessor.Run(parse=True)
        else:
            amassProcessor.Run()
        self.topParent.socketIpc.processFinishedExecution.emit(self.main_window, self.objectName())

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
        # self.process = subprocess.Popen(args=command, shell=True, cwd=RUNDIR + "/src/")
        self.process = OpenProcess(process_name="atomProxy", shell=True, cwd=RUNDIR + "/src/", args=command)
        self.process.wait()
        self.topParent.socketIpc.processFinishedExecution.emit(self.topParent, self.objectName())


class SessionHandlerRunner(QThread, QObject):
    def __init__(self, top_parent):
        super().__init__()
        self.top_parent = top_parent
        self.command = f"python {RUNDIR}src/session.py"
        self.setObjectName("SessionHandler")
        self.process = 0
        self.top_parent.threads.append(self)
        self.top_parent.ThreadStarted.emit(self.top_parent, self.objectName())

    def run(self):
        # self.process = subprocess.Popen(self.command, shell=True)
        self.process = OpenProcess(process_name="sessionHandler", shell=True, args=self.command)
        self.process.wait()
        self.top_parent.socketIpc.processFinishedExecution.emit(self.top_parent, self.objectName())

class AtomRunner(QThread):
    def __init__(self, subdomain,
                 usehttp,
                 useBrowser,
                 parent = None,
                 projectDirPath=None,
                 top_parent = None,
                 objectName = None,
                 mainWindow= None) -> None:
        super().__init__()
        self.mainWindow = mainWindow
        self.setObjectName(objectName)
        self.topParent = top_parent
        self.parent = parent
        self.projectDirPath = projectDirPath
        self.subdomain = subdomain
        self.usehttp = usehttp
        self.usebrowser = useBrowser
        self.recursive = True
        self.pid = 0
        self.process = 0
        self.command  = f"python {RUNDIR + 'src/atomcore.py'} -d {self.subdomain} --dirr {self.subdomain} -p {self.projectDirPath}"
        if self.usehttp is True:
            self.command  = self.command + " --use_http"
        if self.usebrowser is True:
            self.command  = self.command + " --use_browser"
        self.mainWindow.threads.append(self)
        self.topParent.ThreadStarted.emit(self.mainWindow, self.objectName())

    def getPid(self):
        return self.pid

    def run(self):
        # self.runAtom()
        self.process = subprocess.Popen(self.command, shell=True)
        self.pid = self.process.pid
        self.parent.atomRunnerPid = self.process.pid
        self.process.wait()
        self.topParent.socketIpc.processFinishedExecution.emit(self.mainWindow, self.objectName())


class getAllUrlsRunner(QThread):
    def __init__(self, workingDir,
                 subdomain,
                 parent=None,
                 top_parent=None,
                 mainWindow=None):
        super().__init__()
        self.mainWindow = mainWindow
        self.topParent = top_parent
        self.parent = parent
        self.setObjectName("getAllUrlsRunner")
        self.subdomain = subdomain
        self.workingDir = workingDir
        self.pid = 0
        self.process = 0
        self.savePathName = "getAllUrls_" + self.subdomain + "Subdomains.txt"
        self.savePath = os.path.join(self.workingDir, self.savePathName)
        self.mainWindow.threads.append(self)
        self.topParent.ThreadStarted.emit(self.mainWindow, self.objectName())

    def getPid(self):
        return self.pid

    def parseOutput(self):
        newfileLines = []
        if Path(self.savePath).exists():
            with open(self.savePath, "r") as f:
                fileLines = f.readlines()
                seen_structs = []
                seen_urls = []
                for url in fileLines:
                    if not url.endswith((".js", ".pdf", ".css", ".txt", ".png", ".svg", "ico")):
                        url_cmps = urlsplit(url)
                        url_path = url_cmps[1] + url_cmps[2]
                        if "?" in url:
                            if "&" in url_cmps[3]:
                                url_paramsets = url_cmps[3].split("&")
                            else:
                                url_paramsets = url_cmps[3].split(";")
                            url_params_dict = {}
                            for url_paramset in url_paramsets:
                                try:
                                    split_url_paramset = url_paramset.split("=")
                                    key = split_url_paramset[0]
                                    value = split_url_paramset[1]
                                    url_params_dict[key] = value
                                except:
                                    pass
                            url_params_struct = list(url_params_dict.keys())
                            url_struct = [url_path, url_params_struct]
                            if url_struct not in seen_structs:
                                newfileLines.append(url)
                                seen_structs.append(url_struct)
                        else:
                            if url_path not in seen_urls:
                                newfileLines.append(url)
                                seen_urls.append(url_path)
            with open(self.savePath, "w") as file:
                file.writelines(newfileLines)

    def run(self) -> None:
        command = "getallurls " + self.subdomain + " > " + self.savePath
        print(red(f"Running getallurls with command:\n\t {command}"))
        self.process = subprocess.Popen(command, shell=True)
        self.pid = self.process.pid
        self.parent.getAllUrlsRunnerPid = self.process.pid
        # self.sleep(2)
        self.process.wait()
        self.topParent.socketIpc.processFinishedExecution.emit(self.mainWindow, self.objectName())
        self.parseOutput()


class LInkFinderRunner(QThread):
    def __init__(self, workingDir,
                 subdomain: str,
                 top_parent,
                 parent=None,
                 mainWindow=None
                 ):
        super().__init__()
        self.mainWindow = mainWindow
        self.topParent = top_parent
        self.parent = parent
        self.setObjectName("LinkFinderRunner")
        self.workingDir = workingDir
        self.subdomain = subdomain
        self.pid = 0
        self.process = 0
        self.savePathName = "linkFinder_" + self.subdomain + "Subdomains.txt"
        self.savePath = os.path.join(self.workingDir, self.savePathName)
        self.linkfinder = RUNDIR + "Tools/LinkFinder/linkfinder.py"
        if sys.platform == "win32":
            self.linkfinder = RUNDIR + "Tools\\LinkFinder\\linkfinder.py"

    def getPid(self):
        return self.pid

    def linkFinderRun(self):
        self.subdomain = "https://" + self.subdomain.strip()
        command = f"python {self.linkfinder} -i {self.subdomain} -d -o {self.savePath} -t 20"
        print(red(f"running linkFinder with command:\n\t {command}"))
        self.process = subprocess.Popen(command, shell=True)
        self.parent.linkFinderRunnerPid = self.process.pid
        self.pid = self.process.pid
        self.process.wait()

    def run(self) -> None:
        self.linkFinderRun()
        self.topParent.socketIpc.processFinishedExecution.emit(self.mainWindow, self.objectName())