import logging
import os
from pathlib import Path

from gui.guiUtilities import ToolsRunner


def getAtomSubdUrls(subdomain, workingDir):
    atomSbdUrls = set()
    for rootDir, dirs, files in os.walk(workingDir):
        for file in files:
            if file == "href_links":
                with open(file, "r") as f:
                    urls = f.readlines()
    for url in urls:
        if url.startsWith((f"https://{subdomain}", f"http://{subdomain}")):
            atomSbdUrls.add(url)
    return list(atomSbdUrls)



def atomGuiGetUrls(subdomain: str, workingDir, parent=None,
                   top_parent=None, mainWindow=None):
    # tools: Atom, getallUrls, linkFinder, xnLinkFinder(Atom)
    subdomain = subdomain.replace("\n", "").strip()
    UrlsList_ = set()
    pids = []
    pathName = "getAllUrls_" + subdomain + "Subdomains.txt"
    pathName = os.path.join(workingDir, pathName)
    if Path(pathName).exists():
        logging.info(f"Found {pathName}, Not running getAllUrls")
        with open(pathName, "r") as f:
            UrlsList = f.readlines()
            [UrlsList_.add(url) for url in UrlsList]
    else:
        ToolsRunner_ = ToolsRunner(workingDir, subdomain,
                                   tool="getAllUrls",
                                   parent=parent,
                                   top_parent=top_parent,
                                   mainWindow=mainWindow)
        g_pid = ToolsRunner_.runUrlToolsOnSd()
        pids.append(g_pid)

    pathName0 = "linkFinder_"+subdomain+"Subdomains.txt"
    pathName0 = os.path.join(workingDir, pathName0)
    if Path(pathName0).exists():
        logging.info(f"Found {pathName0}, Not running linkFinder")
        # link finder does not produce any urls it just produces output.html
    else:
        ToolsRunner_ = ToolsRunner(workingDir,
                                   subdomain,
                                   tool="LinkFinder",
                                   parent=parent,
                                   top_parent=top_parent,
                                   mainWindow=mainWindow)
        l_pid = ToolsRunner_.runUrlToolsOnSd()
        pids.append(l_pid)

    try:
        atomSubdUrls = getAtomSubdUrls(subdomain, workingDir)
        [UrlsList_.add(url) for url in atomSubdUrls]
    except UnboundLocalError as error:
        ToolsRunner_ = ToolsRunner(workingDir, subdomain, tool="Atom",
                                   parent=parent,
                                   top_parent=top_parent,
                                   mainWindow=mainWindow)
        a_pid = ToolsRunner_.runUrlToolsOnSd()
        pids.append(a_pid)

    if len(list(UrlsList_)) == 0:
        return tuple(pids)
    else:
        return list(UrlsList_)
    # runUrlToolsOnSd(workingDir, subdomain)


def atomGuiGetSubdomains(projectDirPath, toolName):
    filename = ""
    if toolName == "amass":
        filename = "amassSubdomains.txt"
    elif toolName == "sublist3r":
        filename = "sublisterSubdomains.txt"
    elif toolName == "subdomainizer":
        filename = "subdomainizerSubdomains.txt"
    filepath = os.path.join(projectDirPath + "/", filename).replace(" ", "")
    if not Path(filepath).exists():
        return False, None, None
    else:
        with open(filepath, "r") as file:
            list_subdomains = file.readlines()
            len_subdomains = len(list_subdomains)
            subdomiansStr = ""
            for subdomain in list_subdomains:
                subdomiansStr = subdomiansStr + subdomain
        if len_subdomains == 0:
            return False, None, None
        else:
            return True, subdomiansStr, len_subdomains
