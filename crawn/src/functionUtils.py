import os
from pathlib import Path


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