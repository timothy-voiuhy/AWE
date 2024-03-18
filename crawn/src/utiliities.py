from termcolor import colored
import requests
import timeit
import logging
import json
import re
from colorlog import ColoredFormatter
import os
from phply import phplex, phpast
from pathlib import Path

# from utils import is_mac, is_linux, is_windows
import subprocess
from concurrent.futures.process import ProcessPoolExecutor


# def check_system():
#     if is_windows:
#         print(green("DETECTED: windows"))
#     if is_mac:
#         print(green("DETECTED mac os"))
#     if is_linux:
#         print(green("DETECTED linux"))
# colors
def red(text):
    return colored(text, "red", attrs=["bold"])


def green(text):
    return colored(text, "green", attrs=["bold"])


def yellow(text):
    return colored(text, "yellow", attrs=["bold"])


def cyan(text):
    return colored(text, "cyan", attrs=["bold"])


def internet_check() -> bool:
    try:
        response = requests.get("https://www.google.com/")
        if response.status_code == 200:
            return True
    except:
        return False


def rm_same(file):
    """definition: reads a file and removes the line duplicates and leaves only one"""
    try:
        with open(file, "r") as f:
            links = f.readlines()
            f.close()
        newlinks = []
        seen_links = set()
        for link in links:
            if link not in seen_links:
                newlinks.append(link)
                seen_links.add(link)
        with open(file, "w") as g:
            g.writelines(newlinks)
            g.close()
    except FileNotFoundError:
        print(f"file {file} not found")


def parse_php_code(php_code):
    lexer = phplex.lexer
    parser = phpast.parser
    # Tokenize the PHP code
    tokens = lexer.lex(php_code)
    # Parse the tokens
    parsed_code = parser.parse(tokens, lexer=lexer)
    return parsed_code


# logging.basicConfig(filename="ROOTLOG.log", level=logging.INFO)


def makelogger(
    logger_name: str, filename: str, level=logging.INFO, projectDir=None
) -> logging.Logger:
    logsDir = os.path.join(projectDir, "LOGS/")
    if os.path.isdir(logsDir):  # save all the log files in the LOGS directory
        pass
    else:
        os.mkdir(logsDir)

    _logger = logging.getLogger(logger_name)
    # Check if a handler with the same filename already exists
    for handler in _logger.handlers:
        if (
            isinstance(handler, logging.FileHandler)
            and handler.baseFilename == filename
        ):
            return _logger  # Logger already configured for this file
    _logger.setLevel(level)
    filepath = logsDir + filename
    _file_logger = logging.FileHandler(filepath)
    _file_logger.setLevel(level)
    # formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    formatter = ColoredFormatter(
        "%(log_color)s%(levelname)-8s%(reset)s %(log_color)s%(message)s",
        datefmt=None,
        reset=True,
        log_colors={
            "DEBUG": "cyan",
            "INFO": "green",
            "WARNING": "yellow",
            "ERROR": "red",
            "CRITICAL": "red,bg_white",
        },
    )
    _file_logger.setFormatter(formatter)
    _logger.addHandler(_file_logger)
    return _logger


class HTTP_HEADER(object):
    ACCEPT = "Accept"
    ACCEPT_CHARSET = "Accept-Charset"
    ACCEPT_ENCODING = "Accept-Encoding"
    ACCEPT_LANGUAGE = "Accept-Language"
    AUTHORIZATION = "Authorization"
    CACHE_CONTROL = "Cache-Control"
    CONNECTION = "Connection"
    CONTENT_ENCODING = "Content-Encoding"
    CONTENT_LENGTH = "Content-Length"
    CONTENT_RANGE = "Content-Range"
    CONTENT_TYPE = "Content-Type"
    COOKIE = "Cookie"
    EXPIRES = "Expires"
    HOST = "Host"
    IF_MODIFIED_SINCE = "If-Modified-Since"
    IF_NONE_MATCH = "If-None-Match"
    LAST_MODIFIED = "Last-Modified"
    LOCATION = "Location"
    PRAGMA = "Pragma"
    PROXY_AUTHORIZATION = "Proxy-Authorization"
    PROXY_CONNECTION = "Proxy-Connection"
    RANGE = "Range"
    REFERER = "Referer"
    REFRESH = "Refresh"  # Reference: http://stackoverflow.com/a/283794
    SERVER = "Server"
    SET_COOKIE = "Set-Cookie"
    TRANSFER_ENCODING = "Transfer-Encoding"
    URI = "URI"
    USER_AGENT = "User-Agent"
    VIA = "Via"
    X_POWERED_BY = "X-Powered-By"
    X_DATA_ORIGIN = "X-Data-Origin"


class AmassSubdProcessor:
    def __init__(self, domain=None, max_retries=2, workingDir=None) -> None:
        self.workingDir = workingDir
        self.homeDir = os.path.expanduser("~")
        self.projectDir = os.path.join(self.homeDir, self.workingDir)
        self.namerecords = [
            "a_record",
            "cname_record",
            "mx_record",
            "ns_record",
            "ptr_record",
            "aaa_record",
        ]
        self.name_records = []
        [
            self.name_records.append(os.path.join(
                self.projectDir, namerecord + ".txt"))
            for namerecord in self.namerecords
        ]
        self.file_path_names = [
            "a_records",
            "cname_records",
            "mx_records",
            "ns_records",
            "ptr_records",
            "aaa_records",
        ]
        self.file_namerecord_dict = {}
        for name_record, filepathname in zip(self.name_records, self.file_path_names):
            pathname = os.path.join(self.projectDir, filepathname + ".txt")
            self.file_namerecord_dict[name_record] = pathname
        self.domain = domain
        self.results_file = os.path.join(self.projectDir, "amass_.txt")
        if not Path(self.results_file).exists():
            with open(self.results_file, "a") as file:
                file.close()
        self.cwd = self.projectDir
        self.MAX_RETRIES = max_retries
        self.dicts_file = os.path.join(
            self.projectDir, "amass_dicts_file.json")
        if Path(self.dicts_file).exists():
            os.remove(self.dicts_file)
            with open(self.dicts_file, "a") as file:
                file.close()
        else:
            with open(self.dicts_file, "a") as file:
                file.close()
        self.jsondict = {}
        self.jsondict["data"] = []
        self.emcpDataFile = os.path.join(self.projectDir, "emcpData.json")
        if Path(self.emcpDataFile).exists():
            os.remove(self.emcpDataFile)
        else:
            with open(self.emcpDataFile, "a") as file:
                file.close()

    def GetAmassSubdomains(self, active: bool = False):
        """runs amass on the domain you provide and returns the file in which it is saved"""
        if active:
            command = "amass enum -brute -min-for-recursive 2 -d " + self.domain
        else:
            command = "amass enum -d " + self.domain
        print(f"{green('running ')}{cyan(command)}")

        with open(self.results_file, "a") as file:
            for n in range(self.MAX_RETRIES):
                subprocess.run(
                    command, shell=True, stdin=None, stdout=file, cwd=self.cwd
                )
                file.close()
                with open(self.results_file) as file_:
                    lines = file_.readlines()
                    if lines[0] == "No assets were discovered":
                        print(yellow("No assets were discovered"))
                        print(cyan("Retrying"))
                        continue
                    else:
                        break

    def search(self, line: str, file_lines: list) -> bool:
        """search for a line in the file lines and get its index"""
        idx = int(0)
        # print(file_lines)
        while idx < len(file_lines):
            if line == file_lines[idx]:
                break
            elif idx == len(file_lines) - 1:
                return True
            idx = idx + 1

    def compare_append_line_file(self, line: str, file: str):
        """check for the presence of a line in in a file and if it is
        not there then add or else do not"""
        with open(file, "r") as f:
            file_lines = f.readlines()
            f.close()
            if self.search(line=line, file_lines=file_lines):
                with open(file, "a") as h:
                    h.write(line + "\n")

    def getManagerAsnDict(self, from_file: str):
        with open(from_file, "r") as file:
            lines = file.readlines()
            pattern = pattern = "\d+\s\(ASN\)\s\D+\s"
            managerAsnDicts = {}
            for line in lines:
                if (
                    "managed_by" in line
                    and not "Not routed " in line
                    and not "Unknown" in line
                ):
                    line = line.replace("--> managed_by -->", "")
                    if re.match(pattern, line) is not None:
                        # print(line)
                        manager = re.findall(" \D+ -", line)[0]
                        manager = manager.replace(
                            "(ASN)", "").replace("-", "").strip()
                        asn = re.findall("\d+\s", line)[0]
                        if asn not in managerAsnDicts:
                            managerAsnDicts[manager] = []
                        managerAsnDicts[manager].append(asn.strip())
            self.jsondict["data"].append(managerAsnDicts)

    def getAsnNetblockDict(self, from_file: str):
        # for each asn get the netblocks that are in them.
        with open(from_file, "r") as file:
            lines = file.readlines()
            pattern = (
                pattern
            ) = "\d+\s\(ASN\) --> announces --> \d+\.\d+\.\d+\.\d+\/\d+ \(Netblock\)"
            asnNetblockDicts = {}
            for line in lines:
                if re.match(pattern, line) is not None:
                    asn = re.findall("\d+\s", line)[0]
                    netblock = re.findall("\d+\.\d+\.\d+\.\d+\/\d+\s", line)[0]
                    if asn not in asnNetblockDicts:
                        asnNetblockDicts[asn] = []
                    asnNetblockDicts[asn].append(netblock.strip())
            self.jsondict["data"].append(asnNetblockDicts)

    def getSubdomainIpDict(self, from_file: str, name_record):
        # for each subdomain get the matching ip
        try:
            rm_same(from_file)
            with open(from_file, "r") as file:
                lines = file.readlines()
                MainSubdomainIpDict = {}
                SubdomainIpDict = {}
                for line in lines:
                    try:
                        subdomain = line.split(" ")[0]
                        ip = line.split(
                            " ",
                        )[-2]
                        if subdomain not in SubdomainIpDict:
                            SubdomainIpDict[subdomain] = []
                        SubdomainIpDict[subdomain].append(ip.strip())
                    except IndexError:
                        continue
                MainSubdomainIpDict[name_record] = SubdomainIpDict
                self.jsondict["data"].append(MainSubdomainIpDict)
        except FileNotFoundError:
            print(f"file {from_file} does not exists")

    def getNetblockIpDict(self, from_file: str):
        # for each  netblock get the ips in it
        with open(from_file, "r") as file:
            lines = file.readlines()
            pattern = (
                pattern
            ) = "\d+\.\d+\.\d+\.\d\/\d+ \(Netblock\) --> contains --> \d+\.\d+\.\d+\.\d+ \(IPAddress\)"
            NetblocksIpsDicts = {}
            for line in lines:
                if re.match(pattern, line) is not None:
                    netblock = re.findall("\d+\.\d+\.\d+\.\d\/\d+", line)[0]
                    ip = re.findall("\d+\.\d+\.\d+\.\d+\s", line)[0]
                    if netblock not in NetblocksIpsDicts:
                        NetblocksIpsDicts[netblock] = []
                    NetblocksIpsDicts[netblock].append(ip.strip())
            self.jsondict["data"].append(NetblocksIpsDicts)

    def createPerSubDomainData(self):
        with open(self.dicts_file, "r") as dicts_file:
            dictsData = dicts_file.read()
            dicts_file.close()
        dictsData_ = list(dict(json.loads(dictsData)).values())[
            0]  # [data_dict]
        NetblockIpDict = dictsData_[0]  # dictionary {netblock: [ips]}
        AsnNetblockDict = dictsData_[1]  # {asn: [netblocks]}
        ManagerAsnDict = dictsData_[2]  # {manager: [asns]}

        # iterate over the record_names and ip_lists
        idx = 3
        subdomainsCmp = []
        for record_name, ip_list in zip(
            list(list(dictsData_[idx].values())[0].keys()),
            list(list(dictsData_[idx].values()[0].values())),
        ):
            for domain in record_name:
                domainInfo = {
                    "subdomain": domain,
                    "namerecord": "",
                    "ip": "",
                    "netblock": "",
                    "asn": "",
                    "manager": "",
                }
                domain_index = record_name.index(domain)
                for netb in NetblockIpDict:
                    for ip in ip_list:
                        if ip in NetblockIpDict[netb]:
                            domainInfo["netblock"] = netb.strip()
                            break
                for asn, netblocks in AsnNetblockDict.items():
                    if domainInfo["netblock"] in netblocks:
                        domainInfo["asn"] = asn.strip()
                        break
                for manager, asns in ManagerAsnDict.items():
                    if domainInfo["asn"] in asns:
                        domainInfo["manager"] = manager.strip()
                        break
                domainInfo["ip"] = ip_list[domain_index]

                subdomainsCmp.append(domainInfo)
            idx += 1
        emcp = {}
        emcp["data"] = subdomainsCmp
        json_emcp = json.dumps(emcp, indent=4)
        with open(self.emcpDataFile, "a") as file:
            file.write(json_emcp)
        return subdomainsCmp

    def create_name_record_files(self, from_file: str):
        """description: create new record files from the given file containing lines
        from amass"""
        a_recordsPath = os.path.join(self.projectDir, "a_records.txt")
        checkpath = Path(a_recordsPath)
        if checkpath.exists():
            idx = 0
            while idx < len(list(self.file_namerecord_dict.keys())):
                path = Path(list(self.file_namerecord_dict.values())[idx])
                if path.exists():
                    with open(from_file, "r") as file:
                        lines = file.readlines()  # retrieve all the lines
                        file.close()  # close the file
                        for line in lines:
                            if list(self.file_namerecord_dict.keys())[idx] in line:
                                self.compare_append_line_file(
                                    line, list(self.file_namerecord_dict.values())[
                                        idx]
                                )
                idx = idx + 1
        else:
            with open(from_file, "r") as file:
                lines = file.readlines()  # retrieve all the lines
                file.close()  # close the file
                for line in lines:
                    for name_record in self.name_records:
                        if name_record in line:
                            with open(name_record + "s", "a") as c:
                                c.write(line)


    def SaveAmassSubdomains(self):
        with open(self.emcpDataFile, "r") as file:
            data = file.read()
            jsonData = dict(json.loads(data))
            emcpData = jsonData["data"]
            subdomains = ""
            sub_l = set()
            len_subdomains = len(emcpData)
            for domain in emcpData:
                urlDomain = domain["subdomain"]
                if urlDomain not in sub_l:
                    sub_l.add(urlDomain)
                    subdomains = subdomains + urlDomain + "\n"
        filepath = os.path.join(self.projectDir, "amassSubdomains.txt")
        with open(filepath, "a") as file:
            file.write(subdomains)

    def parseAmassData(self):
        self.create_name_record_files(str(self.results_file))
        self.getNetblockIpDict(str(self.results_file))
        self.getAsnNetblockDict(str(self.results_file))
        self.getManagerAsnDict(str(self.results_file))
        for filename in self.file_path_names:
            filename_index = self.file_path_names.index(filename)
            namerecord = self.name_records[filename_index]
            self.getSubdomainIpDict(str(filename), name_record=namerecord)
        stringfiedJsonDict = json.dumps(self.jsondict, indent=4)
        with open(self.dicts_file, "a") as file_:
            file_.write(stringfiedJsonDict)
        self.createPerSubDomainData()
        self.SaveAmassSubdomains()

    def Run(self, run=False, parse=False):
        if run:
            self.GetAmassSubdomains()
        elif parse:
            self.parseAmassData()
        else:
            self.GetAmassSubdomains()
            self.parseAmassData()


class NoneResException(Exception):
    pass


def CheckCreatePath(path_: str):
    path = Path(path_)
    path_cmps = os.path.split(path)
    if os.path.isdir(path_cmps[0]):
        return path_
    else:
        if not os.path.isdir(path_cmps[0]):
            os.makedirs(path_cmps[0])
            return path_


def RxnLinkFinder(
    url: str,
    depth=2,
    scope: list = None,
    output_dir="./LinkFinderResults/",
    cookies: dict = None,
    n_processes: int = None,
    output_file="./LinkFinderResults/url_endpoits.txt",
):
    print(output_dir)
    wordlist_path = CheckCreatePath(output_dir + "wordlist.txt")
    params_path = CheckCreatePath(output_dir + "params.txt")
    # output_file = CheckCreatePath(output_file)
    print(output_file)
    scopeadd_str = ""
    if scope is not None:
        for domain in scope:
            if scope.index(domain) == 0:
                scopeadd_str = scopeadd_str + domain
            else:
                scopeadd_str = scopeadd_str + "," + domain
        command = (
            "./Tools/xnLinkFinder/xnLinkFinder.py -i "
            + url
            + " -o "
            + output_file
            + " -sf "
            + scopeadd_str
            + " -d "
            + str(depth)
            + " --output-wordlist "
            + wordlist_path
            + " --output-params "
            + params_path
        )
    else:
        command = (
            "./Tools/xnLinkFinder/xnLinkFinder.py -i "
            + url
            + " -o "
            + output_file
            + " -d "
            + str(depth)
            + " --output-wordlist "
            + wordlist_path
            + " --output-params "
            + params_path
        )
    if cookies is not None:
        cookie_keys = list(cookies.keys())
        cookie_values = list(cookies.values())
        cookie_str = ""
        key_index = 0
        for key in cookie_keys:
            cookie_str = cookie_str + key + ":" + \
                cookie_values[key_index] + ";"
            key_index += 1
        command = command + " -c " + cookie_str
    else:
        command = command
    if n_processes is not None:
        command = command + " -p " + str(n_processes)
    else:
        command = command
    command = command + " --no-banner"
    print(f"{yellow('Running ')}{command}{yellow(' on ')}{yellow(domain)}")
    subprocess.run(command, shell=True, stdout=None, stdin=None, cwd="./")


def RunNuclei():
    pass


class SublisterRunner:
    """ "  -d DOMAIN, --domain DOMAIN
                          Domain name to enumerate it's subdomains
    -b [BRUTEFORCE], --bruteforce [BRUTEFORCE]
                          Enable the subbrute bruteforce module
    -p PORTS, --ports PORTS
                          Scan the found subdomains against specified tcp ports
    -v [VERBOSE], --verbose [VERBOSE]
                          Enable Verbosity and display results in realtime
    -t THREADS, --threads THREADS
                          Number of threads to use for subbrute bruteforce
    -e ENGINES, --engines ENGINES
                          Specify a comma-separated list of search engines
    -o OUTPUT, --output OUTPUT
                          Save the results to text file
    -n, --no-color        Output without color"""

    def __init__(
        self,
        domain,
        projectDirPath:str,
        threads,
        search_engines:list = None,
        bruteforce:bool=False,
        ports:list=None,
    ):
        self.domain = domain
        self.projectDirPath = projectDirPath
        self.save_file = os.path.join(
            self.projectDirPath, "sublisterSubdomains.txt")
        self.threads = threads
        self.bruteforce = bruteforce
        self.search_engines = search_engines
        self.ports = ports

    def RunOnDomain(self):
        command = "sublist3r" + " -d " + self.domain + " -o " + self.save_file
        if self.search_engines is not None:
            search_engine_string = ""
            for engine in self.search_engines:
                if self.search_engines.index(engine) == len(self.search_engines) - 1:
                    search_engine_string = search_engine_string + engine
                else:
                    search_engine_string = search_engine_string + engine + ","
            command = command +" -e " +search_engine_string
        if self.bruteforce:
            command = command + " -b "

        if self.ports is not None:
            ports = ""
            for port in self.ports:
                if self.ports.index(port) == len(self.ports)-1:
                    ports = ports + port
                else:
                    ports = ports + port+","
                
            command  = command + " -p " + ports

        if self.threads is not None:
            command  = command + " -t " +str(self.threads) 

        print(yellow(f"Running sublist3r with command: {cyan(command)}"))
        subprocess.Popen(
            command,
            shell=True,
        )


class SubDomainizerRunner:
    def __init__(self, url, projectDirPath, cookies=None) -> None:
        self.projectDirPath = projectDirPath
        self.subDomainFile = os.path.join(
            self.projectDirPath, "subdomainizerSubdomains.txt")
        if not Path(self.subDomainFile).exists():
            with open(self.subDomainFile, "a") as file:
                file.close()
        self.url = url
        self.cookies = cookies

    def Run(self):
        command = (
            "python /media/program/01DA55CA5F28E000/MYAPPLICATIONS/AWE/AWE/crawn/Tools/SubDomainizer/SubDomainizer.py "
            + " -u "
            + self.url
            + " -o "
            + self.subDomainFile
            + " -k"
        )
        if self.cookies is not None:
            command = command + "-c " + self.cookies
        subprocess.Popen(command, shell=True)


def addHttpsScheme(url: str):

    if not url.endswith("/"):  # add trailing line character
        url = url + "/"
    if not url.startswith(("https://", "http://")):  # add scheme if does not exist
        url = "https://" + url
    return url