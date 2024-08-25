import hashlib
import json
import logging
import os
import re
import subprocess
from pathlib import Path
from urllib import parse as urlparser
import requests
from colorlog import ColoredFormatter
from phply import phplex, phpast
from scapy.interfaces import get_working_ifaces
from termcolor import colored

def log_exceptions(func):
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except Exception as e:
            logging.error("Encoutering error", exc_info=True)
            raise
        return wrapper

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
    """sends a get request to https://www.google.com and if the response is 200 then 
    True is retured indicating that thei is an internet connnection"""
    try:
        response = requests.get("https://www.google.com/")
        if response.status_code == 200:
            return True
    except:
        return False


def rm_same(file):
    """definition: reads a file and removes the line duplicates and leaves only one"""
    if os.path.exists(file):
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
        return True
    else:
        logging.error(f"file {file} not found")
        return False



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
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
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
        self.results_file = os.path.join(self.projectDir, "amass_.txt")
        self.namerecords = [
            "a_record",
            "cname_record",
            "mx_record",
            "ns_record",
            "ptr_record",
            "aaa_record",
        ]

        self.file_names = [
            "a_records.txt",
            "cname_records.txt",
            "mx_records.txt",
            "ns_records.txt",
            "ptr_records.txt",
            "aaa_records.txt",
        ]

        # scan the file to find out the records that do not exist and remove them from the two lists
        with open(self.results_file, "r") as results_file:
            amass_data = results_file.read()
        for record_index, name_record in enumerate(self.namerecords):
            if name_record not in amass_data:
                self.namerecords.remove(name_record)
                self.file_names.remove(self.file_names[record_index])
        del amass_data

        self.file_namerecord_dict = {}
        for name_record, file_name in zip(self.namerecords, self.file_names):
            pathname = os.path.join(self.projectDir, file_name)
            self.file_namerecord_dict[name_record] = pathname
        self.domain = domain
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
        self.subdomain_dicts_file = os.path.join(self.projectDir, "amassSubdomains.txt")
        if Path(self.emcpDataFile).exists():
            os.remove(self.emcpDataFile)
        else:
            with open(self.emcpDataFile, "a") as file:
                file.close()

    def GetAmassSubdomains(self, active: bool = False):
        """runs amass on the domain you provide and returns the file in which it is saved"""
        if active:
            command = "docker run -v OUTPUT_DIR_PATH:/.config/amass/ caffix/amass enum -brute -min-for-recursive 2 -d " + self.domain
        else:
            command = "docker run -v OUTPUT_DIR_PATH:/.config/amass/ caffix/amass enum -d " + self.domain
        logging.info(f"running command {command}")

        with open(self.results_file, "a") as file:
            for n in range(self.MAX_RETRIES):
                self.process = OpenProcess(process_name="AmassRunner",
                    shell=True, stdin=None, stdout=file, cwd=self.cwd, args=command)
                self.process.wait()
                
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
        if Path(file).exists():
            with open(file, "r") as f:
                file_lines = f.readlines()
            if self.search(line=line, file_lines=file_lines):
                with open(file, "a") as h:
                    h.write(line + "\n")
        else:
            with open(file, "a") as h:
                h.write(line+"\n")

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
                    asn_manager_list = line.split("--> managed_by -->")
                    if re.match(pattern, line) is not None:
                        manager = asn_manager_list[1].strip()
                        asn = asn_manager_list[0].replace("(ASN)", "").strip()
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
            if rm_same(from_file):
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
        except Exception as e:
            logging.error(f"encountered error {e}")

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
        dictsData_ = list(dict(json.loads(dictsData)).values())[0]  # [data_dict]
        NetblockIpDict = dictsData_[0]  # dictionary {netblock: [ips]}
        AsnNetblockDict = dictsData_[1]  # {asn: [netblocks]}
        ManagerAsnDict = dictsData_[2]  # {manager: [asns]}

        # iterate over the record_names and ip_lists
        idx = 3 # this is where the name_records start from
        subdomainsCmp = []
        while idx < len(list(dictsData_)):
            for domain_name, ip_list in zip(
                    list(list(dictsData_[idx].values())[0].keys()),
                    list(list(dictsData_[idx].values())[0].values())):
                record_name = list(dictsData_[idx].keys())[0]
                # domain_name is just a name eg example.com and then ip_list is a list of ips that corresnpond to the domain_name and it is of type list"
                # for domain in domain_name:
                domainInfo = {
                    "subdomain": domain_name,
                    "namerecord": record_name,
                    "ip": ip_list,
                    "netblock": "",
                    "asn": "",
                    "manager": "",
                }
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
        checkpath = Path(a_recordsPath) # check if one of the files exists
        if not checkpath.exists():
            with open(from_file, "r") as file:
                lines = file.readlines()  # retrieve all the lines
            for line in lines:
                for path_index, path in enumerate(list(self.file_namerecord_dict.values())):
                    if self.namerecords[path_index] in line:
                        self.compare_append_line_file(line, path)

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
        if Path(filepath).exists():
            os.remove(filepath)
            open(filepath, "w").close()
        with open(filepath, "a") as file:
            file.write(subdomains)

    def parseAmassData(self):
        amass_run_success_status = 0
        with open(self.results_file, "r") as file:
            results = file.read()
            if results == "No assests were discovered":
                amass_run_success_status = 1

        if Path(self.dicts_file).exists():
            os.remove(self.dicts_file)
        if Path(self.emcpDataFile).exists():
            os.remove(self.emcpDataFile)
        if Path(self.subdomain_dicts_file).exists():
            os.remove(self.subdomain_dicts_file)
        for file_name in self.file_names:
            file_path = os.path.join(self.projectDir, file_name)
            if Path(file_path).exists():
                os.remove(file_path)
                
        if amass_run_success_status == 0:
            self.create_name_record_files(str(self.results_file))
            self.getNetblockIpDict(str(self.results_file))
            self.getAsnNetblockDict(str(self.results_file))
            self.getManagerAsnDict(str(self.results_file))
            for filename_index, filename in enumerate(list(self.file_namerecord_dict.values())):
                namerecord = self.namerecords[filename_index]
                self.getSubdomainIpDict(filename, name_record=namerecord)
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
        rundir,
        project_dir,
        url: str,
        depth=2,
        scope: list = None,
        output_dir="/LinkFinderResults/",
        cookies: dict = None,
        n_processes: int = None,
        output_file="/LinkFinderResults/url_endpoits.txt",
):
    output_dir = os.path.join(project_dir, output_dir)
    output_file = os.path.join(project_dir, output_file)
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
                f"python {rundir}Tools/xnLinkFinder/xnLinkFinder.py -i "
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
                f"python {rundir}Tools/xnLinkFinder/xnLinkFinder.py -i "
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
    subprocess.run(command, shell=True, stdout=None, stdin=None)


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
            projectDirPath: str,
            threads,
            search_engines: list = None,
            bruteforce: bool = False,
            ports: list = None,
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
            command = command + " -e " + search_engine_string
        if self.bruteforce:
            command = command + " -b "

        if self.ports is not None:
            ports = ""
            for port in self.ports:
                if self.ports.index(port) == len(self.ports) - 1:
                    ports = ports + port
                else:
                    ports = ports + port + ","

            command = command + " -p " + ports

        if self.threads is not None:
            command = command + " -t " + str(self.threads)

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
    url = url.replace("\n", "")
    if not url.endswith("/"):  # add trailing line character
        url = url + "/"
    if not url.startswith(("https://", "http://")):  # add scheme if does not exist
        url = "https://" + url
    return url


def isInternetAvailable():
    if len(get_working_ifaces()) == 0:
        return True
    return False


def is_brotli_compressed(data):
    brotli_magic_number = b'\x1b'
    return data[:1] == brotli_magic_number


def is_zlib_compressed(data):
    zlib_magic_number = b'x\x9c'
    return data[:2] == zlib_magic_number


def is_gzip_compressed(data):
    gzip_magic_number = b'\x1f\x8b'
    return data[:2] == gzip_magic_number


class OpenProcess(subprocess.Popen):
    def __init__(self, process_name, shell, cwd=None, args=None, stdout=None, stdin = None):
        super().__init__(args=args, shell=shell, cwd=cwd, stdout=stdout, stdin = stdin)
        self.process_name = process_name


def runWhoisOnTarget(server_name, project_dir_path=None):
    command = f"whois {server_name}"
    logging.info(f"running command '{command}'")
    process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    process.wait()
    whois_output, whois_error = process.communicate()
    if whois_output is not None:
        return whois_output
    else:
        return whois_error


def DissectClientReqPkt(packet: str, http: bool = None):
    "dissect the packets sent by the individual hosts/domains from the client"
    try:
        headersBodyDis_ = packet.split("\r\n\r\n")
        headersDis = headersBodyDis_[0].split("\r\n")  # headers
        try:
            packetBody = headersBodyDis_[1]
            len_packetBody = len(packetBody)
        except IndexError:
            packetBody = None
        # print(headersDis)
        packetHeaders = headersDis[1:]
        packetHeadersDict = {}
        for packetHeader in packetHeaders:
            keyValue = packetHeader.split(":", 1)
            key, value = keyValue[0].strip(), keyValue[1].strip()
            packetHeadersDict[key] = value
        if packetBody is not None:
            packetHeadersDict["Content-Length"] = str(len_packetBody)
        packetMethod = headersDis[0].split(" ")[0]
        host = packetHeadersDict["Host"]
        path = headersDis[0].split(" ")[1]
        if http:
            packetUrl = path.split("?")[0]
            if "https" not in packetUrl:
                packetUrl = host + path.split("?")[0]
                packetUrl = "https://" + packetUrl.strip()
        else:
            packetUrl = host + path.split("?")[0]
            packetUrl = "https://" + packetUrl.strip()
        try:
            f_packetParams = path.split("?")[1]
            packetParams = f_packetParams.split("&")
            packetParamsDict = {}
            for pP in packetParams:
                pP_ = pP.split("=")
                packetParamsDict[pP_[0]] = pP_[1]
        except IndexError:
            packetParams = None
            packetParamsDict = None
        if packetParams is not None:
            if http:
                packetUrlwParams = path
                if "https" not in path:
                    packetUrlwParams = "https://" + host.strip() + path.strip()
            else:
                packetUrlwParams = "https://" + host.strip() + path.strip()
        else:
            packetUrlwParams = packetUrl
        # logging.info(f"{yellow('method:')}{packetMethod}\n{yellow('url:')}{packetUrl}\n{yellow('headers:')}{packetHeadersDict}\n{yellow('params:')}{packetParamsDict}\n{yellow('body:')}{packetBody}\n{yellow('packetUrlWithParams:')}{packetUrlwParams}")
        return packetMethod, packetUrl, packetHeadersDict, packetParamsDict, packetBody, packetUrlwParams
    except Exception as exp:
        logging.error(
            f"Exception in DissectClientReqPkt function :error: {exp}")


def writeLinkContentToFIle(main_dir, link: str, data, max_filename_len=255):
    link_components = urlparser.urlparse(link)
    # the netlock + path,  this already has file name if it does not end with "/"
    relative_path = link_components.netloc + link_components.path

    if link.endswith("/"):
        # giving a file name for the index file
        relative_path = os.path.join(relative_path, "index.html")

    # the the extension to be placed on the hashed relative path
    file_extension = os.path.splitext(relative_path)[1] or ".html"

    if len(relative_path) > max_filename_len:
        hashed_filename = hashlib.md5(relative_path.encode()).hexdigest()
        file_name = hashed_filename + file_extension
    else:
        file_name = relative_path  # the relative path already has an extension

    file_path = os.path.join(main_dir, file_name)

    dir_path, file_name = os.path.split(file_path)

    try:
        if not os.path.exists(path=dir_path):
            os.makedirs(dir_path)

        if os.path.exists(file_path):
            os.remove(file_path)

        with open(file_path, 'wb') as g:
            g.write(data)

        return file_path

    except Exception as e:
        logging.warning(f"failed to save file with error {e}")
