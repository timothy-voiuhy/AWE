from OpenSSL import SSL
from certauth.certauth import CertificateAuthority
from utiliities import red, cyan, yellow
from concurrent.futures import ThreadPoolExecutor

import certifi
import requests
import zlib
import sys

import socket
import os
import re

import gzip
import threading
import random
import functools

import brotli
import httpx
import httpx._client as httpClient
import asyncio

import threading
from pathlib import Path
import json
from urllib import parse as urlparser
import logging


def is_brotli_compressed(data):
    brotli_magic_number = b'\x1b'
    return data[:1] == brotli_magic_number


def is_zlib_compressed(data):
    zlib_magic_number = b'x\x9c'
    return data[:2] == zlib_magic_number


def is_gzip_compressed(data):
    gzip_magic_number = b'\x1f\x8b'
    return data[:2] == gzip_magic_number


def DissectBrowserProxyRequests(browser_request: str):
    """Disect the initial browser request and extract the host, port and keep-alive values"""
    host_regex = "CONNECT .*\:\d\d\d"
    pattern = re.compile(host_regex)
    try:
        hostStr = pattern.findall(browser_request)[0]
        if hostStr is not None:
            host = hostStr.split(" ")[1].split(":")[0]
            port = hostStr.split(" ")[1].split(":")[1]
            keep_alive = True
            return host, port, keep_alive
        else:
            return False
    except IndexError:
        return False


def DissectBrowserReqPkt(packet: str, http: bool = None):
    "dissect the packets sent by the individual hosts/domains from the browser"
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
        keyValue = packetHeader.split(":")
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
    print(
        f"{yellow('method:')}{packetMethod}\n{yellow('url:')}{packetUrl}\n{yellow('headers:')}{packetHeadersDict}\n{yellow('params:')}{packetParamsDict}\n{yellow('body:')}{packetBody}\n{yellow('packetUrlWithParams:')}{packetUrlwParams}")
    return packetMethod, packetUrl, packetHeadersDict, packetParamsDict, packetBody, packetUrlwParams


def writeLinkContentToFIle(main_dir, link: str, data, hostname):
    
    link_components = urlparser.urlparse(link)
    relative_path = link_components[1] + link_components[2] # the netlock + path,  this already has file name if it does not end with "/"

    if link.endswith("/"):
        relative_path = relative_path + "index.html" # giving a file name for the index file 

    if relative_path is not None:
        if not main_dir.endswith("/"):
            file_path = main_dir + "/" + relative_path
        else:
            file_path = main_dir+relative_path
    dir_path, file_name = os.path.split(file_path)
    try:
        if not os.path.exists(path=file_path):
            os.makedirs(dir_path)
            with open(file_path,'wb') as file:  # this is where we caught the error after we try to a file that does not exist
                file.write(data)
        else:
            os.remove(file_path)
            with open(file_path, 'wb') as g:
                g.write(data)
        return file_path
    except Exception as e:
        print(f"failed to save file with error {e}")


def processUrl(url: str):
    https = "https://"
    whttps = "https://www."
    if url.startswith(https):
        h_url = url
        w_url = url.replace(https, whttps)
    elif url.startswith(whttps):
        w_url = url
        h_url = url.replace(whttps, https)
    elif not url.startswith(https) or not url.startswith(whttps):
        url = url.replace("www.", "").strip()
        w_url = whttps + url
        h_url = https + url
    return h_url, w_url


class ProxyHandler:
    def __init__(self, host="127.0.0.1",
                 port=8081,
                 downloadMozillaCAs=False,
                 UsehttpLibs=False,
                 verifyDstServerCerts=True,
                 save_traffic=False,
                 useFileBasedCerts=False,
                 useUrllib=False):
        self.host = host
        self.port = port
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.socket.bind((self.host, self.port))
        except OSError as e:
            print(e)
            sys.exit()
        self.socket.listen(5)
        self.downlaodMozillaCAs = downloadMozillaCAs
        if sys.platform == "WIN32":
            self.runDir = rundir  = "D:\\MYAPPLICATIONS\\AWE\\AWE\\crawn\\src"
        else:
            self.runDir = "/media/program/01DA55CA5F28E000/MYAPPLICATIONS/AWE/AWE/crawn/src"
        if self.downlaodMozillaCAs:
            self.MozillarootCAsUrl = "https://github.com/gisle/mozilla-ca/blob/master/lib/Mozilla/CA/cacert.pem"
            self.MozillaCACertsVerifyFile = self.runDir + "/proxycert/Mozilla/cacert.pem"
            if not os.path.isfile(self.MozillaCACertsVerifyFile):
                res = requests.get(self.MozillarootCAsUrl)
                with open(self.MozillaCACertsVerifyFile, "a") as file:
                    file.write(res.content.decode("utf-8"))
        else:
            self.MozillaCACertsVerifyFile = certifi.where()
        self.lock = threading.Lock()
        self.useFileBasedCerts = useFileBasedCerts
        self.pyCApath = self.runDir + "/proxycert/CA"
        self.certsDir = self.runDir + "/proxycert/Certs"
        self.rootCAcf = os.path.join(self.pyCApath, "rootCAcert.pem")
        if self.useFileBasedCerts is False:
            if not os.path.isfile(self.rootCAcf):
                self.rootCA = CertificateAuthority("LOCALHOST CA", self.rootCAcf, cert_cache=100)
            else:
                self.rootCA = CertificateAuthority("LOCALHOST CA", self.rootCAcf, cert_cache=100)
        else:
            if not os.path.isdir(self.certsDir):
                os.makedirs(self.certsDir)
            self.rootCA = CertificateAuthority("LOCALHOST CA", self.rootCAcf, cert_cache=self.certsDir)
            self.rootCAprivatekeyfile = self.runDir + "/proxycert/CA/privatekey.pem"
        self.usehttpLibs = UsehttpLibs
        self.homeDirectory = os.path.expanduser("~")
        self.defaultWorkspaceDir = os.path.join(self.homeDirectory, "AtomProjects/Proxy/")
        self.verifyDstServerCerts = verifyDstServerCerts
        self.sessionsDict = {}
        self.save_traffic = save_traffic
        self.error_file_count = 0
        self.useUrllib = useUrllib
        self.PoolManager = httpClient.Client(follow_redirects=True, timeout=15)

        self.logging  = True
        self.scope = ["."] # default regex pattern that can match for all hostnames

    def constructResponsePacket(self, u_response: httpx.Response = None,
                                usedRequests: bool = False):
        if self.useUrllib or usedRequests:
            body = u_response.content
            decodedBody = body
            # body_encoding = u_response.encoding
            len_body = len(body)
            status_line = f"HTTP/{str(u_response.http_version)[-3]}.{str(u_response.http_version)[-1]} {u_response.status_code} {u_response.reason_phrase}"
            r_headers = u_response.headers

            if "Transfer-Encoding" in list(r_headers.keys()) or "transfer-encoding" in list(r_headers.keys()):
                r_headers.pop("Transfer-Encoding")
                r_headers["Content-Length"] = str(len_body)

            if "br" in list(r_headers.values()):
                if not is_brotli_compressed(body):
                    br_encodedBody = brotli.compress(body)
                    body = br_encodedBody
                    len_br_encodedBody = len(br_encodedBody)
                    r_headers["Content-Length"] = str(len_br_encodedBody)
            elif "gzip" in list(r_headers.values()):
                if not is_gzip_compressed(body):
                    gzip_encodedBody = gzip.compress(body)
                    body = gzip_encodedBody
                    len_gzip_encoded_body = len(gzip_encodedBody)
                    r_headers["Content-Length"] = str(len_gzip_encoded_body)
            elif "zlib" in list(r_headers.values()):
                if not is_zlib_compressed(body):
                    zlib_encodedBody = zlib.compress(body)
                    body = zlib_encodedBody
                    len_zlib_encoded_body = len(zlib_encodedBody)
                    r_headers["Content-Length"] = str(len_zlib_encoded_body)
            headers = ''.join([f"{key}: {value}\r\n" for key, value in r_headers.items()])
            cookies = ''.join([f"{key}: {value};" for key, value in u_response.cookies.items()])
            # print(f"{yellow('response cookies:')}{cookies}")
            responsePacket = f"{status_line}\r\n{headers}"
            if cookies:
                responsePacket += f"Set-Cookie: {cookies}\r\n"
        # try:
        responsePacket += "\r\n"
        if isinstance(body, bytes):
            responsePacketBytes = responsePacket.encode("utf-8")
            ResponsePacket = responsePacketBytes + body
            decodedResponsePacket = responsePacketBytes + decodedBody
            return ResponsePacket, decodedResponsePacket
        elif isinstance(body, str):
            responsePacket += body
            decodedResponsePacket = responsePacket + decodedBody.decode("utf-8")
            return responsePacket.encode(), decodedResponsePacket

    def generateDomainCerts(self, hostname: str):
        """generate a certificate for a specific host and sign it with the root certificate. Return the path to the certficate (.crt) file"""
        hostname = hostname.strip()
        if self.useFileBasedCerts is False:
            return self.rootCA.load_cert(hostname, wildcard=True)
        else:
            return self.rootCA.cert_for_host(hostname, wildcard=True)  # filename

    def createDestConnection(self, host_portlist):
        """create the destination connection with the proxy, upgrade it to ssl and verify certificates"""
        dest_server_skt = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            dest_server_skt.connect((host_portlist[0], int(host_portlist[1])))
            print("TCP connection to destination server successfull")
            destServerSslContext = SSL.Context(SSL.SSLv23_METHOD)
            destServerSslServerSkt = SSL.Connection(destServerSslContext, dest_server_skt)
            destServerSslServerSkt.set_connect_state()
            if self.verifyDstServerCerts:
                destServerSslContext.set_verify(SSL.VERIFY_PEER | SSL.VERIFY_FAIL_IF_NO_PEER_CERT, self.verify_callback)
            else:
                destServerSslContext.set_verify(SSL.VERIFY_NONE, self.verify_callback)
            destServerSslContext.load_verify_locations(self.MozillaCACertsVerifyFile)
            try:
                destServerSslServerSkt.do_handshake()
                print("Destination server connection setup successfully with ssl support")
            except Exception as e:
                print(red(f"SSL HandShake failure with error :{e}"))
            return destServerSslServerSkt, 0
        except Exception:
            return None, 1

    def verify_callback(self, connection, x509, errno, depth, preverify_ok):
        # Implement your verification logic here
        if self.verifyDstServerCerts:
            if preverify_ok:
                print("Certificate verification passed")
                return True
            else:
                print("Certificate verification failed")
                return False
        else:
            return True

    def ForwardBrowserRequest(self, request: bytes,
                              destSrvSkt: SSL.Connection = None,
                              usehttpLibs=False,
                              http: bool = False
                              ):
        try:
            headers_end = request.find(b"\r\n\r\n")
            headers = request[:headers_end]
            bodyEncoding = False
            encoded_body = request[headers_end + 4:]
            if b'Content-Encoding: gzip' in headers or b'content-encoding: gzip' in headers:
                bodyEncoding = True
                headers_dict = {}
                for header in headers.split("\r\n"):
                    key, value = header.split(":")
                    headers_dict[key] = value
                decompressed_body = gzip.decompress(encoded_body)
                decompressed_utf_body = decompressed_body.decode("utf-8")
                len_decompressed_utf_body = len(decompressed_utf_body)
                headers_dict["Content-Length"] = str(len_decompressed_utf_body)
                headers = ''.join([f"{key}: {value}\r\n" for key, value in headers_dict.items()])
                browserRequest = headers + decompressed_utf_body
            else:
                browserRequest = request.decode("utf-8")
        except UnicodeDecodeError:
            filename = "browser_reqeust.txt" + str(self.error_file_count)
            with open(filename, "wb") as file:
                file.write(request)
                print(f"{red(f'got unicode decode error in browser request , written to file=>')}{filename}")
            self.error_file_count += 1
        print(f"{yellow('browser request:')} {browserRequest[0:100]} ....")
        (requestMethod, requestUrl, requestHeaders, requestParams, requestBody,
         requestUrlwParams) = DissectBrowserReqPkt(browserRequest, http)
        if usehttpLibs:
            if bodyEncoding:
                requestBody = encoded_body

            print(yellow(f"Connecting to remote server ....... on url: {requestUrlwParams}"))
            if self.useUrllib:
                # try:
                try:
                    if requestBody == "":
                        requestBody = None
                    retries = 0
                    while retries < 5:
                        response = self.PoolManager.request(method=requestMethod,
                                                            url=requestUrlwParams,
                                                            headers=requestHeaders,
                                                            data=requestBody,
                                                            follow_redirects=True)
                        if response:
                            break
                        else:
                            print(yellow("retrying...."))
                        retries += 1
                except httpx.ConnectError:
                    print(red(f"failing to resolve to url {requestUrlwParams}"))

                responsePacket, decodedResponsePacket = self.constructResponsePacket(u_response=response)
                # except Exception as e:
                # print(red(f"Experiencing error {e} {yellow('<=>')} \n\t restortig to using requests lib" ))
                #     response = requests.request(requestMethod, requestUrlwParams,
                #                                 headers=requestHeaders,
                #                                 params=requestParams,
                #                                 data=requestBody,
                #                                 allow_redirects=True)
                #     responsePacket = self.constructResponsePacket(u_response=response,usedRequests=True)

        else:
            destSrvSkt.sendall(request)
            responsePacket = destSrvSkt.recv(80000000)  # after sending to server and getting response
        return responsePacket, requestUrl, browserRequest, decodedResponsePacket

    def closeTunnel(self, browser_socket, closeBrowserSocket=True):
        if closeBrowserSocket:
            browser_socket.close()

    def isRequest(self, request: bytes):
        if b'Accept-Encoding:' in request and b'Accept:' in request:
            return True
        else:
            return False

    def createReqResData(self, dec_browserRequest: str, dec_browserResponse: str | bytes):
        if isinstance(dec_browserResponse, bytes):
            req_res_data = dec_browserRequest.encode("utf-8") + b'\nRESPONSE\n' + dec_browserResponse
            return req_res_data
        elif isinstance(dec_browserResponse, str):
            req_res_data = dec_browserRequest + "\nRESPONSE\n" + dec_browserResponse
            return req_res_data.encode("utf-8")

    def OpenHttpsCommTunnel(self, ClientSslSocket: SSL.Connection,
                            hostDir,
                            hostname,
                            hostnameUrl,
                            destServerSslServerSocket: SSL.Connection,
                            usehttpLibs: bool,
                            browser_socket: socket.socket,
                            RequestPacket: bytes = None,
                            http: bool = False,
                            unix= False):
        try:
            if RequestPacket is None:
                RequestPacket = ClientSslSocket.recv(40960)
                print(f"{yellow('Browser Request: ')}{RequestPacket}")

            ResponsePacket, requestUrl, dec_browserRequest, dec_browserResponse = self.ForwardBrowserRequest(
                RequestPacket,
                destServerSslServerSocket,
                usehttpLibs=usehttpLibs,
                http=http)
            if self.save_traffic:
                # remember in the gui the scope are regex patterns
                if self.logging:
                    if self.scope is not None:
                        for scope_regex in self.scope:
                            pattern = re.compile(scope_regex)
                            if len(pattern.findall(hostname)) != 0:
                                req_res_data = self.createReqResData(dec_browserRequest, dec_browserResponse)
                                writeLinkContentToFIle(hostDir, requestUrl, req_res_data, hostname)
            print(f"{yellow('dest_response:')}{ResponsePacket[:200]}")
            try:
                writtenBytes = ClientSslSocket.sendall(ResponsePacket)  # replace with sendall during debugging
            except AttributeError:
                writtenBytes = browser_socket.send(dec_browserResponse)
            print(f"{yellow('Bytes written to browser socket')}\n\t{writtenBytes}")
            self.closeTunnel(browser_socket)
        except SSL.SysCallError as e:
            print(f"{red('Browser Socket Unexpectedly closed with error:')}{e}")
            self.closeTunnel(browser_socket)
        except SSL.Error as e:
            print(f"{red('Browser failed to accept certificates')}\n\t{yellow('Error:')}{red(e)}")
            self.closeTunnel(browser_socket)

    def HandleConnection(self, browser_socket: socket.socket, unix=True):
        print("Waiting for initial browser request\n")
        initial_browser_request = browser_socket.recv(160000).decode("utf-8")
        print(cyan("Browser Intercept Request: "))
        print(initial_browser_request)

        if self.is_proxyCommand(initial_browser_request):
            command_dict = json.loads(initial_browser_request)
            if list(command_dict.keys())[0] == "scope":
                logging.info("Trying to set the hostname's scope")
                self.scope = list(command_dict.values())
                logging.info(f"Successfully set scope to {self.scope}")

            elif list(command_dict.keys())[0] == "log":
                if list(command_dict.values())[0] == 1:
                    logging.info("Recieved disable logging request \n Trying to disable logging")
                    try:
                        self.logging  = False
                        logging.info("Successfully disabled logging")
                    except Exception as e:
                        logging.error("Failed to disable logging with error {e}")
                else:
                    logging.info("Recieved enable logging request \n Trying to enable logging")
                    try:
                        self.logging  =True    
                        logging.info("Successfully enabled logging")
                    except Exception as e:
                        logging.error(f"Failed to enable logging with error {e}")
    
        elif initial_browser_request != "":
            if self.isRequest(initial_browser_request.encode("utf-8")):
                print(yellow("Received valid request as initial browser request"))
                (requestMethod,
                 requestUrl,
                 requestHeaders,
                 requestParams,
                 requestBody,
                 requestUrlwParams) = DissectBrowserReqPkt(initial_browser_request, http=True)
                hostname = requestHeaders["Host"]
                hostDir = os.path.join(self.defaultWorkspaceDir, hostname + "/")
                self.OpenHttpsCommTunnel(ClientSslSocket=None,
                                         hostDir=hostDir,
                                         hostname=hostname,
                                         hostnameUrl=requestUrl,
                                         destServerSslServerSocket=None,
                                         usehttpLibs=self.usehttpLibs,
                                         browser_socket=browser_socket,
                                         RequestPacket=initial_browser_request.encode("utf-8"),
                                         http=True,
                                         unix=unix)
            else:
                host_portlist = DissectBrowserProxyRequests(initial_browser_request)
                if host_portlist is not None:
                    keep_alive = host_portlist[2]
                    hostname = host_portlist[0]
                    host_cer = self.generateDomainCerts(hostname)
                    hostnameUrl = processUrl(hostname)[0]
                    hostDir = os.path.join(self.defaultWorkspaceDir, hostname + "/")
                    # proxy-destination server connection
                    if keep_alive:
                        if self.usehttpLibs == False:
                            try:
                                destServerSslServerSocket, Conn_status = self.createDestConnection(host_portlist)
                                if Conn_status == 0:
                                    usehttpLibs = False
                                elif Conn_status == 1:
                                    print(cyan("Initiating server connection error"))
                                    if self.useUrllib:
                                        print(cyan("Resorting to => urllib3 for destination server connection"))
                                    usehttpLibs = True
                                destConnection = True
                            except Exception as e:
                                print(red(f"Encoutered error {e} when initiating a connection to remote server"))
                                destConnection = False
                        elif self.usehttpLibs == True:
                            print(cyan("Using urllib3 for destination server connection"))
                            usehttpLibs = True
                            destConnection = True
                            destServerSslServerSocket = None

                    # respond to browser after making destination connection
                    if destConnection:
                        response = b"HTTP/1.1 200 Connection established\r\n\r\n"
                        browser_socket.sendall(response)
                        # upgrade the browser-proxy socket to ssl/tls
                        browserSocketSslContext = SSL.Context(SSL.TLSv1_2_METHOD)
                        if self.useFileBasedCerts is False:
                            browserSocketSslContext.use_certificate(host_cer[0])
                            browserSocketSslContext.use_privatekey(host_cer[1])
                        else:
                            browserSocketSslContext.use_certificate_chain_file(host_cer)
                        ClientSslSocket = SSL.Connection(browserSocketSslContext, browser_socket)
                        ClientSslSocket.set_accept_state()
                        print(cyan("Upgraded browser socket to support ssl"))

                        # open browser-proxy-destination tunnel
                        self.OpenHttpsCommTunnel(ClientSslSocket,
                                                 hostDir,
                                                 hostname,
                                                 hostnameUrl,
                                                 destServerSslServerSocket,
                                                 usehttpLibs,
                                                 browser_socket,
                                                 unix=unix)

                    else:
                        response = b"HTTP/1.1 500 Connection Failed"
                        browser_socket.sendall(response)
                        print(red("Connection to remote server failed\n"))
                        browser_socket.close()
                else:
                    print(red("Initial Browser Request is Invalid"))
        else:
            print(red("Initial Browser Request is Invalid"))

    def is_proxyCommand(self, initial_browser_req):
        try:
            if isinstance(json.loads(initial_browser_req), dict):
                return True
            else:
                return False
        except Exception:
            return False

    def startServerInstance(self):
        print(yellow(f"Proxy running on {self.host}, port {self.port}"))
        # with ThreadPoolExecutor(max_workers=100) as executor:
        while True:
            print(yellow("Waiting for Incoming Connections"))
            browser_socket, browser_address = self.socket.accept()
            instanceHandlerThread = threading.Thread(target=self.HandleConnection, args=(browser_socket,))
            instanceHandlerThread.start()
            # executor.submit(self.HandleConnection, browser_socket)
            # self.HandleConnection(browser_socket)


if __name__ == "__main__":

    logging.basicConfig(level=logging.DEBUG, format="%(asctime)s -%(levelname)s - %(filename)s:%(lineno)d - %(message)s")

    proxy = ProxyHandler(
        verifyDstServerCerts=False,
        UsehttpLibs=True,
        useUrllib=True,
        save_traffic=True
    )
    try:
        proxy.startServerInstance()
    except KeyboardInterrupt:
        print(red("\nCleaning Up"))
        proxy.PoolManager.close()
        proxy.socket.close()
