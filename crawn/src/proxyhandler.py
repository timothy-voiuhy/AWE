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

import urllib3
from urllib3.poolmanager import HTTPConnectionPool, HTTPSConnectionPool
import urllib.parse as urlParser
import brotli

def is_brotli_compressed(data):
    # Brotli magic number (first two bytes of a Brotli-compressed stream)
    brotli_magic_number = b'\x1b'

    # Check if the data starts with the Brotli magic number
    return data[:1] == brotli_magic_number

def is_zlib_compressed(data):
    # zlib magic number
    zlib_magic_number = b'x\x9c'

    # check if data starts with the magic number
    return data[:2] == zlib_magic_number

def is_gzip_compressed(data):
    # Gzip magic number (first two bytes of a gzip-compressed stream)
    gzip_magic_number = b'\x1f\x8b'

    # Check if the data starts with the gzip magic number
    return data[:2] == gzip_magic_number

def DissectBrowserProxyRequests(browser_request:str):
    """Disect the initial browser request and extract the host, port and keep-alive values"""
    host_regex = "CONNECT .*\:\d\d\d"
    pattern = re.compile(host_regex)
    try:
        hostStr = pattern.findall(browser_request)[0]
        if hostStr is not None:
            host = hostStr.split(" ")[1].split(":")[0]
            port  = hostStr.split(" ")[1].split(":")[1]
            keep_alive = True
            return host,port, keep_alive
        else:
            return False
    except IndexError:
        return False

def DissectBrowserReqPkt(packet: str, http:bool=None):
    "dissect the packets sent by the individual hosts/domains from the browser"
    headersBodyDis_ = packet.split("\r\n\r\n")
    headersDis = headersBodyDis_[0].split("\r\n")# headers
    try:
        packetBody = headersBodyDis_[1]
    except IndexError:
        packetBody = None
    # print(headersDis)
    packetHeaders = headersDis[1:]
    packetHeadersDict = {}
    for packetHeader in packetHeaders:
        keyValue = packetHeader.split(":")
        key, value = keyValue[0], keyValue[1]
        packetHeadersDict[key] = value
    packetMethod = headersDis[0].split(" ")[0]
    host = packetHeadersDict["Host"]
    path = headersDis[0].split(" ")[1]
    if http:
        packetUrl = path.split("?")[0]
    else:
        packetUrl = host + path.split("?")[0]
        packetUrl = "https://"+packetUrl.strip()
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
        else:
            packetUrlwParams = "https://"+host.strip()+path.strip()
    else:
        if http:
            packetUrlwParams = path
        else:
            packetUrlwParams = packetUrl 
    print(f"{yellow('method:')}{packetMethod}\n{yellow('url:')}{packetUrl}\n{yellow('headers:')}{packetHeadersDict}\n{yellow('params:')}{packetParamsDict}\n{yellow('body:')}{packetBody}\n{yellow('packetUrlWithParams:')}{packetUrlwParams}" )
    return packetMethod, packetUrl, packetHeadersDict, packetParamsDict, packetBody,packetUrlwParams

def writeLinkContentToFIle(MAIN_DIR, link: str, data, type_="txt"):
    scheme_path = link.split("//")  # scheme_path = [https: , path] or  #shceme_path = [https: , path?jfdk]
    if scheme_path is not None:
        _path = MAIN_DIR + "/" + scheme_path[1]+".txt"
    dir_path, file_name = os.path.split(_path)
    try:
        if not os.path.exists(path=_path):
            os.makedirs(dir_path)
            with open(_path,'wb') as file:  # this is where we caught the error after we try to a file that does not exist
                file.write(data)
        else:
            os.rmdir(_path)
            os.makedirs(dir_path)
            with open(_path, 'wb') as g:
                g.write(data)
        return _path
    except Exception as e:
        print(f"failed to save file with error {e}")


def processUrl(url:str):
    https = "https://"
    whttps = "https://www."
    if url.startswith(https):
        h_url = url
        w_url = url.replace(https, whttps)
    elif url.startswith(whttps):
        w_url = url
        h_url = url.replace(whttps, https)
    elif not url.startswith(https) or not url.startswith(whttps):
        url = url.replace("www.","").strip()
        w_url = whttps+url
        h_url = https+url
    return h_url, w_url

class ProxyHandler:
    def __init__(self, host="127.0.0.1",
                 port=8081,
                 downloadMozillaCAs=False,
                 UsehttpLibs=False,
                 verifyDstServerCerts=True,
                 persitSessions= True,
                 save_traffic = False,
                 useFileBasedCerts= False,
                 useUrllib = False):
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
        if self.downlaodMozillaCAs:
            self.MozillarootCAsUrl = "https://github.com/gisle/mozilla-ca/blob/master/lib/Mozilla/CA/cacert.pem"
            self.MozillaCACertsVerifyFile = "./proxycert/Mozilla/cacert.pem"
            if not os.path.isfile(self.MozillaCACertsVerifyFile):
                res = requests.get(self.MozillarootCAsUrl)
                with open(self.MozillaCACertsVerifyFile, "a") as file:
                    file.write(res.content.decode("utf-8"))
        else:
            self.MozillaCACertsVerifyFile = certifi.where()            
        self.lock = threading.Lock()
        self.useFileBasedCerts = useFileBasedCerts
        self.pyCApath = "./proxycert/CA"
        self.certsDir = "./proxycert/Certs"
        self.rootCAcf = os.path.join(self.pyCApath, "rootCAcert.pem")
        if self.useFileBasedCerts is False:
            if not os.path.isfile(self.rootCAcf):
                self.rootCA = CertificateAuthority("LOCALHOST CA", self.rootCAcf, cert_cache=100)
            else:
                self.rootCA = CertificateAuthority("LOCALHOST CA", self.rootCAcf, cert_cache=100)
        else:
            if not os.path.isdir(self.certsDir):
                os.makedirs(self.certsDir)    
            self.rootCA = CertificateAuthority("LOCALHOST CA", self.rootCAcf,cert_cache=self.certsDir)
            self.rootCAprivatekeyfile = "./proxycert/CA/privatekey.pem"
        self.usehttpLibs = UsehttpLibs
        self.homeDirectory = os.path.expanduser("~")
        self.defaultWorkspaceDir = os.path.join(self.homeDirectory, "AtomProjects/")
        self.verifyDstServerCerts = verifyDstServerCerts
        self.sessionsDict = {}
        self.persitSessions = persitSessions
        self.save_traffic = save_traffic
        self.error_file_count = 0
        self.useUrllib = useUrllib        

    def constructResponsePacket(self,u_response:urllib3.HTTPResponse=None,
                                usedRequests:bool=False):
        if self.useUrllib or usedRequests:
            body = u_response.data
            len_body = len(body)
            status_line = f"HTTP/{str(u_response.version)[0]}.{str(u_response.version)[1]} {u_response.status} {u_response.reason}"
            r_headers = u_response.headers
            
            if "Transfer-Encoding" in list(r_headers.keys()):
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
                    gzip_encodedBody= gzip.compress(body)
                    body = gzip_encodedBody
                    len_gzip_encoded_body = len(gzip_encodedBody)
                    r_headers["Content-Length"] = str(len_gzip_encoded_body)
            elif "zlib" in list(r_headers.values()):
                if not is_zlib_compressed(body):
                    zlib_encodedBody = zlib.compress(body)
                    len_zlib_encoded_body = len(zlib_encodedBody)
                    r_headers["Content-Length"] = str(len_zlib_encoded_body)
            headers = ''.join([f"{key}: {value}\r\n" for key, value in r_headers.items()])
            cookies = ';'.join(u_response.headers.getheaders("Set-Cookie"))
            responsePacket = f"{status_line}\r\n{headers}"
            if cookies:
                responsePacket += f"Set-Cookie: {cookies}\r\n"
        # try:
        responsePacket += "\r\n"
        if isinstance(body, bytes):
            responsePacketBytes = responsePacket.encode("utf-8")
            ResponsePacket = responsePacketBytes+body
            return ResponsePacket    
        elif isinstance(body, str):
            responsePacket += body
            return responsePacket.encode()

    def generateDomainCerts(self, hostname:str):
        """generate a certificate for a specific host and sign it with the root certificate. Return the path to the certficate (.crt) file"""
        hostname = hostname.strip()
        if self.useFileBasedCerts  is False:
            return self.rootCA.load_cert(hostname, wildcard=True)
        else:
            return self.rootCA.cert_for_host(hostname, wildcard=True) # filename
        
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

    def HandleBrowserRequest(self,request: bytes,
                            u_ClientSession:HTTPSConnectionPool|HTTPConnectionPool,
                            destSrvSkt:SSL.Connection= None,
                            usehttpLibs=False,
                            http:bool=False
                            ):
        try:
            headers_end = request.find(b"\r\n\r\n")
            headers = request[:headers_end]
            bodyEncoding = False
    
            encoded_body = request[headers_end+4:]
            if b'Content-Encoding: gzip' in headers:
                bodyEncoding = True
                decompressed_body= gzip.decompress(encoded_body)
                decompressed_utf_body = decompressed_body.decode("utf-8")
                browserRequest = headers.decode("utf-8")+decompressed_utf_body 
            else:
                browserRequest = request.decode("utf-8") 
        except UnicodeDecodeError:
            filename = "browser_reqeust.txt"+str(self.error_file_count)
            with open(filename, "wb") as file:
                file.write(request)
                print(f"{red(f'got unicode decode error in browser request , written to file=>')}{filename}")
            self.error_file_count += 1
        print(f"{yellow('browser request:')} {browserRequest[0:100]} ....")
        (requestMethod,requestUrl,requestHeaders,requestParams,requestBody, requestUrlwParams) = DissectBrowserReqPkt(browserRequest, http)
        if usehttpLibs:
            if bodyEncoding:
                requestBody = encoded_body
            print(yellow(f"Connecting to remote server ....... on url: {requestUrl}"))
            if self.useUrllib:
                if isinstance(u_ClientSession, HTTPConnectionPool):
                    print(yellow("Using http connection pool for request"))
                elif isinstance(u_ClientSession, HTTPSConnectionPool):
                    print(yellow("Using https connection pool for request"))
                try:
                    response = u_ClientSession.request(method=requestMethod,
                                                    url=requestUrlwParams,
                                                    headers=requestHeaders,
                                                    body= requestBody,
                                                    redirect=True)
                    responsePacket = self.constructResponsePacket(u_response=response)
                except Exception as e:
                    print(red(f"Experiencing error {e} {yellow('<=>')} \n\t restortig to using requests lib" ))
                    response = requests.request(requestMethod, requestUrlwParams,
                                                headers=requestHeaders,
                                                params=requestParams,
                                                data=requestBody,
                                                allow_redirects=True)
                    responsePacket = self.constructResponsePacket(u_response=response,usedRequests=True)
   
        else:
            destSrvSkt.sendall(request)
            responsePacket = destSrvSkt.recv(80000000) # after sending to server and getting response
        return responsePacket, requestUrl

    def createUrllibProxyDestSession(self, hostname, http:bool=False):
        if self.persitSessions:
            if hostname in list(self.sessionsDict.keys()):
                Proxy_DestSession = self.sessionsDict[hostname]
                if isinstance(Proxy_DestSession, HTTPSConnectionPool):
                    print(yellow("Using found HTTPS sesssion"))
                    return Proxy_DestSession
                elif isinstance(Proxy_DestSession, HTTPConnectionPool):
                    print(yellow("Using found HTTP session"))
                    return Proxy_DestSession
                else:
                    print(f"{yellow('Session has been closed<=>...Opening new session.....')}")
                    if http:
                        Proxy_DestSession = HTTPConnectionPool(hostname)
                    else:
                        Proxy_DestSession = HTTPSConnectionPool(hostname) 
                    return Proxy_DestSession
            else:
                if http:
                    Proxy_DestSession = HTTPConnectionPool(hostname)
                else:
                    Proxy_DestSession = HTTPSConnectionPool(hostname) 
                self.sessionsDict[hostname] = Proxy_DestSession
                return Proxy_DestSession
        else:
            if http:
                Proxy_DestSession = HTTPConnectionPool(hostname)
            else:
                Proxy_DestSession = HTTPSConnectionPool(hostname) 
            return Proxy_DestSession                        

    def closeTunnel(self, browser_socket, Proxy_DestSession, closeBrowserSocket = True):
        if closeBrowserSocket:
            browser_socket.close()
        try:
            if not self.persitSessions:
                if self.usehttpLibs:
                    if Proxy_DestSession is not None:
                        Proxy_DestSession.close()       
        except TypeError as e:
            pass

    def cleanSessions(self):
        if self.persitSessions:
            try:
                for session in list(self.sessionsDict.values()):
                    session.close()
                    self.sessionsDict.clear()
            except:
                pass

    def isRequest(self, request:bytes):
        if b'Accept-Encoding:' in request and b'Accept:' in request:
            return True
        else:
            return False

    def openCommTunnel(self, ClientSslSocket:SSL.Connection,
                   hostDir,
                   hostnameUrl, 
                   Proxy_DestSession:HTTPSConnectionPool|HTTPConnectionPool,
                   destServerSslServerSocket:SSL.Connection,
                   usehttpLibs:bool,
                   browser_socket:socket.socket,
                   RequestPacket:bytes=None,
                   http:bool=False):
        try:
            if RequestPacket is None:    
                RequestPacket = ClientSslSocket.recv(40960)
                print(f"{yellow('Browser Request: ')}{RequestPacket}")
            if self.save_traffic:
                writeLinkContentToFIle(hostDir,hostnameUrl, RequestPacket)  
            ResponsePacket, requestUrl =  self.HandleBrowserRequest(RequestPacket,
                                                                    Proxy_DestSession,
                                                                    destServerSslServerSocket,
                                                                    usehttpLibs=usehttpLibs,
                                                                    http=http)
            if self.save_traffic:
                writeLinkContentToFIle(hostDir, requestUrl,ResponsePacket)
            print(f"{yellow('dest_response:')}{ResponsePacket}")
            writtenBytes = ClientSslSocket.sendall(ResponsePacket) # replace with sendall during debugging
            print(f"{yellow('Bytes written to browser socket')}\n\t{writtenBytes}")
            self.closeTunnel(browser_socket, Proxy_DestSession)
        except SSL.SysCallError as e:
            print(f"{red('Browser Socket Unexpectdly closed with error:')}{e}")
            self.closeTunnel(browser_socket, Proxy_DestSession)
        except SSL.Error as e:
            print(f"{red('Browser failed to accept certificates')}\n\t{yellow('Error:')}{red(e)}")  
            self.closeTunnel(browser_socket, Proxy_DestSession)        

    def HandleConnection(self, browser_socket:socket.socket, placeholder):
            print("Waiting for initial browser request")
            initial_browser_request = browser_socket.recv(160000).decode("utf-8")
            print(cyan("Browser Intercept Request: "))
            print(initial_browser_request)

            if initial_browser_request != "":
                if self.isRequest(initial_browser_request.encode("utf-8")):
                    print(yellow("Received valid request as initial browser request"))
                    (requestMethod,
                     requestUrl,
                     requestHeaders,
                     requestParams,
                     requestBody, 
                     requestUrlwParams)= DissectBrowserReqPkt(initial_browser_request, http=True)
                    hostname = requestHeaders["Host"]
                    hostDir = os.path.join(self.defaultWorkspaceDir, hostname+"/")
                    Proxy_DestSession = self.createUrllibProxyDestSession(hostname, http=True)
                    self.openCommTunnel(ClientSslSocket=None,
                                    hostDir=hostDir,
                                    hostnameUrl=requestUrl,
                                    Proxy_DestSession=Proxy_DestSession,
                                    destServerSslServerSocket=None,
                                    usehttpLibs=self.usehttpLibs,
                                    browser_socket=browser_socket,
                                    RequestPacket=initial_browser_request.encode("utf-8"),
                                    http=True)
                else:
                    host_portlist = DissectBrowserProxyRequests(initial_browser_request)
                    if host_portlist is not None:
                        keep_alive = host_portlist[2]
                        hostname = host_portlist[0]
                        host_cer = self.generateDomainCerts(hostname) 
                        hostnameUrl= processUrl(hostname)[0]
                        hostDir = os.path.join(self.defaultWorkspaceDir, hostname+"/")    
                        # proxy-destination server connection
                        if keep_alive:
                            if self.usehttpLibs == False:
                                try:
                                    destServerSslServerSocket, Conn_status = self.createDestConnection(host_portlist)
                                    if Conn_status == 0:
                                        usehttpLibs = False
                                        Proxy_DestSession = None
                                    elif Conn_status == 1:
                                        print(cyan("Initiating server connection error"))
                                        if self.useUrllib:
                                            print(cyan("Resorting to => urllib3 for destination server connection"))
                                            Proxy_DestSession = self.createUrllibProxyDestSession(hostname, http=True)
                                        usehttpLibs = True
                                    destConnection = True
                                except Exception as e:
                                    print(red(f"Encoutered error {e} when initiating a connection to remote server"))
                                    destConnection = False
                            elif self.usehttpLibs == True:   
                                print(cyan("Using urllib3 for destination server connection"))
                                if self.useUrllib:
                                    Proxy_DestSession = self.createUrllibProxyDestSession(hostname)
                                usehttpLibs = True
                                destConnection = True
                                destServerSslServerSocket = None

                        # respond to browser after making destination connection
                        if destConnection:
                            response = b"HTTP/1.1 200 Connection established\r\n\r\n"
                            browser_socket.sendall(response)
                            #upgrade the browser-proxy socket to ssl/tls
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
                            self.openCommTunnel(ClientSslSocket,
                                            hostDir,
                                            hostnameUrl,
                                            Proxy_DestSession,
                                            destServerSslServerSocket,
                                            usehttpLibs,
                                            browser_socket)
          
                        else:
                            response = b"HTTP/1.1 500 Connection Failed"
                            browser_socket.sendall(response)
                            print(red("Connection to remote server failed\n"))
                            browser_socket.close()
                    else:
                        print(red("Initial Browser Request is Invalid"))
            else:
                print(red("Initial Browser Request is Invalid"))

    def startServerInstance(self):
        print(yellow(f"Proxy running on {self.host}, port {self.port}"))
        with ThreadPoolExecutor(max_workers=3084) as executor:
            while True:
                print(yellow("Waiting for Incoming Connections"))
                browser_socket, browser_address = self.socket.accept()
                executor.submit(self.HandleConnection, browser_socket,None)
                # self.HandleConnection(browser_socket, None)
 
if __name__ == "__main__":
    try:
        proxy = ProxyHandler(
                             verifyDstServerCerts=False,
                             persitSessions=True,
                             useFileBasedCerts=False,
                             UsehttpLibs=True,
                             useUrllib=True,
                             )
        proxy.startServerInstance()
    except KeyboardInterrupt:
        print(red("\nCleaning Up"))
        if proxy.persitSessions:
            proxy.cleanSessions()
        proxy.socket.close()
