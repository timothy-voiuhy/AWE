from OpenSSL import SSL
from certauth.certauth import CertificateAuthority
from utiliities import red, cyan, yellow
from concurrent.futures import ThreadPoolExecutor

import certifi
import requests
import asyncio
import sys

import aiohttp
import socket
import os
import re

import threading

class ProxyHandler:
    def __init__(self, host="127.0.0.1",
                 port=8081,
                 downloadMozillaCAs=False,
                 UseAiohttp=False,
                 verifyDstServerCerts=True,
                 persitSessions= True):
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
        self.pyCApath = "./proxycert/CA"
        self.rootCAcf = os.path.join(self.pyCApath, "rootCAcert.pem")
        if not os.path.isfile(self.rootCAcf):
            self.rootCA = CertificateAuthority("LOCALHOST CA", self.rootCAcf, cert_cache=50)
        else:
            self.rootCA = CertificateAuthority("LOCALHOST CA", self.rootCAcf, cert_cache=50)
        self.useAiohttp = UseAiohttp
        self.connector = aiohttp.TCPConnector(limit_per_host=50)
        self.homeDirectory = os.path.expanduser("~")
        self.defaultWorkspaceDir = os.path.join(self.homeDirectory, "AtomProjects/")
        self.verifyDstServerCerts = verifyDstServerCerts
        self.sessionsDict = {}
        self.persitSessions = persitSessions

    def processUrl(self,url:str):
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

    def writeLinkContentToFIle(self,MAIN_DIR, link: str, data, type_="txt"):
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

    def DissectBrowserReqPkt(self, packet: str):
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
        packetUrl = host + path.split("?")[0]
        packetUrl = "https://"+packetUrl.strip()
        try:
            packetParams = path.split("?")[1].split("&")
            packetParamsDict = {}
            for pP in packetParams:
                pP_ = pP.split("=")
                packetParamsDict[pP_[0]] = pP_[1]
        except IndexError:
            packetParamsDict = None
        print(f"{yellow('method:')}{packetMethod}\n{yellow('url:')}{packetUrl}\n{yellow('headers:')}{packetHeadersDict}\n{yellow('params:')}{packetParamsDict}\n{yellow('body:')}{packetBody}" )
        return packetMethod, packetUrl, packetHeadersDict, packetParamsDict, packetBody

    async def constructResponsePacket(self, response:aiohttp.ClientResponse):
        body = await response.read()
        status_line = f"HTTP/{response.version.major}.{response.version.minor} {response.status} {response.reason}"
        headers = ''.join([f"{key}: {value}\r\n" for key, value in response.headers.items()])
        cookies = response.cookies.output(header='', sep='; ')
        responsePacket = f"{status_line}\r\n{headers}"
        if cookies:
            responsePacket += f"Set-Cookie: {cookies}\r\n"
        try:
            responsePacket += "\r\n" +body.decode()
            return responsePacket.encode()
        except UnicodeDecodeError or UnicodeEncodeError:   
            responsePacket += "\r\n"
            with open("response.txt", "wb") as resp_file:
                resp_file.write(responsePacket.encode())
                resp_file.write(body)
            with open("response.txt", "rb") as resp_file:
                responsePacket = resp_file.read()   
        return responsePacket         
    # except aiohttp.TooManyRedirects:

    def DissectBrowserProxyRequests(self, browser_request:str):
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

    def generateDomainCerts(self, hostname:str):
        """generate a certificate for a specific host and sign it with the root certificate. Return the path to the certficate (.crt) file"""
        hostname = hostname.strip()
        host_cer = self.rootCA.load_cert(hostname)
        return host_cer

    async def createDestConnection(self, host_portlist):
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
            destServerSslServerSkt.do_handshake()
            print("Destination server connection setup successfully with ssl support")
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
        
    async def HandleBrowserRequest(self, request: bytes, destSrvSkt:SSL.Connection= None, ClientSession:aiohttp.ClientSession= None, useAiohttp=False):
        try:
            browserRequest = request.decode("utf-8")
        except UnicodeDecodeError:
            with open("browser_reqeust.txt", "wb") as file:
                file.write(request)
            with open("browser_request.txt", "r") as file:
                browserRequest = file.read()   
        print(f"{yellow('browser request:')} {browserRequest[0:100]} ....")
        (requestMethod,requestUrl,requestHeaders,requestParams,requestBody) = self.DissectBrowserReqPkt(browserRequest)
        if useAiohttp:
            # try:
            async with ClientSession.request(method=requestMethod,url=requestUrl,
                                            headers=requestHeaders,params=requestParams,
                                            data=requestBody) as response:
                responsePacket = await self.constructResponsePacket(response)
        else:
            destSrvSkt.send(request)
            responsePacket = destSrvSkt.recv(80000000) # after sending to server and getting response
        return responsePacket, requestUrl
    
    def createAiohttpProxyDestSession(self, hostname):
        if self.persitSessions:
            if hostname in list(self.sessionsDict.keys()):
                Proxy_DestSession = self.sessionsDict[hostname]
                if isinstance(Proxy_DestSession, aiohttp.ClientSession):
                    print(yellow("Using found sesssion"))
                    return Proxy_DestSession
            else:
                Proxy_DestSession = aiohttp.ClientSession(connector=self.connector) 
                self.sessionsDict[hostname] = Proxy_DestSession
                return Proxy_DestSession
        else:
            Proxy_DestSession = aiohttp.ClientSession(connector=self.connector) 
            return Proxy_DestSession

    async def HandleHostInstance(self, browser_socket:socket.socket):
        # initial http request by browser
        print("Waiting for initial browser request")
        initial_browser_request = browser_socket.recv(1600).decode("utf-8")
        print(cyan("Browser Intercept Request: "))
        print(initial_browser_request)
        if initial_browser_request != "":
            host_portlist = self.DissectBrowserProxyRequests(initial_browser_request)
            if host_portlist is not None:
                keep_alive = host_portlist[2]
                hostname = host_portlist[0]
                host_cer = self.generateDomainCerts(hostname) 
                hostnameUrl= self.processUrl(hostname)[0]
                hostDir = os.path.join(self.defaultWorkspaceDir, hostname+"/")    

                # proxy-destination server connection
                if keep_alive:
                    if self.useAiohttp == False:
                        try:
                            destServerSslServerSocket, Conn_status = await self.createDestConnection(host_portlist)
                            if Conn_status == 0:
                                useAiohttp = False
                                Proxy_DestSession = None
                            elif Conn_status == 1:
                                print(cyan("Initiating server connection error"))
                                print(cyan("Resorting to => aiohttp for destination server connection"))
                                Proxy_DestSession = self.createAiohttpProxyDestSession(hostname)
                                useAiohttp = True
                            destConnection = True
                        except Exception as e:
                            print(red(f"Encoutered error {e} when initiating a connection to remote server"))
                            destConnection = False
                    elif self.useAiohttp == True:   
                        print(cyan("Using aiohttp for destination server connection"))
                        Proxy_DestSession = self.createAiohttpProxyDestSession(hostname)
                        useAiohttp = True
                        destConnection = True
                        destServerSslServerSocket = None

                # respond to browser after making destination connection
                if destConnection:
                    response = b"HTTP/1.1 200 Connection established\r\n\r\n"
                    browser_socket.sendall(response)
                    #upgrade the browser-proxy socket to ssl/tls
                    browserSocketSslContext = SSL.Context(SSL.TLSv1_2_METHOD)
                    browserSocketSslContext.use_certificate(host_cer[0])
                    browserSocketSslContext.use_privatekey(host_cer[1])
                    ClientSslSocket = SSL.Connection(browserSocketSslContext, browser_socket)
                    ClientSslSocket.set_accept_state()
                    print(cyan("Upgraded browser socket with ssl"))
                    
                    # open browser-proxy-destination tunnel
                    try:
                        RequestPacket = ClientSslSocket.recv(4096)
                        self.writeLinkContentToFIle(hostDir,hostnameUrl, RequestPacket)
                        ResponsePacket, requestUrl = await self.HandleBrowserRequest(RequestPacket,destServerSslServerSocket,Proxy_DestSession,useAiohttp)
                        self.writeLinkContentToFIle(hostDir, requestUrl,ResponsePacket)
                        print(f"{yellow('dest_response:')}{ResponsePacket[0:500]}........")
                        ClientSslSocket.sendall(ResponsePacket) # replace with sendall during debugging
                        browser_socket.close()
                        if not self.persitSessions:
                            if self.useAiohttp:
                                Proxy_DestSession.close()
                    except SSL.SysCallError:
                        print(f"{red('Browser Socket Unexpectdly closed')}")
                        browser_socket.close()
                        if not self.persitSessions:
                            if self.useAiohttp:
                                Proxy_DestSession.close()
                    except Exception as e:
                        print(red(f"Encountered error in tunnel: {e}\n"))
                        print(yellow("Cleaning connection"))
                        browser_socket.close()  
                        if useAiohttp:                  
                            Proxy_DestSession.close()
                else:
                    response = b"HTTP/1.1 500 Connection Failed"
                    browser_socket.sendall(response)
                    print(red("Connection to remote server failed\n"))
                    browser_socket.close()
            else:
                print(red("Initial Browser Request is Invalid"))
        else:
            print(red("Initial Browser Request is Invalid"))

    def cleanSessions(self):
        if self.persitSessions:
            try:
                for session in list(self.sessionsDict.values()):
                    session.close()
                    self.sessionsDict.clear()
            except:
                pass

    async def startServerInstance(self):
        try:
            print(yellow(f"Proxy running on {self.host}, port {self.port}"))
            with ThreadPoolExecutor(max_workers=3084) as executor:
                while True:
                    print(yellow("Waiting for Incoming Connections"))
                    browser_socket, browser_address = self.socket.accept()
                    executor.submit(await self.HandleHostInstance(browser_socket))
        except Exception as e:
            print(f"{red('Server Instance had an error')}: {e}")
            print(yellow("Cleaning.."))
            self.cleanSessions()

if __name__ == "__main__":
    try:
        proxy = ProxyHandler(UseAiohttp=False,
                             verifyDstServerCerts=False,
                             persitSessions=False)
        asyncio.run(proxy.startServerInstance())
    except KeyboardInterrupt:
        print(red("\nCleaning Up"))
        if proxy.persitSessions:
            proxy.cleanSessions()
        proxy.socket.close()

        