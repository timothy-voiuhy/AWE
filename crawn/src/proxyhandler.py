from OpenSSL import SSL
from  certauth.certauth import CertificateAuthority
from utiliities import red, cyan, yellow
import certifi
import requests
import asyncio
import sys
import aiohttp
import socket
import os
from subprocess import Popen, PIPE
from concurrent.futures import ThreadPoolExecutor
import re
import threading

class ProxyHandler:
    def __init__(self, host="127.0.0.1", port=8081, certsDir = "./proxycert/certs/", downloadMozillaCAs=False):
        self.host = host  # the default host(this computer)
        self.port = port  # the default
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
        # self.tempCerts = self.pyCApath+"/"+"temp/Certs"
        self.rootCAcf = os.path.join(self.pyCApath, "rootCAcert.pem")
        if not os.path.isfile(self.rootCAcf):
            #self.rootCA = CertificateAuthority("LOCALHOST CA",self.rootCAcf,cert_cache=self.tempCerts )
            self.rootCA = CertificateAuthority("LOCALHOST CA", self.rootCAcf, cert_cache=50)
        else:
            self.rootCA = CertificateAuthority("LOCALHOST CA", self.rootCAcf, cert_cache=50)
        # if not os.path.isdir(self.certsDir):
        #     os.makedirs(self.certsDir)

    def DissectPacket(self, packet: str):
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
        packetParams = path.split("?")[1]
        print(f"{packetMethod} \n {packetUrl}\n{packetHeadersDict}, \n{packetParams}, \n {packetBody}" )
        return packetMethod, packetUrl, packetHeadersDict, packetParams, packetBody

    async def HandleBrowserRequest(self, request: bytes, destSrvSkt:SSL.Connection):
            # browserRequest = request.decode("utf-8")
            # (
            #     requestMethod,
            #     requestUrl,
            #     requestHeaders,
            #     requestParams,
            #     requestBody,
            # ) = self.DissectPacket(browserRequest)
            destSrvSkt.send(request)
            responsePacket = destSrvSkt.recv(8000) # after sending to server and getting response
            return responsePacket

    def DissectBrowserProxyRequests(self, browser_request:str):
        host_regex = "CONNECT .*\:\d\d\d"
        pattern = re.compile(host_regex)
        hostStr = pattern.findall(browser_request)[0]
        host = hostStr.split(" ")[1].split(":")[0]
        port  = hostStr.split(" ")[1].split(":")[1]
        return host,port

    def generateDomainCerts(self, hostname:str):
        """generate a certificate for a specific host and sign it with the root certificate. Return the path to the certficate (.crt) file"""
        hostname = hostname.strip()
        host_cer = self.rootCA.load_cert(hostname)
        return host_cer

    async def createDestConnection(self, host_portlist):
        # open up a tcp socket with destination server
        dest_server_skt = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            dest_server_skt.connect((host_portlist[0], int(host_portlist[1])))
            print("TCP connection to destination server successfull")

            # destination server ssl context(upgrading the destination-server socket to ssl)
            destServerSslContext = SSL.Context(SSL.SSLv23_METHOD)
            destServerSslServerSkt = SSL.Connection(destServerSslContext, dest_server_skt)
            destServerSslServerSkt.set_connect_state()
            # enable certfificate verification 
            # destServerSslContext.set_verify(SSL.VERIFY_PEER | SSL.VERIFY_FAIL_IF_NO_PEER_CERT, self.verify_callback)
            destServerSslContext.set_verify(SSL.VERIFY_NONE, self.verify_callback)
            # load trusted certficates
            destServerSslContext.load_verify_locations(self.MozillaCACertsVerifyFile)
            destServerSslServerSkt.do_handshake()
            print("Destination server connection setup successfully with ssl support")
            return destServerSslServerSkt, 0    
        except Exception as e:
            return None, 1

    def verify_callback(self, connection, x509, errno, depth, preverify_ok):
        # Implement your verification logic here
        # if preverify_ok:
        #     print("Certificate verification passed")
        #     return True
        # else:
        #     print("Certificate verification failed")
        #     return False
        return True

    async def HandleHostInstance(self, browser_socket:socket.socket):
        # handle the initial http request by browser
        print("Waiting for initial browser request")
        initial_browser_request = browser_socket.recv(1600).decode("utf-8")
        print(cyan("Browser Intercept Request: "))
        print(initial_browser_request)
        host_portlist = self.DissectBrowserProxyRequests(initial_browser_request)
        host_cer = self.generateDomainCerts(host_portlist[0])     

        # open up proxy-destination server connection
        destServerSslServerSocket, Conn_status = await self.createDestConnection(host_portlist)

        # respond to browser after making destination connection
        if Conn_status == 0:
            response = b"HTTP/1.1 200 Connection established\r\n\r\n"
            browser_socket.sendall(response)
            browserSocketSslContext = SSL.Context(SSL.TLSv1_2_METHOD)
            browserSocketSslContext.use_certificate(host_cer[0])
            browserSocketSslContext.use_privatekey(host_cer[1])
            ClientSslSocket = SSL.Connection(browserSocketSslContext, browser_socket)
            ClientSslSocket.set_accept_state()
            print("successfully wrapped browser socket with ssl")
            # open browser-proxy-destination tunnel
            while True:
                try:
                    RequestPacket = ClientSslSocket.recv(4096)
                    ResponsePacket = await self.HandleBrowserRequest(RequestPacket,destServerSslServerSocket)
                    print(ResponsePacket)
                    ClientSslSocket.send(ResponsePacket)
                except KeyboardInterrupt:
                    self.sslServerSocket.close()
                    ClientSslSocket.close()
                except Exception as e:
                    print(red(f"Encountered error {e}\n"))
                    break
        elif Conn_status ==1:
            response = b"HTTP/1.1 500 Connection Failed"
            browser_socket.sendall(response)
            print(red("Connection to remote server failed\n"))
            browser_socket.close()

    async def startServerInstance(self):
        print(yellow(f"Proxy running on {self.host} on port {self.port}"))
        while True:
            print(yellow("Waiting for Incoming Connections"))
            browser_socket, browser_address = self.socket.accept()
            with ThreadPoolExecutor(max_workers=8) as executor:
                executor.submit(await self.HandleHostInstance(browser_socket))


if __name__ == "__main__":
    try:
        proxy = ProxyHandler()
        asyncio.run(proxy.startServerInstance())
    except KeyboardInterrupt:
        print(red("\nCleaning Up"))
        proxy.socket.close()