import argparse
import gzip
import json
import logging
import os
import random
import re
import socket
import sys
import threading
import zlib
from urllib import parse as urlparser

import brotli
import certifi
import requests
from OpenSSL import SSL
from certauth.certauth import CertificateAuthority

from session import SesssionHandler, SesssionHandlerResponse
from utiliities import red, cyan, yellow


def is_brotli_compressed(data):
    brotli_magic_number = b'\x1b'
    return data[:1] == brotli_magic_number


def is_zlib_compressed(data):
    zlib_magic_number = b'x\x9c'
    return data[:2] == zlib_magic_number


def is_gzip_compressed(data):
    gzip_magic_number = b'\x1f\x8b'
    return data[:2] == gzip_magic_number


class WebSocketHandler:
    """Handle the whole websocket connection both the client side and
    the server side."""

    def __init__(self, websocket_key):
        self.websocket_key = websocket_key


def DissectClientProxyRequests(client_request: str):
    """Disect the initial client request and extract the host, port and keep-alive values"""
    host_regex = "CONNECT .*\:\d\d\d"
    pattern = re.compile(host_regex)
    try:
        hostStr = pattern.findall(client_request)[0]
        if hostStr is not None:
            host = hostStr.split(" ")[1].split(":")[0]
            port = hostStr.split(" ")[1].split(":")[1]
            keep_alive = True
            return host, port, keep_alive
        else:
            return False
    except IndexError:
        return False


def DissectClientReqPkt(packet: str, http: bool = None):
    "dissect the packets sent by the individual hosts/domains from the client"
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
    # logging.info(f"{yellow('method:')}{packetMethod}\n{yellow('url:')}{packetUrl}\n{yellow('headers:')}{packetHeadersDict}\n{yellow('params:')}{packetParamsDict}\n{yellow('body:')}{packetBody}\n{yellow('packetUrlWithParams:')}{packetUrlwParams}")
    return packetMethod, packetUrl, packetHeadersDict, packetParamsDict, packetBody, packetUrlwParams


def writeLinkContentToFIle(main_dir, link: str, data, hostname):

    link_components = urlparser.urlparse(link)
    # the netlock + path,  this already has file name if it does not end with "/"
    relative_path = link_components[1] + link_components[2]

    if link.endswith("/"):
        # giving a file name for the index file
        relative_path = relative_path + "index.html"

    if relative_path is not None:
        if not main_dir.endswith("/"):
            file_path = main_dir + "/" + relative_path
        else:
            file_path = main_dir+relative_path
    dir_path, file_name = os.path.split(file_path)
    try:
        if not os.path.exists(path=file_path):
            os.makedirs(dir_path)
            # this is where we caught the error after we try to a file that does not exist
            with open(file_path, 'wb') as file:
                file.write(data)
        else:
            os.remove(file_path)
            with open(file_path, 'wb') as g:
                g.write(data)
        return file_path
    except Exception as e:
        logging.warn(f"failed to save file with error {e}")


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
                 port=random.randint(8000, 10000),
                 downloadMozillaCAs=False,
                 UsehttpLibs=False,
                 verifyDstServerCerts=True,
                 save_traffic=False,
                 useFileBasedCerts=False,
                 useHttpx=False,):
        self.host = host
        self.port = port
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.socket.bind((self.host, self.port))
        except OSError as e:
            logging.error(f"{red('enountered error')} {e}")
            sys.exit()
        self.socket.listen(5)
        self.downlaodMozillaCAs = downloadMozillaCAs
        if sys.platform == "WIN32":
            self.runDir = rundir = "D:\\MYAPPLICATIONS\\AWE\\AWE\\crawn\\src"
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
                self.rootCA = CertificateAuthority(
                    "LOCALHOST CA", self.rootCAcf, cert_cache=100)
            else:
                self.rootCA = CertificateAuthority(
                    "LOCALHOST CA", self.rootCAcf, cert_cache=100)
        else:
            if not os.path.isdir(self.certsDir):
                os.makedirs(self.certsDir)
            self.rootCA = CertificateAuthority(
                "LOCALHOST CA", self.rootCAcf, cert_cache=self.certsDir)
            self.rootCAprivatekeyfile = self.runDir + "/proxycert/CA/privatekey.pem"
        self.usehttpLibs = UsehttpLibs
        self.homeDirectory = os.path.expanduser("~")
        self.defaultWorkspaceDir = os.path.join(
            self.homeDirectory, "AtomProjects/Proxy/")
        self.verifyDstServerCerts = verifyDstServerCerts
        self.sessionsDict = {}
        self.save_traffic = save_traffic
        self.error_file_count = 0
        self.useHttpx = useHttpx
        self.logging = True
        # default regex pattern that can match for all hostnames
        self.scope = ["."]

    def constructResponsePacket(self, u_response:SesssionHandlerResponse = None):
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
        headers = ''.join(
            [f"{key}: {value}\r\n" for key, value in r_headers.items()])
        cookies = ''.join(
            [f"{key}: {value};" for key, value in u_response.cookies.items()])
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
            decodedResponsePacket = responsePacket + \
                decodedBody.decode("utf-8")
            return responsePacket.encode(), decodedResponsePacket

    def ForwardClientRequest(self, request: bytes,
                              destSrvSkt: SSL.Connection = None,
                              usehttpLibs=False,
                              http: bool = False
                              ):
        headers_end = request.find(b"\r\n\r\n")
        headers = request[:headers_end]
        # handle possible websocket comms
        if b'Upgrade: websocket' in headers or b'upgrade: websocket' in headers:
            websocket_key = headers_dict.get("Sec-WebSocket-Key")
            if websocket_key is None:
                websocket_key = headers_dict.get("sec-websocket-key")
            logging.warn(red(f"Client asking for websocket support"))
            # webskt_comm = WebSocketHandler(websocket_key)
        try:
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
                headers = ''.join(
                    [f"{key}: {value}\r\n" for key, value in headers_dict.items()])
                clientRequest = headers + decompressed_utf_body
            else:
                clientRequest = request.decode("utf-8")
        except UnicodeDecodeError:
            filename = "client_reqeust.txt" + str(self.error_file_count)
            with open(filename, "wb") as file:
                file.write(request)
                logging.error(f"{red(f'got unicode decode error in client request , written to file=>')}{filename}")
            self.error_file_count += 1
        (requestMethod, requestUrl, requestHeaders, requestParams, requestBody,
         requestUrlwParams) = DissectClientReqPkt(clientRequest, http)
        if usehttpLibs:
            if bodyEncoding:
                requestBody = encoded_body
            logging.info(
                yellow(f"Connecting to remote server ....... on url: {requestUrlwParams}"))
            if requestBody == "":
                requestBody = None

            session_handler = SesssionHandler()
            response = session_handler.makeRequest(request_method=requestMethod,
                                    request_url=requestUrlwParams,
                                    request_headers= requestHeaders,
                                    request_data=requestBody)

            responsePacket, decodedResponsePacket = self.constructResponsePacket(
                u_response=response)
        return responsePacket, requestUrl, clientRequest, decodedResponsePacket


    def closeTunnel(self, client_socket, closeClientSocket=True):
        if closeClientSocket:
            client_socket.close()


    def isRequest(self, request: bytes):
        if b'Accept-Encoding:' in request and b'Accept:' in request:
            return True
        else:
            return False


    def createReqResData(self, dec_clientRequest: str, dec_clientResponse: str | bytes):
        if isinstance(dec_clientResponse, bytes):
            req_res_data = dec_clientRequest.encode(
                "utf-8") + b'\nRESPONSE\n' + dec_clientResponse
            return req_res_data
        elif isinstance(dec_clientResponse, str):
            req_res_data = dec_clientRequest + "\nRESPONSE\n" + dec_clientResponse
            return req_res_data.encode("utf-8")


    def OpenHttpsCommTunnel(self, ClientSslSocket: SSL.Connection,
                            hostDir,
                            hostname,
                            hostnameUrl,
                            destServerSslServerSocket: SSL.Connection,
                            usehttpLibs: bool,
                            client_socket: socket.socket,
                            RequestPacket: bytes = None,
                            http: bool = False,
                            unix=False):
        try:
            if RequestPacket is None:
                RequestPacket = ClientSslSocket.recv(40960)

            ResponsePacket, requestUrl, dec_clientRequest, dec_clientResponse = self.ForwardClientRequest(
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
                                req_res_data = self.createReqResData(
                                    dec_clientRequest, dec_clientResponse)
                                writeLinkContentToFIle(
                                    hostDir, requestUrl, req_res_data, hostname)
            try:
                # replace with sendall during debugging
                writtenBytes = ClientSslSocket.sendall(ResponsePacket)
            except AttributeError:
                writtenBytes = client_socket.sendall(dec_clientResponse)
            # logging.info(f"{yellow('Bytes written to client socket')}\n\t{writtenBytes}")
            self.closeTunnel(client_socket)
        except SSL.SysCallError as e:
            logging.error(f"{red('Client Socket Unexpectedly closed with error:')}{e}")
            self.closeTunnel(client_socket)
        except SSL.Error as e:
            logging.error(f"{red('Client failed to accept certificates')}\n\t{yellow('Error:')}{red(e)}")
            self.closeTunnel(client_socket)


    def HandleProxyCommands(self, initial_client_request):
        command_dict = json.loads(initial_client_request)
        if list(command_dict.keys())[0] == "scope":
            logging.info("Trying to set the hostname's scope")
            self.scope = list(command_dict.values())
            logging.info(f"Successfully set scope to {self.scope}")

        elif list(command_dict.keys())[0] == "log":
            if list(command_dict.values())[0] == 1:
                logging.info(
                    "Recieved disable logging request \n Trying to disable logging")
                try:
                    self.logging = False
                    logging.info("Successfully disabled logging")
                except Exception as e:
                    logging.error(red(f"Failed to disable logging with error {e}"))
            else:
                logging.info(
                    "Recieved enable logging request \n Trying to enable logging")
                try:
                    self.logging = True
                    logging.info("Successfully enabled logging")
                except Exception as e:
                    logging.error(red(f"Failed to enable logging with error {e}"))

    def HandleValidClientRequest(self, initial_client_request, client_socket, unix):
        logging.info(yellow("Received valid request as initial client request"))
        (requestMethod,
            requestUrl,
            requestHeaders,
            requestParams,
            requestBody,
            requestUrlwParams) = DissectClientReqPkt(initial_client_request, http=True)
        hostname = requestHeaders["Host"]
        hostDir = os.path.join(self.defaultWorkspaceDir, hostname + "/")
        self.OpenHttpsCommTunnel(ClientSslSocket=None,
                                    hostDir=hostDir,
                                    hostname=hostname,
                                    hostnameUrl=requestUrl,
                                    destServerSslServerSocket=None,
                                    usehttpLibs=self.usehttpLibs,
                                    client_socket=client_socket,
                                    RequestPacket=initial_client_request.encode(
                                        "utf-8"),
                                    http=True,
                                    unix=unix)

    def generateDomainCerts(self, hostname: str):
        """generate a certificate for a specific host and sign it with the root certificate. Return the path to the certficate (.crt) file"""
        hostname = hostname.strip()
        if self.useFileBasedCerts is False:
            return self.rootCA.load_cert(hostname, wildcard=True)
        else:
            # filename
            return self.rootCA.cert_for_host(hostname, wildcard=True)

    def HandleProxyClientRequest(self, initial_client_request, client_socket, unix):
        host_portlist = DissectClientProxyRequests(initial_client_request)
        if host_portlist is not None:
            keep_alive = host_portlist[2]
            hostname = host_portlist[0]
            host_cer = self.generateDomainCerts(hostname)
            hostnameUrl = processUrl(hostname)[0]
            hostDir = os.path.join(
                self.defaultWorkspaceDir, hostname + "/")
            # proxy-destination server connection
            if keep_alive:
                if self.usehttpLibs == False:
                    try:
                        destServerSslServerSocket, Conn_status = self.createDestConnection(
                            host_portlist)
                        if Conn_status == 0:
                            usehttpLibs = False
                        elif Conn_status == 1:
                            logging.info(cyan("Initiating server connection error"))
                            if self.useHttpx:
                                logging.info(cyan("Resorting to => urllib3 for destination server connection"))
                            usehttpLibs = True
                        destConnection = True
                    except Exception as e:
                        logging.error(red(f"Encoutered error {e} when initiating a connection to remote server"))
                        destConnection = False
                elif self.usehttpLibs == True:
                    logging.info(cyan("Using httplibs for destination server connection"))
                    usehttpLibs = True
                    destConnection = True
                    destServerSslServerSocket = None

            # respond to client after making destination connection
            if destConnection:
                response = b"HTTP/1.1 200 Connection established\r\n\r\n"
                client_socket.sendall(response)
                # upgrade the client-proxy socket to ssl/tls
                clientSocketSslContext = SSL.Context(SSL.TLSv1_2_METHOD)
                if self.useFileBasedCerts is False:
                    clientSocketSslContext.use_certificate(
                        host_cer[0])
                    clientSocketSslContext.use_privatekey(
                        host_cer[1])
                else:
                    clientSocketSslContext.use_certificate_chain_file(
                        host_cer)
                ClientSslSocket = SSL.Connection(
                    clientSocketSslContext, client_socket)
                ClientSslSocket.set_accept_state()
                logging.info(cyan("Upgraded client socket to support ssl"))

                # open client-proxy-destination tunnel
                self.OpenHttpsCommTunnel(ClientSslSocket,
                                            hostDir,
                                            hostname,
                                            hostnameUrl,
                                            destServerSslServerSocket,
                                            usehttpLibs,
                                            client_socket,
                                            unix=unix)

            else:
                response = b"HTTP/1.1 500 Connection Failed"
                client_socket.sendall(response)
                logging.error(red("Connection to remote server failed\n"))
                client_socket.close()
        else:
            logging.error(red("Initial Client Request is Invalid"))

    def HandleConnection(self, client_socket: socket.socket, unix=True):
        try:
            logging.info(cyan("Waiting for initial client request\n"))
            initial_client_request = client_socket.recv(
                160000).decode("utf-8")
            if self.is_proxyCommand(initial_client_request):
                self.HandleProxyCommands(initial_client_request)
            elif initial_client_request != "":
                if self.isRequest(initial_client_request.encode("utf-8")):
                    self.HandleValidClientRequest(initial_client_request, client_socket, unix)
                else:
                    self.HandleProxyClientRequest(initial_client_request, client_socket, unix)
            else:
                logging.error(red("Initial Client Request is Invalid"))
        except Exception as error:
            logging.error(red(f"Encountered error : {error} while handling connection"))


    def is_proxyCommand(self, initial_client_req):
        try:
            if isinstance(json.loads(initial_client_req), dict):
                return True
            else:
                return False
        except Exception:
            return False

    def startServer(self):
        logging.info(yellow(f"Proxy running on {self.host}, port {self.port}"))
        while True:
            logging.info(yellow("Waiting for Incoming Connections"))
            client_socket, client_address = self.socket.accept()
            instanceHandlerThread = threading.Thread(
                target=self.HandleConnection, args=(client_socket,))
            instanceHandlerThread.start()

    def notifyThreadMonitor(self):
        pass

    def startServerInstance(self):
        self.startServer()

if __name__ == "__main__":

    logging.basicConfig(
        level=logging.DEBUG, format="%(asctime)s -%(levelname)s - %(filename)s:%(lineno)d - %(message)s")

    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-p", "--port", help="port on which the proxy should listen")
    args = parser.parse_args()
    if args.port:
        proxy = ProxyHandler(
            UsehttpLibs=True,
            save_traffic=True,
            port=int(args.port)
        )
        try:
            proxy.startServerInstance()
        except KeyboardInterrupt:
            logging.info(cyan("\nCleaning Up"))
            proxy.socket.close()
    else:
        print("you ran this program with few arguments")
        parser.print_help()
