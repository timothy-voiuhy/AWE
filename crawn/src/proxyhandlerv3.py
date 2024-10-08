import argparse
import hashlib
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
import brotli
from OpenSSL import SSL
from config.config import RUNDIR
from utiliities import DissectClientReqPkt, makelogger, writeLinkContentToFIle
from concurrent.futures import ThreadPoolExecutor
from awe_net.awe_ca import ProxyCertificateAuthority
from session import SessionHandler, SessionHandlerResponse
from awe_net.awe_net import ProxyServerSslSocket


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


def is_proxyCommand(initial_client_req):
    try:
        if isinstance(json.loads(initial_client_req), dict):
            return True
        else:
            return False
    except Exception:
        return False


def DissectClientProxyRequests(client_request: str):
    """Disect the initial client request and extract the host, port and keep-alive values"""
    host_regex = "CONNECT .*\:\d\d\d"
    pattern = re.compile(host_regex)
    try:
        hostStr = pattern.findall(client_request)[0]
        if hostStr is not None:
            host = hostStr.split(" ")[1].split(":", 1)[0]
            port = hostStr.split(" ")[1].split(":", 1)[1]
            keep_alive = True
            return host, port, keep_alive
        else:
            return False
    except IndexError:
        return False


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
                 save_traffic=False):
        self.host = host
        self.port = port
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.socket.bind((self.host, self.port))
        except OSError as e:
            logging.error(f"'enountered error' {e}")
            sys.exit()
        self.socket.listen(500)
        if sys.platform == "WIN32":
            self.runDir = rundir = RUNDIR
        else:
            self.runDir = RUNDIR
        self.lock = threading.Lock()

        self.certificate_authority = ProxyCertificateAuthority()

        self.homeDirectory = os.path.expanduser("~")
        self.defaultWorkspaceDir = os.path.join(
            self.homeDirectory, "AWE/AtomProjects/Proxy/")
        self.sessionsDict = {}
        self.save_traffic = save_traffic
        self.error_file_count = 0
        self.logging = False
        # default regex pattern that can match for all hostnames
        self.scope = ["."]
        self.proxy_log_dir = self.runDir + "/logs/"
        if not os.path.isdir(self.proxy_log_dir):
            os.makedirs(self.proxy_log_dir)
        self.proxy_validation_logger = makelogger("proxy_validation_logger",
                                                  "proxy_validation_logger.log",
                                                  projectDir=self.proxy_log_dir)

    def constructResponsePacket(self, u_response: SessionHandlerResponse):
        try:
            body = u_response._content
            decodedBody = u_response.text.encode()
            # body_encoding = u_response.encoding
            len_body = len(body)
            status_line = f"HTTP/{str(u_response.http_version)[-3]}.{str(u_response.http_version)[-1]} {u_response.status_code} {u_response.reason_phrase}"
            if u_response.http_version and u_response.status_code and u_response.reason_phrase:
                logging.debug("got body, body_len & status_line")

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
        except Exception as exp:
            logging.error(f"Encountering error : {exp}", exc_info=True)

    def ForwardClientRequest(self, request: bytes,
                             http: bool = False
                             ):
        try:
            headers_end = request.find(b"\r\n\r\n")
            headers = request[:headers_end]
            headers_str = headers.decode("utf-8")
            headers_list = headers_str.split("\r\n")[1:]
            headers_dict = {}
            for header in headers_list:
                key_value_pair = header.split(":", 1)
                headers_dict[key_value_pair[0]] = key_value_pair[1]
            # handle possible websocket comms
            if b'Upgrade: websocket' in headers or b'upgrade: websocket' in headers:
                websocket_key = headers_dict.get("Sec-WebSocket-Key")
                if websocket_key is None:
                    websocket_key = headers_dict.get("sec-websocket-key")
                logging.warning(f"Client asking for websocket support")
                # webskt_comm = WebSocketHandler(websocket_key)

            try:
                bodyEncoding = False
                encoded_body = request[headers_end + 4:]
                if b'Content-Encoding: gzip' in headers or b'content-encoding: gzip' in headers:
                    bodyEncoding = True
                    headers_dict = {}
                    for header in headers.split("\r\n"):
                        key, value = header.split(":", 1)
                        headers_dict[key] = value
                    decompressed_body = gzip.decompress(encoded_body)
                    decompressed_utf_body = decompressed_body.decode("utf-8")
                    len_decompressed_utf_body = len(decompressed_utf_body)
                    headers_dict["Content-Length"] = str(
                        len_decompressed_utf_body)
                    headers = ''.join(
                        [f"{key}: {value}\r\n" for key, value in headers_dict.items()])
                    clientRequest = headers + decompressed_utf_body
                else:
                    clientRequest = request.decode("utf-8")
            except UnicodeDecodeError:
                filename = "client_reqeust.txt" + str(self.error_file_count)
                with open(filename, "wb") as file:
                    file.write(request)
                    logging.error(f"got unicode decode error in client request , written to file=>'){filename}",
                                  exc_info=True)
                self.error_file_count += 1
            except Exception as exp:
                logging.error(f"Encountered error: {exp}", exc_info=True)
            (requestMethod, requestUrl, requestHeaders, requestParams, requestBody,
             requestUrlwParams) = DissectClientReqPkt(clientRequest, http)
            if bodyEncoding:
                requestBody = encoded_body
            logging.info(
                f"Connecting to remote server ....... on url: {requestUrlwParams}")
            if requestBody == "":
                requestBody = None

            session_handler = SessionHandler()
            response = session_handler.makeRequest(request_method=requestMethod,
                                                   request_url=requestUrlwParams,
                                                   request_headers=requestHeaders,
                                                   request_data=requestBody)
            if type(response) is SessionHandlerResponse:
                if response.status_code is None:
                    logging.error(f"failed to fetch response :url: {requestUrl} :status_code: {response.status_code}",
                                  exc_info=True)
                else:
                    logging.debug(
                        f"function makeRequest returned valid response :url: {requestUrl} :status_code: {response.status_code}")
                    responsePacket, decodedResponsePacket = self.constructResponsePacket(
                        u_response=response)
                    return responsePacket, requestUrl, clientRequest, decodedResponsePacket
            elif response == "close":
                return response
            elif type(response) is bytes:
                return response
        except Exception as exp:
            logging.error(f"failure in forwarding client request :url: {requestUrl} :error: {exp}", exc_info=True)

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

    def handle_forwarding(self, RequestPacket,
                          http,
                          hostname,
                          host_dir,
                          client_ssl_socket,
                          client_socket,
                          ):
        try:
            forward_response = self.ForwardClientRequest(RequestPacket, http=http)
            if type(forward_response) is tuple:
                ResponsePacket, requestUrl, dec_clientRequest, dec_clientResponse = forward_response
                if self.save_traffic:
                    # remember in the gui the scope are regex patterns
                    if self.logging is True:
                        if self.scope is not None:
                            for scope_regex in self.scope:
                                pattern = re.compile(scope_regex)
                                if len(pattern.findall(hostname)) != 0:
                                    req_res_data = self.createReqResData(
                                        dec_clientRequest, dec_clientResponse)
                                    writeLinkContentToFIle(
                                        host_dir, requestUrl, req_res_data)
                try:
                    # replace with sendall during debugging
                    writtenBytes = client_ssl_socket.sendall(ResponsePacket)
                except AttributeError:
                    writtenBytes = client_socket.sendall(dec_clientResponse)
                # logging.info(f"{yellow('Bytes written to client socket')}\n\t{writtenBytes}")
            elif forward_response == "close":
                client_socket.close()
            elif type(forward_response) is bytes:
                client_socket.sendall(forward_response)
        except Exception as exp:
            logging.error(f"fowarding failed :error: {exp}", exc_info=True)

    def OpenHttpsCommTunnel(self, client_ssl_socket,
                            host_dir,
                            hostname,
                            client_socket: socket.socket,
                            request_packet: bytes = None,
                            http: bool = False,
                            keep_alive=False):
        try:
            if request_packet is None:
                # this is the instance where the keep alive is valid
                if keep_alive:
                    request_packet = client_ssl_socket.recv(40960)
                    # forward original request
                    self.handle_forwarding(request_packet, http, hostname, host_dir, client_ssl_socket, client_socket)
                    # now handle the keep alive connection loop
                    while keep_alive:
                        browser_req_data = client_ssl_socket.recv(40960)
                        host_portlist = DissectClientProxyRequests(
                            browser_req_data.decode("utf-8"))
                        if host_portlist:
                            keep_alive = host_portlist[2]
                        if not browser_req_data:
                            break
                        if self.isRequest(browser_req_data):
                            try:
                                self.handle_forwarding(browser_req_data, http, hostname, host_dir, client_ssl_socket,
                                                       client_socket)
                                # self.HandleValidClientRequest(browser_req_data.decode("utf-8"), client_socket)
                            except Exception as exp:
                                logging.error(f"Encountered error during keep_alive loop with error: {exp}",
                                              exc_info=True)
                            # self.handle_forwarding(browser_req_data,http,hostname,host_dir,client_ssl_socket,client_socket)
                else:
                    request_packet = client_ssl_socket.recv(40960)
                    self.handle_forwarding(request_packet,
                                           http, hostname, host_dir, client_ssl_socket, client_socket)

            else:
                self.handle_forwarding(request_packet, http, hostname, host_dir, client_ssl_socket, client_socket)

            self.closeTunnel(client_socket)
        except SSL.SysCallError as e:
            logging.error(f"Client Socket Unexpectedly closed with error:{e}")
            self.closeTunnel(client_socket)
        except SSL.Error as e:
            # logging.warning(f"Client failed to accept certificates\n\t'Error:'{e}")
            self.closeTunnel(client_socket)

    def HandleProxyCommands(self, initial_client_request):
        command_dict = json.loads(initial_client_request)
        if list(command_dict.keys())[0] == "scope":
            self.scope = list(command_dict.values())

        elif list(command_dict.keys())[0] == "log":
            if list(command_dict.values())[0] == 1:
                self.logging = False
            else:
                self.logging = True

    def HandleValidClientRequest(self, initial_client_request, client_socket):
        """this function handles a valid request forexample 
        GET /resource HTTP/2
        ....."""
        """recieve request from browser
        forward it to the session handler 
        get response from session handler
        forward the response from the session handler to the browser"""
        logging.info("Received valid request as initial client request")
        dissected_req = DissectClientReqPkt(initial_client_request, http=True)
        requestUrl = dissected_req[1]
        requestHeaders = dissected_req[2]
        # self.proxy_validation_logger.info(f"recieved browser request to url : {requestUrl}")
        try:
            hostname = requestHeaders["Host"]
            hostDir = os.path.join(self.defaultWorkspaceDir, hostname + "/")
            self.OpenHttpsCommTunnel(client_ssl_socket=None, host_dir=hostDir, hostname=hostname,
                                           client_socket=client_socket,
                                           request_packet=initial_client_request.encode("utf-8"),
                                           http=True)
            # self.proxy_validation_logger.info(f"successfully returned response to browser :url: {requestUrl}")
            logging.info(
                f"successfully returned response to browser :url: {requestUrl}")
        except Exception as exp:
            # self.proxy_validation_logger.error(f"failed to return response to browser :url: {requestUrl}")
            logging.error(f"failed to return response to browser :url: {requestUrl} with error: {exp}", exc_info=True)

    def HandleProxyClientRequest(self, initial_client_request, client_socket):
        """handle a direct request directed to the proxy.
        This normally starts with CONNECT ..."""
        host_portlist = DissectClientProxyRequests(initial_client_request)
        if host_portlist is not None:
            keep_alive = host_portlist[2]
            hostname = host_portlist[0]
            hostnameUrl = processUrl(hostname)[0]
            hostDir = os.path.join(
                self.defaultWorkspaceDir, hostname + "/")
            destConnection = True  # todo: check internet connection(ping host)
            # respond to client
            if destConnection:
                response = b"HTTP/1.1 200 Connection established\r\n\r\n"
                client_socket.sendall(response)
                # upgrade the client-proxy socket to ssl/tls
                certificate, private_key = self.certificate_authority.generateCertificate(hostname)
                _client_ssl_skt = ProxyServerSslSocket(n_socket=client_socket,
                                                       certificate=certificate,
                                                       private_key=private_key)

                ClientSslSocket = _client_ssl_skt.createConnection()
                if ClientSslSocket:
                    logging.info("Upgraded client socket to support ssl")

                # open client-proxy-destination tunnel
                self.OpenHttpsCommTunnel(ClientSslSocket,
                                               hostDir,
                                               hostname,
                                               client_socket=client_socket,
                                               keep_alive=keep_alive)

            else:
                response = b"HTTP/1.1 500 Connection Failed"
                client_socket.sendall(response)
                logging.error(
                    "Connection to remote server failed\n", exc_info=True)
                client_socket.close()
        else:
            logging.error("Initial Client Request is Invalid", exc_info=True)

    def HandleConnection(self, client_socket: socket.socket):
        initial_client_request =client_socket.recv(160000)
        initial_client_request = initial_client_request.decode()
        if is_proxyCommand(initial_client_request):
            self.HandleProxyCommands(initial_client_request)
        elif initial_client_request != "":
            if self.isRequest(initial_client_request.encode("utf-8")):
                self.HandleValidClientRequest(initial_client_request, client_socket)
            else:
                self.HandleProxyClientRequest(initial_client_request, client_socket)
        else:
            logging.error("Initial Client Request is Invalid", exc_info=True)

    def startServer(self):
        logging.info(f"Proxy running on {self.host}, port {self.port}")
        with ThreadPoolExecutor(max_workers=3084) as executor:
            while True:
                client_socket, client_address = self.socket.accept()
                executor.submit(self.HandleConnection, client_socket)

    def notifyThreadMonitor(self):
        pass

    def startServerInstance(self):
        self.startServer()


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.WARNING,
        format="%(asctime)s -%(levelname)s - %(filename)s:%(lineno)d - %(funcName)s - %(message)s")

    for logger_name in logging.root.manager.loggerDict:
        if logger_name not in ["__main__"]:
            logging.getLogger(logger_name).setLevel(logging.WARNING)

    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-p", "--port", help="port on which the proxy should listen")
    args = parser.parse_args()
    if args.port:
        proxy = ProxyHandler(save_traffic=True, port=int(args.port))
        try:
            proxy.startServerInstance()
        except KeyboardInterrupt:
            logging.info("\nCleaning Up")
            proxy.socket.close()
    else:
        print("you ran this program with few arguments")
        parser.print_help()

"""
handle logging that uses json: for each request made all possible info, incase of failure then show reason.
handle Connection:close in the keep_alive
handle errors and status_codes that are not 200 try retrying and so on
cookies """
