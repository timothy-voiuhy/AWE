import httpx
import httpx._client as httpClient
import socket
import json
import logging
from utiliities import (yellow, cyan, red,
                        is_brotli_compressed, is_gzip_compressed, is_zlib_compressed)
from urllib import parse as UrlParser
import brotli
import zlib
import gzip

class SesssionHandler():
    def __init__(self, host_address:str= None,
                 listening_port:int= None,
                 use_tor= False) -> None:
        self.host = host_address
        if self.host is None:
            self.host = "127.0.0.1"
        self.port = listening_port
        self.use_tor = use_tor
        self.server_socket = socket.create_server(address=(self.host, self.port))
        if self.use_tor:
            proxies = {
                "http://": "socks5://127.0.0.1:9050",
                "https://": "socks5://127.0.0.1:9050",
            }
            self.PoolManager = httpClient.Client(
                follow_redirets=True, timeout=15, proxies=proxies)
        else:
            self.PoolManager = httpClient.Client(
                follow_redirects=True, timeout=15)
    
    def decodeClientRequest(self, client_request:str):
        client_request_dict = dict(json.loads(client_request))
        method = client_request_dict["method"]
        url = client_request_dict["url"]
        params = dict(client_request_dict["params"])
        data = client_request_dict["body"]
        headers = client_request_dict["headers"]
        return method, url, params

    def joinUrlwParams(self, url:str, params:dict):
        params_str = UrlParser.urlencode(params)
        return url+"?"+params_str

    def constructResponsePacket(self, u_response: httpx.Response = None,
                                usedRequests: bool = False):
        if self.useHttpx or usedRequests:
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

    def handleClientConnection(self, clientSocket:socket.socket):
        client_request = clientSocket.recv(160000).decode("utf-8")
        method, url, params, data, headers = self.decodeClientRequest(client_request)
        request_urlw_params = self.joinUrlwParams(url, params)
        try:
            retries = 0
            while retries < 5:
                response = self.PoolManager.request(method=method,
                                                    url=request_urlw_params,
                                                    headers=headers,
                                                    data=data,
                                                    follow_redirects=True)
                if response:
                    break
                else:
                    logging.info(yellow("retrying...."))
                retries += 1
        except httpx.ConnectError:
            logging.error(red(f"failing to resolve to url {request_urlw_params}"))

    def startServer(self):
        self.server_socket.listen()
        while True:
            client_socket = self.server_socket.accept()[0]
            self.handleClientConnectioni(client_socket)