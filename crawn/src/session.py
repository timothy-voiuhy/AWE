from copy import deepcopy
from datetime import timedelta
import json
import logging
import os
import random
import socket
import string
import sys
from concurrent.futures import ThreadPoolExecutor
from urllib import parse as url_parser
import httpx
import httpx._client as http_client

from config.config import RUNDIR
from utiliities import (yellow, cyan, red)


# from PySide6.QtNetwork import QNetworkRequest
# request = QNetworkRequest()
# request.setSslConfiguration()  # note that a ssl configuration can be specified not as httpx, requests, where the ssl
# configuration cannot be set.
# request.setUrl()


class SessionHandlerResponse(httpx.Response):

    def __init__(self, response_str=None, status_code_=None, content:bytes = None) -> None:
        super().__init__(status_code_)
        self.response_str_ = response_str
        self.encoding = None
        self._content = content

    @property
    def response_str(self):
        return self.response_str_

    def redo_extensions(self, extensions: dict):
        ext = {}
        for key, value in zip(extensions.keys(), extensions.values()):
            if type(value) is str:
                ext[key] = value.encode("utf-8")
            else:
                ext[key] = value
        return ext

    def redo_headers(self, headers: dict):
        return httpx.Headers(headers)

    def redo_request(self, request: tuple):
        return httpx.Request(method=request[0], url=request[1])

    def redo_elapsed(self, elapsed:list):
        return timedelta(seconds=elapsed[0],microseconds=elapsed[1], days=elapsed[2] )

    def decodeResponse(self):
        try:
            response_dict = json.loads(self.response_str.decode("utf-8"))
            # assign the keys to the respective http.Response properties
            # set the __dict__ attribute of the httpx.Response object hence assigning
            # the keys to the respective http.Response properties.

            response_dict["headers"] = self.redo_headers(response_dict["headers"])

            response_dict["extensions"] = self.redo_extensions(response_dict["extensions"])

            response_dict["_request"] = self.redo_request(response_dict["_request"])

            response_dict["_content"] = self._content

            response_dict["_elapsed"] = self.redo_elapsed(response_dict["_elapsed"])

            self.__dict__ = response_dict
            logging.debug("response_dict is now self.__dict__")
        except Exception as exp:
            logging.error(f"Encountered error : {exp}")


class SessionHandler:
    def __init__(self, host_address: str = "127.0.0.1",
                 listening_port: int = 8181,
                 use_tor=False) -> None:
        self.done_bit = 0
        self.error_bit = 1
        self.host = host_address
        self.server_port = listening_port
        if sys.platform == "WIN32":
            self.runDir = RUNDIR
            self.exchange_file = self.runDir + "\\tmp\\_tmp"
        else:
            self.runDir = RUNDIR
            self.exchange_file = self.runDir + "/tmp/_tmp"
        self.use_tor = use_tor
        self.client_socket = 0
        if self.use_tor:
            proxies = {
                "http://": "socks5://127.0.0.1:9050",
                "https://": "socks5://127.0.0.1:9050",
            }
            self.PoolManager = http_client.Client(
                follow_redirects=True, timeout=15, proxies=proxies)
        else:
            self.PoolManager = http_client.Client(
                follow_redirects=True, timeout=15)

    def makeRequest(self, request_method, request_url, request_headers, request_data=None, raw_pkt_bytes = None):
        if raw_pkt_bytes is None:
            try:
                self.createClientConnection()
                proxy_ses_req_dict = {}
                proxy_ses_req_dict["method"] = request_method
                proxy_ses_req_dict["url"] = request_url
                proxy_ses_req_dict["headers"] = request_headers
                proxy_ses_req_dict["data"] = request_data
                proxy_ses_request_str = json.dumps(proxy_ses_req_dict)
                self.clientSendAll(proxy_ses_request_str)
                response = self.clientRecv()
                if type(response) is SessionHandlerResponse:
                    if response.status_code is None:
                        logging.error(f"failed to retrieve response :url: {request_url} :status_code: {response.status_code}", exc_info=True)
                    else:
                        logging.debug(f"response retrieved by clientRecv :status_code: {response.status_code}")
                        return response
                elif response == "close":
                    return response
                elif type(response) is bytes:
                    return response
            except Exception as e:
                logging.error(f"makeRequest failed :error: {e}", exc_info=True)
        else:
            pass

    def get_response_headers_dict(self, headers: httpx.Headers):
        header_keys = headers.keys()
        header_values = headers.values()
        headers_dict = {}
        for key, value in zip(header_keys, header_values):
            headers_dict[key] = value
        return headers_dict

    def get_request(self, request: httpx.Request):
        return request.method, str(request.url)

    def get_extensions(self, extensions: dict):
        ext_dict = {}
        for key, value in zip(extensions.keys(), extensions.values()):
            if type(value) is bytes:
                ext_dict[key] = value.decode("utf-8")
            else:
                ext_dict[key] = None
        return ext_dict

    def get_elapsed(self, elapsed:timedelta):
        return [elapsed.seconds, elapsed.microseconds, elapsed.days]

    def serializeResponse(self, response: httpx.Response):
        response_dict = response.__dict__
        response_encoded_content = deepcopy(response._content)
        response_dict["headers"] = self.get_response_headers_dict(response.headers)
        response_dict["_request"] = self.get_request(response.request)
        response_dict["_content"] = None
        response_dict["stream"] = None  # parse if needed and those below
        response_dict["_encoding"] = response.encoding
        response_dict["_decoder"] = None
        response_dict["_elapsed"] = self.get_elapsed(response.elapsed)
        response_dict["extensions"] = self.get_extensions(response_dict["extensions"])
        # logging.debug(f"response headers: {response.headers}")

        try:
            logging.debug("serializing response to str")
            # logging.debug(f"response_dict: {response_dict}")
            response_str = json.dumps(response_dict)
            if response_str:
                logging.debug("successfully serialized response to json_str")
            else:
                logging.debug("failed to serialize response to json_str")
            return response_str, response_encoded_content
        except Exception as exp:
            logging.debug(f"failed to serialize response to a json_str after encountering error {exp}")

    # @staticmethod
    def joinUrlwParams(self, url: str, params: dict):
        params_str = url_parser.urlencode(params)
        return url + "?" + params_str

    def decodeClientRequest(self, client_request: str):
        client_request_dict = dict(json.loads(client_request))
        method = client_request_dict["method"]
        url = client_request_dict["url"]
        headers = dict(client_request_dict["headers"])
        data = client_request_dict["data"]
        return method, url, data, headers

    def closeTunnel(self, client_socket, closeClientSocket=True):
        if closeClientSocket:
            client_socket.close()

    def generate_random_filename(self):
        chars = string.ascii_letters + string.digits
        filename = "".join(random.choices(chars, k=72))
        return filename

    def handleClientConnection(self, client_socket: socket.socket):
        # try:
        client_request = client_socket.recv(160000).decode("utf-8")
        method, url, data, headers = self.decodeClientRequest(client_request)
        retries = 0
        while retries < 5:
            try:
                response = self.PoolManager.request(method=method,
                                                    url=url,
                                                    headers=headers,
                                                    data=data,
                                                    follow_redirects=True)
                break
            except httpx.ConnectError:
                logging.warning(f"failing to resolve to url {url}")
                if retries == 4:
                    response = None
                    logging.error(f"failed to resolve to url {url} after 4 retries, probaly no internet connection or wrong url",)
                    break
            retries += 1
        if type(response) is httpx.Response:
            logging.debug("successfully fetched response")
            response_str, resp_content = self.serializeResponse(response)
            try:
                exchange_file = self.exchange_file + self.generate_random_filename()
                exch_file_dir, exch_file_name = os.path.split(exchange_file)

                if not os.path.isdir(exch_file_dir):
                    os.makedirs(exch_file_dir)

                file_data = response_str.encode() + b'--:::cont:::--' + resp_content

                with open(exchange_file, "wb") as file:
                    file.write(file_data)
              
                # prepare the data to be sent ie done bit and the filename
                data = {"bit": self.done_bit, "filename": exchange_file}

                if client_socket.send(json.dumps(data).encode("utf-8")):
                    logging.debug("sent done bit")
                    client_socket.close()
                else:
                    logging.error("failed to send done bit", exc_info=True)
                logging.debug("successfully sent response to session client")  # instead of
                # sending the data, a done message is going to be sent and the data written to a file from
                # where the other side reads it from.
            except Exception as e:
                logging.error(f"Encountered error: {e} while processing {url}", exc_info=True)
            self.closeTunnel(client_socket)
            # except Exception as error:
            #     logging.error(f"Encountered error: {error}")
            #     self.client_socket.send(self.error_bit)
        elif response is None:
            data = {"bit":self.error_bit}
            if client_socket.send(json.dumps(data).encode("utf-8")):
                    logging.debug("sent error_bit")
                    client_socket.close()
            else:
                logging.error("failed to send error bit", exc_info=True)
                logging.debug("successfully sent response to session client")

    def createServer(self):
        self.server_socket = socket.create_server(address=(self.host, self.server_port),
                                                  family=socket.AF_INET)
        self.server_socket.listen()
        logging.info(f"Session handler listening on port {self.server_port}")
        with ThreadPoolExecutor(max_workers=3084) as executor:
            while True:
                # logging.info("Session Handler waiting for incoming connection ...")
                client_socket = self.server_socket.accept()[0]
                executor.submit(self.handleClientConnection, client_socket)

    def createClientConnection(self):
        self.client_socket = socket.create_connection(address=("127.0.0.1", self.server_port))

    def clientSendAll(self, req: str):
        self.client_socket.sendall(req.encode("utf-8"))

    def get_status_code(self, ses_resp_str: str):
        ses_resp_dict = json.loads(ses_resp_str)
        return ses_resp_dict["status_code"]

    def clientRecv(self):
        try:
            data = self.client_socket.recv(1000).decode("utf-8")
            data_dict = json.loads(data)
            if data_dict["bit"] == 0:
                logging.debug("received response from session server")
                exchange_file = data_dict["filename"]
                with open(exchange_file, "rb") as file:
                    _data = file.read()
                dat_cont = _data.split(b'--:::cont:::--')
                resp_data = dat_cont[0]
                resp_content = dat_cont[1]
                status_code = self.get_status_code(resp_data.decode("utf-8"))
                response = SessionHandlerResponse(response_str=resp_data, status_code_=status_code, content = resp_content)
                response.decodeResponse()
                logging.debug("successfully decoded ses_response")
                os.remove(exchange_file)
                return response

            elif data_dict["bit"] == 1:
                response = ("HTTP/1.1 502 Bad Gateway\r\n"
                             "Content-Type: text/html; charset=UTF-8\r\n"
                             "Content-Length: 89\r\n"
                             "X-Proxy-Server: aweProxy\r\n"
                             "\r\n"
                             "<html><body><h1>502 Bad Gateway : Unable to connect to the destination server.</h1></body></html>")
                return response.encode()
        except json.decoder.JSONDecodeError:
            return "close"

        except Exception as exp:
            logging.error(f"Encountered error: {exp}", exc_info=True)

    def closeServer(self):
        logging.info(red("Exiting"))
        logging.info(cyan("closing SessionHandler socket"))
        self.server_socket.close()
        logging.info(cyan("closing http(s) pool manager"))
        self.PoolManager.close()


if __name__ == "__main__":
    logging.basicConfig(level=logging.WARNING,
                        format='%(asctime)s - %(levelname)s - %(filename)s:%(lineno)d - %(message)s')
    
    for logger_name in logging.root.manager.loggerDict:
        if logger_name not in ["__main__"]:
            logging.getLogger(logger_name).setLevel(logging.WARNING)

    try:
        session_handler = SessionHandler()
        session_handler.createServer()
    except KeyboardInterrupt:
        session_handler.closeServer()

""" note: the sendall methods of the socket do not accept string like
objects.
The problem may arise in converting a response.__dict__ object"""
