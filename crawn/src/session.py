import json
import logging
import os
import socket
import sys
import threading
from urllib import parse as url_parser

import certifi
import httpx
import httpx._client as http_client
import requests
from OpenSSL import SSL
from certauth.certauth import CertificateAuthority

from utiliities import (yellow, cyan, red)


class SesssionHandlerResponse(httpx.Response):
    """response(http.Response) is encoded using a json decoder into a str that can be sent to a socket.
    The response_str is encoded into a response-like object which is the class itself
    """
    def __init__(self, status_code: int, response_str=None) -> None:
        super().__init__(status_code)
        self.response_str = response_str

    def decodeResponse(self):
        response_dict = json.loads(self.response_str)
        # assign the keys to the respective http.Response properties
        # set the __dict__ attribute of the httpx.Response object hence assigning
        # the keys to the respective http.Response properties.
        self.__dict__ = response_dict

class SesssionHandler():
    def __init__(self, host_address:str= None,
                 listening_port:int= None,
                 use_tor= False,
                 useFileBasedCerts = False,
                 downloadMozillaCAs = False) -> None:
        self.host = host_address
        if self.host is None:
            self.host = "127.0.0.1"
        self.server_port = listening_port
        if self.server_port is None:
            self.server_port = 8181
        if sys.platform == "WIN32":
            self.runDir = rundir = "D:\\MYAPPLICATIONS\\AWE\\AWE\\crawn\\src"
        else:
            self.runDir = "/media/program/01DA55CA5F28E000/MYAPPLICATIONS/AWE/AWE/crawn/src"
        self.use_tor = use_tor
        self.client_socket = 0
        if self.use_tor:
            proxies = {
                "http://": "socks5://127.0.0.1:9050",
                "https://": "socks5://127.0.0.1:9050",
            }
            self.PoolManager = http_client.Client(
                follow_redirets=True, timeout=15, proxies=proxies)
        else:
            self.PoolManager = http_client.Client(
                follow_redirects=True, timeout=15)
        self.downloadMozillaCAs = downloadMozillaCAs
        if self.downloadMozillaCAs:
            self.MozillarootCAsUrl = "https://github.com/gisle/mozilla-ca/blob/master/lib/Mozilla/CA/cacert.pem"
            self.MozillaCACertsVerifyFile = self.runDir + "/proxycert/Mozilla/cacert.pem"
            if not os.path.isfile(self.MozillaCACertsVerifyFile):
                res = requests.get(self.MozillarootCAsUrl)
                with open(self.MozillaCACertsVerifyFile, "a") as file:
                    file.write(res.content.decode("utf-8"))
        else:
            self.MozillaCACertsVerifyFile = certifi.where()
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

    def generateDomainCerts(self, hostname: str):
        """generate a certificate for a specific host and sign it with the root certificate. Return the path to the certficate (.crt) file"""
        hostname = hostname.strip()
        if self.useFileBasedCerts is False:
            return self.rootCA.load_cert(hostname, wildcard=True)
        else:
            # filename
            return self.rootCA.cert_for_host(hostname, wildcard=True)

    def createDestConnection(self, host_portlist):
        """create the destination connection with the proxy, upgrade it to ssl and verify certificates"""
        dest_server_skt = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            dest_server_skt.connect((host_portlist[0], int(host_portlist[1])))
            logging.info("TCP connection to destination server successfull")
            destServerSslContext = SSL.Context(SSL.SSLv23_METHOD)
            destServerSslServerSkt = SSL.Connection(
                destServerSslContext, dest_server_skt)
            destServerSslServerSkt.set_connect_state()
            if self.verifyDstServerCerts:
                destServerSslContext.set_verify(
                    SSL.VERIFY_PEER | SSL.VERIFY_FAIL_IF_NO_PEER_CERT, self.verify_callback)
            else:
                destServerSslContext.set_verify(
                    SSL.VERIFY_NONE, self.verify_callback)
            destServerSslContext.load_verify_locations(
                self.MozillaCACertsVerifyFile)
            try:
                destServerSslServerSkt.do_handshake()
                logging.info(
                    "Destination server connection setup successfully with ssl support")
            except Exception as e:
                logging.error(red(f"SSL HandShake failure with error :{e}"))
            return destServerSslServerSkt, 0
        except Exception:
            return None, 1

    def verify_callback(self, connection, x509, errno, depth, preverify_ok):
        # Implement your verification logic here
        if self.verifyDstServerCerts:
            if preverify_ok:
                logging.info("Certificate verification passed")
                return True
            else:
                logging.error(red("Certificate verification failed"))
                return False
        else:
            return True

    def makeRequest(self, request_method, request_url, request_headers, request_data=None):
        self.createClientConnection()
        proxy_ses_req_dict = {}
        proxy_ses_req_dict["method"] = request_method
        proxy_ses_req_dict["url"] = request_url
        proxy_ses_req_dict["headers"] = request_headers
        proxy_ses_req_dict["data"] = request_data
        proxy_ses_request_str = json.dumps(proxy_ses_req_dict)
        self.clientSendAll(proxy_ses_request_str)
        response = self.clientRecv()
        return response

    def decodeClientRequest(self, client_request:str):
        client_request_dict = dict(json.loads(client_request))
        method = client_request_dict["method"]
        url = client_request_dict["url"]
        data = client_request_dict["body"]
        headers = client_request_dict["headers"]
        return method, url, data, headers

    @staticmethod
    def serializeResponse(response: httpx.Response):
        response_str = json.dumps(response.__dict__)
        return response_str

    @staticmethod
    def joinUrlwParams(self, url:str, params:dict):
        params_str = url_parser.urlencode(params)
        return url+"?"+params_str

    def closeTunnel(self, client_socket, closeClientSocket=True):
        if closeClientSocket:
            client_socket.close()

    def handleClientConnection(self, client_socket:socket.socket):
        client_request = client_socket.recv(160000).decode("utf-8")
        method, url, data, headers = self.decodeClientRequest(client_request)
        try:
            retries = 0
            while retries < 5:
                response = self.PoolManager.request(method=method,
                                                    url=url,
                                                    headers=headers,
                                                    data=data,
                                                    follow_redirects=True)
                if response:
                    break
                else:
                    logging.info(yellow("retrying...."))
                retries += 1
        except httpx.ConnectError:
            logging.error(red(f"failing to resolve to url {url}"))
        response_str = self.serializeResponse(response)
        try:
            client_socket.sendall(response_str)
        except Exception as e:
            logging.error(red(f"Encountered error: {e} while processing {url}"))
        self.closeTunnel(client_socket)


    def createServer(self):
        self.server_socket = socket.create_server(address=(self.host, self.server_port),
                                                  family=socket.AF_INET)
        self.server_socket.listen()
        logging.info(yellow(f"Session handler listening on port {self.server_port}"))
        while True:
            logging.info(yellow("Session Handler waiting for incoming connection ..."))
            client_socket = self.server_socket.accept()[0]
            threading.Thread(target=self.handleClientConnection, args=(client_socket,))

    def createClientConnection(self):
        self.client_socket = socket.create_connection(address=("127.0.0.1", self.server_port))
        
    def clientSendAll(self, req:str):
        self.client_socket.sendall(req.encode("utf-8"))

    def clientRecv(self):
        res = ""
        self.client_socket.recv_into(res)
        response = SesssionHandlerResponse(response_str=res)
        response.decodeResponse()
        return response

    def closeServer(self):
        logging.info(red("Exiting"))
        logging.info(cyan("closing SessionHandler socket"))
        self.server_socket.close()
        logging.info(cyan("closing http(s) pool manager"))
        self.PoolManager.close()

if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG, format= '%(asctime)s - %(levelname)s - %(filename)s:%(lineno)d - %(message)s')
    try:
        session_handler = SesssionHandler()
        session_handler.createServer()
    except KeyboardInterrupt:
        session_handler.closeServer()

""" note: the sendall methods of the socket do not accept string like
objects.
The problem may arise in converting a response.__dict__ object to a 
bytes like object since it includes the content of the response and yet it 
may be encoded so the problem may arise in trying to convert the data 
to bytes like object."""