
from datetime import datetime
import logging
import socket
from OpenSSL import SSL
import certifi
from awe_net.awe_net import Request
from utiliities import DissectClientReqPkt


class ClientSslSocket:
    def __init__(self, host_name: str, port = 443, keepalive_timeout=120, retry_count=5, verify_certs=True):
        self.host_name = host_name
        self.port = port
        self.keepalive_timeout = keepalive_timeout

        self.n_skt = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # self.n_skt.settimeout(self.keepalive_timeout)

        self.retry_count = retry_count
        self.verify_certs = verify_certs

    def makeTcpConnection(self):
        while self.retry_count > 0:
            try:
                self.n_skt.connect((self.host_name, self.port))
                logging.info("Tcp connection successful")
                return True
            except Exception as e:
                logging.error(
                    f"failed to make tcp connection to host {self.host_name} on port {self.port} with error {e}")
                self.retry_count -= 1
                if self.retry_count == 0:
                    return False

    def verify_callback(self, connection, x509, errno, depth, preverify_ok):
        # Implement verification logic here
        # if self.verify_certs:
        #     if preverify_ok:
        #         logging.info("Certificate verification passed")
        #         return True
        #     else:
        #         logging.error("Certificate verification failed")
        #         return False
        # else:
        return True

    def setSslContext(self):
        ssl_context = SSL.Context(SSL.SSLv23_METHOD)
        if self.verify_certs:
            ssl_context.set_verify(SSL.VERIFY_PEER | SSL.VERIFY_FAIL_IF_NO_PEER_CERT, self.verify_callback)
        else:
            ssl_context.set_verify(SSL.VERIFY_NONE, self.verify_callback)
        ssl_context.load_verify_locations(certifi.where())
        return ssl_context

    def createConnection(self):
        if self.makeTcpConnection():
            self.ssl_context = self.setSslContext()
            self.ssl_socket = SSL.Connection(self.ssl_context, self.n_skt)
            self.ssl_socket.set_connect_state()  # client mode
            return self.ssl_socket, self.n_skt


class AweSession:
    def __init__(self, hostname, connection:SSL.Connection = None, new = False, n_skt:socket.socket = None, timeout = 120):
        self.hostname = hostname
        self.start_time = datetime.now()
        self.connection = connection
        self.new_session = new
        self.keepalive_timeout = timeout
        self.n_skt = n_skt
        self.retry_count = 0
        self.max_retry_count = 3
        
        if self.new_session:
            self.makessl_connection()

    def get_elapsed_time(self):
        elapsed_time = datetime.now() - self.start_time
        return elapsed_time.seconds()

    def makessl_connection(self):
        ssl_sock = ClientSslSocket(host_name=self.hostname, keepalive_timeout = self.keepalive_timeout)
        self.connection, self.n_skt = ssl_sock.createConnection()

    def make_request(self, method:str = None, url:str = None, headers:dict = None, data=None, raw_req_pkt = None, get_raw_resp = False):
        """This can either recieve the raw request packet from the proxy ie as it came 
        from the browser or application.
        OR
        the method, url, headers, data etc
        """
        pkt_bytes = raw_req_pkt
        if raw_req_pkt is None:
            request = Request(method=method, url=url, headers=headers, body=data)
            awe_req_pkt  = request.packet
            pkt_bytes = awe_req_pkt._bytes
        while self.retry_count < self.max_retry_count:
            try:
                self.connection.sendall(pkt_bytes)
                break
            except SSL.Error:
                self.n_skt.close()
                self.connection = None
                self.makessl_connection()
            self.retry_count += 1

        response = b""
        while True:
            try:
                chunk  = self.connection.recv(4096)
                print(chunk)
                if not chunk:
                    break
                response += chunk
            except SSL.ZeroReturnError:
                break
        
        if get_raw_resp is True:
            return response

    @property
    def _connection(self):
        return self.connection
    

class AweSessionManager:
    def __init__(self):
        self.keepalive_timeout = 120
        self.sessions = []

    def request(self, method:str= None, url:str= None, headers:dict= None, data = None, raw_req_pkt:bytes = None):
        if raw_req_pkt is None:
            host_name= headers["Host"]
            connection= headers["Connection"]
        else:
            headers = DissectClientReqPkt(raw_req_pkt.decode())[2]
            host_name = headers["Host"]
            connection = headers["Connection"]
        session = False
        awe_session = None

        for session in self.sessions:
            if session.hostname == host_name:
                # session exists
                # check if session is still viable
                if session.get_elapsed_time() < self.keepalive_timeout:
                    session.start_time = datetime.now() # reset the session start time
                    session.n_skt.settimeout(self.keepalive_timeout) # reset the timeout
                    session = True
                    awe_session = session
                    break
                else:
                    session.n_skt.close()
                    self.sessions.remove(session)
                    del session
                    break

        if session is True:
            awe_session
        else:
            # make a new session
            awe_session = AweSession(hostname=host_name, new=True, timeout=self.keepalive_timeout)
            self.sessions.append(awe_session)
        if raw_req_pkt is not None:
            response_bytes = awe_session.make_request(raw_req_pkt = raw_req_pkt, get_raw_resp = True)
        else:
            response_bytes = awe_session.make_request(method=method, url=url, headers=headers, data = data, get_raw_resp = True)
        return response_bytes

