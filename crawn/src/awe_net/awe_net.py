from urllib.parse import urlsplit
from OpenSSL import SSL
import socket


class AweHeader:
    def __init__(self, key=None, value=None, header_str: str = None, std=True):
        self.key = key
        self.value = value
        self.header_str = header_str
        self.std = std

    def get_header_dict(self):
        h_dict = {}
        if self.header_str is not None:
            if self.std:
                if not self.header_str.endswith("\r\n"):
                    self.header_str = self.header_str + "\r\n"
            header_split = self.header_str.split(":", 1)
            self.key = header_split[0]
            self.value = header_split[1].strip()
            h_dict[self.key] = self.value
            return h_dict

    def get_header_string(self):
        if self.std:
            return self.key + ": " + self.value + "\r\n"
        else:
            return self.key + ": " + self.value

    @property
    def header_string(self):
        return self.get_header_string()

    @property
    def header_key(self):
        return self.key

    @property
    def header_value(self):
        return self.value


class AweHeaders:
    def __init__(self):
        self.keys = []
        self.values = []
        self.headers_dict = {}
        self.awe_headers_list = []
        self.str_headers_list = []

    def append_header(self, header: str | AweHeader | dict):
        if type(header) is AweHeader:
            awe_header = header
            header_str = awe_header.get_header_string()
            self.awe_headers_list.append(header)
            self.str_headers_list.append(header_str)
        elif type(header) is str:
            header_str = header
            awe_header = AweHeader(header_str=header_str)
            awe_header.get_header_dict()
            self.awe_headers_list.append(awe_header)
            self.str_headers_list.append(header_str)
        elif type(header) is dict:
            key = list(header.key())[0]
            value = list(header.values())[0]
            awe_header = AweHeader(key, value)
            header_str = awe_header.header_string
            self.awe_headers_list.append(awe_header)
            self.str_headers_list.append(header_str)

    def append(self, *args, **kwargs):
        """This function allows a variety of header styles ie all those allowed
        by self.append_header however this allows more of them as comma separated arguments
        even if they are all of different data types"""
        if len(args) == 1:
            self.append_header(args[0])
        elif len(args) > 1:
            headers = args
            for header in headers:
                self.append_header(header)

    def get_headers_string(self):
        headers_str = ""
        for header in self.str_headers_list:
            headers_str = headers_str + header
        if not headers_str.endswith("\r\n\r\n") and headers_str.endswith("\r\n"):
            headers_str = headers_str + "\r\n"
        return headers_str


class AwePacket:
    def __int__(self, method: str = None, host: str = None, path: str = None, protocol=None,
                headers: dict | AweHeaders = None, retry_count=5,
                additional_headers: dict = None, body: str | bytes = None,
                std = True):
        self.method = method
        self.path = path
        self.protocol = protocol
        self.host = host
        self.headers = headers
        self.body = body
        self.retry_count = retry_count
        self.additional_headers = additional_headers
        self.packet_str = None
        self.packet_bytes = None
        self.awe_headers = AweHeaders()
        self.std = std


class AweRequestPacket(AwePacket):
    def __init__(self, params: dict = None, scheme: str = None):
        super().__init__()
        self.params = params
        self.scheme = scheme
        self.default_req_headers = {
            "Host": self.host,
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate, br",
            "Upgrade-Insecure-Requests": 1,
            "Connection": "keep-alive",
            "Cookie": None,
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-User": "?1"
        }

    @property
    def _path(self):
        return self.path

    @property
    def body_bytes(self):
        return self.get_body(as_bytes=True)
    
    @property
    def string(self):
        return self.get_packet_string()

    @property
    def _bytes(self):
        return self.get_packet_bytes()

    def get_body(self, as_bytes=False):
        pass

    def body_str(self):
        self.get_body()

    def get_packet_bytes(self):
        pass

    def get_packet_string(self):
        pass

    def construct_packet(self):
        pass


class AweResponsePacket(AwePacket):
    def __init__(self):
        super().__init__()
        self.encoding = None


class Request:
    def __init__(self, method: str = None, host: str = None, path: str = None, headers: dict | AweHeaders = None,
                 body: str | bytes = None, url: str = None, std=True, params: dict = None):
        self.host = host
        self.path = path
        self.headers = headers
        self.body = body
        self.method = method
        self.url = url
        self.std = std
        self.parameters = params

        self.packet = AweRequestPacket()
        self.packet.body = self.body
        self.packet.headers = headers
        self.packet.std = std
        if self.url is None:
            self.packet.host = self.host
        else:
            url_parts = urlsplit(self.url)
            self.packet.scheme = url_parts[0]
            self.host = self.packet.host = url_parts[1]
            self.path = self.packet.path = url_parts[2]


    def get(self, url: str, params: dict = None):
        self.method = "GET"
        pass

    def post(self, url: str, params: dict = None, body: str = None):
        self.method = "POST"
        pass

    def head(self, host=None, url=None):
        self.method = "HEAD"
        pass


class ProxyServerSslSocket:
    """this is the ssl socket that is responsible for interfacing between the proxy and the client
    forexample a browser
    certificate: this is the one generated by the certificate authority
    private_key: this is also generated by the certificate authority
    the certificate authority returns a tuple of the certificate and the private key"""

    def __init__(self, certificate,
                 private_key,
                 n_socket: socket.socket):
        self.certificate = certificate
        self.n_skt = n_socket
        self.private_key = private_key

    def setProxyServerSslContext(self):
        ssl_context = SSL.Context(SSL.SSLv23_METHOD)  # check the ssl version
        # see whether it requires the private key file
        ssl_context.use_privatekey(self.private_key)
        ssl_context.use_certificate(self.certificate)
        return ssl_context

    def createConnection(self):
        ssl_context = self.setProxyServerSslContext()
        ssl_socket = SSL.Connection(ssl_context, self.n_skt)
        ssl_socket.set_accept_state()
        return ssl_socket

