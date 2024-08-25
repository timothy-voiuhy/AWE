import os
import subprocess
from pathlib import Path
from asyncio import AbstractEventLoop, StreamWriter, StreamReader, WriteTransport, BaseProtocol
from OpenSSL import SSL
import ssl
from certauth.certauth import CertificateAuthority
import socket
import logging
import asyncio
import certifi
from config.config import CERT_CACHE_DIR, CERT_KEYS_DIR, HOST_CERTS_DIR, PRIVATE_KEY_FILE, ROOT_CERT_FILE, CERTIFICATE_FILE


class ClientSslSocket:
    def __init__(self, host_name: str, port: int, timeout=10, retry_count=5, verify_certs=True):
        self.host_name = host_name
        self.port = port

        self.n_skt = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.n_skt.settimeout(timeout)  # 15 seconds

        self.retry_count = retry_count
        self.verify_certs = verify_certs

    def makeTcpConnection(self):
        while self.retry_count > 0:
            try:
                self.n_skt.connect((self.host_name, self.port))
                return True
            except Exception as e:
                logging.error(
                    f"failed to make tcp connection to host {self.host_name} on port {self.port} with error {e}")
                self.retry_count -= 1
                if self.retry_count == 0:
                    return False

    def verify_callback(self, connection, x509, errno, depth, preverify_ok):
        # Implement verification logic here
        if self.verify_certs:
            if preverify_ok:
                logging.info("Certificate verification passed")
                return True
            else:
                logging.error("Certificate verification failed")
                return False
        else:
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
            return self.ssl_socket


class ProxyCertificateAuthority:
    # To be made once when session begins.
    def __init__(self, ca_name="LOCALHOST CA"):
        self.ca_name = ca_name
        self.certs_dir = CERT_CACHE_DIR
        self.cert_keys_dir = CERT_KEYS_DIR
        if not os.path.isdir(self.cert_keys_dir):
            os.makedirs(self.cert_keys_dir)
        self.host_certs_dir = HOST_CERTS_DIR
        if not os.path.isdir(self.host_certs_dir):
            os.makedirs(self.host_certs_dir)
        self.added_cert_to_sys = False
        self.root_cert_file = ROOT_CERT_FILE
        self.certificate_file = CERTIFICATE_FILE
        self.root_cert_authority = CertificateAuthority(ca_name=self.ca_name,
                                                        cert_cache=self.certs_dir,
                                                        ca_file_cache=self.root_cert_file)
        self.get_certificate()
        self.system_trust_certificate()

    def get_certificate(self):
        if not Path(CERTIFICATE_FILE).exists():
            command = f"openssl x509 -in {self.root_cert_file} -out {self.certificate_file}"
            proc = subprocess.Popen(command, shell=True)
            proc.wait()
            self.added_cert_to_sys = True

    def system_trust_certificate(self):
        if self.added_cert_to_sys is True:
            command = f"sudo cp {self.certificate_file} /usr/local/share/ca-certificates/ && sudo update-ca-certificates"
            subprocess.Popen(command, shell=True)

    def generate_private_key_file(self, host_name):
        chain_file_name = key_file_name = host_name+".pem"
        chain_file_path = os.path.join(self.certs_dir, chain_file_name)
        key_file_path = os.path.join(self.cert_keys_dir, key_file_name)
        if Path(key_file_path).exists():
            os.remove(key_file_path)
        command = f"openssl pkey -in {chain_file_path} -out {key_file_path}"
        proc = subprocess.Popen(command, shell=True)
        proc.wait()
        return key_file_path

    def generate_certificate_file(self, host_name):
        chain_file_name = cert_file_name = host_name+".pem"
        chain_file_path = os.path.join(self.certs_dir, chain_file_name)
        cert_file_path = os.path.join(self.host_certs_dir, cert_file_name)
        if Path(cert_file_path).exists():
            os.remove(cert_file_path)
        command = f"openssl x509 -in {chain_file_path} -out {cert_file_path}"
        proc = subprocess.Popen(command, shell=True)
        proc.wait()
        return cert_file_path

    def generateCertificate(self, host_name):
        """returns a tuple of the certificate and the private key for the hostname"""
        hostname = host_name.strip()
        certificate, private_key = self.root_cert_authority.load_cert(hostname, wildcard=True)
        cert_file_path = self.generate_certificate_file(host_name)
        key_file_path = self.generate_private_key_file(host_name)
        return certificate, private_key, cert_file_path, key_file_path

class ProxyServerSslSocket:
    """this is the ssl socket that is responsible for interfacing between the proxy and the client
    forexample a browser
    certificate: this is the one generated by the certificate authority
    private_key: this is also generated by the certificate authority
    the certificate authority returns a tuple of the certificate and the private key"""

    def __init__(self, certificate,
                 private_key,
                 n_socket: socket.socket,
                 loop: AbstractEventLoop = None,
                 cert_file_path = None,
                 key_file_path = None):
        self.certificate = certificate
        self.n_skt = n_socket
        self.private_key = private_key
        self.cert_file_path = cert_file_path
        self.key_file_path = key_file_path
        self.loop = loop

    def setProxyServerSslContext(self):
        if self.loop is not None:
            # ssl_context = ssl.create_default_context()
            ssl_context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
            ssl_context.load_cert_chain(certfile=self.cert_file_path, keyfile = self.key_file_path)
            return ssl_context
        else:
            ssl_context = SSL.Context(SSL.SSLv23_METHOD)  # check the ssl version
            # see whether it requires the private key file
            ssl_context.use_privatekey(self.private_key)
            ssl_context.use_certificate(self.certificate)
            return ssl_context

    async def attach_reader_writer(self, client_socket: socket.socket, loop:AbstractEventLoop):
        client_reader = asyncio.StreamReader(loop=loop)
        protocol = asyncio.StreamReaderProtocol(client_reader, loop=loop)
        transport, _ = await loop.connect_accepted_socket(lambda: protocol, client_socket)
        client_writer,  = asyncio.StreamWriter(transport, protocol, client_reader, loop)
        return client_writer, client_reader, _, transport

    async def createConnection(self):
        ssl_context = self.setProxyServerSslContext()
        if self.loop is None:
            ssl_socket = SSL.Connection(ssl_context, self.n_skt)
            ssl_socket.set_accept_state()
            return ssl_socket
        else:
            client_writer, client_reader, protocol, transport = await self.attach_reader_writer(self.n_skt, self.loop)
            ssl_socket = await self.loop.start_tls(transport, protocol, ssl_context)
            return ssl_socket
