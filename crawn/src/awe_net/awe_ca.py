import os
from pathlib import Path
import subprocess
from config.config import CERT_CACHE_DIR, CERT_KEYS_DIR, CERTIFICATE_FILE, HOST_CERTS_DIR, ROOT_CERT_FILE
from certauth.certauth import CertificateAuthority

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
        chain_file_name = key_file_name = host_name + ".pem"
        chain_file_path = os.path.join(self.certs_dir, chain_file_name)
        key_file_path = os.path.join(self.cert_keys_dir, key_file_name)
        if Path(key_file_path).exists():
            os.remove(key_file_path)
        command = f"openssl pkey -in {chain_file_path} -out {key_file_path}"
        proc = subprocess.Popen(command, shell=True)
        proc.wait()
        return key_file_path

    def generate_certificate_file(self, host_name):
        chain_file_name = cert_file_name = host_name + ".pem"
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
        # cert_file_path = self.generate_certificate_file(host_name)
        # key_file_path = self.generate_private_key_file(host_name)
        return certificate, private_key

