"""
Certificate Authority for MITM — pure `cryptography` library, no certauth/pyOpenSSL.

Layout on disk
--------------
ROOT_CERT_FILE   : root CA certificate PEM  (import into OS / browser)
PRIVATE_KEY_FILE : root CA private key PEM  (never exported)
CERTIFICATE_FILE : same cert as ROOT_CERT_FILE but with .crt extension
                   (needed by update-ca-certificates on Linux)
CERT_CACHE_DIR/  : per-hostname cert+key PEM files (avoids regen on restart)

Thread-safety
-------------
A single lock guards the on-disk cache check and the in-memory SSLContext cache
so that concurrent CONNECT requests for the same host don't race to generate.
"""
from __future__ import annotations

import datetime
import ipaddress
import os
import ssl
import tempfile
import threading
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from config.config import (
    CERT_CACHE_DIR, CERTIFICATE_FILE, PRIVATE_KEY_FILE, ROOT_CERT_FILE,
)

_CA_NAME          = "AWE Proxy CA"
_CA_KEY_BITS      = 4096
_HOST_KEY_BITS    = 2048
_CERT_DAYS        = 825    # max accepted by modern browsers
_CA_CERT_DAYS     = 3650   # ~10 years for the root


class CertificateAuthority:
    def __init__(self, ca_name: str = _CA_NAME) -> None:
        self._ca_name = ca_name
        for d in (CERT_CACHE_DIR, str(Path(ROOT_CERT_FILE).parent)):
            Path(d).mkdir(parents=True, exist_ok=True)

        self._ca_cert, self._ca_key = self._load_or_create_root()
        self._ctx_cache: dict[str, ssl.SSLContext] = {}
        self._lock = threading.Lock()

    # ── public ────────────────────────────────────────────────────────────────

    @property
    def root_cert_path(self) -> str:
        return ROOT_CERT_FILE

    def ssl_context_for(self, hostname: str) -> ssl.SSLContext:
        """Return a cached TLS server SSLContext for *hostname*."""
        key = hostname.strip().lower()
        with self._lock:
            if key not in self._ctx_cache:
                self._ctx_cache[key] = self._build_context(hostname.strip())
            return self._ctx_cache[key]

    # ── root CA ───────────────────────────────────────────────────────────────

    def _load_or_create_root(self) -> tuple[x509.Certificate, rsa.RSAPrivateKey]:
        if Path(ROOT_CERT_FILE).exists() and Path(PRIVATE_KEY_FILE).exists():
            try:
                return self._load_root()
            except Exception:
                pass
        return self._create_root()

    def _load_root(self):
        cert = x509.load_pem_x509_certificate(Path(ROOT_CERT_FILE).read_bytes())
        key  = serialization.load_pem_private_key(
            Path(PRIVATE_KEY_FILE).read_bytes(), password=None
        )
        return cert, key

    def _create_root(self):
        key = rsa.generate_private_key(public_exponent=65537, key_size=_CA_KEY_BITS)
        name = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, self._ca_name),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "AWE"),
        ])
        now  = _utcnow()
        cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=_CA_CERT_DAYS))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True, key_cert_sign=True, crl_sign=True,
                    content_commitment=False, key_encipherment=False,
                    data_encipherment=False, key_agreement=False,
                    encipher_only=False, decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
                critical=False,
            )
            .sign(key, hashes.SHA256())
        )

        cert_pem = cert.public_bytes(serialization.Encoding.PEM)
        key_pem  = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )

        Path(ROOT_CERT_FILE).write_bytes(cert_pem)
        Path(PRIVATE_KEY_FILE).write_bytes(key_pem)
        Path(CERTIFICATE_FILE).write_bytes(cert_pem)   # .crt = same PEM, different ext

        return cert, key

    # ── per-hostname cert ─────────────────────────────────────────────────────

    def _build_context(self, hostname: str) -> ssl.SSLContext:
        cert_pem, key_pem = self._host_cert(hostname)

        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.check_hostname  = False

        fd, tmppath = tempfile.mkstemp(suffix=".pem")
        try:
            with os.fdopen(fd, "wb") as fh:
                fh.write(cert_pem + key_pem)
            ctx.load_cert_chain(tmppath)
        finally:
            try:
                os.unlink(tmppath)
            except OSError:
                pass

        return ctx

    def _host_cert(self, hostname: str) -> tuple[bytes, bytes]:
        """Return (cert_pem, key_pem), reading from disk cache when available."""
        cache_file = Path(CERT_CACHE_DIR) / f"{_safe_name(hostname)}.pem"
        if cache_file.exists():
            data = cache_file.read_bytes()
            # Split at the second PEM block boundary
            idx = data.find(b"-----BEGIN", 1)
            if idx != -1:
                return data[:idx], data[idx:]

        cert_pem, key_pem = self._generate_host_cert(hostname)
        try:
            cache_file.write_bytes(cert_pem + key_pem)
        except OSError:
            pass
        return cert_pem, key_pem

    def _generate_host_cert(self, hostname: str) -> tuple[bytes, bytes]:
        key = rsa.generate_private_key(public_exponent=65537, key_size=_HOST_KEY_BITS)

        san: list[x509.GeneralName] = []
        try:
            san.append(x509.IPAddress(ipaddress.ip_address(hostname)))
        except ValueError:
            apex = hostname.lstrip("*").lstrip(".")
            san.append(x509.DNSName(apex))
            san.append(x509.DNSName(f"*.{apex}"))

        now  = _utcnow()
        cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname)]))
            .issuer_name(self._ca_cert.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(seconds=60))
            .not_valid_after(now + datetime.timedelta(days=_CERT_DAYS))
            .add_extension(x509.SubjectAlternativeName(san), critical=False)
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None), critical=True
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True, key_encipherment=True,
                    content_commitment=False, data_encipherment=False,
                    key_agreement=False, key_cert_sign=False,
                    crl_sign=False, encipher_only=False, decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
                critical=False,
            )
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(
                    self._ca_key.public_key()
                ),
                critical=False,
            )
            .sign(self._ca_key, hashes.SHA256())
        )

        cert_pem = cert.public_bytes(serialization.Encoding.PEM)
        key_pem  = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
        return cert_pem, key_pem


# ── helpers ───────────────────────────────────────────────────────────────────

def _utcnow() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


def _safe_name(hostname: str) -> str:
    return hostname.replace("*", "wildcard").replace(":", "_")
