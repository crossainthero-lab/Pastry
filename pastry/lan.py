"""LAN mode: serve over HTTPS with a self-signed certificate so other devices on the
local network can sign in (the session cookie is Secure and needs HTTPS)."""

from __future__ import annotations

import datetime as dt
import ipaddress
import os
import socket
import subprocess
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

LAN_DEFAULT_PORT = 8443


def local_names_and_ips() -> tuple[list[str], list[str]]:
    """Return (hostnames, IPv4 addresses) that this machine can be reached at."""
    host = socket.gethostname()
    names = {host, f"{host}.local", f"{host}.lan", "localhost"}
    ips = {"127.0.0.1"}
    try:
        for info in socket.getaddrinfo(host, None, socket.AF_INET):
            ips.add(info[4][0])
    except OSError:
        pass
    try:  # routing-table lookup: no packet is sent
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("10.255.255.255", 1))
            ips.add(s.getsockname()[0])
    except OSError:
        pass
    try:
        out = subprocess.run(["hostname", "-I"], capture_output=True, text=True, timeout=3).stdout
        for token in out.split():
            try:
                if ipaddress.ip_address(token).version == 4:
                    ips.add(token)
            except ValueError:
                pass
    except (OSError, subprocess.SubprocessError):
        pass
    return sorted(names), sorted(ips)


def _san_set(cert: x509.Certificate) -> set[str]:
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except x509.ExtensionNotFound:
        return set()
    return {str(v) for v in san.get_values_for_type(x509.DNSName)} | {
        str(v) for v in san.get_values_for_type(x509.IPAddress)
    }


def ensure_certificate(tls_dir: Path, names: list[str], ips: list[str]) -> tuple[Path, Path]:
    """Create (or refresh, if the host's names or addresses changed) the self-signed cert."""
    tls_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(tls_dir, 0o700)
    cert_path, key_path = tls_dir / "lan-cert.pem", tls_dir / "lan-key.pem"
    wanted = set(names) | set(ips)

    if cert_path.exists() and key_path.exists():
        try:
            cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
            soon = dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=30)
            if _san_set(cert) >= wanted and cert.not_valid_after_utc > soon:
                return cert_path, key_path
        except ValueError:
            pass

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Pastry LAN")])
    now = dt.datetime.now(dt.timezone.utc)
    san = [x509.DNSName(n) for n in names] + [x509.IPAddress(ipaddress.ip_address(i)) for i in ips]
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=1))
        .not_valid_after(now + dt.timedelta(days=825))
        .add_extension(x509.SubjectAlternativeName(san), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .sign(key, hashes.SHA256())
    )
    fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ))
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return cert_path, key_path
