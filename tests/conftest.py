from __future__ import annotations

import datetime
from pathlib import Path
from typing import Tuple

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


def make_self_signed(cn: str, serial: int) -> Tuple[bytes, bytes]:
    """Return (cert_pem, key_pem) for a throwaway self-signed leaf with a fixed serial."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(serial)
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=365))
        .sign(key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )
    return cert_pem, key_pem


@pytest.fixture
def write_leaf(tmp_path):
    """Write a combined cert+key PEM (as the sidecar does). Returns the path."""

    def _write(name: str, cn: str, serial: int) -> Path:
        cert_pem, key_pem = make_self_signed(cn, serial)
        p = tmp_path / f"{name}.pem"
        p.write_bytes(cert_pem + key_pem)
        return p

    return _write
