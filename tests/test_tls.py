from __future__ import annotations

import asyncio
import socket
import ssl
import threading
from pathlib import Path

import pytest
from cryptography import x509

from tests.conftest import make_self_signed
from vault_agent_companion.core.tls import CertRotator


def _served_serial(server_ctx: ssl.SSLContext) -> int:
    """Complete one TLS handshake over a socketpair and return the served leaf's serial."""
    cs, ss = socket.socketpair()
    cs.settimeout(5)
    ss.settimeout(5)
    err: dict = {}

    def _serve() -> None:
        try:
            conn = server_ctx.wrap_socket(ss, server_side=True)
            conn.do_handshake()
            conn.close()
        except Exception as exc:  # noqa: BLE001 - surfaced via err
            err["e"] = exc

    t = threading.Thread(target=_serve)
    t.start()
    client_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    client_ctx.check_hostname = False
    client_ctx.verify_mode = ssl.CERT_NONE  # binary_form still returns the DER
    c = client_ctx.wrap_socket(cs, server_hostname="x")
    der = c.getpeercert(binary_form=True)
    c.close()
    t.join(timeout=5)
    assert "e" not in err, f"server handshake failed: {err.get('e')}"
    return x509.load_der_x509_certificate(der).serial_number


class _FakeCtx:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str]] = []

    def load_cert_chain(self, certfile: str, keyfile: str) -> None:
        self.calls.append((certfile, keyfile))


@pytest.mark.parametrize(
    "serials",
    [pytest.param((1001, 2002), id="serial-1001-to-2002")],
)
def test_reload_swaps_served_cert(write_leaf, serials):
    old, new = serials
    leaf = write_leaf("leaf", "svc.internal", old)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=str(leaf), keyfile=str(leaf))
    assert _served_serial(ctx) == old

    rotator = CertRotator().register(ctx, leaf)
    cert_pem, key_pem = make_self_signed("svc.internal", new)
    Path(leaf).write_bytes(cert_pem + key_pem)  # rotation
    rotator.reload()

    assert _served_serial(ctx) == new, "reload must swap the served leaf"


@pytest.mark.parametrize(
    "combined",
    [pytest.param(True, id="cert-and-key-same-file")],
)
def test_reload_calls_load_cert_chain(tmp_path, combined):
    f = tmp_path / "leaf.pem"
    f.write_text("pem")
    ctx = _FakeCtx()
    CertRotator().register(ctx, f).reload()
    assert ctx.calls == [(str(f.resolve()), str(f.resolve()))]


@pytest.mark.parametrize(
    "bad",
    [pytest.param("not a pem", id="half-written-file-skipped")],
)
def test_reload_swallows_bad_file(tmp_path, bad):
    f = tmp_path / "leaf.pem"
    f.write_text(bad)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    # must not raise — a partial render should be skipped, not crash the process
    CertRotator().register(ctx, f).reload()


@pytest.mark.parametrize(
    "serials",
    [pytest.param((3003, 4004), id="watch-reload-3003-to-4004")],
)
async def test_watch_reloads_on_change(write_leaf, serials):
    old, new = serials
    leaf = write_leaf("leaf", "svc.internal", old)
    ctx = _FakeCtx()
    rotator = CertRotator().register(ctx, leaf)
    task = asyncio.ensure_future(rotator.watch(debounce=50, step=10))
    await asyncio.sleep(0.4)
    cert_pem, key_pem = make_self_signed("svc.internal", new)
    Path(leaf).write_bytes(cert_pem + key_pem)
    for _ in range(20):
        if ctx.calls:
            break
        await asyncio.sleep(0.1)
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass
    assert ctx.calls, "watch must reload the context when the cert file changes"
