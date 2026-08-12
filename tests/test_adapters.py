from __future__ import annotations

import ssl

import pytest

from vault_agent_companion.adapters.dynaconf import make_reload
from vault_agent_companion.adapters.uvicorn import attach
from vault_agent_companion.core.tls import CertRotator


class _FakeSettings:
    def __init__(self) -> None:
        self.reloaded = 0

    def reload(self) -> None:
        self.reloaded += 1


@pytest.mark.parametrize(
    "async_reresolve",
    [pytest.param(False, id="sync-re_resolve"), pytest.param(True, id="async-re_resolve")],
)
async def test_make_reload_runs_reload_then_reresolve(async_reresolve):
    settings = _FakeSettings()
    hits: list[int] = []

    if async_reresolve:
        async def rr() -> None:
            hits.append(1)
    else:
        def rr() -> None:  # type: ignore[misc]
            hits.append(1)

    cb = make_reload(settings, rr)
    await cb()

    assert settings.reloaded == 1
    assert hits == [1]


@pytest.mark.parametrize(
    "case",
    [pytest.param("no-reresolve", id="settings-only")],
)
async def test_make_reload_without_reresolve(case):
    settings = _FakeSettings()
    await make_reload(settings)()
    assert settings.reloaded == 1


class _FakeConfig:
    def __init__(self, ctx) -> None:
        self.loaded = False
        self._ctx = ctx
        self.ssl = None

    def load(self) -> None:
        self.loaded = True
        self.ssl = self._ctx


class _FakeServer:
    def __init__(self, config) -> None:
        self.config = config


@pytest.mark.parametrize(
    "pass_server",
    [pytest.param(False, id="pass-config"), pytest.param(True, id="pass-server")],
)
def test_attach_loads_and_registers(tmp_path, pass_server):
    leaf = tmp_path / "leaf.pem"
    leaf.write_text("pem")
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    config = _FakeConfig(ctx)
    target = _FakeServer(config) if pass_server else config
    rotator = CertRotator()

    got = attach(rotator, target, leaf)

    assert config.loaded is True
    assert got is ctx
    assert len(rotator._targets) == 1


@pytest.mark.parametrize(
    "case",
    [pytest.param("ssl-none", id="raises-when-tls-absent")],
)
def test_attach_raises_without_ssl(case):
    class _NoSSL:
        loaded = True
        ssl = None

    with pytest.raises(RuntimeError):
        attach(CertRotator(), _NoSSL(), "leaf.pem")
