"""uvicorn adapter: register uvicorn's live server SSLContext with a CertRotator.

uvicorn builds its ``SSLContext`` in ``Config.load()`` and keeps it on ``config.ssl``.
``Server.serve()`` would build it too, but then we'd have no handle — so we force
``config.load()`` first, grab ``config.ssl``, register it, and let the caller ``serve()``.
"""

from __future__ import annotations

import ssl
from pathlib import Path
from typing import Optional, Union

from vault_agent_companion.core.tls import CertRotator


def attach(
    rotator: CertRotator,
    server_or_config: object,
    cert_path: Union[str, Path],
    key_path: Optional[Union[str, Path]] = None,
) -> ssl.SSLContext:
    """Register uvicorn's inbound SSLContext for hot-reload; return the context.

    Accepts a ``uvicorn.Server`` or a ``uvicorn.Config``. Forces ``config.load()`` if
    needed so ``config.ssl`` exists. Raises if TLS isn't configured (no ``ssl_certfile``).
    """
    config = getattr(server_or_config, "config", server_or_config)
    if not getattr(config, "loaded", False):
        config.load()  # type: ignore[attr-defined]
    ctx: Optional[ssl.SSLContext] = getattr(config, "ssl", None)
    if ctx is None:
        raise RuntimeError(
            "uvicorn config has no SSLContext — is ssl_certfile set (mTLS enabled)?"
        )
    rotator.register(ctx, cert_path, key_path)
    return ctx
