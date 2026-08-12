"""Hot-reload rotating mTLS leaf certs into live SSLContexts.

``SSLContext.load_cert_chain`` is re-callable: it swaps the cert used for NEW handshakes
while in-flight connections keep the old one, and it leaves ``verify_mode`` /
``load_verify_locations`` (the trust root) untouched. So rotating a leaf is just
re-loading the chain — no restart, no monkey-patching.

Both roles register here: the inbound server context (uvicorn's ``config.ssl``) AND any
outbound http-client context the service presents on east-west calls.
"""

from __future__ import annotations

import logging
import ssl
from pathlib import Path
from typing import List, Optional, Tuple, Union

from watchfiles import awatch

logger = logging.getLogger(__name__)

_Target = Tuple[ssl.SSLContext, str, str]  # (context, cert_path, key_path)


class CertRotator:
    """Registry of (SSLContext, cert file) pairs, reloaded when the file changes."""

    def __init__(self) -> None:
        self._targets: List[_Target] = []

    def register(
        self,
        ctx: ssl.SSLContext,
        cert_path: Union[str, Path],
        key_path: Optional[Union[str, Path]] = None,
    ) -> "CertRotator":
        """Register a context. ``key_path`` defaults to ``cert_path`` (the sidecar renders
        cert+key into one PEM). Chainable."""
        cert = str(Path(cert_path).resolve())
        key = str(Path(key_path or cert_path).resolve())
        self._targets.append((ctx, cert, key))
        return self

    def reload(self, only_cert: Optional[str] = None) -> None:
        """Re-load the chain for every registered context (or just ``only_cert``).

        A failed load (e.g. a half-written file) is logged and skipped, never raised —
        the context keeps serving the previous cert until the next good render.
        """
        for ctx, cert, key in self._targets:
            if only_cert is not None and cert != only_cert:
                continue
            try:
                ctx.load_cert_chain(certfile=cert, keyfile=key)
                logger.info("mtls cert reloaded: %s", cert)
            except (ssl.SSLError, OSError) as exc:
                logger.warning("mtls cert reload failed for %s: %s", cert, exc)

    async def watch(
        self,
        *,
        stop_event: Optional[object] = None,
        debounce: int = 200,
        step: int = 50,
    ) -> None:
        """Watch every registered cert file; reload the affected context(s) on change."""
        certs = {cert for _, cert, _ in self._targets}
        dirs = {str(Path(cert).parent) for cert in certs}
        async for changes in awatch(
            *dirs, stop_event=stop_event, debounce=debounce, step=step
        ):
            touched = {str(Path(p).resolve()) for _, p in changes} & certs
            for cert in touched:
                self.reload(only_cert=cert)
