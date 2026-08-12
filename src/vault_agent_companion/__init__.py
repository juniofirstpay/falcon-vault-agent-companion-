"""App-side companion for the Vault Agent sidecar.

The sidecar renders secrets + rotating mTLS leaf certs to a shared volume; this package
watches those files and hot-reloads them in-process — no restart. The core is
framework-free (it only fires callbacks / calls ``SSLContext.load_cert_chain``); the
optional adapters wire it to dynaconf and uvicorn.

Reload DEPTH (what to re-resolve after settings change) is deliberately the app's concern:
the core just fires the callback the app supplies.
"""

from __future__ import annotations

from vault_agent_companion.core import secrets
from vault_agent_companion.core.tls import CertRotator

__all__ = ("secrets", "CertRotator")
