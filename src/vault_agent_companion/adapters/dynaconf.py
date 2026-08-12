"""dynaconf adapter: turn a settings object into an on_change callback.

``settings.reload()`` re-reads every source file (including the sidecar-rendered file, if
it's in ``settings_files``) and re-applies the merge. That refreshes the *settings object*
only — resources already built from it (DB pools, provider instances) are the app's to
rebuild, via the optional ``re_resolve`` hook. Reload DEPTH is intentionally the app's call.
"""

from __future__ import annotations

import inspect
from typing import Awaitable, Callable, Optional

from vault_agent_companion.core.secrets import OnChange

ReResolve = Callable[[], Optional[Awaitable[None]]]


def make_reload(settings: object, re_resolve: Optional[ReResolve] = None) -> OnChange:
    """Return an on_change that calls ``settings.reload()`` then the optional re_resolve.

    ``re_resolve`` (sync or async) is where the app rebuilds anything that captured secret
    values at boot — e.g. re-init providers, reconnect a pool. Omit it for the Tier-0
    settings-only reload.
    """

    async def on_change() -> None:
        settings.reload()  # type: ignore[attr-defined]
        if re_resolve is not None:
            result = re_resolve()
            if inspect.isawaitable(result):
                await result

    return on_change
