"""One filesystem watcher per process.

A service that watches the rendered secrets file AND a rotating leaf (for the server
context + client contexts) does NOT need a watch loop per file. The Vault Agent renders
everything under one shared root (e.g. ``/shared``); ``watchfiles.awatch`` is recursive,
so a SINGLE ``awatch(root)`` sees every rendered file. This ``Watcher`` runs that one loop
and dispatches each change to the handlers registered for that path.

Reload DEPTH stays the app's concern — the watcher only fires the handlers it's given
(e.g. ``settings.reload()``; ``CertRotator.reload``; a client-lib ``reload_cert``).
"""

from __future__ import annotations

import asyncio
import inspect
from pathlib import Path
from typing import Awaitable, Callable, Dict, List, Optional, Union

from watchfiles import awatch

Handler = Callable[[], Optional[Awaitable[None]]]


async def _maybe_await(result: object) -> None:
    if inspect.isawaitable(result):
        await result


class Watcher:
    """Single ``awatch`` over a root dir; fires the handlers registered for each changed file.

    Handlers may be sync or async, and several may be registered for one path (they fire in
    registration order — e.g. reload the server ctx AND the client libs on a leaf change). A
    handler that raises is logged by the caller's callback, not here; keep them defensive.
    """

    def __init__(self, root: Union[str, Path]) -> None:
        self._root = Path(root).resolve()
        self._handlers: Dict[str, List[Handler]] = {}

    def on(self, path: Union[str, Path], handler: Handler) -> "Watcher":
        """Register ``handler`` for changes to ``path`` (must live under the root). Chainable."""
        self._handlers.setdefault(str(Path(path).resolve()), []).append(handler)
        return self

    async def watch(
        self,
        *,
        stop_event: Optional[object] = None,
        debounce: int = 200,
        step: int = 50,
    ) -> None:
        """Run the single watch loop until cancelled / stopped."""
        async for changes in awatch(
            self._root, stop_event=stop_event, debounce=debounce, step=step
        ):
            touched = {str(Path(p).resolve()) for _, p in changes} & self._handlers.keys()
            for path in touched:
                for handler in self._handlers[path]:
                    await _maybe_await(handler())

    def spawn(self, **kwargs: object) -> asyncio.Task:
        """Start :meth:`watch` as a background task. Cancel the task to stop watching."""
        return asyncio.ensure_future(self.watch(**kwargs))  # type: ignore[arg-type]
