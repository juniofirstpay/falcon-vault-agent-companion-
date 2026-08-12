"""Watch a sidecar-rendered secrets file and fire a callback on change.

The Vault Agent renders to a temp file then atomically RENAMES it into place, which
changes the inode — so we watch the parent directory (watching the file path alone can
miss the rename) and filter for the target. Coalesced by watchfiles' debounce so one
render fires the callback once.
"""

from __future__ import annotations

import asyncio
import inspect
from pathlib import Path
from typing import Awaitable, Callable, Optional, Union

from watchfiles import awatch

OnChange = Callable[[], Optional[Awaitable[None]]]


async def _maybe_await(result: object) -> None:
    if inspect.isawaitable(result):
        await result


def _touches_target(changes: object, target: Path) -> bool:
    """True if any (Change, path) in a watchfiles batch resolves to ``target``.

    Pure so it's testable without the filesystem (fsevents on macOS can replay a
    file's own creation at watcher startup, which makes real-fs negative tests flaky).
    """
    return any(Path(changed).resolve() == target for _, changed in changes)  # type: ignore[union-attr]


async def watch(
    path: Union[str, Path],
    on_change: OnChange,
    *,
    stop_event: Optional[object] = None,
    debounce: int = 200,
    step: int = 50,
) -> None:
    """Invoke ``on_change`` whenever ``path`` changes. Runs until cancelled / stopped.

    ``on_change`` may be sync or async. ``debounce``/``step`` are milliseconds passed to
    watchfiles (small values suit atomic renames; the default coalesces a burst).
    """
    target = Path(path).resolve()
    parent = target.parent
    async for changes in awatch(
        parent, stop_event=stop_event, debounce=debounce, step=step
    ):
        if _touches_target(changes, target):
            await _maybe_await(on_change())


def spawn(path: Union[str, Path], on_change: OnChange, **kwargs: object) -> asyncio.Task:
    """Start :func:`watch` as a background task. Cancel the task to stop watching."""
    return asyncio.ensure_future(watch(path, on_change, **kwargs))  # type: ignore[arg-type]
