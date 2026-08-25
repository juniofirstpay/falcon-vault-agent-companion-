from __future__ import annotations

import asyncio

import pytest

from vault_agent_companion.core.watcher import Watcher


async def _drain(task: asyncio.Task) -> None:
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass


async def _wait_for(pred, timeout: float = 3.0) -> bool:
    for _ in range(int(timeout / 0.05)):
        if pred():
            return True
        await asyncio.sleep(0.05)
    return pred()


@pytest.mark.parametrize(
    "raising",
    [
        pytest.param(True, id="handler-raises"),
        pytest.param(False, id="handler-ok"),
    ],
)
async def test_handler_exception_does_not_kill_loop(tmp_path, raising):
    """A raising handler must not stop the watcher: a later change still fires the handler,
    and the exception is routed to on_error rather than breaking the awatch loop."""
    f = tmp_path / "vault-secrets.yaml"
    f.write_text("password: v1\n")

    calls: list[int] = []
    errors: list[tuple[BaseException, str]] = []

    def handler() -> None:
        calls.append(1)
        if raising and len(calls) == 1:
            raise RuntimeError("boom on first change")

    def on_error(exc: BaseException, path: str) -> None:
        errors.append((exc, path))

    watcher = Watcher(tmp_path).on(f, handler)
    task = watcher.spawn(debounce=50, step=10, on_error=on_error)
    try:
        await asyncio.sleep(0.4)  # let the watcher settle

        f.write_text("password: v2\n")
        assert await _wait_for(lambda: len(calls) >= 1)

        f.write_text("password: v3\n")
        assert await _wait_for(lambda: len(calls) >= 2), "loop died after first handler raised"

        assert not task.done(), "watch task must survive a handler exception"
        assert len(errors) == (1 if raising else 0)
    finally:
        await _drain(task)
