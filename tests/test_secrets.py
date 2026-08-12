from __future__ import annotations

import asyncio

import pytest

from vault_agent_companion.core import secrets


async def _drain(task: asyncio.Task) -> None:
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass


@pytest.mark.parametrize(
    "sync_cb",
    [pytest.param(True, id="sync-callback"), pytest.param(False, id="async-callback")],
)
async def test_watch_fires_on_change(tmp_path, sync_cb):
    f = tmp_path / "vault-secrets.yaml"
    f.write_text("password: v1\n")
    hits: list[int] = []

    if sync_cb:
        def cb() -> None:
            hits.append(1)
    else:
        async def cb() -> None:  # type: ignore[misc]
            hits.append(1)

    task = secrets.spawn(f, cb, debounce=50, step=10)
    await asyncio.sleep(0.4)  # let the watcher settle
    f.write_text("password: v2-rotated\n")
    for _ in range(20):
        if hits:
            break
        await asyncio.sleep(0.1)
    await _drain(task)

    assert hits, "on_change should fire when the watched file changes"


@pytest.mark.parametrize(
    "changed_name, expected",
    [
        pytest.param("vault-secrets.yaml", True, id="target-matches"),
        pytest.param("other.txt", False, id="sibling-ignored"),
        pytest.param("vault-secrets.yaml.tmp", False, id="tempfile-ignored"),
    ],
)
def test_touches_target_predicate(tmp_path, changed_name, expected):
    # Deterministic filter test — no fs events (macOS fsevents replays a file's own
    # creation at startup, which makes real-fs negative assertions flaky).
    target = (tmp_path / "vault-secrets.yaml").resolve()
    changes = {(1, str(tmp_path / changed_name))}  # {(Change, path)}
    assert secrets._touches_target(changes, target) is expected
