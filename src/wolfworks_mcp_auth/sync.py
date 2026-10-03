"""Call the async verifiers from synchronous code: Flask, Django, a worker thread.

One long-lived event loop runs on one daemon thread, and every call is handed to
it with `asyncio.run_coroutine_threadsafe`. Never a loop per request: an
`asyncio.run` per call gives each request its own refresh inside the verifier, so
concurrent requests no longer share one JWKS fetch, and each pays for a new loop.

The loop starts on the first call, not on import. A forked child (a gunicorn
worker) starts its own on its first call: the parent's loop thread does not
exist there.
"""

from __future__ import annotations

import asyncio
import atexit
import concurrent.futures
import math
import os
import threading
import weakref
from collections.abc import Coroutine
from typing import Any, TypeVar

T = TypeVar("T")

_DEFAULT_TIMEOUT_SECONDS = 10.0
_THREAD_NAME = "wolfworks-mcp-auth-loop"

_bridges: weakref.WeakSet[SyncBridge] = weakref.WeakSet()


class BridgeClosed(RuntimeError):
    """The bridge was closed - by `close()`, or at exit - while this call was running.

    Not the caller's fault and not the token's: answer it `503`, as a timeout.
    """


class SyncBridge:
    """One background event loop that synchronous callers hand coroutines to.

    Safe to share between threads; the first call starts the loop, once. Each
    call waits at most `timeout` seconds (`default_timeout` when not given),
    then cancels the coroutine and raises `TimeoutError`. `close()` stops the
    loop and cancels whatever is still running on it, whose callers get
    `BridgeClosed`; a later call starts a new one. A bridge dropped without
    `close()` stops its loop when it is collected.
    """

    def __init__(self, *, default_timeout: float = _DEFAULT_TIMEOUT_SECONDS) -> None:
        self._default_timeout = _checked_timeout(default_timeout)
        self._guard = threading.Lock()
        self._loop: asyncio.AbstractEventLoop | None = None
        self._thread: threading.Thread | None = None
        self._finalizer: weakref.finalize | None = None
        _bridges.add(self)

    @property
    def running(self) -> bool:
        """Whether this process has a loop thread serving this bridge."""
        thread = self._thread
        return thread is not None and thread.is_alive()

    def start(self) -> None:
        """Start the loop now rather than on the first call. Idempotent."""
        self._ensure_loop()

    def run(self, coro: Coroutine[Any, Any, T], *, timeout: float | None = None) -> T:
        """Run `coro` on the bridge's loop and return its result, or raise what it raised."""
        if not asyncio.iscoroutine(coro):
            raise TypeError(
                f"run() takes a coroutine, such as verifier.verify(token); not {coro!r}"
            )
        try:
            limit = self._default_timeout if timeout is None else _checked_timeout(timeout)
            _refuse_inside_a_running_loop()
            # Submitted under the guard, so `close()` cannot stop the loop in between:
            # the call is either on this loop before it stops, or on the next one.
            with self._guard:
                future = asyncio.run_coroutine_threadsafe(coro, self._ensure_loop_locked())
        except BaseException:
            coro.close()  # never scheduled: close it, or it warns that it was never awaited
            raise
        try:
            return future.result(timeout=limit)
        except concurrent.futures.TimeoutError as exc:
            if not future.cancel() and future.done():
                return future.result()  # it finished as the timeout fired: not a timeout
            raise TimeoutError(f"the call did not finish within {limit} seconds") from exc
        except concurrent.futures.CancelledError as exc:
            raise BridgeClosed("the bridge was closed while the call was running") from exc
        except BaseException:
            future.cancel()  # Ctrl-C, or SystemExit, while waiting: do not leave it running
            raise

    def close(self, *, timeout: float = 5.0) -> None:
        """Stop the loop, cancelling what is still running, and wait for its thread."""
        with self._guard:
            loop, thread = self._loop, self._thread
            if thread is threading.current_thread():
                raise RuntimeError("a bridge cannot be closed from its own loop")
            self._loop = self._thread = None
            if self._finalizer is not None:
                self._finalizer.detach()
                self._finalizer = None
        if loop is None or thread is None:
            return
        _stop(loop)
        thread.join(timeout)

    def __enter__(self) -> SyncBridge:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    def _ensure_loop(self) -> asyncio.AbstractEventLoop:
        with self._guard:
            return self._ensure_loop_locked()

    def _ensure_loop_locked(self) -> asyncio.AbstractEventLoop:
        loop = self._loop
        if loop is None:
            loop = asyncio.new_event_loop()
            # The thread holds the loop, never the bridge: dropped, the bridge is collected
            # and its finalizer stops the loop, whose thread then ends.
            thread = threading.Thread(target=_serve, args=(loop,), name=_THREAD_NAME, daemon=True)
            thread.start()
            self._loop, self._thread = loop, thread
            self._finalizer = weakref.finalize(self, _stop, loop)
        return loop

    def _forget_after_fork(self) -> None:
        # In the child the loop thread is gone and the guard may be held by a thread
        # that no longer exists. The parent's loop is abandoned, not closed: it still
        # looks like it is running, and closing a running loop raises.
        self._guard = threading.Lock()
        self._loop = self._thread = None
        if self._finalizer is not None:
            self._finalizer.detach()  # the parent's loop is not this process's to stop
            self._finalizer = None


def _stop(loop: asyncio.AbstractEventLoop) -> None:
    try:
        loop.call_soon_threadsafe(loop.stop)
    except RuntimeError:
        pass  # the loop already closed itself


def _serve(loop: asyncio.AbstractEventLoop) -> None:
    asyncio.set_event_loop(loop)
    try:
        loop.run_forever()
    finally:
        pending = asyncio.all_tasks(loop)
        for task in pending:
            task.cancel()
        loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
        loop.run_until_complete(loop.shutdown_asyncgens())
        loop.close()


def _checked_timeout(timeout: float) -> float:
    number = isinstance(timeout, int | float) and not isinstance(timeout, bool)
    if not (number and math.isfinite(timeout) and timeout > 0):
        raise ValueError(f"timeout is a positive number of seconds, not {timeout!r}")
    return float(timeout)


def _refuse_inside_a_running_loop() -> None:
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return
    # On the bridge's own loop this would deadlock; on any other it stalls that loop.
    raise RuntimeError("run_sync() called from async code; await the coroutine instead")


def _after_fork_in_child() -> None:
    for bridge in list(_bridges):
        bridge._forget_after_fork()


def _close_all_at_exit() -> None:
    for bridge in list(_bridges):
        bridge.close(timeout=1.0)


if hasattr(os, "register_at_fork"):
    os.register_at_fork(after_in_child=_after_fork_in_child)
atexit.register(_close_all_at_exit)

_default_bridge = SyncBridge()


def run_sync(coro: Coroutine[Any, Any, T], *, timeout: float | None = None) -> T:
    """Run `coro` on this process's shared bridge. See `SyncBridge.run`.

    `timeout` defaults to ten seconds. Answer a `TimeoutError` as you would
    `jwks_unavailable`: with `503`, since the issuer is what is slow.
    """
    return _default_bridge.run(coro, timeout=timeout)
