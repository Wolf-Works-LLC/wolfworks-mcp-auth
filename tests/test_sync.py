"""AUTH-2: one long-lived background loop for synchronous hosts, never a loop per request."""

from __future__ import annotations

import asyncio
import concurrent.futures
import gc
import os
import signal
import threading
import time

import pytest
from conftest import ISSUER, FakeFetcher

from wolfworks_mcp_auth import (
    BridgeClosed,
    SurfaceTokenRefused,
    SurfaceTokenVerifier,
    SyncBridge,
    run_sync,
)

SURFACE = "https://surface.test/api/v1"
CLIENT = "client_01DEVICE"


@pytest.fixture
def bridge():
    bridge = SyncBridge()
    yield bridge
    bridge.close()


def _surface(fetcher: FakeFetcher) -> SurfaceTokenVerifier:
    return SurfaceTokenVerifier(
        issuer=ISSUER, resource=SURFACE, expected_clients={CLIENT: "device"}, fetch_json=fetcher
    )


async def _loop_thread() -> threading.Thread:
    # The Thread object, not its ident: the OS reuses an ident once a thread has ended.
    return threading.current_thread()


# --- the one loop -----------------------------------------------------------------------


def test_nothing_starts_until_the_first_call():
    bridge = SyncBridge()
    try:
        assert not bridge.running
        assert bridge.run(_loop_thread()) is not threading.current_thread()
        assert bridge.running
    finally:
        bridge.close()


def test_a_verifier_runs_on_the_bridge_and_its_refusal_comes_back(bridge, mint, fetcher):
    verifier = _surface(fetcher)
    accepted = bridge.run(verifier.verify(mint(aud=SURFACE, client_id=CLIENT)))
    assert accepted.kind == "device"
    with pytest.raises(SurfaceTokenRefused) as raised:
        bridge.run(verifier.verify(mint(aud=SURFACE, client_id="client_01NOBODY")))
    assert raised.value.reason == "client_unexpected"


def test_two_threads_at_once_share_one_loop_and_run_concurrently(bridge):
    # A waits for an event only B sets: if the bridge ran calls one at a time, A would time out.
    holder: dict[str, asyncio.Event] = {}
    results: dict[str, int] = {}
    errors: list[BaseException] = []
    first_waiting = threading.Event()

    async def waits() -> int:
        holder["event"] = asyncio.Event()
        first_waiting.set()
        await holder["event"].wait()
        return threading.get_ident()

    async def releases() -> int:
        holder["event"].set()
        return threading.get_ident()

    def call(name, factory):
        try:
            results[name] = bridge.run(factory(), timeout=5)
        except BaseException as exc:  # surfaced below
            errors.append(exc)

    a = threading.Thread(target=call, args=("a", waits))
    a.start()
    assert first_waiting.wait(5)
    b = threading.Thread(target=call, args=("b", releases))
    b.start()
    a.join(10)
    b.join(10)
    assert not errors, errors
    assert results["a"] == results["b"] != threading.get_ident()


def test_a_crowded_first_call_starts_exactly_one_loop(bridge):
    gate = threading.Barrier(16)
    idents: list[threading.Thread] = []

    def call():
        gate.wait()
        idents.append(bridge.run(_loop_thread(), timeout=5))

    threads = [threading.Thread(target=call) for _ in range(16)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(10)
    assert len(idents) == 16
    assert len({id(thread) for thread in idents}) == 1
    loops = [t for t in threading.enumerate() if t.name.startswith("wolfworks-mcp-auth")]
    assert len(loops) == 1


def test_many_threads_verify_through_one_bridge(bridge, mint, fetcher):
    verifier = _surface(fetcher)
    token, kinds, errors = mint(aud=SURFACE, client_id=CLIENT), [], []

    def call():
        try:
            for _ in range(20):
                kinds.append(bridge.run(verifier.verify(token), timeout=5).kind)
        except BaseException as exc:
            errors.append(exc)

    threads = [threading.Thread(target=call) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(30)
    assert not errors, errors[:3]
    assert kinds == ["device"] * 160
    assert not verifier._jwt._refreshes  # one loop's refresh, finished and forgotten


def test_the_module_level_run_sync_uses_one_shared_bridge():
    assert run_sync(_loop_thread()) == run_sync(_loop_thread())


# --- timeouts ---------------------------------------------------------------------------


def test_a_call_that_overruns_its_timeout_raises_and_is_cancelled(bridge):
    cancelled = threading.Event()

    async def slow():
        try:
            await asyncio.sleep(30)
        except asyncio.CancelledError:
            cancelled.set()
            raise

    began = time.monotonic()
    with pytest.raises(TimeoutError, match="0.05"):
        bridge.run(slow(), timeout=0.05)
    assert time.monotonic() - began < 5
    assert cancelled.wait(5), "the abandoned call kept running on the loop"
    assert bridge.run(_loop_thread(), timeout=5)  # the loop is still serving


def test_the_default_timeout_applies_when_none_is_given():
    bridge = SyncBridge(default_timeout=0.05)
    try:
        with pytest.raises(TimeoutError):
            bridge.run(asyncio.sleep(30))
    finally:
        bridge.close()


@pytest.mark.parametrize("timeout", [0, -1, float("nan")])
def test_a_timeout_must_be_positive(bridge, timeout):
    coro = asyncio.sleep(0)
    with pytest.raises(ValueError, match="timeout"):
        bridge.run(coro, timeout=timeout)


# --- misuse -----------------------------------------------------------------------------


async def test_calling_from_inside_a_running_loop_is_refused(bridge):
    # Blocking a loop on another loop deadlocks the bridge's own thread, or stalls this one.
    with pytest.raises(RuntimeError, match="await"):
        bridge.run(_loop_thread())


def test_calling_from_the_bridges_own_loop_is_refused(bridge):
    async def reenters():
        bridge.run(_loop_thread())

    with pytest.raises(RuntimeError, match="await"):
        bridge.run(reenters(), timeout=5)


def test_only_a_coroutine_is_accepted(bridge):
    with pytest.raises(TypeError, match="coroutine"):
        bridge.run(_loop_thread)  # the function, not a call of it


# --- shutdown ---------------------------------------------------------------------------


def test_close_stops_the_thread_and_a_later_call_starts_a_new_one():
    bridge = SyncBridge()
    first = bridge.run(_loop_thread())
    bridge.close()
    assert not bridge.running
    assert not first.is_alive()
    try:
        assert bridge.run(_loop_thread()) is not first
    finally:
        bridge.close()


def test_close_cancels_what_is_still_running_and_is_idempotent():
    bridge = SyncBridge()
    cancelled = threading.Event()

    async def forever():
        try:
            await asyncio.sleep(3600)
        except asyncio.CancelledError:
            cancelled.set()
            raise

    seen: list[BaseException] = []

    def caller_body():
        try:
            bridge.run(forever(), timeout=30)
        except BaseException as exc:
            seen.append(exc)

    caller = threading.Thread(target=caller_body)
    caller.start()
    time.sleep(0.1)
    bridge.close()
    assert cancelled.wait(5)
    caller.join(5)
    assert not caller.is_alive()
    assert [type(exc) for exc in seen] == [BridgeClosed]
    bridge.close()  # a second close, and a close before any start, do nothing
    SyncBridge().close()


def test_a_bridge_used_as_a_context_manager_closes(mint):
    with SyncBridge() as bridge:
        bridge.run(_loop_thread())
        assert bridge.running
    assert not bridge.running


# --- fork -------------------------------------------------------------------------------


@pytest.mark.skipif(not hasattr(os, "fork"), reason="no os.fork on this platform")
@pytest.mark.filterwarnings("ignore:This process .* is multi-threaded:DeprecationWarning")
def test_the_bridge_and_its_verifier_work_in_a_forked_child(bridge, mint, fetcher):
    # gunicorn forks workers: the parent's loop thread does not exist in the child.
    verifier = _surface(fetcher)
    token = mint(aud=SURFACE, client_id=CLIENT)
    parent_loop = bridge.run(_loop_thread())
    assert bridge.run(verifier.verify(token)).kind == "device"

    pid = os.fork()
    if pid == 0:  # the child: report through the exit status only, never return into pytest
        status = 1
        try:
            child_loop = bridge.run(_loop_thread(), timeout=5)
            kind = bridge.run(verifier.verify(token), timeout=5).kind
            same_bridge_again = bridge.run(_loop_thread(), timeout=5) is child_loop
            module_level = run_sync(_loop_thread(), timeout=5)
            if child_loop is not parent_loop and kind == "device" and same_bridge_again:
                status = 0 if module_level else 1
        finally:
            os._exit(status)

    _, wait_status = os.waitpid(pid, 0)
    assert os.waitstatus_to_exitcode(wait_status) == 0
    assert bridge.run(_loop_thread()) is parent_loop  # the parent's loop is untouched


def test_closing_from_its_own_loop_is_refused_and_leaves_the_bridge_serving(bridge):
    async def closes_itself():
        bridge.close()

    with pytest.raises(RuntimeError, match="own loop"):
        bridge.run(closes_itself(), timeout=5)
    assert bridge.running
    assert bridge.run(_loop_thread(), timeout=5).is_alive()


# --- a slow issuer behind a bridge timeout ----------------------------------------------


class SlowAfterTheFirstFetch(FakeFetcher):
    def __init__(self, documents, release: threading.Event):
        super().__init__(documents)
        self.release = release

    async def __call__(self, url: str):
        if self.calls:
            self.calls.append(url)
            while not self.release.is_set():  # set from the test's thread
                await asyncio.sleep(0.01)
            return self.documents[url]
        return await super().__call__(url)


def _stale_surface(fetcher, monkeypatch, **kwargs):
    clock = [1000.0]
    monkeypatch.setattr(
        "wolfworks_mcp_auth.jwt.time", type("T", (), {"monotonic": staticmethod(lambda: clock[0])})
    )
    verifier = SurfaceTokenVerifier(
        issuer=ISSUER,
        resource=SURFACE,
        expected_clients={CLIENT: "device"},
        jwks_url="https://keys.test/jwks",
        fetch_json=fetcher,
    )
    verifier._jwt._fetch_budget = kwargs.get("budget", verifier._jwt._fetch_budget)
    return verifier, clock


def _in_threads(count, call):
    outcomes: list[object] = []

    def body():
        try:
            outcomes.append(call())
        except BaseException as exc:
            outcomes.append(exc)

    threads = [threading.Thread(target=body) for _ in range(count)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(30)
    return outcomes


def test_a_slow_issuer_still_answers_valid_tokens_from_the_held_keys(
    bridge, mint, jwks, monkeypatch
):
    # The fetch budget is below the bridge's timeout: the refresh gives up first, and the
    # cached keys answer, as "When the issuer is down" promises. Not 503s for valid tokens.
    release = threading.Event()
    fetcher = SlowAfterTheFirstFetch({"https://keys.test/jwks": jwks}, release)
    verifier, clock = _stale_surface(fetcher, monkeypatch, budget=0.1)
    token = mint(aud=SURFACE, client_id=CLIENT)
    bridge.run(verifier.verify(token))
    clock[0] += 301  # the keys are stale: the next call refreshes, and the issuer is slow
    try:
        outcomes = _in_threads(4, lambda: bridge.run(verifier.verify(token), timeout=2).kind)
    finally:
        release.set()
    assert outcomes == ["device"] * 4
    assert len(fetcher.calls) == 2  # one refresh for all four, then the back-off


def test_a_bridge_timeout_does_not_cancel_the_refresh_everyone_shares(
    bridge, mint, jwks, monkeypatch
):
    release = threading.Event()
    fetcher = SlowAfterTheFirstFetch({"https://keys.test/jwks": jwks}, release)
    verifier, clock = _stale_surface(fetcher, monkeypatch)  # a budget longer than the timeout
    token = mint(aud=SURFACE, client_id=CLIENT)
    bridge.run(verifier.verify(token))
    clock[0] += 301
    outcomes = _in_threads(4, lambda: bridge.run(verifier.verify(token), timeout=0.1))
    assert [type(outcome) for outcome in outcomes] == [TimeoutError] * 4
    assert len(fetcher.calls) == 2  # one refresh, still running for whoever comes next
    release.set()
    assert bridge.run(verifier.verify(token), timeout=5).kind == "device"
    assert bridge.run(verifier.verify(token), timeout=5).kind == "device"
    assert len(fetcher.calls) == 2  # the abandoned refresh landed and filled the cache


# --- run() racing close(), a dropped bridge, an interrupted wait -------------------------


def test_a_call_racing_close_fails_fast_with_bridge_closed(bridge, monkeypatch):
    # The call has its loop and is about to submit when another thread closes the bridge.
    real_submit = asyncio.run_coroutine_threadsafe

    def submit_while_closing(coro, loop):
        closer = threading.Thread(target=bridge.close)
        closer.start()
        closer.join(0.2)  # long enough for an unguarded close to stop and close the loop
        return real_submit(coro, loop)

    bridge.start()
    monkeypatch.setattr(
        "wolfworks_mcp_auth.sync.asyncio.run_coroutine_threadsafe", submit_while_closing
    )
    began = time.monotonic()
    with pytest.raises(BridgeClosed, match="closed"):
        bridge.run(asyncio.sleep(30), timeout=10)
    assert time.monotonic() - began < 5


def test_a_started_bridge_dropped_without_close_stops_its_thread():
    bridge = SyncBridge()
    thread = bridge.run(_loop_thread())
    del bridge
    gc.collect()
    thread.join(5)
    assert not thread.is_alive()


@pytest.mark.skipif(not hasattr(signal, "setitimer"), reason="no interval timer here")
def test_an_interrupted_wait_cancels_the_call(bridge):
    cancelled = threading.Event()

    async def slow():
        try:
            await asyncio.sleep(30)
        except asyncio.CancelledError:
            cancelled.set()
            raise

    def interrupt(signum, frame):
        raise KeyboardInterrupt

    previous = signal.signal(signal.SIGALRM, interrupt)
    try:
        signal.setitimer(signal.ITIMER_REAL, 0.1)
        with pytest.raises(KeyboardInterrupt):
            bridge.run(slow(), timeout=10)
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)
    assert cancelled.wait(5), "Ctrl-C left the call running on the loop"


def test_a_result_that_lands_as_the_timeout_fires_is_returned(bridge, monkeypatch):
    real_submit = asyncio.run_coroutine_threadsafe

    class FinishedJustAfterTheTimeout(concurrent.futures.Future):
        def result(self, timeout=None):
            if timeout is not None:
                raise concurrent.futures.TimeoutError
            return super().result()

    def submit(coro, loop):
        late = FinishedJustAfterTheTimeout()
        late.set_result(real_submit(coro, loop).result(5))
        return late

    monkeypatch.setattr("wolfworks_mcp_auth.sync.asyncio.run_coroutine_threadsafe", submit)
    assert bridge.run(asyncio.sleep(0, result="landed"), timeout=1) == "landed"
