"""Verify a WorkOS-issued JWT against the issuer's JWKS.

This is the one thing the `mcp` SDK cannot do for us: it defines where a
token verifier plugs in, not how a particular identity provider's tokens are
checked. It needs no MCP server, and `SurfaceTokenVerifier` wraps it for the
surfaces that are not MCP. Do not use it alone there: it checks no client.
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Awaitable, Callable, Sequence
from typing import Any

import httpx
import jwt
from jwt import PyJWK, PyJWKSet

JsonFetcher = Callable[[str], Awaitable[Any]]

_ALGORITHMS = ["RS256"]
_REQUIRED_CLAIMS = ["exp", "iat", "sub"]
# Anyone can send a token naming an unknown key id. It buys one refetch per
# cooldown, not one each; PyJWT's own `PyJWKClient` uses the same 30 seconds.
_REFETCH_COOLDOWN_SECONDS = 30
# Discovery and the key set together, so a slow issuer counts as a failed fetch, and the
# held keys answer, before a caller's own deadline: `run_sync` waits ten seconds.
_FETCH_BUDGET_SECONDS = 5.0
_MAX_MESSAGE_LENGTH = 300

logger = logging.getLogger(__name__)


class JWTVerificationError(Exception):
    """The token is not acceptable. The message says why and is safe to log.

    Safe because it is made so here: the libraries underneath echo parts of the
    token, which its sender wrote, so the text is cut to one bounded line.

    `reason` is the same answer as a fixed word a caller can branch on:
    `malformed`, `signature`, `issuer`, `audience`, `expired`, `claims`,
    `jwks_unavailable` or `invalid`.
    """

    def __init__(self, message: str, *, reason: str = "invalid") -> None:
        one_line = "".join(c if c.isprintable() else " " for c in message)
        super().__init__(one_line[:_MAX_MESSAGE_LENGTH])
        self.reason = reason


def looks_like_jwt(token: str) -> bool:
    """Tell a JWT from an opaque API token without parsing either."""
    return token.count(".") == 2 and len(token) > 60


async def _fetch_json(url: str) -> Any:
    async with httpx.AsyncClient(timeout=5) as client:
        response = await client.get(url)
        response.raise_for_status()
        return response.json()


class WorkOSJWTVerifier:
    """Checks signature, `iss`, `aud`, `exp`, `iat` and `sub`.

    `audiences` is an allow-list: a token passes when any of its `aud` values
    is in it. Pass resource URIs, never client IDs: a WorkOS token requested
    without a `resource` carries the tenant's default application client ID as
    its `aud`, so a client-ID audience accepts tokens minted for anything. An MCP
    server passes its one canonical resource URI; any other surface uses
    `SurfaceTokenVerifier`, which also requires an expected `client_id`.
    """

    def __init__(
        self,
        *,
        issuer: str,
        audiences: Sequence[str],
        jwks_url: str | None = None,
        leeway_seconds: int = 60,
        cache_ttl_seconds: int = 300,
        max_stale_seconds: int = 86400,
        fetch_budget_seconds: float = _FETCH_BUDGET_SECONDS,
        fetch_json: JsonFetcher = _fetch_json,
    ) -> None:
        if not issuer:
            raise ValueError("issuer is required")
        if isinstance(audiences, str):
            raise TypeError("audiences is a list of audiences, not one string")
        if not audiences or not all(audiences):
            raise ValueError("at least one non-empty audience is required")
        if not fetch_budget_seconds > 0:
            raise ValueError("fetch_budget_seconds must be positive")
        self._issuer = issuer.rstrip("/")
        self._audiences = list(audiences)
        self._jwks_url = jwks_url
        self._leeway = leeway_seconds
        self._ttl = cache_ttl_seconds
        self._max_stale = max_stale_seconds
        self._fetch_budget = fetch_budget_seconds
        self._fetch_json = fetch_json
        self._keys: dict[str, PyJWK] = {}
        self._keys_fetched_at = 0.0
        self._refetched_at = float("-inf")
        self._failed_at = float("-inf")
        # The refresh in flight on each event loop. A task belongs to the loop that made
        # it, and a module-level verifier outlives its loop and may serve several at once.
        # Each loop's thread writes only its own entry, and nothing iterates the table.
        self._refreshes: dict[asyncio.AbstractEventLoop, asyncio.Task[dict[str, PyJWK]]] = {}

    async def verify(self, token: str) -> dict[str, Any]:
        """Return the token's claims, or raise `JWTVerificationError`."""
        # The excepts below end in `Exception` because the SDK turns anything a
        # verifier raises into a 500, and the token, its claims and the JWKS are
        # all somebody else's input.
        try:
            kid = jwt.get_unverified_header(token).get("kid")
        except Exception as exc:
            raise JWTVerificationError(f"malformed token: {exc}", reason="malformed") from exc

        key = await self._signing_key(kid)
        try:
            return jwt.decode(
                token,
                key.key,
                algorithms=_ALGORITHMS,
                issuer=self._issuer,
                audience=self._audiences,
                leeway=self._leeway,
                options={"require": _REQUIRED_CLAIMS},
            )
        except jwt.ExpiredSignatureError as exc:
            raise JWTVerificationError("token expired", reason="expired") from exc
        except jwt.InvalidIssuerError as exc:
            raise JWTVerificationError("issuer mismatch", reason="issuer") from exc
        except (jwt.InvalidAudienceError, jwt.MissingRequiredClaimError) as exc:
            missing = isinstance(exc, jwt.MissingRequiredClaimError) and exc.claim != "aud"
            raise JWTVerificationError(
                f"audience or required claim rejected: {exc}",
                reason="claims" if missing else "audience",
            ) from exc
        except jwt.InvalidSignatureError as exc:
            raise JWTVerificationError("signature verification failed", reason="signature") from exc
        except jwt.InvalidAlgorithmError as exc:
            # A token in an algorithm we do not accept carries no signature we can check.
            raise JWTVerificationError(f"token rejected: {exc}", reason="signature") from exc
        except Exception as exc:
            raise JWTVerificationError(f"token rejected: {exc}") from exc

    async def _signing_key(self, kid: str | None) -> PyJWK:
        keys = await self._load_keys(force=False)
        if kid not in keys:
            # An unknown key id usually means the issuer rotated its keys.
            keys = await self._load_keys(force=True)
        if kid not in keys:
            raise JWTVerificationError(
                f"no signing key published for kid {kid!r}", reason="signature"
            )
        return keys[kid]

    def _cache_answers(self, *, force: bool) -> bool:
        if not self._keys:
            return False
        if force:
            return (time.monotonic() - self._refetched_at) < _REFETCH_COOLDOWN_SECONDS
        return (time.monotonic() - self._keys_fetched_at) < self._ttl

    async def _load_keys(self, *, force: bool) -> dict[str, PyJWK]:
        # A cache hit never waits behind a fetch in flight.
        if self._cache_answers(force=force):
            return self._keys
        loop = asyncio.get_running_loop()
        refresh = self._refreshes.get(loop)
        if refresh is None or refresh.done():
            # Nothing awaits between here and the task's creation, so a loop runs at most
            # one refresh at a time and everyone else on it waits for that one.
            if (time.monotonic() - self._failed_at) < _REFETCH_COOLDOWN_SECONDS:
                # The last fetch failed moments ago: do not queue another behind it.
                return self._held_keys_or_raise("backing off after a failed fetch")
            if force:
                self._refetched_at = time.monotonic()
            refresh = self._start_refresh(loop)
        # Shielded: a caller that gives up - a sync bridge's timeout cancels it - leaves
        # the refresh running for everyone else, and its outcome is still recorded.
        return await asyncio.shield(refresh)

    def _start_refresh(self, loop: asyncio.AbstractEventLoop) -> asyncio.Task[dict[str, PyJWK]]:
        refresh = loop.create_task(self._refresh())
        self._refreshes[loop] = refresh

        def finished(done: asyncio.Task[dict[str, PyJWK]]) -> None:
            if self._refreshes.get(loop) is done:
                self._refreshes.pop(loop, None)
            if not done.cancelled():
                done.exception()  # retrieved: a refusal nobody awaited is not logged again

        refresh.add_done_callback(finished)
        return refresh

    async def _refresh(self) -> dict[str, PyJWK]:
        try:
            async with asyncio.timeout(self._fetch_budget):
                url = self._jwks_url or await self._discover_jwks_url()
                key_set = PyJWKSet.from_dict(await self._fetch_json(url))
            keys = {key.key_id: key for key in key_set.keys if key.key_id}
            if not keys:
                # `kid` is optional in a JWK. Holding nothing would skip every cooldown
                # below, and each request would then cost the issuer two fetches.
                raise ValueError("the JWKS publishes no key with a kid")
        except Exception as exc:
            self._failed_at = time.monotonic()
            # `repr`, because a timeout's text is empty and its type is the whole reason.
            try:
                held = self._held_keys_or_raise(repr(exc), cause=exc)
            except JWTVerificationError:
                logger.error("JWKS refresh failed with no usable keys, refusing JWTs: %r", exc)
                raise
            logger.warning("JWKS refresh failed, serving the cached keys: %r", exc)
            return held
        self._keys = keys
        self._keys_fetched_at = time.monotonic()
        return self._keys

    def _held_keys_or_raise(
        self, reason: str, *, cause: Exception | None = None
    ) -> dict[str, PyJWK]:
        """Keys are public and were published by the issuer, so an outage there is no
        reason to refuse every valid token here - until they are older than the cap."""
        age = time.monotonic() - self._keys_fetched_at
        if self._keys and age < self._max_stale:
            return self._keys
        raise JWTVerificationError(
            f"JWKS unavailable: {reason}", reason="jwks_unavailable"
        ) from cause

    async def _discover_jwks_url(self) -> str:
        document = await self._fetch_json(f"{self._issuer}/.well-known/openid-configuration")
        self._jwks_url = document["jwks_uri"]
        return self._jwks_url
