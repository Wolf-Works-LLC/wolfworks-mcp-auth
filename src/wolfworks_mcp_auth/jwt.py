"""Verify a WorkOS-issued JWT against the issuer's JWKS.

This is the one thing the `mcp` SDK cannot do for us: it defines where a
token verifier plugs in, not how a particular identity provider's tokens are
checked. It needs no MCP server, so the same check guards REST, WebSocket and
webhook paths that the SDK never sees.
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
_MAX_MESSAGE_LENGTH = 300

logger = logging.getLogger(__name__)


class JWTVerificationError(Exception):
    """The token is not acceptable. The message says why and is safe to log.

    Safe because it is made so here: the libraries underneath echo parts of the
    token, which its sender wrote, so the text is cut to one bounded line.
    """

    def __init__(self, message: str) -> None:
        one_line = "".join(c if c.isprintable() else " " for c in message)
        super().__init__(one_line[:_MAX_MESSAGE_LENGTH])


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
    is in it. An MCP server passes its one canonical resource URI; a REST path
    passes the client IDs it accepts tokens from.
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
        fetch_json: JsonFetcher = _fetch_json,
    ) -> None:
        if not issuer:
            raise ValueError("issuer is required")
        if isinstance(audiences, str):
            raise TypeError("audiences is a list of audiences, not one string")
        if not audiences or not all(audiences):
            raise ValueError("at least one non-empty audience is required")
        self._issuer = issuer.rstrip("/")
        self._audiences = list(audiences)
        self._jwks_url = jwks_url
        self._leeway = leeway_seconds
        self._ttl = cache_ttl_seconds
        self._max_stale = max_stale_seconds
        self._fetch_json = fetch_json
        self._keys: dict[str, PyJWK] = {}
        self._keys_fetched_at = 0.0
        self._refetched_at = float("-inf")
        self._failed_at = float("-inf")
        # One lock per event loop: a lock made here would belong to whichever loop
        # first contended for it, and a module-level verifier outlives its loop.
        self._locks: dict[asyncio.AbstractEventLoop, asyncio.Lock] = {}

    async def verify(self, token: str) -> dict[str, Any]:
        """Return the token's claims, or raise `JWTVerificationError`."""
        # The excepts below end in `Exception` because the SDK turns anything a
        # verifier raises into a 500, and the token, its claims and the JWKS are
        # all somebody else's input.
        try:
            kid = jwt.get_unverified_header(token).get("kid")
        except Exception as exc:
            raise JWTVerificationError(f"malformed token: {exc}") from exc

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
            raise JWTVerificationError("token expired") from exc
        except jwt.InvalidIssuerError as exc:
            raise JWTVerificationError("issuer mismatch") from exc
        except (jwt.InvalidAudienceError, jwt.MissingRequiredClaimError) as exc:
            raise JWTVerificationError(f"audience or required claim rejected: {exc}") from exc
        except jwt.InvalidSignatureError as exc:
            raise JWTVerificationError("signature verification failed") from exc
        except Exception as exc:
            raise JWTVerificationError(f"token rejected: {exc}") from exc

    async def _signing_key(self, kid: str | None) -> PyJWK:
        keys = await self._load_keys(force=False)
        if kid not in keys:
            # An unknown key id usually means the issuer rotated its keys.
            keys = await self._load_keys(force=True)
        if kid not in keys:
            raise JWTVerificationError(f"no signing key published for kid {kid!r}")
        return keys[kid]

    def _cache_answers(self, *, force: bool) -> bool:
        if not self._keys:
            return False
        if force:
            return (time.monotonic() - self._refetched_at) < _REFETCH_COOLDOWN_SECONDS
        return (time.monotonic() - self._keys_fetched_at) < self._ttl

    async def _load_keys(self, *, force: bool) -> dict[str, PyJWK]:
        # Checked before the lock so a fetch in flight never stalls a cache hit,
        # and again inside it because the request ahead may have just fetched.
        if self._cache_answers(force=force):
            return self._keys
        async with self._lock():
            if self._cache_answers(force=force):
                return self._keys
            if (time.monotonic() - self._failed_at) < _REFETCH_COOLDOWN_SECONDS:
                # The last fetch failed moments ago: do not queue another behind it.
                return self._held_keys_or_raise("backing off after a failed fetch")
            if force:
                self._refetched_at = time.monotonic()
            try:
                url = self._jwks_url or await self._discover_jwks_url()
                key_set = PyJWKSet.from_dict(await self._fetch_json(url))
                keys = {key.key_id: key for key in key_set.keys if key.key_id}
            except Exception as exc:
                self._failed_at = time.monotonic()
                held = self._held_keys_or_raise(str(exc), cause=exc)
                logger.warning("JWKS refresh failed, serving the cached keys: %s", exc)
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
        raise JWTVerificationError(f"JWKS unavailable: {reason}") from cause

    def _lock(self) -> asyncio.Lock:
        loop = asyncio.get_running_loop()
        lock = self._locks.get(loop)
        if lock is None:
            self._locks = {k: v for k, v in self._locks.items() if not k.is_closed()}
            lock = self._locks[loop] = asyncio.Lock()
        return lock

    async def _discover_jwks_url(self) -> str:
        document = await self._fetch_json(f"{self._issuer}/.well-known/openid-configuration")
        self._jwks_url = document["jwks_uri"]
        return self._jwks_url
