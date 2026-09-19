"""Verify a WorkOS-issued JWT against the issuer's JWKS.

This is the one thing the `mcp` SDK cannot do for us: it defines where a
token verifier plugs in, not how a particular identity provider's tokens are
checked. It needs no MCP server, so the same check guards REST, WebSocket and
webhook paths that the SDK never sees.
"""

from __future__ import annotations

import asyncio
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


class JWTVerificationError(Exception):
    """The token is not acceptable. The message says why and is safe to log."""


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
        fetch_json: JsonFetcher = _fetch_json,
    ) -> None:
        if not issuer:
            raise ValueError("issuer is required")
        if not audiences or not all(audiences):
            raise ValueError("at least one non-empty audience is required")
        self._issuer = issuer.rstrip("/")
        self._audiences = list(audiences)
        self._jwks_url = jwks_url
        self._leeway = leeway_seconds
        self._ttl = cache_ttl_seconds
        self._fetch_json = fetch_json
        self._keys: dict[str, PyJWK] = {}
        self._keys_fetched_at = 0.0
        self._refetched_at = float("-inf")
        self._lock = asyncio.Lock()

    async def verify(self, token: str) -> dict[str, Any]:
        """Return the token's claims, or raise `JWTVerificationError`."""
        try:
            kid = jwt.get_unverified_header(token).get("kid")
        except jwt.PyJWTError as exc:
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
        except jwt.PyJWTError as exc:
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
        async with self._lock:
            if self._cache_answers(force=force):
                return self._keys
            if force:
                self._refetched_at = time.monotonic()
            try:
                url = self._jwks_url or await self._discover_jwks_url()
                key_set = PyJWKSet.from_dict(await self._fetch_json(url))
            except (httpx.HTTPError, jwt.PyJWTError, KeyError, TypeError, ValueError) as exc:
                raise JWTVerificationError(f"JWKS unavailable: {exc}") from exc
            self._keys = {key.key_id: key for key in key_set.keys if key.key_id}
            self._keys_fetched_at = time.monotonic()
            return self._keys

    async def _discover_jwks_url(self) -> str:
        document = await self._fetch_json(f"{self._issuer}/.well-known/openid-configuration")
        self._jwks_url = document["jwks_uri"]
        return self._jwks_url
