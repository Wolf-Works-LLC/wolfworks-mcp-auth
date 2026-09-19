"""The `TokenVerifier` an `MCPServer` is constructed with."""

from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable
from typing import Any

from mcp.server.auth.provider import AccessToken, TokenVerifier

from wolfworks_mcp_auth.jwt import (
    JsonFetcher,
    JWTVerificationError,
    WorkOSJWTVerifier,
    _fetch_json,
    looks_like_jwt,
)

logger = logging.getLogger(__name__)

FallbackResolver = Callable[[str], Awaitable[AccessToken | None]]


def api_token_access(token: str, *, user_id: str, resource: str, scopes: list[str]) -> AccessToken:
    """Build the `AccessToken` a fallback resolver returns for an opaque API token.

    Every field is load-bearing. The SDK rejects a token whose `resource` is not
    the server's own with 401, and one whose `scopes` fall short of
    `required_scopes` with 403; `subject` is what the application's identity
    resolver maps to a user; `client_id` is one component of session ownership,
    so it is made stable per user.
    """
    return AccessToken(
        token=token,
        client_id=f"api-token:{user_id}",
        scopes=scopes,
        resource=resource,
        subject=user_id,
    )


class WorkOSTokenVerifier(TokenVerifier):
    """Accepts a WorkOS JWT minted for this server's canonical resource.

    A bearer that is not a JWT is offered to `fallback`, when one is configured,
    so long-lived API tokens keep working. A JWT that fails verification is
    never offered to it.
    """

    def __init__(
        self,
        *,
        issuer: str,
        resource: str,
        fallback: FallbackResolver | None = None,
        jwks_url: str | None = None,
        fetch_json: JsonFetcher = _fetch_json,
    ) -> None:
        if not resource:
            raise ValueError("resource is required")
        self._resource = resource
        self._fallback = fallback
        self._jwt = WorkOSJWTVerifier(
            issuer=issuer, audiences=[resource], jwks_url=jwks_url, fetch_json=fetch_json
        )

    async def verify_token(self, token: str) -> AccessToken | None:
        if not looks_like_jwt(token):
            return await self._fallback(token) if self._fallback else None
        try:
            claims = await self._jwt.verify(token)
        except JWTVerificationError as exc:
            logger.info("rejected bearer token: %s", exc)
            return None
        return self._access_token(token, claims)

    def _access_token(self, token: str, claims: dict[str, Any]) -> AccessToken:
        return AccessToken(
            token=token,
            client_id=str(claims.get("client_id") or claims.get("azp") or claims["sub"]),
            scopes=str(claims.get("scope") or "").split(),
            expires_at=int(claims["exp"]),  # a NumericDate may carry a fraction
            # `aud` may be a list; the verifier has already proved this server is in it.
            resource=self._resource,
            subject=str(claims["sub"]),
            claims=claims,
        )
