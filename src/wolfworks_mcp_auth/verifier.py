"""The `TokenVerifier` an `MCPServer` is constructed with."""

from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable, Collection
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


def api_token_access(
    token: str, *, user_id: str | int, resource: str, scopes: list[str]
) -> AccessToken:
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
        subject=str(user_id),
    )


def _scopes(claim: Any) -> list[str]:
    """RFC 8693 makes `scope` one space-separated string; some issuers send a list."""
    if isinstance(claim, list):
        return [str(scope) for scope in claim]
    return str(claim or "").split()


class WorkOSTokenVerifier(TokenVerifier):
    """Accepts a WorkOS JWT minted for this server's canonical resource.

    A bearer that is not a JWT is offered to `fallback`, when one is configured,
    so long-lived API tokens keep working. A JWT that fails verification is
    never offered to it.

    `refused_client_ids` names clients that may hold a token for this resource
    but must never use it here: the device and service clients registered for
    a product's other surfaces. A JWT whose `client_id`, `azp`, or the client
    this verifier would otherwise report, is one of them is an invalid token.
    """

    def __init__(
        self,
        *,
        issuer: str,
        resource: str,
        fallback: FallbackResolver | None = None,
        jwks_url: str | None = None,
        fetch_json: JsonFetcher = _fetch_json,
        refused_client_ids: Collection[str] = (),
    ) -> None:
        if not resource:
            raise ValueError("resource is required")
        self._refused = _client_ids(refused_client_ids)
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
        access = self._access_token(token, claims)
        refused = self._refused & {access.client_id, claims.get("client_id"), claims.get("azp")}
        if refused:
            logger.info("rejected bearer token: client %r is refused here", min(refused))
            return None
        return access

    @property
    def refused_client_ids(self) -> frozenset[str]:
        """The clients this verifier refuses, whatever else their token proves."""
        return self._refused

    def _access_token(self, token: str, claims: dict[str, Any]) -> AccessToken:
        return AccessToken(
            token=token,
            client_id=str(claims.get("client_id") or claims.get("azp") or claims["sub"]),
            scopes=_scopes(claims.get("scope")),
            expires_at=int(claims["exp"]),  # a NumericDate may carry a fraction
            # `aud` may be a list; the verifier has already proved this server is in it.
            resource=self._resource,
            subject=str(claims["sub"]),
            claims=claims,
        )


def _client_ids(ids: Collection[str]) -> frozenset[str]:
    # A bare string is a collection too: of single characters, none of them a client.
    if isinstance(ids, str) or not isinstance(ids, Collection):
        raise TypeError("refused_client_ids is a collection of client IDs, not one string")
    if not all(isinstance(client_id, str) and client_id for client_id in ids):
        raise ValueError("refused_client_ids holds only non-empty client ID strings")
    return frozenset(ids)
