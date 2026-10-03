"""Accept a WorkOS access token on a surface that is not MCP.

A REST route, a WebSocket or an ingest endpoint has no SDK enforcing anything
for it. It accepts a token only when the token was minted for that surface's
resource *and* to a client the surface expects: a tenant with open client
registration issues genuine tokens, for any registered resource, to clients
nobody here has heard of.

Unlike `WorkOSTokenVerifier`, this check never falls back to `azp` or `sub`
for the client. A token with no `client_id` claim is refused.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Literal, cast, get_args
from urllib.parse import urlsplit

from wolfworks_mcp_auth.jwt import (
    JsonFetcher,
    JWTVerificationError,
    WorkOSJWTVerifier,
    _fetch_json,
)

PrincipalKind = Literal["user", "service", "device"]
RefusalReason = Literal[
    "malformed",
    "signature",
    "issuer",
    "audience",
    "expired",
    "claims",
    "jwks_unavailable",
    "invalid",
    "client_id_missing",
    "client_unexpected",
]

_KINDS = frozenset(get_args(PrincipalKind))
# User Management issues first-party tokens under its own path, one issuer per
# application. They are sign-in tokens for one product, never a surface's.
_FIRST_PARTY_SEGMENT = "user_management"


class SurfaceTokenRefused(JWTVerificationError):
    """The surface refuses this token. `reason` says why, as a fixed word.

    `client_id_missing` and `client_unexpected` are this check's own; every other
    reason is the underlying `JWTVerificationError`'s. A subclass of it, so one
    `except JWTVerificationError` still catches every refusal.

    `jwks_unavailable` is an outage at the issuer, not a fault in the token:
    answer it `503`, not `401`, or a device that sees `401` signs itself out.
    """

    reason: RefusalReason


@dataclass(frozen=True)
class SurfaceToken:
    """A token this surface accepts, and what it was told about the caller.

    `kind` is what the surface's configuration says `client_id` is, never a
    guess from the token's shape. `subject` is the WorkOS `sub`: a person for a
    `user` or `device` client, and whatever the issuer puts there for a
    `service` client. Map it to your own principal; nothing here creates one.

    A `device` token is not yet a device: before it acts, run your product's
    device-record check (FR-10) and refuse with `401` if the record is missing
    or revoked. This package keeps no device records.
    """

    claims: dict[str, Any]
    client_id: str
    subject: str
    kind: PrincipalKind


class SurfaceTokenVerifier:
    """Checks signature, issuer, expiry, that `aud` contains `resource`, and that
    the required `client_id` claim names a client in `expected_clients`.

    `expected_clients` maps each client ID this surface accepts to the kind of
    principal it signs in: `"user"`, `"service"` or `"device"`. It is
    configuration, per surface, and is copied when the verifier is built.
    """

    def __init__(
        self,
        *,
        issuer: str,
        resource: str,
        expected_clients: Mapping[str, PrincipalKind],
        jwks_url: str | None = None,
        fetch_json: JsonFetcher = _fetch_json,
    ) -> None:
        if not isinstance(resource, str):
            raise TypeError(f"resource is one URI string, not {type(resource).__name__}")
        if not resource:
            raise ValueError("resource is required")
        if _FIRST_PARTY_SEGMENT in urlsplit(issuer or "").path.split("/"):
            raise ValueError(
                "issuer is a first-party /user_management/ issuer; a surface accepts AuthKit's only"
            )
        if not isinstance(expected_clients, Mapping):
            raise TypeError("expected_clients is a mapping of client ID to principal kind")
        if not expected_clients:
            raise ValueError("expected_clients names no client: this surface would refuse all")
        for client_id, kind in expected_clients.items():
            if not isinstance(client_id, str) or not client_id:
                raise ValueError(f"expected client ID {client_id!r} is not a non-empty string")
            if kind not in _KINDS:
                raise ValueError(
                    f"client {client_id!r} has kind {kind!r}, not one of {sorted(_KINDS)}"
                )
        self._expected: Mapping[str, PrincipalKind] = MappingProxyType(dict(expected_clients))
        self._jwt = WorkOSJWTVerifier(
            issuer=issuer, audiences=[resource], jwks_url=jwks_url, fetch_json=fetch_json
        )

    @property
    def expected_clients(self) -> Mapping[str, PrincipalKind]:
        """The clients this surface accepts, read-only."""
        return self._expected

    async def verify(self, token: str) -> SurfaceToken:
        """Return the accepted token, or raise `SurfaceTokenRefused`."""
        try:
            claims = await self._jwt.verify(token)
        except JWTVerificationError as exc:
            raise SurfaceTokenRefused(str(exc), reason=cast(RefusalReason, exc.reason)) from exc

        client_id = claims.get("client_id")
        if client_id is None or client_id == "":
            # No `azp`, no `sub`: either may name something other than the client.
            raise SurfaceTokenRefused("token carries no client_id", reason="client_id_missing")
        if not isinstance(client_id, str) or client_id not in self._expected:
            raise SurfaceTokenRefused(
                f"client {client_id!r} is not expected on this surface",
                reason="client_unexpected",
            )
        subject = claims["sub"]  # PyJWT has required it and checked it is a string
        if not subject:
            raise SurfaceTokenRefused("token carries an empty sub", reason="claims")
        return SurfaceToken(
            claims=claims,
            client_id=client_id,
            subject=subject,
            kind=self._expected[client_id],
        )
