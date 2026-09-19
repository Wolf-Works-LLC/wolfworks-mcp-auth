"""The identity gate: where an application's own user lookup meets the SDK.

The application writes a resolver. This module only gives it somewhere to run
and carries its refusal to the client in the one shape the SDK can deliver once
a token has been accepted: HTTP 200 with a JSON-RPC error and no challenge.
"""

from __future__ import annotations

import contextvars
from collections.abc import Awaitable, Callable
from typing import Any

from mcp.server.auth.middleware.auth_context import get_access_token
from mcp.server.auth.provider import AccessToken
from mcp.server.context import CallNext, HandlerResult, ServerRequestContext
from mcp.shared.exceptions import MCPError

# MCP 2026-07-28 reserves -32768..-32000 for JSON-RPC and the specification, and
# says application-defined codes belong outside it.
IDENTITY_REFUSED_CODE = -31403

IdentityResolver = Callable[[AccessToken], Awaitable[Any]]

_identity: contextvars.ContextVar[Any] = contextvars.ContextVar("wolfworks_mcp_identity")


class IdentityRefused(Exception):  # noqa: N818 - named for what happened, not as an error type
    """Raised by a resolver for a genuine token it will not act for.

    The message reaches the end user, so it should say what to do next.
    """


def current_identity() -> Any:
    """Return whatever the resolver returned for the request being handled."""
    return _identity.get()


class IdentityGate:
    """A `ServerMiddleware`: `MCPServer(middleware=[IdentityGate(resolver)])`."""

    def __init__(self, resolver: IdentityResolver) -> None:
        self._resolver = resolver

    async def __call__(
        self, ctx: ServerRequestContext[Any, Any], call_next: CallNext
    ) -> HandlerResult:
        access = get_access_token()
        if access is None:
            # Auth is switched off (local development); there is no one to resolve.
            return await call_next(ctx)
        try:
            identity = await self._resolver(access)
        except IdentityRefused as exc:
            raise MCPError(IDENTITY_REFUSED_CODE, str(exc), {"reason": "identity_refused"}) from exc
        reset = _identity.set(identity)
        try:
            return await call_next(ctx)
        finally:
            _identity.reset(reset)
