"""The identity gate: where an application's own user lookup meets the SDK.

The application writes a resolver. This module only gives it somewhere to run
and carries its refusal to the client in the one shape the SDK can deliver once
a token has been accepted: HTTP 200 with a JSON-RPC error and no challenge.
"""

from __future__ import annotations

import contextvars
import logging
from collections.abc import Awaitable, Callable
from typing import Any

from mcp.server.auth.middleware.auth_context import get_access_token
from mcp.server.auth.provider import AccessToken
from mcp.server.context import CallNext, HandlerResult, ServerRequestContext
from mcp.shared.exceptions import MCPError
from mcp.types import INTERNAL_ERROR

logger = logging.getLogger(__name__)

# MCP 2026-07-28 reserves -32768..-32000 for JSON-RPC and the specification, and
# says application-defined codes belong outside it.
IDENTITY_REFUSED_CODE = -31403

IdentityResolver = Callable[[AccessToken], Awaitable[Any]]

_identity: contextvars.ContextVar[Any] = contextvars.ContextVar("wolfworks_mcp_identity")


class IdentityRefused(Exception):
    """Raised by a resolver for a genuine token it will not act for.

    The message reaches the end user, so it should say what to do next.
    """


def current_identity() -> Any:
    """Return whatever the resolver returned for the request being handled.

    Raises `LookupError` when nothing was resolved: outside a request, or on a
    server running without auth.
    """
    return _identity.get()


class IdentityGate:
    """A `ServerMiddleware`: `MCPServer(middleware=[IdentityGate(resolver)])`."""

    def __init__(self, resolver: IdentityResolver, *, allow_unauthenticated: bool = False) -> None:
        self._resolver = resolver
        self._allow_unauthenticated = allow_unauthenticated

    async def __call__(
        self, ctx: ServerRequestContext[Any, Any], call_next: CallNext
    ) -> HandlerResult:
        access = get_access_token()
        if access is None:
            # The SDK only lets a request through without a token when the server was
            # built without auth. That is a choice for local development, never a default:
            # a server that merely forgot `auth=` must not run tools for strangers.
            if self._allow_unauthenticated:
                return await call_next(ctx)
            logger.error(
                "IdentityGate saw a request with no verified token, so the server has no "
                "auth configured; refusing. Pass allow_unauthenticated=True to run without it."
            )
            raise MCPError(INTERNAL_ERROR, "Internal server error")
        try:
            identity = await self._resolver(access)
        except IdentityRefused as exc:
            raise MCPError(IDENTITY_REFUSED_CODE, str(exc), {"reason": "identity_refused"}) from exc
        except MCPError:
            raise
        except Exception:
            # The SDK would put this exception's text in the response, and a failed
            # lookup can name anything. It withholds a failing tool's text already.
            logger.exception("identity resolver failed")
            raise MCPError(INTERNAL_ERROR, "Internal server error") from None
        reset = _identity.set(identity)
        try:
            return await call_next(ctx)
        finally:
            _identity.reset(reset)
