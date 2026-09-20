# wolfworks-mcp-auth

WorkOS token verification and an identity gate for MCP servers built on the
official [`mcp`](https://pypi.org/project/mcp/) Python SDK, version 2.2.0 or later.

**The SDK owns the protocol. This package owns WorkOS. Your application owns its identity.**

The SDK already serves protected resource metadata (RFC 9728), emits the
`WWW-Authenticate` challenge, and enforces audience and scope. This package adds
the three things it cannot know:

| | |
|---|---|
| `WorkOSTokenVerifier` | the SDK `TokenVerifier` for WorkOS-issued JWTs, with an optional fallback for long-lived API tokens |
| `IdentityGate` | a `ServerMiddleware` that runs *your* user lookup and turns its refusal into the one response shape the SDK can deliver |
| `python -m wolfworks_mcp_auth.conformance <url>` | walks a server's discovery chain the way a client does |

It names no host. Every URL is configuration you pass in.

## Install

There is no package index. Pin the tag archive — it needs no `git` in the image:

```
wolfworks-mcp-auth @ https://github.com/Wolf-Works-LLC/wolfworks-mcp-auth/archive/refs/tags/v0.1.0.tar.gz
```

A project built with hatchling refuses a URL dependency until its own
`pyproject.toml` allows one:

```toml
[tool.hatch.metadata]
allow-direct-references = true
```

## Use

```python
import contextlib
import os

from fastapi import FastAPI  # or Starlette
from mcp.server.auth.settings import AuthSettings
from mcp.server.mcpserver import MCPServer
from mcp.server.transport_security import TransportSecuritySettings
from starlette.routing import Route
from wolfworks_mcp_auth import (
    IdentityGate,
    IdentityRefused,
    WorkOSTokenVerifier,
    api_token_access,
    current_identity,
)

# Neither takes a trailing slash. The SDK advertises both exactly as written, and
# a client compares the issuer with the authorization server's own, as a string.
ISSUER = os.environ["WORKOS_ISSUER"]  # your AuthKit domain
RESOURCE = os.environ["MCP_RESOURCE"]  # this server's MCP URL


async def api_tokens(token: str):
    """Optional. Keeps long-lived API tokens working alongside OAuth.

    Only a bearer that does not look like a JWT arrives here. One with exactly
    two dots and more than 60 characters is a JWT, and is never offered.
    """
    row = await db.find_api_token(token)  # `db` stands for your own storage
    if row is None:
        return None
    return api_token_access(
        token, user_id=row.user_id, resource=RESOURCE, scopes=["openid", "profile", "email"]
    )


async def resolve(access):
    """Yours. Map a verified token to your own user, or refuse.

    `access.claims` is `None` for an API token, whose `subject` is the `user_id`
    you gave `api_token_access`. For a JWT it holds the claims, and `subject` is
    the WorkOS `sub`. They are different namespaces: look each up its own way.
    """
    user = await db.user_for(access)  # never create users here
    if user is None:
        raise IdentityRefused("Sign in at https://your.app once, then reconnect.")
    return user


server = MCPServer(
    "your-server",
    token_verifier=WorkOSTokenVerifier(issuer=ISSUER, resource=RESOURCE, fallback=api_tokens),
    auth=AuthSettings(
        issuer_url=ISSUER,
        resource_server_url=RESOURCE,
        required_scopes=["openid", "profile", "email"],
        validate_token_resource=True,
    ),
    middleware=[IdentityGate(resolve)],
)


@server.tool()
def whoami() -> str:
    return current_identity().email
```

### Mounting it inside FastAPI or Starlette

Four things are easy to miss, and an unauthenticated smoke test sees none of them:

```python
mcp_app = server.streamable_http_app(
    streamable_http_path="/mcp",
    json_response=True,
    stateless_http=True,  # sessions in memory do not survive a deploy
    # 1. Without this the SDK accepts only a localhost `Host`, and every
    #    authenticated request is answered `421 Invalid Host header`.
    transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=False),
)

# 2. `POST /mcp/` otherwise answers 307, and clients drop Authorization across it.
route = next(r for r in mcp_app.router.routes if getattr(r, "path", None) == "/mcp")
mcp_app.router.routes.append(Route("/mcp/", endpoint=route.endpoint))


# 3. A mounted app's lifespan does not run by itself: enter it from the host's.
#    Skip this and the smoke test still sees its 401, while every authenticated
#    call raises `RuntimeError: Task group is not initialized`.
@contextlib.asynccontextmanager
async def lifespan(app):
    async with mcp_app.router.lifespan_context(mcp_app):
        yield


host = FastAPI(lifespan=lifespan)  # or enter it inside the lifespan you already have
# ... your own routers and static mounts ...

# 4. Mount at the root, LAST. `Mount("/")` matches every path, so anything
#    registered after it is unreachable.
host.mount("/", mcp_app)
```

`transport_security` moved from the `MCPServer` constructor to
`streamable_http_app()` in `mcp` 2.x; passing it to the constructor raises `TypeError`.

One `streamable_http_app()` serves one lifespan: entering it a second time
raises `RuntimeError`. If your tests build the host more than once, build
`mcp_app` inside the same factory.

### Verifying a WorkOS token outside MCP

```python
from wolfworks_mcp_auth import JWTVerificationError, WorkOSJWTVerifier

verifier = WorkOSJWTVerifier(issuer=ISSUER, audiences=[MY_OAUTH_APPLICATION_CLIENT_ID])
claims = await verifier.verify(bearer)  # raises JWTVerificationError
```

`audiences` is an allow-list. Bind every path to the client it expects tokens
from: a tenant with open client registration issues genuine tokens to clients
you have never heard of.

## What a refusal looks like

When a token is genuine but your resolver raises `IdentityRefused`, the client
receives HTTP `200` carrying JSON-RPC error `-31403` with
`data: {"reason": "identity_refused"}` and no `WWW-Authenticate` header. It is not
a `401`, which would send the client round a re-authorization loop, and the SDK
produces `403` only for `insufficient_scope`. The code sits outside the range MCP
2026-07-28 reserves (`-32768` to `-32000`).

Anything else your resolver raises is logged and answered with `-32603`
"Internal server error". Left alone, the SDK would send the exception's own text
to the client. An `MCPError` you raise on purpose passes through unchanged.

`current_identity()` raises `LookupError` when nothing was resolved: outside a
request, or on a server running without auth, where the gate steps aside.

## Development

```
uv venv && source .venv/bin/activate && uv pip install -e ".[dev]"
pytest
ruff check . && ruff format --check .
```
