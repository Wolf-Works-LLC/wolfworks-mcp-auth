# wolfworks-mcp-auth

WorkOS token verification and an identity gate for MCP servers built on the
official [`mcp`](https://pypi.org/project/mcp/) Python SDK, version 2.2
(`mcp>=2.2.0,<2.3`). The ceiling is deliberate: `IdentityGate` implements
`ServerMiddleware`, which the SDK marks provisional and free to change in a 2.x
minor release. A project that requires `mcp>=2.3` will not resolve until this
package raises it.

**The SDK owns the protocol. This package owns WorkOS. Your application owns its identity.**

The SDK already serves protected resource metadata (RFC 9728), emits the
`WWW-Authenticate` challenge, and enforces audience and scope. This package adds
the three things it cannot know:

| | |
|---|---|
| `WorkOSTokenVerifier` | the SDK `TokenVerifier` for WorkOS-issued JWTs, with an optional fallback for long-lived API tokens |
| `IdentityGate` | a `ServerMiddleware` that runs *your* user lookup and turns its refusal into the one response shape the SDK can deliver |
| `SurfaceTokenVerifier` | the same WorkOS check for a surface that is not MCP — a REST route, a socket, an ingest endpoint — bound to that surface's resource and to the clients it expects (0.2.0) |
| `run_sync` / `SyncBridge` / `BridgeClosed` | one long-lived background event loop, so synchronous hosts such as Flask can call the async verifiers (0.2.0) |
| `python -m wolfworks_mcp_auth.conformance <url>` | walks a server's discovery chain the way a client does |

It names no host. Every URL is configuration you pass in.

## Install

There is no package index. Pin the wheel attached to a release:

```
wolfworks-mcp-auth @ https://github.com/Wolf-Works-LLC/wolfworks-mcp-auth/releases/download/v0.1.0/wolfworks_mcp_auth-0.1.0-py3-none-any.whl
```

It needs no `git` and no build backend in your image, and unlike the archive
GitHub generates from a tag, a release asset's bytes never change — which a
hash-pinning lock file depends on.

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

# Write both plainly: lower-case host, no default port, no trailing slash. Both are
# compared as strings. A client checks the issuer against the authorization
# server's own, and this package checks a token's `aud` against RESOURCE as you
# wrote it, while the SDK advertises RESOURCE normalised. `https://Host:443/mcp`
# here means a 401 for every token a well-behaved client presents.
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

### Refusing other surfaces' clients at `/mcp`

`WorkOSTokenVerifier` accepts any client a genuine token names, because MCP
clients register themselves. The device and service clients a product registers
for its *other* surfaces are the exception: a phished device sign-in must never
become an MCP session, even if WorkOS would mint that client a token for the MCP
resource. Products pass every GC-4 device and service `client_id`:

```python
WorkOSTokenVerifier(
    issuer=ISSUER,
    resource=RESOURCE,
    fallback=api_tokens,
    refused_client_ids={os.environ["AGENT_CLIENT_ID"], os.environ["PIPELINE_CLIENT_ID"]},
)
```

A JWT is refused, and the SDK answers `401` `invalid_token`, when its `client_id`,
its `azp`, or the `sub` the verifier would otherwise report as its client is in
the set. It takes any collection of non-empty strings, never one bare string.
The default is empty, which changes nothing. API tokens never reach this check.

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

### Accepting a WorkOS token on a surface that is not MCP

Nothing else here verifies a WorkOS token outside `/mcp`, and nothing should
until it is bound twice: to the surface's own resource, and to the clients that
surface expects.

```python
from wolfworks_mcp_auth import SurfaceTokenRefused, SurfaceTokenVerifier

ingest = SurfaceTokenVerifier(
    issuer=ISSUER,
    resource=os.environ["INGEST_RESOURCE"],  # this surface's RFC 8707 resource
    expected_clients={
        os.environ["PIPELINE_CLIENT_ID"]: "service",  # client credentials
        os.environ["AGENT_CLIENT_ID"]: "device",  # device grant
    },
)

try:
    accepted = await ingest.verify(bearer)
except SurfaceTokenRefused as refused:
    log.info("refused: %s", refused.reason)  # e.g. "audience", "client_unexpected"
    # The issuer's outage is not the caller's fault: a 401 tells a device it was revoked.
    return 503 if refused.reason == "jwks_unavailable" else 401

accepted.kind  # "user" | "service" | "device": what you configured, never guessed
accepted.subject  # the WorkOS `sub`, never empty; map it to your own principal
accepted.client_id
accepted.claims
```

It accepts a token only when its signature, issuer and expiry are valid, its
`aud` contains `resource`, and its `client_id` claim is a key of
`expected_clients`. A token with no `client_id` is refused (`client_id_missing`):
unlike `WorkOSTokenVerifier`, it never falls back to `azp` or `sub`. A client the
surface does not list is refused (`client_unexpected`): a tenant with open client
registration issues genuine tokens, for any registered resource, to clients you
have never heard of. A first-party User Management token is refused on its
issuer, and a `/user_management/` issuer cannot be configured.

`SurfaceTokenRefused` is a `JWTVerificationError`. Its `reason` is one of
`client_id_missing`, `client_unexpected`, `audience`, `issuer`, `expired`,
`signature`, `malformed`, `claims`, `jwks_unavailable` or `invalid`; its message
is safe to log. Answer `jwks_unavailable` with `503` and every other reason with
`401`. `jwks_unavailable` means the issuer's keys could not be had, not that the
token is bad, and a device agent that receives `401` straight after a refresh
concludes it was revoked and signs itself out.

A `device` token is not yet a device. Before it acts, run your product's own
device-record check (FR-10) and refuse with `401` if the record is missing or
revoked. Revoking a single device in WorkOS is unverified, and this package
keeps no device records.

Do not pass client IDs to `WorkOSJWTVerifier` as `audiences`. A WorkOS token
requested without a `resource` carries the tenant's default application client
ID as its `aud`, so a client-ID audience accepts tokens minted for anything.
`audiences` takes resource URIs.

### Calling a verifier from synchronous code (Flask)

The verifiers are async. A synchronous host hands each call to one long-lived
background event loop with `run_sync`, and never runs a loop per request:
`asyncio.run` per call gives every request its own refresh inside the verifier,
so concurrent requests stop sharing one JWKS fetch, and each one pays for a new
loop.

```python
from flask import Flask, abort, request
from wolfworks_mcp_auth import (
    BridgeClosed,
    SurfaceTokenRefused,
    SurfaceTokenVerifier,
    looks_like_jwt,
    run_sync,
)

app = Flask(__name__)
api = SurfaceTokenVerifier(issuer=ISSUER, resource=API_RESOURCE, expected_clients=API_CLIENTS)


def oauth_principal():
    scheme, _, bearer = request.headers.get("Authorization", "").partition(" ")
    bearer = bearer.strip()
    if scheme.lower() != "bearer" or not looks_like_jwt(bearer):
        return None  # not a WorkOS token: your existing authentication, unchanged
    try:
        return run_sync(api.verify(bearer), timeout=10)
    except SurfaceTokenRefused as refused:
        # The issuer's outage is ours to answer, not the caller's: never 401 for it.
        abort(503 if refused.reason == "jwks_unavailable" else 401)
    except (TimeoutError, BridgeClosed):
        abort(503)  # too slow, or shutting down: the token may well be fine
```

`run_sync` is safe from any number of threads. The loop runs on one daemon
thread, which starts on the first call, not on import. Under gunicorn, each
worker starts its own on its first request: a forked child forgets the parent's
loop, whose thread does not exist there. `--preload` is safe as long as the
master never calls `run_sync` or `start()` itself: that would fork a process
with a running thread. To start the loop at worker boot instead, give the host
its own `SyncBridge` and call its `start()` from gunicorn's `post_fork` hook.

Every call waits at most `timeout` seconds (ten by default), then cancels the
coroutine and raises `TimeoutError`; Ctrl-C while waiting cancels it too. A
caller giving up never cancels the key refresh other requests share, and a
refresh gets five seconds in all before it counts as failed and the held keys
answer. So keep `timeout` above five seconds, or a slow issuer reaches your
callers as `TimeoutError` instead of being answered from the cache. A call still
running when the loop stops, at `close()` or at exit, raises `BridgeClosed`;
answer it `503` too. Calling `run_sync` from async code raises `RuntimeError`:
`await` there instead.

`SyncBridge()` gives a host its own loop, with its own `default_timeout`,
`close()` and context manager; one dropped without `close()` stops its loop when
it is collected. Most hosts need only the shared one behind `run_sync`.

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

`current_identity()` raises `LookupError` when nothing was resolved.

**The gate fails closed.** A request reaches it without a verified token only
when the server was built without `auth=` and `token_verifier=`. It answers that
with `-32603` and logs why, so a server that merely forgot its auth settings runs
no tool for anyone. To run without auth on purpose, in local development, say so:
`IdentityGate(resolve, allow_unauthenticated=True)`. Nothing is resolved in that
mode, so `current_identity()` raises `LookupError` in every tool. A request that
does carry a verified token still goes through your resolver.

## When the issuer is down

Signing keys are cached for five minutes. If a refresh fails, the verifier keeps
serving the keys it holds — they are public, and the issuer published them — and
tries again after thirty seconds rather than once per request. A refresh that
takes more than five seconds, discovery and key set together, has failed
(`fetch_budget_seconds` changes it on `WorkOSJWTVerifier`), and a caller that
stops waiting leaves it running for the rest. It stops serving held keys
a day after the last successful fetch, and with no keys at all it refuses every
JWT; either is logged as an error. `WorkOSJWTVerifier` takes `max_stale_seconds`
to change the day; `WorkOSTokenVerifier` and `SurfaceTokenVerifier` use the
default, and pass through neither it, `leeway_seconds`, `cache_ttl_seconds` nor
`fetch_budget_seconds`.
`SurfaceTokenVerifier` reports the refusal as `jwks_unavailable`: answer it `503`.
API tokens never touch the JWKS and are unaffected.

## What the probe checks

`python -m wolfworks_mcp_auth.conformance <url>` fails unless: the endpoint answers
an unauthenticated `POST` with `401` directly (a redirect fails — clients drop
`Authorization` across one) and a `Bearer` challenge carrying `resource_metadata`;
that document is a JSON object whose `resource` is exactly the URL probed and
which names an authorization server; that server's RFC 8414 or OpenID metadata is
a JSON object whose `issuer` is exactly that string; and `offline_access` appears
in neither the challenge nor the resource's `scopes_supported`. Anything
unreachable, malformed or slower than sixty seconds is reported as a failure, not
a traceback. It checks discovery, not a token exchange.

## Development

```
uv venv && source .venv/bin/activate && uv pip install -e ".[dev]"
pytest
ruff check . && ruff format --check .
```
