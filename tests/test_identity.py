"""FR-5's identity gate, run against a real `MCPServer` over its real ASGI app."""

from __future__ import annotations

import contextlib

import httpx
import pytest
from mcp.server.auth.provider import AccessToken, TokenVerifier
from mcp.server.auth.settings import AuthSettings
from mcp.server.mcpserver import MCPServer
from mcp.server.transport_security import TransportSecuritySettings

from wolfworks_mcp_auth import (
    IDENTITY_REFUSED_CODE,
    IdentityGate,
    IdentityRefused,
    current_identity,
)

RESOURCE = "https://server.test/mcp"
HEADERS = {"Accept": "application/json, text/event-stream", "Content-Type": "application/json"}
INITIALIZE = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {
        "protocolVersion": "2025-06-18",
        "capabilities": {},
        "clientInfo": {"name": "test", "version": "0"},
    },
}
CALL_WHOAMI = {
    "jsonrpc": "2.0",
    "id": 2,
    "method": "tools/call",
    "params": {"name": "whoami", "arguments": {}},
}


class _StubVerifier(TokenVerifier):
    async def verify_token(self, token: str) -> AccessToken | None:
        if not token.startswith("good-"):
            return None
        return AccessToken(
            token=token, client_id="c", scopes=["openid"], resource=RESOURCE, subject=token[5:]
        )


async def _resolver(access: AccessToken) -> dict[str, str]:
    if access.subject == "stranger":
        raise IdentityRefused("Sign in at https://server.test once, then reconnect.")
    return {"user_id": f"row-for-{access.subject}"}


@contextlib.asynccontextmanager
async def _client():
    server = MCPServer(
        "test",
        token_verifier=_StubVerifier(),
        auth=AuthSettings(
            issuer_url="https://issuer.test",
            resource_server_url=RESOURCE,
            required_scopes=["openid"],
            validate_token_resource=True,
        ),
        middleware=[IdentityGate(_resolver)],
    )

    @server.tool()
    def whoami() -> str:
        return current_identity()["user_id"]

    app = server.streamable_http_app(
        streamable_http_path="/mcp",
        json_response=True,
        stateless_http=True,
        transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=False),
    )
    async with app.router.lifespan_context(app):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="https://server.test") as client:
            yield client


def _auth(token: str) -> dict[str, str]:
    return {**HEADERS, "Authorization": f"Bearer {token}"}


@pytest.mark.parametrize("body", [INITIALIZE, CALL_WHOAMI], ids=["initialize", "tools/call"])
async def test_refusal_is_a_jsonrpc_error_with_no_challenge(body):
    async with _client() as client:
        response = await client.post("/mcp", headers=_auth("good-stranger"), json=body)
    assert response.status_code == 200
    assert "www-authenticate" not in response.headers
    error = response.json()["error"]
    assert error["code"] == IDENTITY_REFUSED_CODE == -31403
    assert error["message"] == "Sign in at https://server.test once, then reconnect."
    assert error["data"] == {"reason": "identity_refused"}


async def test_resolved_identity_is_readable_inside_a_tool():
    async with _client() as client:
        response = await client.post("/mcp", headers=_auth("good-alice"), json=CALL_WHOAMI)
    assert response.status_code == 200
    assert response.json()["result"]["structuredContent"] == {"result": "row-for-alice"}


async def test_identities_do_not_leak_between_requests():
    async with _client() as client:
        first = await client.post("/mcp", headers=_auth("good-alice"), json=CALL_WHOAMI)
        second = await client.post("/mcp", headers=_auth("good-bob"), json=CALL_WHOAMI)
    assert first.json()["result"]["structuredContent"] == {"result": "row-for-alice"}
    assert second.json()["result"]["structuredContent"] == {"result": "row-for-bob"}


async def test_invalid_token_is_still_a_401_with_a_challenge():
    async with _client() as client:
        response = await client.post("/mcp", headers=_auth("bad"), json=INITIALIZE)
    assert response.status_code == 401
    assert "resource_metadata" in response.headers["www-authenticate"]


def test_current_identity_outside_a_request_raises():
    with pytest.raises(LookupError):
        current_identity()


def test_refusal_code_is_outside_the_jsonrpc_reserved_range():
    # MCP 2026-07-28 reserves -32768..-32000; application codes belong outside it.
    assert not (-32768 <= IDENTITY_REFUSED_CODE <= -32000)
