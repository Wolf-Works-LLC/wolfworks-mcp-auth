"""FR-5's identity gate, run against a real `MCPServer` over its real ASGI app."""

from __future__ import annotations

import asyncio
import contextlib

import httpx
import pytest
from mcp.server.auth.provider import AccessToken, TokenVerifier
from mcp.server.auth.settings import AuthSettings
from mcp.server.mcpserver import MCPServer
from mcp.server.transport_security import TransportSecuritySettings
from mcp.shared.exceptions import MCPError

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


def _call(tool: str) -> dict:
    return {
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/call",
        "params": {"name": tool, "arguments": {}},
    }


CALL_WHOAMI = _call("whoami")
LIST_TOOLS = {"jsonrpc": "2.0", "id": 3, "method": "tools/list", "params": {}}


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
async def _client(
    resolver=_resolver, *, auth: bool = True, ran: list[str] | None = None, **gate_options
):
    secured = {
        "token_verifier": _StubVerifier(),
        "auth": AuthSettings(
            issuer_url="https://issuer.test",
            resource_server_url=RESOURCE,
            required_scopes=["openid"],
            validate_token_resource=True,
        ),
    }
    gate = IdentityGate(resolver, **gate_options)
    server = MCPServer("test", middleware=[gate], **(secured if auth else {}))
    arrivals: list[int] = []
    second_is_past_the_gate, first_has_read = asyncio.Event(), asyncio.Event()

    @server.tool()
    def whoami() -> str:
        return current_identity()["user_id"]

    @server.tool()
    async def whoami_overlapping() -> str:
        # The first caller reads its identity while the second is past the gate and
        # still in flight, which is exactly when a shared slot holds the wrong one.
        arrivals.append(1)
        if len(arrivals) == 1:
            await asyncio.wait_for(second_is_past_the_gate.wait(), timeout=5)
            mine = current_identity()["user_id"]
            first_has_read.set()
            return mine
        second_is_past_the_gate.set()
        await asyncio.wait_for(first_has_read.wait(), timeout=5)
        return current_identity()["user_id"]

    @server.tool()
    def leave_a_mark() -> str:
        assert ran is not None
        ran.append("ran")
        return "done"

    @server.tool()
    def identity_or_none() -> str:
        try:
            return str(current_identity())
        except LookupError:
            return "none"

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


async def test_resolver_failure_tells_the_client_nothing(caplog):
    # The SDK sends an unexpected exception's text to the client, and a failed
    # lookup can name anything: a connection string, another user's address.
    async def broken(access: AccessToken) -> None:
        raise RuntimeError("could not connect to postgres://app:hunter2@db.internal/prod")

    async with _client(broken) as client:
        response = await client.post("/mcp", headers=_auth("good-alice"), json=CALL_WHOAMI)
    assert response.status_code == 200
    assert "hunter2" not in response.text
    assert response.json()["error"] == {"code": -32603, "message": "Internal server error"}
    assert "hunter2" in caplog.text  # the operator still gets it


async def test_resolver_may_raise_its_own_mcp_error():
    async def suspended(access: AccessToken) -> None:
        raise MCPError(-31402, "Subscription lapsed.", {"reason": "payment_required"})

    async with _client(suspended) as client:
        response = await client.post("/mcp", headers=_auth("good-alice"), json=CALL_WHOAMI)
    assert response.json()["error"] == {
        "code": -31402,
        "message": "Subscription lapsed.",
        "data": {"reason": "payment_required"},
    }


async def test_resolved_identity_is_readable_inside_a_tool():
    async with _client() as client:
        response = await client.post("/mcp", headers=_auth("good-alice"), json=CALL_WHOAMI)
    assert response.status_code == 200
    assert response.json()["result"]["structuredContent"] == {"result": "row-for-alice"}


async def test_refused_identity_never_runs_the_tool():
    ran: list[str] = []
    async with _client(ran=ran) as client:
        refused = await client.post(
            "/mcp", headers=_auth("good-stranger"), json=_call("leave_a_mark")
        )
        allowed = await client.post("/mcp", headers=_auth("good-alice"), json=_call("leave_a_mark"))
    assert refused.json()["error"]["code"] == IDENTITY_REFUSED_CODE
    assert "result" in allowed.json()
    assert ran == ["ran"]  # once, for alice


async def test_refusal_covers_methods_other_than_initialize_and_tool_calls():
    async with _client() as client:
        response = await client.post("/mcp", headers=_auth("good-stranger"), json=LIST_TOOLS)
    assert response.json()["error"]["code"] == IDENTITY_REFUSED_CODE


async def test_no_bearer_never_reaches_a_tool():
    ran: list[str] = []
    async with _client(ran=ran) as client:
        response = await client.post("/mcp", headers=HEADERS, json=_call("leave_a_mark"))
    assert response.status_code == 401
    assert ran == []


async def test_a_server_built_without_auth_runs_no_tool_behind_the_gate(caplog):
    # Forgetting `auth=` and `token_verifier=` must not turn the gate into an open door.
    ran: list[str] = []
    async with _client(auth=False, ran=ran) as client:
        response = await client.post("/mcp", headers=HEADERS, json=_call("leave_a_mark"))
    assert response.json()["error"]["code"] == -32603
    assert ran == []
    assert "allow_unauthenticated" in caplog.text


async def test_the_gate_steps_aside_only_when_told_to_and_publishes_no_identity():
    async with _client(auth=False, allow_unauthenticated=True) as client:
        response = await client.post("/mcp", headers=HEADERS, json=_call("identity_or_none"))
    assert response.json()["result"]["structuredContent"] == {"result": "none"}


async def test_the_opt_out_does_not_switch_the_resolver_off_for_a_verified_token():
    # The flag left on in production must cost nothing: it covers a missing token only.
    ran: list[str] = []
    async with _client(allow_unauthenticated=True, ran=ran) as client:
        response = await client.post(
            "/mcp", headers=_auth("good-stranger"), json=_call("leave_a_mark")
        )
    assert response.json()["error"]["code"] == IDENTITY_REFUSED_CODE
    assert ran == []


async def test_overlapping_requests_each_see_their_own_identity():
    async with _client() as client:
        alice, bob = await asyncio.gather(
            client.post("/mcp", headers=_auth("good-alice"), json=_call("whoami_overlapping")),
            client.post("/mcp", headers=_auth("good-bob"), json=_call("whoami_overlapping")),
        )
    assert alice.json()["result"]["structuredContent"] == {"result": "row-for-alice"}
    assert bob.json()["result"]["structuredContent"] == {"result": "row-for-bob"}


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
