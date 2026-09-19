"""FR-6: the probe passes a conformant server and names what is wrong with a broken one."""

from __future__ import annotations

import contextlib
import json

import httpx
import pytest
from mcp.server.auth.provider import AccessToken, TokenVerifier
from mcp.server.auth.settings import AuthSettings
from mcp.server.mcpserver import MCPServer
from mcp.server.transport_security import TransportSecuritySettings

from wolfworks_mcp_auth.conformance import main, probe

SERVER = "https://server.test/mcp"
PRM = "https://server.test/.well-known/oauth-protected-resource/mcp"
ISSUER = "https://issuer.test"
AS_METADATA = f"{ISSUER}/.well-known/oauth-authorization-server"
CHALLENGE = f'Bearer error="invalid_token", error_description="x", resource_metadata="{PRM}"'


def _client(**overrides) -> httpx.AsyncClient:
    """A fake deployment. Each keyword replaces the response for one hop."""
    responses = {
        SERVER: httpx.Response(401, headers={"WWW-Authenticate": CHALLENGE}),
        PRM: httpx.Response(
            200,
            json={
                "resource": SERVER,
                "authorization_servers": [ISSUER],
                "scopes_supported": ["openid", "profile", "email"],
            },
        ),
        AS_METADATA: httpx.Response(200, json={"issuer": ISSUER}),
    }
    responses.update(overrides)

    def handler(request: httpx.Request) -> httpx.Response:
        return responses.get(str(request.url), httpx.Response(404))

    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


async def test_conformant_server_passes():
    async with _client() as client:
        report = await probe(SERVER, client=client)
    assert report.ok, report.failures
    assert [status for _, status in report.hops] == [401, 200, 200]


async def test_missing_challenge_fails_with_the_reason():
    async with _client(**{SERVER: httpx.Response(401)}) as client:
        report = await probe(SERVER, client=client)
    assert not report.ok
    assert "WWW-Authenticate" in report.failures[0]


async def test_redirect_at_the_challenge_hop_fails():
    redirect = httpx.Response(307, headers={"Location": "http://server.test/mcp/"})
    async with _client(**{SERVER: redirect}) as client:
        report = await probe(SERVER, client=client)
    assert not report.ok
    assert "307" in report.failures[0]


async def test_dead_metadata_url_fails_with_the_reason():
    async with _client(**{PRM: httpx.Response(404)}) as client:
        report = await probe(SERVER, client=client)
    assert not report.ok
    assert PRM in report.failures[0] and "404" in report.failures[0]


async def test_dead_authorization_server_metadata_fails():
    async with _client(**{AS_METADATA: httpx.Response(404)}) as client:
        report = await probe(SERVER, client=client)
    assert not report.ok
    assert ISSUER in report.failures[0]


async def test_openid_configuration_is_accepted_in_place_of_rfc8414():
    oidc = f"{ISSUER}/.well-known/openid-configuration"
    overrides = {AS_METADATA: httpx.Response(404), oidc: httpx.Response(200, json={})}
    async with _client(**overrides) as client:
        report = await probe(SERVER, client=client)
    assert report.ok, report.failures


async def test_offline_access_in_resource_metadata_fails():
    body = {
        "resource": SERVER,
        "authorization_servers": [ISSUER],
        "scopes_supported": ["openid", "offline_access"],
    }
    async with _client(**{PRM: httpx.Response(200, json=body)}) as client:
        report = await probe(SERVER, client=client)
    assert not report.ok
    assert "offline_access" in report.failures[0]


async def test_offline_access_in_the_challenge_fails():
    challenge = CHALLENGE + ', scope="openid offline_access"'
    response = httpx.Response(401, headers={"WWW-Authenticate": challenge})
    async with _client(**{SERVER: response}) as client:
        report = await probe(SERVER, client=client)
    assert not report.ok
    assert "offline_access" in report.failures[0]


class _RejectAll(TokenVerifier):
    async def verify_token(self, token: str) -> AccessToken | None:
        return None


@contextlib.asynccontextmanager
async def _sdk_backed_client():
    """Hops one and two come from the real SDK, so the probe parses what it really emits."""
    server = MCPServer(
        "probe-target",
        token_verifier=_RejectAll(),
        auth=AuthSettings(
            issuer_url=ISSUER,
            resource_server_url=SERVER,
            required_scopes=["openid", "profile", "email"],
            validate_token_resource=True,
        ),
    )
    app = server.streamable_http_app(
        streamable_http_path="/mcp",
        json_response=True,
        stateless_http=True,
        transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=False),
    )
    issuer = httpx.MockTransport(lambda request: httpx.Response(200, json={"issuer": ISSUER}))
    async with app.router.lifespan_context(app):
        mounts = {"all://server.test": httpx.ASGITransport(app=app), "all://issuer.test": issuer}
        async with httpx.AsyncClient(mounts=mounts) as client:
            yield client


async def test_passes_against_the_real_sdk():
    async with _sdk_backed_client() as client:
        report = await probe(SERVER, client=client)
    assert report.ok, report.failures
    assert report.hops[1][0] == PRM


def test_cli_exit_code_and_output(monkeypatch, capsys):
    async def fake_probe(url: str, **_):
        from wolfworks_mcp_auth.conformance import ProbeReport

        return ProbeReport(hops=[(url, 401)], failures=["challenge carries no resource_metadata"])

    monkeypatch.setattr("wolfworks_mcp_auth.conformance.probe", fake_probe)
    assert main([SERVER]) == 1
    out = capsys.readouterr().out
    assert "FAIL" in out and "resource_metadata" in out


def test_cli_without_a_url_is_a_usage_error():
    with pytest.raises(SystemExit):
        main([])


def test_report_serialises():
    from wolfworks_mcp_auth.conformance import ProbeReport

    report = ProbeReport(hops=[(SERVER, 401)], failures=[])
    assert json.loads(report.to_json()) == {"ok": True, "hops": [[SERVER, 401]], "failures": []}
