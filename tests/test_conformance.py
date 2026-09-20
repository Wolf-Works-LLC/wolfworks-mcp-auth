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


def _handler(**overrides):
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

    return handler


def _client(**overrides) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.MockTransport(_handler(**overrides)))


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
    overrides = {
        AS_METADATA: httpx.Response(404),
        oidc: httpx.Response(200, json={"issuer": ISSUER}),
    }
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


@pytest.mark.parametrize("resource", ["https://elsewhere.test/mcp", SERVER + "/"])
async def test_resource_metadata_describing_another_resource_fails(resource):
    # A trailing slash counts here too: RFC 9728 s3.3 has the client compare the strings.
    body = {"resource": resource, "authorization_servers": [ISSUER]}
    async with _client(**{PRM: httpx.Response(200, json=body)}) as client:
        report = await probe(SERVER, client=client)
    assert not report.ok
    assert repr(resource) in report.failures[0]


@pytest.mark.parametrize("issuer", ["https://someone-else.test", ISSUER + "/"])
async def test_authorization_server_metadata_for_another_issuer_fails(issuer):
    # A trailing slash counts: RFC 8414 requires the two strings to be identical.
    async with _client(**{AS_METADATA: httpx.Response(200, json={"issuer": issuer})}) as client:
        report = await probe(SERVER, client=client)
    assert not report.ok
    assert repr(issuer) in report.failures[0] and repr(ISSUER) in report.failures[0]


@pytest.mark.parametrize("hop", [PRM, AS_METADATA])
async def test_metadata_that_is_not_a_json_object_is_a_failure_not_a_traceback(hop):
    for body in (httpx.Response(200, text="<html>hello</html>"), httpx.Response(200, json=[1])):
        async with _client(**{hop: body}) as client:
            report = await probe(SERVER, client=client)
        assert not report.ok
        assert report.failures


@pytest.mark.parametrize(
    "overrides",
    [
        {
            SERVER: httpx.Response(
                401, headers={"WWW-Authenticate": CHALLENGE.replace(PRM, "https://[::1/x")}
            )
        },
        {
            PRM: httpx.Response(
                200, json={"resource": SERVER, "authorization_servers": {"a": ISSUER}}
            )
        },
    ],
    ids=["metadata-url-is-no-url", "servers-is-an-object"],
)
async def test_a_malformed_url_or_server_list_is_a_failure_not_a_traceback(overrides):
    async with _client(**overrides) as client:
        report = await probe(SERVER, client=client)
    assert not report.ok
    assert "could not read a hop" in report.failures[0]


async def test_unreachable_server_is_a_failure_not_a_traceback():
    def refuse(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("no route to host")

    async with httpx.AsyncClient(transport=httpx.MockTransport(refuse)) as client:
        report = await probe(SERVER, client=client)
    assert not report.ok
    assert "no route to host" in report.failures[0]


async def test_a_server_that_never_answers_meets_the_deadline(monkeypatch):
    import asyncio

    async def stall(request: httpx.Request) -> httpx.Response:
        await asyncio.sleep(5)
        return httpx.Response(401)

    monkeypatch.setattr("wolfworks_mcp_auth.conformance._DEADLINE_SECONDS", 0.05)
    async with httpx.AsyncClient(transport=httpx.MockTransport(stall)) as client:
        report = await probe(SERVER, client=client)
    assert not report.ok
    assert "deadline" in report.failures[0]


async def test_without_a_client_the_probe_builds_one_and_holds_it_to_the_deadline(monkeypatch):
    # The command line takes this branch and no other.
    import asyncio

    async def stall(request: httpx.Request) -> httpx.Response:
        await asyncio.sleep(5)
        return httpx.Response(401)

    real_client, handlers = httpx.AsyncClient, [_handler()]

    def owned(**kwargs):
        return real_client(transport=httpx.MockTransport(handlers[0]), **kwargs)

    monkeypatch.setattr("wolfworks_mcp_auth.conformance.httpx.AsyncClient", owned)
    report = await probe(SERVER)
    assert report.ok, report.failures

    handlers[0] = stall
    monkeypatch.setattr("wolfworks_mcp_auth.conformance._DEADLINE_SECONDS", 0.05)
    report = await probe(SERVER)
    assert "deadline" in report.failures[0]


def test_cli_pass_path_and_json_output(monkeypatch, capsys):
    async def fake_probe(url: str, **_):
        from wolfworks_mcp_auth.conformance import ProbeReport

        return ProbeReport(hops=[(url, 401), (PRM, 200), (AS_METADATA, 200)], failures=[])

    monkeypatch.setattr("wolfworks_mcp_auth.conformance.probe", fake_probe)
    assert main([SERVER]) == 0
    assert "PASS" in capsys.readouterr().out
    assert main([SERVER, "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["ok"] is True
