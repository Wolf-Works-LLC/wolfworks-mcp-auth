"""FR-2's `TokenVerifier` and FR-3's legacy-token fallback."""

from __future__ import annotations

import time

import pytest
from conftest import ISSUER, RESOURCE, FakeFetcher
from mcp.server.auth.provider import AccessToken

from wolfworks_mcp_auth import WorkOSTokenVerifier, api_token_access

API_TOKEN = "0123456789abcdef0123456789abcdef"


def _verifier(fetcher: FakeFetcher, fallback=None) -> WorkOSTokenVerifier:
    return WorkOSTokenVerifier(
        issuer=ISSUER, resource=RESOURCE, fallback=fallback, fetch_json=fetcher
    )


async def test_valid_jwt_becomes_an_access_token(mint, fetcher):
    token = mint()
    access = await _verifier(fetcher).verify_token(token)
    assert isinstance(access, AccessToken)
    assert access.token == token
    assert access.client_id == "client_01XYZ"
    assert access.scopes == ["openid", "profile", "email"]
    assert access.resource == RESOURCE
    assert access.subject == "user_01ABC"
    assert access.claims["iss"] == ISSUER
    assert access.expires_at == access.claims["exp"]


async def test_client_id_falls_back_to_azp_then_sub(mint, fetcher):
    verifier = _verifier(fetcher)
    via_azp = await verifier.verify_token(mint(drop=("client_id",), azp="client_azp"))
    via_sub = await verifier.verify_token(mint(drop=("client_id",)))
    assert via_azp.client_id == "client_azp"
    assert via_sub.client_id == "user_01ABC"


async def test_array_audience_reports_this_server_as_the_resource(mint, fetcher):
    access = await _verifier(fetcher).verify_token(mint(aud=["https://other.test/mcp", RESOURCE]))
    assert access.resource == RESOURCE


async def test_fractional_exp_is_accepted_as_whole_seconds(mint, fetcher):
    # RFC 7519 allows a non-integer NumericDate; `AccessToken.expires_at` is an int.
    exp = time.time() + 3600.5
    access = await _verifier(fetcher).verify_token(mint(exp=exp))
    assert access.expires_at == int(exp)


async def test_token_without_scope_claim_has_no_scopes(mint, fetcher):
    access = await _verifier(fetcher).verify_token(mint(drop=("scope",)))
    assert access.scopes == []


@pytest.mark.parametrize(
    "overrides",
    [
        {"aud": "https://other.test/mcp"},
        {"iss": "https://evil.test"},
        {"exp": 1, "iat": 1},
    ],
)
async def test_unacceptable_jwt_returns_none(mint, fetcher, overrides):
    assert await _verifier(fetcher).verify_token(mint(**overrides)) is None


async def test_unacceptable_jwt_is_never_offered_to_the_fallback(mint, fetcher):
    seen: list[str] = []

    async def fallback(token: str) -> AccessToken | None:
        seen.append(token)
        return None

    assert await _verifier(fetcher, fallback).verify_token(mint(iss="https://evil.test")) is None
    assert seen == []


async def test_non_jwt_bearer_resolves_through_the_fallback(fetcher):
    async def fallback(token: str) -> AccessToken | None:
        if token == API_TOKEN:
            return api_token_access(
                token, user_id="row-42", resource=RESOURCE, scopes=["openid", "profile", "email"]
            )
        return None

    access = await _verifier(fetcher, fallback).verify_token(API_TOKEN)
    assert access.subject == "row-42"
    assert access.resource == RESOURCE
    assert access.scopes == ["openid", "profile", "email"]
    assert access.client_id == "api-token:row-42"
    assert fetcher.calls == []  # an API token never triggers a JWKS fetch


async def test_unrecognised_non_jwt_bearer_returns_none(fetcher):
    async def fallback(token: str) -> AccessToken | None:
        return None

    assert await _verifier(fetcher, fallback).verify_token("nope") is None


async def test_non_jwt_bearer_without_a_fallback_returns_none(fetcher):
    assert await _verifier(fetcher).verify_token(API_TOKEN) is None


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"issuer": "", "resource": RESOURCE}, "issuer"),
        ({"issuer": ISSUER, "resource": ""}, "resource"),
    ],
)
def test_construction_without_required_configuration_raises(kwargs, message):
    with pytest.raises(ValueError, match=message):
        WorkOSTokenVerifier(**kwargs)
