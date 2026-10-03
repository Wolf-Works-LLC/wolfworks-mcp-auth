"""FR-2's `TokenVerifier` and FR-3's legacy-token fallback."""

from __future__ import annotations

import logging
import time

import httpx
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


async def test_scope_claim_delivered_as_a_list_is_read_as_one(mint, fetcher):
    access = await _verifier(fetcher).verify_token(mint(scope=["openid", "email"]))
    assert access.scopes == ["openid", "email"]


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


@pytest.mark.parametrize(
    "case",
    [
        "wrong-audience",
        "wrong-issuer",
        "expired",
        "signed-by-another-key",
        "unknown-kid",
        "no-kid",
        "missing-sub",
        "not-even-a-token",
        "jwks-unreachable",
    ],
)
async def test_no_failed_jwt_reaches_a_fallback_that_would_accept_it(
    mint, fetcher, other_key, case
):
    # The fallback here says yes to anything, so reaching it at all is the failure.
    # "Keys are down, try the API-token table" is the tempting regression.
    seen: list[str] = []

    async def accepts_anything(token: str) -> AccessToken | None:
        seen.append(token)
        return api_token_access(token, user_id="intruder", resource=RESOURCE, scopes=["openid"])

    tokens = {
        "wrong-audience": mint(aud="https://other.test/mcp"),
        "wrong-issuer": mint(iss="https://evil.test"),
        "expired": mint(iat=1, exp=2),
        "signed-by-another-key": mint(key=other_key),
        "unknown-kid": mint(key=other_key, kid="never-published"),
        "no-kid": mint(kid=None),
        "missing-sub": mint(drop=("sub",)),
        "not-even-a-token": f"{'x' * 30}.{'y' * 30}.{'z' * 30}",
        "jwks-unreachable": mint(),
    }
    if case == "jwks-unreachable":
        fetcher.documents[f"{ISSUER}/oauth2/jwks"] = httpx.ConnectError("down")
    assert await _verifier(fetcher, accepts_anything).verify_token(tokens[case]) is None
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


def test_api_token_access_takes_an_integer_primary_key():
    # `AccessToken.subject` is a string; an application's primary key need not be.
    access = api_token_access(API_TOKEN, user_id=42, resource=RESOURCE, scopes=["openid"])
    assert access.subject == "42"
    assert access.client_id == "api-token:42"


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


# --- GC-6: clients registered for other surfaces are refused at /mcp --------------------

DEVICE_CLIENT = "client_01DEVICE"
SERVICE_CLIENT = "client_01SERVICE"
REFUSED = (DEVICE_CLIENT, SERVICE_CLIENT)


def _refusing(fetcher: FakeFetcher, refused=REFUSED, fallback=None) -> WorkOSTokenVerifier:
    return WorkOSTokenVerifier(
        issuer=ISSUER,
        resource=RESOURCE,
        fallback=fallback,
        fetch_json=fetcher,
        refused_client_ids=refused,
    )


@pytest.mark.parametrize("client_id", REFUSED)
async def test_a_refused_client_id_is_an_invalid_token(mint, fetcher, client_id, caplog):
    # `None` is what the SDK answers 401 `invalid_token` for.
    caplog.set_level(logging.INFO, logger="wolfworks_mcp_auth.verifier")
    assert await _refusing(fetcher).verify_token(mint(client_id=client_id)) is None
    assert client_id in caplog.text


async def test_a_refused_client_arriving_through_the_azp_fallback_is_refused(mint, fetcher):
    token = mint(drop=("client_id",), azp=DEVICE_CLIENT)
    assert await _refusing(fetcher).verify_token(token) is None


async def test_a_refused_client_arriving_through_the_sub_fallback_is_refused(mint, fetcher):
    # A client-credentials token may carry its client ID as `sub` and neither other claim.
    token = mint(drop=("client_id",), sub=SERVICE_CLIENT)
    assert await _refusing(fetcher).verify_token(token) is None


async def test_a_refused_azp_is_refused_whatever_client_id_says(mint, fetcher):
    token = mint(client_id="client_01XYZ", azp=DEVICE_CLIENT)
    assert await _refusing(fetcher).verify_token(token) is None


async def test_other_clients_are_still_accepted(mint, fetcher):
    access = await _refusing(fetcher).verify_token(mint())
    assert access is not None and access.client_id == "client_01XYZ"
    via_azp = await _refusing(fetcher).verify_token(mint(drop=("client_id",), azp="client_azp"))
    assert via_azp.client_id == "client_azp"


async def test_with_no_refused_clients_nothing_changes(mint, fetcher):
    for verifier in (_verifier(fetcher), _refusing(fetcher, refused=())):
        for token in (
            mint(client_id=DEVICE_CLIENT),
            mint(drop=("client_id",), azp=DEVICE_CLIENT),
            mint(drop=("client_id",), sub=SERVICE_CLIENT),
        ):
            assert (await verifier.verify_token(token)).client_id in REFUSED


async def test_the_api_token_fallback_is_unaffected(fetcher):
    async def fallback(token: str) -> AccessToken | None:
        # Even an API token whose user id collides with a refused client ID.
        return api_token_access(token, user_id=DEVICE_CLIENT, resource=RESOURCE, scopes=["openid"])

    access = await _refusing(fetcher, fallback=fallback).verify_token(API_TOKEN)
    assert access is not None and access.subject == DEVICE_CLIENT


def test_refused_client_ids_accepts_any_collection_and_keeps_its_own_copy(mint, fetcher):
    refused = [DEVICE_CLIENT]
    verifier = _refusing(fetcher, refused=refused)
    refused.append(SERVICE_CLIENT)
    assert verifier.refused_client_ids == frozenset({DEVICE_CLIENT})
    assert _refusing(fetcher, refused={DEVICE_CLIENT}).refused_client_ids == {DEVICE_CLIENT}


@pytest.mark.parametrize(
    ("refused", "error"),
    [
        (DEVICE_CLIENT, TypeError),  # one string is a collection of characters
        ([DEVICE_CLIENT, ""], ValueError),
        ([DEVICE_CLIENT, 7], ValueError),
        (None, TypeError),
        ([DEVICE_CLIENT + "\n"], ValueError),  # from a config file: it would never match
        ([" " + DEVICE_CLIENT], ValueError),
        (["client 01DEVICE"], ValueError),
        (["\t"], ValueError),
    ],
    ids=[
        "bare-string",
        "empty-id",
        "not-a-string",
        "none",
        "trailing-newline",
        "leading-space",
        "inner-space",
        "whitespace-only",
    ],
)
def test_refused_client_ids_must_be_a_collection_of_non_empty_strings(fetcher, refused, error):
    with pytest.raises(error, match="refused_client_ids"):
        _refusing(fetcher, refused=refused)


ODD_SHAPES = [[DEVICE_CLIENT], {"id": DEVICE_CLIENT}, 7, True]


@pytest.mark.parametrize("claim", ["client_id", "azp"])
@pytest.mark.parametrize("value", ODD_SHAPES, ids=["list", "dict", "int", "bool"])
async def test_with_no_refused_clients_an_odd_client_claim_is_accepted_as_before(
    mint, fetcher, claim, value
):
    # Main accepts these; the check must not turn them into a 500 when it is off.
    token = mint(**{claim: value}) if claim == "client_id" else mint(drop=("client_id",), azp=value)
    assert await _verifier(fetcher).verify_token(token) is not None


@pytest.mark.parametrize("claim", ["client_id", "azp"])
@pytest.mark.parametrize("value", ODD_SHAPES, ids=["list", "dict", "int", "bool"])
async def test_with_refused_clients_an_odd_client_claim_is_refused_not_raised(
    mint, fetcher, claim, value
):
    # Dropping it silently would let `[refused_client]` through: refuse it instead.
    token = mint(**{claim: value})
    assert await _refusing(fetcher).verify_token(token) is None
