"""H-FR-4's surface check: the resource audience and a required, expected `client_id`.

The library half of H-AC-1 (audience), H-AC-2 (client) and H-AC-3 (first-party issuer).
"""

from __future__ import annotations

import copy
import pickle
import time
from types import MappingProxyType

import httpx
import pytest
from conftest import ISSUER, RESOURCE, FakeFetcher

from wolfworks_mcp_auth import (
    JWTVerificationError,
    SurfaceToken,
    SurfaceTokenRefused,
    SurfaceTokenVerifier,
)

SURFACE = "https://surface.test/ingest/v1"
USER_CLIENT = "client_01USER"
SERVICE_CLIENT = "client_01SERVICE"
DEVICE_CLIENT = "client_01DEVICE"
EXPECTED = {USER_CLIENT: "user", SERVICE_CLIENT: "service", DEVICE_CLIENT: "device"}
# What User Management stamps on a first-party token: its own path, one per application.
FIRST_PARTY_ISSUER = "https://api.issuer.test/user_management/client_01FIRSTPARTY"


def _verifier(fetcher: FakeFetcher, expected=None, **kwargs) -> SurfaceTokenVerifier:
    return SurfaceTokenVerifier(
        issuer=ISSUER,
        resource=SURFACE,
        expected_clients=EXPECTED if expected is None else expected,
        fetch_json=fetcher,
        **kwargs,
    )


async def _refusal(verifier: SurfaceTokenVerifier, token: str) -> SurfaceTokenRefused:
    with pytest.raises(SurfaceTokenRefused) as raised:
        await verifier.verify(token)
    return raised.value


# --- accepted ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("client_id", "kind"),
    [(USER_CLIENT, "user"), (SERVICE_CLIENT, "service"), (DEVICE_CLIENT, "device")],
)
async def test_each_expected_client_is_accepted_with_its_configured_kind(
    mint, fetcher, client_id, kind
):
    accepted = await _verifier(fetcher).verify(mint(aud=SURFACE, client_id=client_id))
    assert isinstance(accepted, SurfaceToken)
    assert accepted.client_id == client_id
    assert accepted.kind == kind
    assert accepted.subject == "user_01ABC"
    assert accepted.claims["client_id"] == client_id
    assert accepted.claims["iss"] == ISSUER


async def test_kind_comes_from_configuration_not_from_the_token(mint, fetcher):
    # A client-credentials `sub` may look like a client ID; the map decides, never the shape.
    token = mint(aud=SURFACE, client_id=SERVICE_CLIENT, sub=SERVICE_CLIENT)
    assert (await _verifier(fetcher).verify(token)).kind == "service"


async def test_an_audience_list_containing_the_resource_is_accepted(mint, fetcher):
    token = mint(aud=["https://elsewhere.test/api", SURFACE], client_id=USER_CLIENT)
    assert (await _verifier(fetcher).verify(token)).kind == "user"


# --- H-AC-1: the audience ---------------------------------------------------------------


async def test_refuses_a_token_whose_audience_lacks_the_resource(mint, fetcher):
    # `mint()` defaults to the MCP resource: a genuine token for a sibling resource.
    refusal = await _refusal(_verifier(fetcher), mint(aud=RESOURCE, client_id=USER_CLIENT))
    assert refusal.reason == "audience"


async def test_refuses_a_token_with_no_audience(mint, fetcher):
    refusal = await _refusal(_verifier(fetcher), mint(drop=("aud",), client_id=USER_CLIENT))
    assert refusal.reason == "audience"


async def test_refuses_a_token_bound_to_a_client_id_rather_than_the_resource(mint, fetcher):
    # An unbound WorkOS token carries the default application's client ID as `aud`.
    refusal = await _refusal(_verifier(fetcher), mint(aud=USER_CLIENT, client_id=USER_CLIENT))
    assert refusal.reason == "audience"


# --- H-AC-2: the client -----------------------------------------------------------------


@pytest.mark.parametrize(
    "extra",
    [{}, {"azp": USER_CLIENT}, {"azp": USER_CLIENT, "sub": USER_CLIENT}],
    ids=["neither", "azp", "azp-and-sub"],
)
async def test_refuses_a_token_without_client_id_with_no_fallback(mint, fetcher, extra):
    # `WorkOSTokenVerifier` falls back to `azp` and then `sub`; this check never does.
    token = mint(aud=SURFACE, drop=("client_id",), **extra)
    refusal = await _refusal(_verifier(fetcher), token)
    assert refusal.reason == "client_id_missing"


async def test_refuses_an_empty_client_id(mint, fetcher):
    refusal = await _refusal(_verifier(fetcher), mint(aud=SURFACE, client_id=""))
    assert refusal.reason == "client_id_missing"


async def test_refuses_a_client_this_surface_does_not_expect(mint, fetcher):
    # A tenant with open registration issues genuine tokens to clients nobody configured.
    token = mint(aud=SURFACE, client_id="client_01SELFREGISTERED")
    refusal = await _refusal(_verifier(fetcher), token)
    assert refusal.reason == "client_unexpected"
    assert "client_01SELFREGISTERED" in str(refusal)


@pytest.mark.parametrize("client_id", [[USER_CLIENT], {"id": USER_CLIENT}, 7])
async def test_refuses_a_client_id_that_is_not_a_string(mint, fetcher, client_id):
    refusal = await _refusal(_verifier(fetcher), mint(aud=SURFACE, client_id=client_id))
    assert refusal.reason == "client_unexpected"


async def test_expected_clients_are_per_surface(mint, fetcher):
    only_devices = _verifier(fetcher, expected={DEVICE_CLIENT: "device"})
    refusal = await _refusal(only_devices, mint(aud=SURFACE, client_id=SERVICE_CLIENT))
    assert refusal.reason == "client_unexpected"


async def test_changing_the_callers_mapping_later_changes_nothing(mint, fetcher):
    expected = dict(EXPECTED)
    verifier = _verifier(fetcher, expected=expected)
    expected["client_01LATECOMER"] = "user"
    refusal = await _refusal(verifier, mint(aud=SURFACE, client_id="client_01LATECOMER"))
    assert refusal.reason == "client_unexpected"


# --- H-AC-3: the first-party issuer -----------------------------------------------------


async def test_refuses_a_first_party_user_management_token(mint, fetcher):
    # Everything else about it is right: the issuer check alone refuses it.
    token = mint(iss=FIRST_PARTY_ISSUER, aud=SURFACE, client_id=USER_CLIENT)
    refusal = await _refusal(_verifier(fetcher), token)
    assert refusal.reason == "issuer"


def test_a_user_management_issuer_cannot_be_configured():
    with pytest.raises(ValueError, match="user_management"):
        SurfaceTokenVerifier(issuer=FIRST_PARTY_ISSUER, resource=SURFACE, expected_clients=EXPECTED)


# --- the token itself -------------------------------------------------------------------


async def test_refuses_an_expired_token(mint, fetcher):
    past = int(time.time()) - 7200
    token = mint(aud=SURFACE, client_id=USER_CLIENT, iat=past, exp=past + 60)
    assert (await _refusal(_verifier(fetcher), token)).reason == "expired"


async def test_refuses_a_token_signed_by_another_key(mint, fetcher, other_key):
    token = mint(key=other_key, aud=SURFACE, client_id=USER_CLIENT)
    assert (await _refusal(_verifier(fetcher), token)).reason == "signature"


async def test_refuses_a_token_naming_an_unpublished_key(mint, fetcher, other_key):
    token = mint(key=other_key, kid="never-published", aud=SURFACE, client_id=USER_CLIENT)
    assert (await _refusal(_verifier(fetcher), token)).reason == "signature"


async def test_refuses_an_empty_subject(mint, fetcher):
    # PyJWT's `require` passes `""`; mapped to a principal, it could match a defaulted column.
    token = mint(aud=SURFACE, client_id=USER_CLIENT, sub="")
    assert (await _refusal(_verifier(fetcher), token)).reason == "claims"


async def test_an_unreachable_jwks_is_refused_as_jwks_unavailable(mint, fetcher):
    fetcher.documents[f"{ISSUER}/oauth2/jwks"] = httpx.ConnectError("issuer is down")
    token = mint(aud=SURFACE, client_id=USER_CLIENT)
    assert (await _refusal(_verifier(fetcher), token)).reason == "jwks_unavailable"


async def test_refuses_garbage_as_malformed(fetcher):
    assert (await _refusal(_verifier(fetcher), "not.a.jwt")).reason == "malformed"


def _pickled(error: Exception) -> Exception:
    return pickle.loads(pickle.dumps(error))  # noqa: S301 - our own object, round-tripped


@pytest.mark.parametrize("duplicate", [copy.copy, _pickled], ids=["copy", "pickle"])
async def test_a_refusal_survives_copy_and_pickle(mint, fetcher, duplicate):
    # Process pools and job queues copy exceptions; the reason must come through.
    token = mint(aud=SURFACE, client_id="client_01NOBODY")
    refusal = await _refusal(_verifier(fetcher), token)
    duplicated = duplicate(refusal)
    assert isinstance(duplicated, SurfaceTokenRefused)
    assert duplicated.reason == "client_unexpected"
    assert str(duplicated) == str(refusal)


async def test_a_refusal_is_a_jwt_verification_error(mint, fetcher):
    # One `except JWTVerificationError` keeps catching every refusal.
    with pytest.raises(JWTVerificationError):
        await _verifier(fetcher).verify(mint(aud=SURFACE, client_id="client_01NOBODY"))


# --- configuration ----------------------------------------------------------------------


@pytest.mark.parametrize(
    ("kwargs", "error", "message"),
    [
        ({"resource": ""}, ValueError, "resource"),
        ({"resource": [SURFACE]}, TypeError, "resource"),
        ({"resource": None}, TypeError, "resource"),
        ({"expected_clients": {}}, ValueError, "expected_clients"),
        ({"expected_clients": {"": "user"}}, ValueError, "client"),
        ({"expected_clients": {USER_CLIENT: "admin"}}, ValueError, "kind"),
        ({"expected_clients": [USER_CLIENT]}, TypeError, "mapping"),
        ({"expected_clients": USER_CLIENT}, TypeError, "mapping"),
    ],
    ids=[
        "no-resource",
        "resource-list",
        "resource-none",
        "no-clients",
        "empty-client",
        "unknown-kind",
        "list",
        "string",
    ],
)
def test_construction_without_usable_configuration_raises(kwargs, error, message):
    arguments = {"issuer": ISSUER, "resource": SURFACE, "expected_clients": EXPECTED} | kwargs
    with pytest.raises(error, match=message):
        SurfaceTokenVerifier(**arguments)


def test_the_expected_clients_are_readable_but_not_writable(fetcher):
    verifier = _verifier(fetcher)
    assert verifier.expected_clients == EXPECTED
    assert isinstance(verifier.expected_clients, MappingProxyType)
    with pytest.raises(TypeError):
        verifier.expected_clients["client_01INTRUDER"] = "user"
