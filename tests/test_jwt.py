"""FR-2's plain verifier: one case per failure mode, one success case."""

from __future__ import annotations

import time

import httpx
import pytest
from conftest import ISSUER, KID, RESOURCE, FakeFetcher

from wolfworks_mcp_auth import JWTVerificationError, WorkOSJWTVerifier, looks_like_jwt


def _verifier(fetcher: FakeFetcher, audiences=(RESOURCE,)) -> WorkOSJWTVerifier:
    return WorkOSJWTVerifier(issuer=ISSUER, audiences=audiences, fetch_json=fetcher)


async def test_verifies_well_formed_token(mint, fetcher):
    claims = await _verifier(fetcher).verify(mint())
    assert claims["sub"] == "user_01ABC"
    assert claims["aud"] == RESOURCE


async def test_rejects_wrong_audience(mint, fetcher):
    with pytest.raises(JWTVerificationError, match="audience"):
        await _verifier(fetcher).verify(mint(aud="https://other.test/mcp"))


async def test_accepts_array_audience(mint, fetcher):
    claims = await _verifier(fetcher).verify(mint(aud=["https://other.test/mcp", RESOURCE]))
    assert RESOURCE in claims["aud"]


async def test_accepts_any_audience_in_the_allow_list(mint, fetcher):
    verifier = _verifier(fetcher, audiences=("client_web", "client_alexa"))
    assert (await verifier.verify(mint(aud="client_alexa")))["aud"] == "client_alexa"


async def test_rejects_missing_audience(mint, fetcher):
    with pytest.raises(JWTVerificationError):
        await _verifier(fetcher).verify(mint(drop=("aud",)))


async def test_rejects_wrong_issuer(mint, fetcher):
    with pytest.raises(JWTVerificationError, match="issuer"):
        await _verifier(fetcher).verify(mint(iss="https://evil.test"))


async def test_rejects_expired_token(mint, fetcher):
    past = int(time.time()) - 7200
    with pytest.raises(JWTVerificationError, match="expired"):
        await _verifier(fetcher).verify(mint(iat=past, exp=past + 60))


async def test_rejects_token_issued_in_the_future(mint, fetcher):
    future = int(time.time()) + 7200
    with pytest.raises(JWTVerificationError):
        await _verifier(fetcher).verify(mint(iat=future, exp=future + 60))


@pytest.mark.parametrize("claim", ["exp", "iat", "sub"])
async def test_rejects_token_missing_a_required_claim(mint, fetcher, claim):
    with pytest.raises(JWTVerificationError):
        await _verifier(fetcher).verify(mint(drop=(claim,)))


async def test_rejects_signature_from_another_key(mint, fetcher, other_key):
    with pytest.raises(JWTVerificationError, match="signature"):
        await _verifier(fetcher).verify(mint(key=other_key))


async def test_rejects_symmetric_algorithm(fetcher):
    import jwt as pyjwt

    forged = pyjwt.encode(
        {"iss": ISSUER, "aud": RESOURCE, "sub": "x", "iat": 1, "exp": 9999999999},
        "a-shared-secret-that-is-long-enough-for-hs256",
        algorithm="HS256",
        headers={"kid": KID},
    )
    with pytest.raises(JWTVerificationError):
        await _verifier(fetcher).verify(forged)


async def test_rejects_garbage(fetcher):
    with pytest.raises(JWTVerificationError):
        await _verifier(fetcher).verify("not.a.jwt")


async def test_jwks_http_error_raises_verification_error(mint, fetcher):
    fetcher.documents[f"{ISSUER}/oauth2/jwks"] = httpx.ConnectError("down")
    with pytest.raises(JWTVerificationError, match="JWKS unavailable"):
        await _verifier(fetcher).verify(mint())


async def test_jwks_garbage_json_raises_verification_error(mint, fetcher):
    fetcher.documents[f"{ISSUER}/oauth2/jwks"] = {"not": "a key set"}
    with pytest.raises(JWTVerificationError, match="JWKS unavailable"):
        await _verifier(fetcher).verify(mint())


async def test_jwks_is_cached_between_verifications(mint, fetcher):
    verifier = _verifier(fetcher)
    await verifier.verify(mint())
    await verifier.verify(mint())
    assert fetcher.calls.count(f"{ISSUER}/oauth2/jwks") == 1


async def test_unknown_kid_refetches_once_for_key_rotation(mint, fetcher, other_key, make_jwk):
    verifier = _verifier(fetcher)
    await verifier.verify(mint())  # primes the cache with the old key set
    fetcher.documents[f"{ISSUER}/oauth2/jwks"] = {"keys": [make_jwk(other_key, "rotated")]}
    claims = await verifier.verify(mint(key=other_key, kid="rotated"))
    assert claims["sub"] == "user_01ABC"
    assert fetcher.calls.count(f"{ISSUER}/oauth2/jwks") == 2


async def test_unknown_kid_after_refetch_is_rejected(mint, fetcher, other_key):
    with pytest.raises(JWTVerificationError, match="signing key"):
        await _verifier(fetcher).verify(mint(key=other_key, kid="never-published"))


async def test_explicit_jwks_url_skips_discovery(mint, jwks):
    fetcher = FakeFetcher({"https://keys.test/jwks": jwks})
    verifier = WorkOSJWTVerifier(
        issuer=ISSUER, audiences=(RESOURCE,), jwks_url="https://keys.test/jwks", fetch_json=fetcher
    )
    await verifier.verify(mint())
    assert fetcher.calls == ["https://keys.test/jwks"]


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"issuer": "", "audiences": (RESOURCE,)}, "issuer"),
        ({"issuer": ISSUER, "audiences": ()}, "audience"),
        ({"issuer": ISSUER, "audiences": ("",)}, "audience"),
    ],
)
def test_construction_without_required_configuration_raises(kwargs, message):
    with pytest.raises(ValueError, match=message):
        WorkOSJWTVerifier(**kwargs)


def test_looks_like_jwt(mint):
    assert looks_like_jwt(mint())
    assert not looks_like_jwt("0123456789abcdef0123456789abcdef")
    assert not looks_like_jwt("a.b.c")
