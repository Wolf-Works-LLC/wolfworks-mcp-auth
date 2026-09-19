"""FR-2's plain verifier: one case per failure mode, one success case."""

from __future__ import annotations

import asyncio
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
    # `match` matters: with HS256 allowed the token still fails, on the key's type.
    with pytest.raises(JWTVerificationError, match="alg value is not allowed"):
        await _verifier(fetcher).verify(forged)


@pytest.mark.parametrize("algorithm", ["RS384", "RS512", "PS256"])
async def test_rejects_other_rsa_algorithms(mint, fetcher, algorithm):
    with pytest.raises(JWTVerificationError, match="alg value is not allowed"):
        await _verifier(fetcher).verify(mint(algorithm=algorithm))


async def test_rejects_garbage(fetcher):
    with pytest.raises(JWTVerificationError):
        await _verifier(fetcher).verify("not.a.jwt")


async def test_jwks_http_error_raises_verification_error(mint, fetcher):
    fetcher.documents[f"{ISSUER}/oauth2/jwks"] = httpx.ConnectError("down")
    with pytest.raises(JWTVerificationError, match="JWKS unavailable"):
        await _verifier(fetcher).verify(mint())


@pytest.mark.parametrize(
    "document",
    [{"not": "a key set"}, [], None, "an error page", {"keys": [1]}],
    ids=["no-keys", "list", "null", "string", "key-is-not-an-object"],
)
async def test_jwks_garbage_json_raises_verification_error(mint, fetcher, document):
    fetcher.documents[f"{ISSUER}/oauth2/jwks"] = document
    with pytest.raises(JWTVerificationError, match="JWKS unavailable"):
        await _verifier(fetcher).verify(mint())


async def test_jwks_key_with_an_unhashable_kid_raises_verification_error(
    mint, fetcher, signing_key, make_jwk
):
    fetcher.documents[f"{ISSUER}/oauth2/jwks"] = {
        "keys": [make_jwk(signing_key, ["not", "a", "str"])]
    }
    with pytest.raises(JWTVerificationError, match="JWKS unavailable"):
        await _verifier(fetcher).verify(mint())


@pytest.mark.parametrize("exp", [[1], {"a": 1}, float("inf")], ids=["list", "object", "infinity"])
async def test_signed_token_with_an_unusable_exp_raises_verification_error(mint, fetcher, exp):
    # The SDK turns anything else a verifier raises into a 500.
    with pytest.raises(JWTVerificationError):
        await _verifier(fetcher).verify(mint(exp=exp))


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


async def test_unknown_kids_buy_one_refetch_not_one_each(mint, fetcher, other_key):
    # Anyone can send an unknown key id, so it must not cost an outbound request every time.
    verifier = _verifier(fetcher)
    await verifier.verify(mint())  # primes the cache
    for n in range(5):
        with pytest.raises(JWTVerificationError, match="signing key"):
            await verifier.verify(mint(key=other_key, kid=f"bogus-{n}"))
    assert fetcher.calls.count(f"{ISSUER}/oauth2/jwks") == 2  # the priming fetch, one refetch


async def test_concurrent_unknown_kids_share_one_refetch(mint, fetcher, other_key):
    verifier = _verifier(fetcher)
    await verifier.verify(mint())
    bogus = [verifier.verify(mint(key=other_key, kid=f"bogus-{n}")) for n in range(20)]
    results = await asyncio.gather(*bogus, return_exceptions=True)
    assert all(isinstance(result, JWTVerificationError) for result in results)
    assert fetcher.calls.count(f"{ISSUER}/oauth2/jwks") == 2


async def test_refetch_is_allowed_again_once_the_cooldown_has_passed(
    mint, fetcher, other_key, make_jwk, monkeypatch
):
    verifier = _verifier(fetcher)
    await verifier.verify(mint())
    with pytest.raises(JWTVerificationError, match="signing key"):
        await verifier.verify(mint(key=other_key, kid="bogus"))  # spends the refetch
    fetcher.documents[f"{ISSUER}/oauth2/jwks"] = {"keys": [make_jwk(other_key, "rotated")]}
    with pytest.raises(JWTVerificationError, match="signing key"):
        await verifier.verify(mint(key=other_key, kid="rotated"))  # still cooling down
    monkeypatch.setattr("wolfworks_mcp_auth.jwt._REFETCH_COOLDOWN_SECONDS", 0)
    assert (await verifier.verify(mint(key=other_key, kid="rotated")))["sub"] == "user_01ABC"


async def test_cached_key_verifies_while_a_refetch_is_in_flight(mint, jwks, other_key):
    jwks_url = "https://keys.test/jwks"
    release = asyncio.Event()

    class StallsAfterTheFirstFetch(FakeFetcher):
        async def __call__(self, url: str):
            if self.calls:
                self.calls.append(url)
                await release.wait()
            return await super().__call__(url)

    fetcher = StallsAfterTheFirstFetch({jwks_url: jwks})
    verifier = WorkOSJWTVerifier(
        issuer=ISSUER, audiences=(RESOURCE,), jwks_url=jwks_url, fetch_json=fetcher
    )
    await verifier.verify(mint())
    stalled = asyncio.create_task(verifier.verify(mint(key=other_key, kid="bogus")))
    await asyncio.sleep(0)  # let it reach the fetch and hold the lock
    try:
        claims = await asyncio.wait_for(verifier.verify(mint()), timeout=1)
    finally:
        release.set()
    assert claims["sub"] == "user_01ABC"
    with pytest.raises(JWTVerificationError, match="signing key"):
        await stalled


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


def test_a_bare_string_is_not_an_audience_list():
    # `list("client_01ABC")` is an allow-list of single characters, and it type-checks.
    with pytest.raises(TypeError, match="audiences"):
        WorkOSJWTVerifier(issuer=ISSUER, audiences="client_01ABC")


def test_looks_like_jwt(mint):
    assert looks_like_jwt(mint())
    assert not looks_like_jwt("0123456789abcdef0123456789abcdef")
    assert not looks_like_jwt("a.b.c")
