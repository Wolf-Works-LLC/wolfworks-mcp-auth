"""Shared fixtures: a locally minted RSA key, its JWKS, and a token factory.

Nothing here touches the network. The verifier takes an injectable JSON
fetcher, so tests hand it documents directly.
"""

from __future__ import annotations

import json
import time
from collections.abc import Callable
from typing import Any

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm

ISSUER = "https://issuer.test"
RESOURCE = "https://server.test/mcp"
KID = "test-key-1"


def _new_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _jwk(key: rsa.RSAPrivateKey, kid: str) -> dict[str, Any]:
    jwk = json.loads(RSAAlgorithm.to_jwk(key.public_key()))
    jwk.update({"kid": kid, "alg": "RS256", "use": "sig"})
    return jwk


@pytest.fixture(scope="session")
def signing_key() -> rsa.RSAPrivateKey:
    return _new_key()


@pytest.fixture(scope="session")
def other_key() -> rsa.RSAPrivateKey:
    return _new_key()


@pytest.fixture
def jwks(signing_key: rsa.RSAPrivateKey) -> dict[str, Any]:
    return {"keys": [_jwk(signing_key, KID)]}


@pytest.fixture
def make_jwk() -> Callable[[rsa.RSAPrivateKey, str], dict[str, Any]]:
    return _jwk


@pytest.fixture
def mint(signing_key: rsa.RSAPrivateKey) -> Callable[..., str]:
    """Return a factory for signed tokens; keyword arguments override claims."""

    def _mint(
        *,
        key: rsa.RSAPrivateKey | None = None,
        kid: str | None = KID,
        algorithm: str = "RS256",
        drop: tuple[str, ...] = (),
        **overrides: Any,
    ) -> str:
        now = int(time.time())
        claims: dict[str, Any] = {
            "iss": ISSUER,
            "aud": RESOURCE,
            "sub": "user_01ABC",
            "iat": now,
            "exp": now + 3600,
            "scope": "openid profile email",
            "client_id": "client_01XYZ",
        }
        claims.update(overrides)
        for name in drop:
            claims.pop(name, None)
        headers = {"kid": kid} if kid else {}
        return jwt.encode(claims, key or signing_key, algorithm=algorithm, headers=headers)

    return _mint


class FakeFetcher:
    """Stands in for the HTTP layer: maps URL -> document, and counts calls."""

    def __init__(self, documents: dict[str, Any]) -> None:
        self.documents = documents
        self.calls: list[str] = []

    async def __call__(self, url: str) -> Any:
        self.calls.append(url)
        value = self.documents[url]
        if isinstance(value, Exception):
            raise value
        return value


@pytest.fixture
def fetcher(jwks: dict[str, Any]) -> FakeFetcher:
    return FakeFetcher(
        {
            f"{ISSUER}/.well-known/openid-configuration": {
                "issuer": ISSUER,
                "jwks_uri": f"{ISSUER}/oauth2/jwks",
            },
            f"{ISSUER}/oauth2/jwks": jwks,
        }
    )
