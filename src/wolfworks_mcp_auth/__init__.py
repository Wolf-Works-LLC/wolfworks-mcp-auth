"""WorkOS token verification and an identity gate for MCP servers.

The `mcp` SDK owns the protocol. This package owns WorkOS. The application
owns its identity.
"""

from wolfworks_mcp_auth.identity import (
    IDENTITY_REFUSED_CODE,
    IdentityGate,
    IdentityRefused,
    current_identity,
)
from wolfworks_mcp_auth.jwt import JWTVerificationError, WorkOSJWTVerifier, looks_like_jwt
from wolfworks_mcp_auth.verifier import WorkOSTokenVerifier, api_token_access

__all__ = [
    "IDENTITY_REFUSED_CODE",
    "IdentityGate",
    "IdentityRefused",
    "JWTVerificationError",
    "WorkOSJWTVerifier",
    "WorkOSTokenVerifier",
    "api_token_access",
    "current_identity",
    "looks_like_jwt",
]
