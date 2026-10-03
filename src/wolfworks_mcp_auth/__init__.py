"""WorkOS token verification and an identity gate for MCP servers, and a
resource-and-client check for every surface that is not MCP.

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
from wolfworks_mcp_auth.surface import (
    PrincipalKind,
    RefusalReason,
    SurfaceToken,
    SurfaceTokenRefused,
    SurfaceTokenVerifier,
)
from wolfworks_mcp_auth.sync import SyncBridge, run_sync
from wolfworks_mcp_auth.verifier import WorkOSTokenVerifier, api_token_access

__all__ = [
    "IDENTITY_REFUSED_CODE",
    "IdentityGate",
    "IdentityRefused",
    "JWTVerificationError",
    "PrincipalKind",
    "RefusalReason",
    "SurfaceToken",
    "SurfaceTokenRefused",
    "SurfaceTokenVerifier",
    "SyncBridge",
    "WorkOSJWTVerifier",
    "WorkOSTokenVerifier",
    "api_token_access",
    "current_identity",
    "looks_like_jwt",
    "run_sync",
]
