"""Walk an MCP server's authorization discovery chain the way a client does.

    python -m wolfworks_mcp_auth.conformance https://example.com/mcp

Three hops: the unauthenticated challenge, the protected resource metadata it
points at, and the authorization server metadata that names. Exit status is 0
only when every hop answers as the MCP authorization specification requires.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import re
from dataclasses import dataclass, field
from urllib.parse import urlsplit

import httpx

_INITIALIZE = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {
        "protocolVersion": "2025-06-18",
        "capabilities": {},
        "clientInfo": {"name": "wolfworks-mcp-auth-conformance", "version": "0"},
    },
}
_HEADERS = {"Accept": "application/json, text/event-stream", "Content-Type": "application/json"}
_RESOURCE_METADATA = re.compile(r'resource_metadata="([^"]+)"')


@dataclass
class ProbeReport:
    hops: list[tuple[str, int]] = field(default_factory=list)
    failures: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.failures

    def to_json(self) -> str:
        return json.dumps({"ok": self.ok, "hops": self.hops, "failures": self.failures})


def _authorization_server_metadata_urls(issuer: str) -> list[str]:
    """RFC 8414 first, then OpenID Connect discovery; clients try both."""
    parts = urlsplit(issuer.rstrip("/"))
    origin = f"{parts.scheme}://{parts.netloc}"
    return [
        f"{origin}/.well-known/oauth-authorization-server{parts.path}",
        f"{origin}{parts.path}/.well-known/openid-configuration",
    ]


async def probe(url: str, *, client: httpx.AsyncClient | None = None) -> ProbeReport:
    report = ProbeReport()
    if client is None:
        async with httpx.AsyncClient(timeout=10, follow_redirects=False) as owned:
            await _walk(url, owned, report)
    else:
        await _walk(url, client, report)
    return report


async def _walk(url: str, client: httpx.AsyncClient, report: ProbeReport) -> None:
    challenge = await client.post(url, headers=_HEADERS, json=_INITIALIZE, follow_redirects=False)
    report.hops.append((url, challenge.status_code))
    if challenge.status_code != 401:
        # A redirect here is the common failure: clients drop Authorization across it.
        report.failures.append(
            f"challenge hop returned {challenge.status_code}, expected 401 directly"
        )
        return
    header = challenge.headers.get("WWW-Authenticate", "")
    if "offline_access" in header:
        report.failures.append("challenge advertises offline_access")
    match = _RESOURCE_METADATA.search(header)
    if not header.lower().startswith("bearer") or not match:
        report.failures.append("challenge carries no WWW-Authenticate Bearer resource_metadata")
        return

    metadata_url = match.group(1)
    metadata = await client.get(metadata_url, follow_redirects=False)
    report.hops.append((metadata_url, metadata.status_code))
    if metadata.status_code != 200:
        report.failures.append(
            f"protected resource metadata {metadata_url} returned {metadata.status_code}"
        )
        return
    document = metadata.json()
    if "offline_access" in document.get("scopes_supported", []):
        report.failures.append("protected resource metadata advertises offline_access")
    servers = document.get("authorization_servers") or []
    if not servers:
        report.failures.append("protected resource metadata names no authorization server")
        return

    issuer = servers[0]
    for candidate in _authorization_server_metadata_urls(issuer):
        response = await client.get(candidate, follow_redirects=False)
        if response.status_code == 200:
            report.hops.append((candidate, 200))
            return
    report.hops.append((candidate, response.status_code))
    report.failures.append(f"authorization server {issuer} serves no metadata document")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m wolfworks_mcp_auth.conformance")
    parser.add_argument("url", help="the MCP endpoint, e.g. https://example.com/mcp")
    parser.add_argument("--json", action="store_true", help="print the report as JSON")
    args = parser.parse_args(argv)

    report = asyncio.run(probe(args.url))
    if args.json:
        print(report.to_json())
    else:
        for hop, status in report.hops:
            print(f"  {status}  {hop}")
        for failure in report.failures:
            print(f"FAIL  {failure}")
        print("PASS" if report.ok else "FAIL", args.url)
    return 0 if report.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
