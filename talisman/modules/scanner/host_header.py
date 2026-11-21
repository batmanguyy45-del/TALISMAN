"""Host-header trust checks with strict redirect-host verification.

Reflection of a supplied header value is not itself a vulnerability. This
scanner reports only redirects that actually select an external hostname.
Password-reset poisoning requires a real transaction and two-account validation,
so it is deliberately not attempted by this passive scanner.
"""
from __future__ import annotations

import asyncio
from typing import Any
from urllib.parse import urlsplit

from talisman.engine.scope import ScopeViolationError
from talisman.utils.http_client import TalismanHTTPClient
from talisman.utils.logger import get_logger, console, print_finding

log = get_logger(__name__)

CANARY_HOST = "talisman.invalid"
HOST_HEADER_VARIANTS = [CANARY_HOST, "redirect-check.invalid"]
FORWARDED_HOST_HEADERS = ["X-Forwarded-Host", "X-Original-Host"]


def _location_uses_canary(location: str) -> bool:
    try:
        parsed = urlsplit(location)
        return (parsed.hostname or "").lower().rstrip(".") in {
            CANARY_HOST,
            "redirect-check.invalid",
        }
    except ValueError:
        return False


async def _probe_header(
    url: str,
    client: TalismanHTTPClient,
    header_name: str,
    value: str,
) -> dict[str, Any] | None:
    try:
        response = await client.get(
            url,
            headers={header_name: value},
            allow_redirects=False,
            timeout=8,
        )
    except Exception as exc:
        log.debug("host_header_probe", header=header_name, error=type(exc).__name__)
        return None

    location = response.headers.get("location", "")
    if not location:
        return None

    # Resolve relative Location values against the requested URL; only report
    # when the actual parsed authority is the reserved test hostname.
    from urllib.parse import urljoin

    destination = urljoin(str(response.url), location)
    if not _location_uses_canary(destination):
        return None

    return {
        "header": header_name,
        "value": value,
        "status": response.status_code,
        "location": location,
        "destination": destination,
        "evidence": f"HTTP {response.status_code} Location: {location}",
    }


async def run(
    target: str,
    session: Any = None,
    scope: Any = None,
    rate_limiter: Any = None,
    proxy: str | None = None,
    **kwargs: Any,
) -> dict[str, Any]:
    url = target if "://" in target else f"https://{target}"
    if scope is None:
        return {
            "target": url,
            "findings": [],
            "count": 0,
            "error": "scope_enforcer_required",
        }
    try:
        scope.assert_in_scope(url)
    except ScopeViolationError as exc:
        return {"target": url, "findings": [], "count": 0, "error": str(exc)}

    console.print(
        f"\n[module][+] Host Header Trust Check[/module] -> [target]{url}[/target]"
    )
    findings: list[dict[str, Any]] = []

    async with TalismanHTTPClient(
        proxy=proxy,
        timeout=10,
        verify_ssl=True,
        follow_redirects=False,
        scope=scope,
    ) as client:
        probes = []
        for host_value in HOST_HEADER_VARIANTS:
            probes.append(_probe_header(url, client, "Host", host_value))
            for header_name in FORWARDED_HOST_HEADERS:
                probes.append(_probe_header(url, client, header_name, host_value))

        # Bounded concurrency keeps this a small, predictable passive check.
        results = await asyncio.gather(*probes, return_exceptions=True)
        for result in results:
            if not isinstance(result, dict):
                continue
            findings.append(result)
            title = (
                f"Host-derived external redirect via {result['header']} "
                f"({result['value']})"
            )
            print_finding(title, "medium", url)
            if session:
                await session.add_finding(
                    target=url,
                    module="host_header",
                    vuln_type="host_header_external_redirect",
                    severity="medium",
                    confidence="confirmed",
                    title=title,
                    description=(
                        f"The server returned a redirect whose parsed destination "
                        f"uses the supplied host canary after setting "
                        f"{result['header']}. Header reflection alone is not "
                        f"considered a finding."
                    ),
                    evidence=result["evidence"],
                    reproduction=(
                        f"Send GET {url} with {result['header']}: {result['value']} "
                        f"and inspect the Location response header."
                    ),
                    remediation=(
                        "Validate the Host header against an explicit server-name "
                        "allowlist. Trust forwarding headers only from configured "
                        "reverse proxies and construct canonical URLs from trusted configuration."
                    ),
                    cwe="CWE-644",
                )

    console.print(f"  Host header check complete — {len(findings)} verified redirects")
    return {"target": url, "findings": findings, "count": len(findings)}
