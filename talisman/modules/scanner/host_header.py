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
HOST_HEADER_VARIANTS = [CANARY_HOST, "redirect-check.invalid", "host-header.invalid"]
FORWARDED_HOST_HEADERS = ["X-Forwarded-Host", "X-Original-Host"]


def _location_uses_canary(location: str) -> bool:
    try:
        parsed = urlsplit(location)
        return (parsed.hostname or "").lower().rstrip(".") in set(
            HOST_HEADER_VARIANTS
        )
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
            "candidates": [],
            "count": 0,
            "error": "scope_enforcer_required",
        }
    try:
        scope.assert_in_scope(url)
    except ScopeViolationError as exc:
        return {
            "target": url,
            "findings": [],
            "candidates": [],
            "count": 0,
            "error": str(exc),
        }

    console.print(
        f"\\n[module][+] Host Header Trust Assessment[/module] -> [target]{url}[/target]"
    )
    candidates: list[dict[str, Any]] = []
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

        results = await asyncio.gather(*probes, return_exceptions=True)
        for result in results:
            if not isinstance(result, dict):
                continue
            candidates.append({
                **result,
                "confidence": "candidate",
                "requires_sensitive_flow_validation": True,
                "verification_required": (
                    "The redirect target changes when an untrusted Host/forwarded "
                    "header is supplied. This does not prove password-reset "
                    "poisoning or account impact. Validate a real security-sensitive "
                    "absolute-URL flow with a controlled test account and verify "
                    "that the generated link uses the untrusted authority."
                ),
            })

    console.print(
        f"  Host header assessment complete — {len(candidates)} redirect candidates; "
        "no account or password-reset flow was triggered"
    )
    return {
        "target": url,
        "findings": [],
        "candidates": candidates,
        "count": 0,
        "candidate_count": len(candidates),
    }
