"""Open redirect scanner with scoped requests and final-destination verification."""
from __future__ import annotations

import asyncio
import urllib.parse
from typing import Any

from talisman.engine.scope import ScopeViolationError
from talisman.utils.http_client import TalismanHTTPClient
from talisman.utils.logger import get_logger, console, print_finding

log = get_logger(__name__)

# Reserved .invalid names avoid depending on or sending traffic to real third parties.
ATTACKER_DOMAIN = "talisman.invalid"
ATTACKER_DOMAIN_2 = "redirect-check.invalid"
ATTACKER_HOSTNAMES = {ATTACKER_DOMAIN, ATTACKER_DOMAIN_2}

REDIRECT_PAYLOADS: list[tuple[str, str]] = [
    (f"https://{ATTACKER_DOMAIN}/", "absolute HTTPS"),
    (f"http://{ATTACKER_DOMAIN}/", "absolute HTTP"),
    (f"//{ATTACKER_DOMAIN}/", "protocol-relative"),
    (f"%2F%2F{ATTACKER_DOMAIN}%2F", "URL-encoded protocol-relative"),
    (f"////{ATTACKER_DOMAIN}/", "multiple leading slashes"),
    (f"/%2F%2F{ATTACKER_DOMAIN}/", "encoded slash sequence"),
]

REDIRECT_PARAMS = [
    "redirect", "redirect_uri", "redirect_url", "return", "return_to",
    "next", "url", "goto", "dest", "destination", "continue", "callback",
]


def _is_attacker_destination(value: str) -> bool:
    try:
        parsed = urllib.parse.urlsplit(value)
        host = (parsed.hostname or "").lower().rstrip(".")
        return host in ATTACKER_HOSTNAMES or any(
            host.endswith("." + domain) for domain in ATTACKER_HOSTNAMES
        )
    except ValueError:
        return False


def _first_hop_is_attacker(location: str) -> bool:
    """Recognize an external Location by parsed hostname, not substring/prefix."""
    decoded = urllib.parse.unquote(location.strip())
    if not decoded or "\r" in decoded or "\n" in decoded or "\\" in decoded:
        return False
    candidate = decoded
    if candidate.startswith("//"):
        candidate = "https:" + candidate
    elif not urllib.parse.urlsplit(candidate).scheme:
        if candidate.startswith("/"):
            return False
        candidate = "https://" + candidate
    return _is_attacker_destination(candidate)


async def _follow_redirect_chain(
    client: TalismanHTTPClient,
    start_url: str,
    max_hops: int = 5,
) -> tuple[str, list[str]]:
    """Follow only in-scope hops; external destinations are inspected, never contacted."""
    current_url = start_url
    locations: list[str] = []

    for _ in range(max_hops):
        if _is_attacker_destination(current_url):
            return current_url, locations
        try:
            response = await client.get(
                current_url,
                allow_redirects=False,
                timeout=8,
            )
        except Exception as exc:
            log.debug("open_redirect_chain", error=type(exc).__name__)
            break

        if response.status_code not in {301, 302, 303, 307, 308}:
            break
        location = response.headers.get("location", "")
        if not location:
            break
        locations.append(location)
        current_url = urllib.parse.urljoin(str(response.url), location)
        if _is_attacker_destination(current_url):
            break

    return current_url, locations


async def _test_param(
    url: str,
    param: str,
    client: TalismanHTTPClient,
) -> dict[str, Any] | None:
    parsed = urllib.parse.urlsplit(url)
    base_params = dict(urllib.parse.parse_qsl(parsed.query, keep_blank_values=True))

    for payload, description in REDIRECT_PAYLOADS:
        test_params = {**base_params, param: payload}
        test_url = parsed._replace(
            query=urllib.parse.urlencode(test_params)
        ).geturl()

        try:
            first_response = await client.get(
                test_url,
                allow_redirects=False,
                timeout=8,
            )
            if first_response.status_code not in {301, 302, 303, 307, 308}:
                continue

            first_location = first_response.headers.get("location", "")
            if not first_location:
                continue

            if _first_hop_is_attacker(first_location):
                return {
                    "param": param,
                    "payload": payload,
                    "description": description,
                    "first_location": first_location,
                    "final_url": urllib.parse.urljoin(test_url, first_location),
                    "confidence": "confirmed",
                    "request": f"GET {test_url} HTTP/1.1",
                    "evidence": f"HTTP {first_response.status_code} Location: {first_location}",
                }

            next_url = urllib.parse.urljoin(str(first_response.url), first_location)
            final_url, chain = await _follow_redirect_chain(client, next_url, max_hops=5)
            if _is_attacker_destination(final_url):
                return {
                    "param": param,
                    "payload": payload,
                    "description": description,
                    "first_location": first_location,
                    "final_url": final_url,
                    "redirect_chain": chain,
                    "confidence": "confirmed",
                    "request": f"GET {test_url} HTTP/1.1",
                    "evidence": (
                        f"Final destination: {final_url}\n"
                        f"Redirect chain: {' -> '.join(chain[:5])}"
                    ),
                }
        except Exception as exc:
            log.debug("open_redirect_test", param=param, error=type(exc).__name__)

    return None


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
        return {"target": url, "findings": [], "count": 0, "error": "scope_enforcer_required"}
    try:
        scope.assert_in_scope(url)
    except ScopeViolationError as exc:
        return {"target": url, "findings": [], "count": 0, "error": str(exc)}

    console.print(f"\n[module][+] Open Redirect Scanner[/module] -> [target]{url}[/target]")
    parsed = urllib.parse.urlsplit(url)
    existing_params = list(dict.fromkeys(
        key for key, _ in urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    ))
    params_to_test = list(dict.fromkeys(existing_params + REDIRECT_PARAMS))[:16]
    findings: list[dict[str, Any]] = []

    async with TalismanHTTPClient(
        proxy=proxy,
        timeout=12,
        verify_ssl=True,
        follow_redirects=False,
        scope=scope,
    ) as client:
        tasks = [_test_param(url, param, client) for param in params_to_test]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        seen_params: set[str] = set()
        for result in results:
            if not isinstance(result, dict) or result["param"] in seen_params:
                continue
            seen_params.add(result["param"])

            title = f"Open redirect through '{result['param']}' parameter"
            severity = "medium"
            print_finding(title, severity, url)
            findings.append(result)

            if session:
                await session.add_finding(
                    target=url,
                    module="open_redirect",
                    vuln_type="open_redirect",
                    severity=severity,
                    confidence=result.get("confidence", "likely"),
                    title=title,
                    description=(
                        f"The server returned a redirect to an external attacker-controlled test hostname "
                        f"through parameter '{result['param']}'."
                    ),
                    request=result["request"],
                    evidence=result["evidence"],
                    reproduction=(
                        f"Send a GET request to {url} with "
                        f"{result['param']}={urllib.parse.quote(result['payload'])}; inspect the Location header."
                    ),
                    remediation=(
                        "Validate redirect targets against an allowlist of trusted destinations. "
                        "Prefer relative paths for internal redirects."
                    ),
                    cvss_score=6.1,
                    cwe="CWE-601",
                )

    console.print(f" Found {len(findings)} verified open redirect candidates")
    return {"target": url, "findings": findings, "count": len(findings)}
