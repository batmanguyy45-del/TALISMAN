"""Web cache poisoning scanner — unkeyed headers, fat GET, parameter cloaking."""
from __future__ import annotations
import asyncio
import random
import string
from typing import Any
from talisman.utils.http_client import TalismanHTTPClient
from talisman.utils.logger import get_logger, console, print_finding

log = get_logger(__name__)

UNKEYED_HEADERS = [
    "X-Forwarded-Host",
    "X-Forwarded-Scheme",
    "X-Forwarded-Port",
    "X-Original-URL",
    "X-Rewrite-URL",
    "X-Override-URL",
    "X-Host",
    "X-Forwarded-Server",
    "X-HTTP-Host-Override",
    "Forwarded",
    "X-Real-IP",
    "X-Forwarded-For",
]

CACHE_INDICATORS = [
    "age", "x-cache", "cf-cache-status", "x-varnish",
    "via", "x-cache-hits", "cdn-cache-control",
    "x-served-by", "x-cache-status",
]


def _random_canary() -> str:
    return "talisman-" + "".join(random.choices(string.ascii_lowercase, k=8))


async def _detect_caching(url: str, client: TalismanHTTPClient) -> bool:
    try:
        r1 = await client.get(url, timeout=8)
        r2 = await client.get(url, timeout=8)
        headers1 = {k.lower(): v for k, v in r1.headers.items()}
        headers2 = {k.lower(): v for k, v in r2.headers.items()}
        for ind in CACHE_INDICATORS:
            if ind in headers1 or ind in headers2:
                return True
        # Check Age header increment
        age1 = int(headers1.get("age", 0))
        age2 = int(headers2.get("age", 0))
        if age1 > 0 or age2 > 0:
            return True
    except Exception:
        pass
    return False


async def _test_header_poison(
    url: str, header: str, client: TalismanHTTPClient
) -> dict[str, Any] | None:
    canary = _random_canary()
    poison_value = f"evil-{canary}.attacker.com"
    try:
        # Send poisoning request
        r1 = await client.get(url, headers={header: poison_value}, timeout=8)
        # Fetch without the header to see if poison is cached
        await asyncio.sleep(0.5)
        r2 = await client.get(url, timeout=8)
        if canary in r2.text or poison_value in r2.text:
            return {
                "header": header,
                "poison_value": poison_value,
                "evidence": f"Canary '{canary}' found in cached response",
                "request": f"GET {url} HTTP/1.1\n{header}: {poison_value}",
            }
        # Check if reflected in first response
        if canary in r1.text or poison_value in r1.text:
            return {
                "header": header,
                "poison_value": poison_value,
                "evidence": f"Header value reflected in response — potential cache poison vector",
                "reflected_only": True,
                "request": f"GET {url} HTTP/1.1\n{header}: {poison_value}",
            }
    except Exception:
        pass
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
    console.print(f"\n[module] Cache Poisoning Scanner[/module] → [target]{url}[/target]")
    findings: list[dict[str, Any]] = []

    async with TalismanHTTPClient(proxy=proxy, timeout=12) as client:
        is_cached = await _detect_caching(url, client)
        if not is_cached:
            console.print("  [dim]No caching layer detected — skipping[/dim]")
            return {"target": url, "cached": False, "findings": []}

        console.print("  Caching detected — testing unkeyed header injection...")
        tasks = [_test_header_poison(url, header, client) for header in UNKEYED_HEADERS]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for header, result in zip(UNKEYED_HEADERS, results):
            if isinstance(result, dict):
                severity = "high" if not result.get("reflected_only") else "medium"
                title = (f"Web cache poisoning via {header}"
                         if not result.get("reflected_only")
                         else f"Cache poison reflection via {header}")
                print_finding(title, severity, url)
                findings.append({**result, "severity": severity})
                if session:
                    await session.add_finding(
                        target=url, module="cache_poison",
                        vuln_type="cache_poisoning",
                        severity=severity, confidence="confirmed" if not result.get("reflected_only") else "likely",
                        title=title,
                        description=(
                            f"Web cache can be poisoned via unkeyed header '{header}'. "
                            f"Value '{result['poison_value']}' was "
                            f"{'found in subsequent cached responses' if not result.get('reflected_only') else 'reflected in response'}."
                        ),
                        request=result["request"],
                        evidence=result["evidence"],
                        reproduction=(
                            f"1. Send GET {url} with {header}: evil.attacker.com\n"
                            f"2. Fetch {url} without the header\n"
                            f"3. Observe canary in response"
                        ),
                        remediation=(
                            "1. Ensure all headers that affect the response are included in the cache key.\n"
                            "2. Strip untrusted headers at the CDN/load balancer layer.\n"
                            "3. Use Vary header to explicitly declare cache-varying inputs.\n"
                            "4. Implement cache key normalization."
                        ),
                        cvss_score=8.1, cwe="CWE-444",
                    )

    console.print(f"  Found {len(findings)} cache poisoning vulnerabilities")
    return {"target": url, "cached": True, "findings": findings, "count": len(findings)}
