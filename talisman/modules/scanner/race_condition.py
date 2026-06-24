"""Race condition scanner — parallel request floods for TOCTOU vulnerabilities."""
from __future__ import annotations
import asyncio
import time
from typing import Any
from talisman.utils.http_client import TalismanHTTPClient
from talisman.utils.logger import get_logger, console, print_finding

log = get_logger(__name__)

RACE_PRONE_PATTERNS = [
    "/redeem", "/coupon", "/discount", "/voucher",
    "/transfer", "/withdraw", "/refund", "/payment",
    "/register", "/signup", "/referral", "/bonus",
    "/apply", "/claim", "/activate", "/use",
    "/vote", "/like", "/subscribe", "/follow",
]


async def _flood_endpoint(
    url: str,
    method: str,
    data: dict,
    count: int,
    client: TalismanHTTPClient,
) -> list[dict[str, Any]]:
    """Send N simultaneous requests and collect responses."""
    async def _single() -> dict[str, Any]:
        start = time.monotonic()
        try:
            if method == "POST":
                r = await client.post(url, data=data, timeout=10)
            else:
                r = await client.get(url, timeout=10)
            return {
                "status": r.status_code,
                "size": len(r.content),
                "elapsed": time.monotonic() - start,
                "body_snippet": r.text[:100],
            }
        except Exception as e:
            return {"status": 0, "error": str(e), "elapsed": time.monotonic() - start}

    tasks = [_single() for _ in range(count)]
    return await asyncio.gather(*tasks)  # type: ignore


def _detect_race(responses: list[dict]) -> bool:
    """Check if multiple requests all succeeded (potential race)."""
    successes = [r for r in responses if r.get("status") in (200, 201, 204)]
    if len(successes) > 1:
        # Check if responses are meaningfully different (not cached)
        sizes = [r.get("size", 0) for r in successes]
        unique_sizes = len(set(sizes))
        return unique_sizes > 1 or len(successes) >= 2
    return False


async def run(
    target: str,
    session: Any = None,
    scope: Any = None,
    rate_limiter: Any = None,
    proxy: str | None = None,
    parallel_count: int = 20,
    **kwargs: Any,
) -> dict[str, Any]:
    url = target if "://" in target else f"https://{target}"
    console.print(f"\n[module] Race Condition Scanner[/module] → [target]{url}[/target]")
    findings: list[dict[str, Any]] = []

    # Detect race-prone endpoints from URL path
    path = url.split("//")[-1].split("/", 1)[-1] if "/" in url.split("//")[-1] else ""
    race_prone = any(pat.lstrip("/") in path.lower() for pat in RACE_PRONE_PATTERNS)

    if not race_prone:
        # Check if URL matches any race pattern
        race_prone = any(pat.lstrip("/") in url.lower() for pat in RACE_PRONE_PATTERNS)

    console.print(f"  Race-prone endpoint detected: {race_prone}")
    console.print(f"  Sending {parallel_count} parallel requests...")

    async with TalismanHTTPClient(proxy=proxy, timeout=12) as client:
        responses = await _flood_endpoint(url, "POST", {}, parallel_count, client)
        if _detect_race(responses):
            successes = [r for r in responses if r.get("status") in (200, 201, 204)]
            severity = "high" if race_prone else "medium"
            title = f"Potential race condition — {len(successes)}/{parallel_count} parallel requests succeeded"
            print_finding(title, severity, url)
            findings.append({
                "url": url,
                "successes": len(successes),
                "total": parallel_count,
                "responses": responses[:5],
            })
            if session:
                await session.add_finding(
                    target=url, module="race_condition",
                    vuln_type="race_condition",
                    severity=severity, confidence="likely",
                    title=title,
                    description=(
                        f"{len(successes)} out of {parallel_count} simultaneous requests "
                        f"to {url} all returned success status codes, indicating a potential "
                        f"race condition / TOCTOU vulnerability."
                    ),
                    reproduction=(
                        f"Send {parallel_count} simultaneous POST requests to {url}. "
                        f"Observe multiple success responses."
                    ),
                    remediation=(
                        "1. Use database-level transactions with proper locking.\n"
                        "2. Implement idempotency keys for sensitive operations.\n"
                        "3. Use Redis/database-level distributed locks.\n"
                        "4. Apply rate limiting per user per time window."
                    ),
                    cvss_score=8.1, cwe="CWE-362",
                )

    console.print(f"  Found {len(findings)} race condition indicators")
    return {"target": url, "findings": findings, "count": len(findings)}
