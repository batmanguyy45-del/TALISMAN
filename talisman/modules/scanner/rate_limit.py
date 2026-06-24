"""Rate limit tester -- detects missing or weak rate limiting on auth, OTP, and API endpoints."""
from __future__ import annotations
import asyncio
import random
import string
from typing import Any
from talisman.utils.http_client import TalismanHTTPClient
from talisman.utils.logger import get_logger, console, print_finding

log = get_logger(__name__)

AUTH_ENDPOINTS = [
    "/login", "/api/login", "/auth", "/api/auth",
    "/signin", "/api/signin", "/authenticate",
]

OTP_ENDPOINTS = [
    "/verify-otp", "/verify", "/api/verify",
    "/otp", "/api/otp", "/2fa", "/mfa",
]

PASSWORD_RESET_ENDPOINTS = [
    "/forgot-password", "/api/forgot-password",
    "/reset-password", "/api/reset-password",
    "/forgot", "/api/forgot",
]

RAPID_REQUEST_COUNT = 20
CONCURRENT_BURST_COUNT = 10


async def _test_single_endpoint(
    url: str,
    endpoint: str,
    method: str,
    client: TalismanHTTPClient,
    payload_template: dict[str, Any],
    burst_count: int = RAPID_REQUEST_COUNT,
) -> dict[str, Any]:
    """Send rapid requests to an endpoint and analyze rate limiting behavior."""
    test_url = url.rstrip("/") + endpoint
    statuses: list[int] = []
    response_times: list[float] = []

    for i in range(burst_count):
        payload = {
            k: (v + str(i) if isinstance(v, str) and "{i}" in v else v)
            for k, v in payload_template.items()
        }
        # Replace {i} with the actual index
        payload = {
            k: v.replace("{i}", str(i)) if isinstance(v, str) else v
            for k, v in payload.items()
        }
        try:
            start = asyncio.get_event_loop().time()
            if method.upper() == "POST":
                r = await client.post(test_url, json=payload, timeout=8)
            else:
                r = await client.get(test_url, params=payload, timeout=8)
            elapsed = asyncio.get_event_loop().time() - start
            statuses.append(r.status_code)
            response_times.append(elapsed)
        except Exception:
            statuses.append(0)
            response_times.append(0)

    unique_statuses = set(statuses)
    has_429 = 429 in unique_statuses
    has_200 = 200 in unique_statuses

    # Analyze rate limiting effectiveness
    result: dict[str, Any] = {
        "endpoint": test_url,
        "requests": burst_count,
        "statuses": statuses,
        "unique_statuses": sorted(unique_statuses),
        "has_rate_limiting": has_429,
        "all_successful": all(s == 200 for s in statuses if s != 0),
        "avg_response_time": sum(response_times) / max(len(response_times), 1),
    }

    return result


async def _test_concurrent_burst(
    url: str,
    endpoint: str,
    method: str,
    client: TalismanHTTPClient,
    payload_template: dict[str, Any],
    concurrency: int = CONCURRENT_BURST_COUNT,
) -> dict[str, Any]:
    """Send concurrent requests to test rate limiting under parallel load."""
    test_url = url.rstrip("/") + endpoint

    async def _send_one(idx: int) -> int:
        payload = {
            k: v.replace("{i}", str(idx)) if isinstance(v, str) else v
            for k, v in payload_template.items()
        }
        try:
            if method.upper() == "POST":
                r = await client.post(test_url, json=payload, timeout=10)
            else:
                r = await client.get(test_url, params=payload, timeout=10)
            return r.status_code
        except Exception:
            return 0

    results = await asyncio.gather(*[_send_one(i) for i in range(concurrency)])
    unique = set(results)
    has_429 = 429 in unique
    has_200 = 200 in unique
    rate_limited_count = sum(1 for s in results if s in (429, 429))

    return {
        "endpoint": test_url,
        "concurrent_requests": concurrency,
        "statuses": results,
        "unique_statuses": sorted(unique),
        "has_rate_limiting": has_429,
        "some_successful": has_200,
        "rate_limited_count": rate_limited_count,
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
    console.print(f"\n[module][+] Rate Limit Tester[/module] -> [target]{url}[/target]")
    findings: list[dict[str, Any]] = []

    username = f"test_{''.join(random.choices(string.ascii_lowercase, k=6))}_rl"
    password = "wrongpass123!"

    async with TalismanHTTPClient(proxy=proxy, timeout=10) as client:
        # -- 1. Auth endpoint rapid requests -----------------------------------------
        console.print("  Testing auth endpoints...")
        for auth_path in AUTH_ENDPOINTS:
            result = await _test_single_endpoint(
                url, auth_path, "POST", client,
                {"username": username, "password": password},
                burst_count=RAPID_REQUEST_COUNT,
            )
            if not result["has_rate_limiting"] and result["all_successful"]:
                print_finding(f"No rate limiting on {auth_path} -- all {RAPID_REQUEST_COUNT} requests accepted", "high", url)
                findings.append({"issue": "no_rate_limit_auth", "endpoint": auth_path, **result})
                if session:
                    await session.add_finding(
                        target=url, module="rate_limit",
                        vuln_type="no_rate_limit_auth",
                        severity="high", confidence="confirmed",
                        title=f"No rate limiting on auth endpoint {auth_path}",
                        description=f"Sent {RAPID_REQUEST_COUNT} rapid login requests to {auth_path} and all were accepted. No rate limiting detected. Attackers can brute-force credentials without restriction.",
                        evidence=f"Statuses: {result['unique_statuses']}",
                        reproduction=f"Rapid {RAPID_REQUEST_COUNT} requests to {auth_path} -- no rate limit triggered.",
                        remediation="1. Implement rate limiting on authentication endpoints. 2. Use account lockout after N failed attempts. 3. Consider CAPTCHA after threshold.",
                        cvss_score=7.5, cwe="CWE-307",
                    )
            elif not result["has_rate_limiting"]:
                # Mixed results - some succeeded, indicating rate limiting is incomplete
                print_finding(f"Weak rate limiting on {auth_path} -- some requests still accepted", "medium", url)
                findings.append({"issue": "weak_rate_limit_auth", "endpoint": auth_path, **result})

        # -- 2. Concurrent burst test -------------------------------------------------
        console.print("  Testing concurrent burst resilience...")
        for auth_path in AUTH_ENDPOINTS[:2]:
            burst_result = await _test_concurrent_burst(
                url, auth_path, "POST", client,
                {"username": username, "password": password},
                concurrency=CONCURRENT_BURST_COUNT,
            )
            if not burst_result["has_rate_limiting"] and burst_result["some_successful"]:
                print_finding(f"Concurrent rate limit bypass on {auth_path} -- {CONCURRENT_BURST_COUNT} parallel requests accepted", "high", url)
                findings.append({"issue": "concurrent_rate_limit_bypass", "endpoint": auth_path, **burst_result})
                if session:
                    await session.add_finding(
                        target=url, module="rate_limit",
                        vuln_type="concurrent_rate_limit_bypass",
                        severity="high", confidence="confirmed",
                        title=f"Concurrent rate limit bypass on {auth_path}",
                        description=f"Sent {CONCURRENT_BURST_COUNT} concurrent requests to {auth_path} and {burst_result.get('rate_limited_count', 0)} were rate-limited. Attackers can use concurrent connections to bypass per-IP rate limits.",
                        evidence=f"Statuses: {burst_result['unique_statuses']}",
                        remediation="1. Use a sliding window rate limiter with atomic counters. 2. Rate limit by session or user ID in addition to IP. 3. Use global rate limits, not just per-IP.",
                        cvss_score=7.5, cwe="CWE-307",
                    )

        # -- 3. OTP endpoint testing -------------------------------------------------
        console.print("  Testing OTP endpoints...")
        for otp_path in OTP_ENDPOINTS:
            otp_result = await _test_single_endpoint(
                url, otp_path, "POST", client,
                {"otp": "{i}", "user": username},
                burst_count=15,
            )
            if not otp_result["has_rate_limiting"] and otp_result["all_successful"]:
                print_finding(f"No rate limiting on OTP endpoint {otp_path}", "high", url)
                findings.append({"issue": "no_rate_limit_otp", "endpoint": otp_path, **otp_result})
                if session:
                    await session.add_finding(
                        target=url, module="rate_limit",
                        vuln_type="no_rate_limit_otp",
                        severity="high", confidence="confirmed",
                        title=f"No rate limiting on OTP endpoint {otp_path}",
                        description=f"Sent 15 rapid OTP verification requests to {otp_path} and all were accepted. OTP codes can be brute-forced without restriction.",
                        evidence=f"Statuses: {otp_result['unique_statuses']}",
                        remediation="1. Rate limit OTP verification per session. 2. Lockout after 3-5 failed attempts. 3. Use short-lived OTP codes (30-60 seconds).",
                        cvss_score=8.2, cwe="CWE-307",
                    )

        # -- 4. Password reset endpoint testing ---------------------------------------
        console.print("  Testing password reset endpoints...")
        reset_email = f"test_{''.join(random.choices(string.ascii_lowercase, k=4))}@example.com"
        for reset_path in PASSWORD_RESET_ENDPOINTS:
            reset_result = await _test_single_endpoint(
                url, reset_path, "POST", client,
                {"email": reset_email},
                burst_count=10,
            )
            if not reset_result["has_rate_limiting"] and reset_result["all_successful"]:
                print_finding(f"No rate limiting on password reset {reset_path}", "medium", url)
                findings.append({"issue": "no_rate_limit_reset", "endpoint": reset_path, **reset_result})
                if session:
                    await session.add_finding(
                        target=url, module="rate_limit",
                        vuln_type="no_rate_limit_password_reset",
                        severity="medium", confidence="confirmed",
                        title=f"No rate limiting on password reset endpoint {reset_path}",
                        description=f"Sent 10 rapid password reset requests to {reset_path}. No rate limiting detected. Can be used for email bombing or enumeration.",
                        evidence=f"Statuses: {reset_result['unique_statuses']}",
                        remediation="1. Rate limit password reset requests per email and per IP. 2. Add CAPTCHA for password reset. 3. Implement cooldown period between requests.",
                        cvss_score=5.3, cwe="CWE-307",
                    )

    console.print(f"  Rate limit testing complete -- {len(findings)} issues")
    return {"target": url, "findings": findings, "count": len(findings)}
