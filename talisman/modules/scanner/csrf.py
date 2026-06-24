"""CSRF deep scanner — SameSite analysis, token validation, method override, cookie injection."""
from __future__ import annotations
import asyncio
import random
import re
import string
from typing import Any
from talisman.utils.http_client import TalismanHTTPClient
from talisman.utils.logger import get_logger, console, print_finding

log = get_logger(__name__)

STATE_CHANGING_ENDPOINTS = [
    "/change-email", "/my-account/change-email",
    "/api/change-email", "/api/v1/change-email",
    "/change-password", "/my-account/change-password",
    "/api/change-password", "/api/v1/change-password",
    "/update-profile", "/api/profile", "/api/v1/profile",
    "/settings", "/api/settings",
    "/delete-account", "/api/delete-account",
    "/transfer", "/api/transfer",
    "/logout", "/api/logout",
]

METHOD_OVERRIDE_VARIANTS = [
    ("_method", "POST"),
    ("_method", "PUT"),
    ("_method", "DELETE"),
    ("X-HTTP-Method-Override", "POST"),
    ("X-HTTP-Method-Override", "PUT"),
    ("REQUEST_METHOD", "POST"),
]


async def _analyze_cookies(url: str, client: TalismanHTTPClient) -> list[dict[str, Any]]:
    """Analyze Set-Cookie headers for SameSite and security attributes."""
    findings: list[dict[str, Any]] = []
    try:
        r = await client.get(url, timeout=8)
        set_cookie = r.headers.get_list("set-cookie") or [r.headers.get("set-cookie", "")]
        for cookie_str in set_cookie:
            if not cookie_str:
                continue
            cookie_lower = cookie_str.lower()
            name = cookie_str.split("=")[0].strip() if "=" in cookie_str else "unknown"
            has_samesite = "samesite=" in cookie_lower
            samesite_strict = "samesite=strict" in cookie_lower
            samesite_lax = "samesite=lax" in cookie_lower
            samesite_none = "samesite=none" in cookie_lower
            has_secure = "secure" in cookie_lower
            has_httponly = "httponly" in cookie_lower

            if not has_samesite:
                findings.append({
                    "type": "missing_samesite",
                    "cookie": name,
                    "detail": "No SameSite attribute set — browser defaults to Lax",
                })
            elif samesite_none and not has_secure:
                findings.append({
                    "type": "samesite_none_no_secure",
                    "cookie": name,
                    "detail": "SameSite=None without Secure flag — ignored by modern browsers",
                })
            if not has_httponly and "session" in cookie_lower or "token" in cookie_lower:
                findings.append({
                    "type": "missing_httponly",
                    "cookie": name,
                    "detail": "Session/token cookie missing HttpOnly flag",
                })
    except Exception:
        pass
    return findings


async def _test_csrf_token_handling(
    url: str, endpoint: str, client: TalismanHTTPClient,
) -> list[dict[str, Any]]:
    """Test CSRF token validation robustness."""
    findings: list[dict[str, Any]] = []
    test_url = url.rstrip("/") + endpoint
    test_email = f"csrf_{''.join(random.choices(string.ascii_lowercase, k=4))}@test.com"
    headers = {"Content-Type": "application/json"}

    # 1. Normal request first — see if a CSRF token is expected
    try:
        r = await client.post(test_url, json={"email": test_email}, headers=headers, timeout=8)
        if r.status_code in (200, 201, 204):
            # No CSRF protection detected — request succeeded without a token
            findings.append({
                "type": "no_csrf_token",
                "method": "POST",
                "endpoint": endpoint,
                "status": r.status_code,
            })
            return findings
    except Exception:
        pass

    # 2. Method swap: GET instead of POST
    try:
        r = await client.get(test_url, params={"email": test_email}, timeout=8)
        if r.status_code in (200, 201, 204):
            findings.append({
                "type": "method_swap_bypass",
                "original": "POST",
                "bypass": "GET",
                "endpoint": endpoint,
                "status": r.status_code,
            })
    except Exception:
        pass

    # 3. Method override via URL parameter
    for override_param, override_method in METHOD_OVERRIDE_VARIANTS:
        try:
            params = {"email": test_email, override_param: override_method}
            r = await client.get(test_url, params=params, timeout=8)
            if r.status_code in (200, 201, 204):
                findings.append({
                    "type": "method_override_bypass",
                    "parameter": override_param,
                    "override_method": override_method,
                    "endpoint": endpoint,
                    "status": r.status_code,
                })
                break
        except Exception:
            pass

    # 4. Content-type swap: JSON -> form-encoded
    try:
        r = await client.post(test_url, data={"email": test_email}, headers={"Content-Type": "application/x-www-form-urlencoded"}, timeout=8)
        if r.status_code in (200, 201, 204):
            findings.append({
                "type": "content_type_swap_bypass",
                "original": "application/json",
                "bypass": "application/x-www-form-urlencoded",
                "endpoint": endpoint,
                "status": r.status_code,
            })
    except Exception:
        pass

    # 5. Remove CSRF token parameter entirely
    try:
        r = await client.post(test_url, json={}, headers=headers, timeout=8)
        if r.status_code in (200, 201, 204):
            findings.append({
                "type": "token_removal_bypass",
                "endpoint": endpoint,
                "status": r.status_code,
            })
    except Exception:
        pass

    # 6. Empty CSRF token
    try:
        r = await client.post(test_url, json={"email": test_email, "csrf_token": "", "csrf": "", "token": "", "authenticity_token": ""}, headers=headers, timeout=8)
        if r.status_code in (200, 201, 204):
            findings.append({
                "type": "empty_token_bypass",
                "endpoint": endpoint,
                "status": r.status_code,
            })
    except Exception:
        pass

    return findings


async def run(
    target: str,
    session: Any = None,
    scope: Any = None,
    rate_limiter: Any = None,
    proxy: str | None = None,
    **kwargs: Any,
) -> dict[str, Any]:
    url = target if "://" in target else f"https://{target}"
    console.print(f"\n[module][+] CSRF Deep Scanner[/module] -> [target]{url}[/target]")
    findings: list[dict[str, Any]] = []

    async with TalismanHTTPClient(proxy=proxy, timeout=10) as client:
        # -- 1. Cookie SameSite analysis ---------------------------------------------
        cookie_findings = await _analyze_cookies(url, client)
        for cf in cookie_findings:
            ctype = cf["type"]
            if ctype == "missing_samesite":
                title = f"Cookie '{cf['cookie']}' missing SameSite attribute"
                print_finding(title, "medium", url)
                findings.append(cf)
                if session:
                    await session.add_finding(
                        target=url, module="csrf",
                        vuln_type="missing_samesite",
                        severity="medium", confidence="confirmed",
                        title=title,
                        description=f"Cookie '{cf['cookie']}' has no SameSite attribute. Browser defaults to Lax, which is bypassable via GET requests and 2-minute window.",
                        remediation="Set SameSite=Strict or SameSite=Lax on all session cookies. Use __Host- prefix for session cookies.",
                        cvss_score=6.5, cwe="CWE-1275",
                    )
            elif ctype == "samesite_none_no_secure":
                title = f"Cookie '{cf['cookie']}' has SameSite=None without Secure"
                print_finding(title, "medium", url)
                findings.append(cf)
            elif ctype == "missing_httponly":
                title = f"Session cookie '{cf['cookie']}' missing HttpOnly flag"
                print_finding(title, "low", url)
                findings.append(cf)

        # -- 2. CSRF token validation tests ------------------------------------------
        console.print(f"  Testing {len(STATE_CHANGING_ENDPOINTS)} state-changing endpoints for CSRF...")
        for endpoint in STATE_CHANGING_ENDPOINTS:
            token_findings = await _test_csrf_token_handling(url, endpoint, client)
            for tf in token_findings:
                ttype = tf["type"]
                endpoint_path = tf.get("endpoint", endpoint)
                if ttype == "no_csrf_token":
                    title = f"No CSRF protection on POST {endpoint_path}"
                    print_finding(title, "high", url)
                    findings.append(tf)
                    if session:
                        await session.add_finding(
                            target=url, module="csrf",
                            vuln_type="no_csrf_token",
                            severity="high", confidence="confirmed",
                            title=title,
                            description=f"Endpoint {endpoint_path} accepts POST requests without any CSRF token. An attacker can forge cross-site requests to modify victim data.",
                            evidence=f"POST to {endpoint_path} succeeded without CSRF token (status {tf.get('status')})",
                            remediation="1. Implement CSRF tokens on all state-changing endpoints. 2. Validate Origin/Referer headers. 3. Use SameSite=Strict on session cookies.",
                            cvss_score=7.5, cwe="CWE-352",
                        )
                elif ttype == "method_swap_bypass":
                    title = f"CSRF bypass via method swap on {endpoint_path} (POST -> GET)"
                    print_finding(title, "high", url)
                    findings.append(tf)
                    if session:
                        await session.add_finding(
                            target=url, module="csrf",
                            vuln_type="csrf_method_swap",
                            severity="high", confidence="confirmed",
                            title=title,
                            description=f"CSRF token validation bypassed by changing POST to GET on {endpoint_path}. Token validation is method-conditioned.",
                            remediation="Validate CSRF tokens on ALL methods, not just POST.",
                            cvss_score=7.5, cwe="CWE-352",
                        )
                elif ttype == "method_override_bypass":
                    title = f"CSRF bypass via method override on {endpoint_path}"
                    print_finding(title, "high", url)
                    findings.append(tf)
                elif ttype == "content_type_swap_bypass":
                    title = f"CSRF bypass via content-type swap on {endpoint_path}"
                    print_finding(title, "high", url)
                    findings.append(tf)
                elif ttype in ("token_removal_bypass", "empty_token_bypass"):
                    title = f"CSRF bypass via {'token removal' if ttype == 'token_removal_bypass' else 'empty token'} on {endpoint_path}"
                    print_finding(title, "high", url)
                    findings.append(tf)

    console.print(f"  CSRF scan complete -- {len(findings)} issues")
    return {"target": url, "findings": findings, "count": len(findings)}
