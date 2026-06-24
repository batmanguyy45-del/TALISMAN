"""Web cache deception scanner — static path confusion, session/JWT leakage via cache."""
from __future__ import annotations
import asyncio
import random
import string
from typing import Any
from talisman.utils.http_client import TalismanHTTPClient
from talisman.utils.logger import get_logger, console, print_finding

log = get_logger(__name__)

STATIC_EXTENSIONS = [".css", ".js", ".ico", ".png", ".jpg", ".gif", ".svg", ".woff", ".woff2", ".ttf", ".eot"]
DYNAMIC_PATHS = [
    "/profile", "/api/user", "/api/users/me",
    "/account", "/settings",
    "/dashboard", "/api/dashboard",
    "/orders", "/api/orders",
    "/messages", "/api/messages",
]


async def _test_cache_deception(
    url: str, client: TalismanHTTPClient,
) -> list[dict[str, Any]]:
    """Test web cache deception by appending static extensions to dynamic paths."""
    findings: list[dict[str, Any]] = []
    nonce = ''.join(random.choices(string.ascii_lowercase, k=6))

    for dynamic_path in DYNAMIC_PATHS:
        for ext in STATIC_EXTENSIONS[:4]:  # Test the most common extensions
            # Append static extension to the dynamic path
            deceptive_path = f"{dynamic_path}/{nonce}{ext}"
            test_url = url.rstrip("/") + deceptive_path

            try:
                r = await client.get(
                    test_url,
                    headers={"Cache-Control": "no-cache", "Pragma": "no-cache"},
                    timeout=8,
                )

                # Check if the response is cacheable
                cache_control = (r.headers.get("cache-control", "") or "").lower()
                content_type = (r.headers.get("content-type", "") or "").lower()
                set_cookie = r.headers.get("set-cookie", "")

                is_cacheable = (
                    "public" in cache_control
                    or "max-age" in cache_control
                    or r.status_code in (200, 203, 204, 206, 300, 301, 404, 410)
                )

                if is_cacheable:
                    # Check if sensitive content is served with the cached response
                    has_sensitive = (
                        "profile" in r.text.lower()
                        or "email" in r.text.lower()
                        or "session" in r.text.lower()
                        or "token" in r.text.lower()
                        or "api" in r.text.lower()
                    )

                    if has_sensitive and (not set_cookie or "samesite" not in set_cookie.lower()):
                        findings.append({
                            "path": deceptive_path,
                            "extension": ext,
                            "status": r.status_code,
                            "content_type": content_type,
                            "cache_control": cache_control,
                            "has_set_cookie": bool(set_cookie),
                            "response_preview": r.text[:300],
                            "issue": "cacheable_dynamic_response",
                        })

                # Check for different response when requesting with static extension
                # vs without
                normal_url = url.rstrip("/") + dynamic_path
                try:
                    r2 = await client.get(
                        normal_url,
                        headers={"Cache-Control": "no-cache"},
                        timeout=8,
                    )
                    if r.status_code == r2.status_code and len(r.text) > 0:
                        # Same response — CDN is serving dynamic content as static
                        findings.append({
                            "path": deceptive_path,
                            "extension": ext,
                            "issue": "path_confusion",
                            "evidence": "Dynamic path and static-extension path return identical content",
                        })
                        break
                except Exception:
                    pass

            except Exception:
                pass

        if any(f.get("issue") in ("path_confusion",) for f in findings):
            break

    return findings


async def _test_cache_key_confusion(
    url: str, client: TalismanHTTPClient,
) -> list[dict[str, Any]]:
    """Test if cache keys ignore certain parameters, allowing cache poisoning."""
    findings: list[dict[str, Any]] = []
    canary = f"TLSMCACHE{''.join(random.choices(string.ascii_uppercase + string.digits, k=8))}"
    param_name = f"cb_{''.join(random.choices(string.ascii_lowercase, k=4))}"

    # Request 1: with a unique parameter
    try:
        r1 = await client.get(url, params={param_name: canary}, timeout=8)
        body1 = r1.text
    except Exception:
        return findings

    # Request 2: without the parameter (should hit same cache if key ignores it)
    try:
        r2 = await client.get(url, timeout=8)
        body2 = r2.text
    except Exception:
        return findings

    # If different parameters produce same response, cache key is parameter-agnostic
    if body1 == body2 and len(body1) > 100:
        findings.append({
            "issue": "cache_key_confusion",
            "description": f"Parameter '{param_name}' is ignored in cache key",
        })

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
    console.print(f"\n[module][+] Web Cache Deception Scanner[/module] -> [target]{url}[/target]")
    findings: list[dict[str, Any]] = []

    async with TalismanHTTPClient(proxy=proxy, timeout=12) as client:
        # -- 1. Static extension path confusion --------------------------------------
        console.print("  Testing path confusion (static extension appending)...")
        deception_findings = await _test_cache_deception(url, client)
        for df in deception_findings:
            issue_type = df.get("issue", "")
            deceptive_path = df.get("path", "unknown")

            if issue_type == "path_confusion":
                title = f"Web cache deception via path confusion at {deceptive_path}"
                print_finding(title, "high", url)
                findings.append(df)
                if session:
                    await session.add_finding(
                        target=url, module="cache_deception",
                        vuln_type="web_cache_deception",
                        severity="high", confidence="confirmed",
                        title=title,
                        description=f"Dynamic path {deceptive_path} returns identical content when accessed with a static extension ({df.get('extension')}). A CDN may cache this as static content, exposing it to other users.",
                        evidence=df.get("evidence", f"Path {deceptive_path} returns status {df.get('status')} with content-type {df.get('content_type')}"),
                        remediation="1. Never serve dynamic content via CDN. 2. Set Cache-Control: no-store on authenticated pages. 3. Use Vary: Cookie, Authorization headers.",
                        cvss_score=7.4, cwe="CWE-525",
                    )

            elif issue_type == "cacheable_dynamic_response":
                title = f"Cacheable dynamic response at {deceptive_path}"
                print_finding(title, "medium", url)
                findings.append(df)
                if session:
                    await session.add_finding(
                        target=url, module="cache_deception",
                        vuln_type="cacheable_dynamic_response",
                        severity="medium", confidence="confirmed",
                        title=title,
                        description=f"Dynamic endpoint {deceptive_path} is cacheable (Cache-Control: {df.get('cache_control')}). If this page contains user-specific data, it may be served to other users from cache.",
                        remediation="1. Set Cache-Control: no-store on all authenticated responses. 2. Use Vary headers appropriately. 3. Review CDN caching rules.",
                        cvss_score=5.3, cwe="CWE-525",
                    )

        # -- 2. Cache key confusion ---------------------------------------------------
        console.print("  Testing cache key confusion...")
        key_findings = await _test_cache_key_confusion(url, client)
        for kf in key_findings:
            title = f"Cache key confusion: {kf.get('description', 'unknown')}"
            print_finding(title, "low", url)
            findings.append(kf)

    console.print(f"  Cache deception scan complete -- {len(findings)} issues")
    return {"target": url, "findings": findings, "count": len(findings)}
