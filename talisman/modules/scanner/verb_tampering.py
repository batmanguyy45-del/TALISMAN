"""HTTP Verb Tampering scanner — tests all HTTP methods, method override bypass, OPTIONS verb enumeration."""
from __future__ import annotations
import asyncio
from typing import Any
from talisman.utils.http_client import TalismanHTTPClient
from talisman.utils.logger import get_logger, console, print_finding

log = get_logger(__name__)

HTTP_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "TRACE", "CONNECT"]

SENSITIVE_ENDPOINTS = [
    "/", "/admin", "/api/admin", "/api/user", "/api/users",
    "/api/profile", "/api/config", "/api/status",
    "/api/settings", "/api/delete", "/api/transfer",
    "/login", "/api/login", "/logout", "/api/logout",
]

METHOD_OVERRIDE_HEADERS = [
    ("X-HTTP-Method", "POST"),
    ("X-HTTP-Method-Override", "POST"),
    ("X-Method-Override", "POST"),
    ("X-HTTP-Method", "PUT"),
    ("X-HTTP-Method-Override", "PUT"),
    ("X-Method-Override", "DELETE"),
]


async def _test_methods(
    url: str, endpoint: str, client: TalismanHTTPClient,
) -> list[dict[str, Any]]:
    """Test all HTTP methods on an endpoint and report unexpected acceptances."""
    findings: list[dict[str, Any]] = []
    test_url = url.rstrip("/") + endpoint
    expected_allow: set[str] = set()
    accepted: dict[str, int] = {}

    # First, check OPTIONS for allowed methods
    try:
        r = await client.request("OPTIONS", test_url, timeout=8)
        allow_header = r.headers.get("allow", "")
        if allow_header:
            expected_allow = set(m.strip().upper() for m in allow_header.split(","))
    except Exception:
        pass

    for method in HTTP_METHODS:
        try:
            r = await client.request(method, test_url, timeout=8)
            # Consider 200, 201, 204, 301, 302, 303, 307, 308 as "accepted"
            if r.status_code in (200, 201, 204, 301, 302, 303, 307, 308):
                accepted[method] = r.status_code
        except Exception:
            pass

    # TRACE method is always interesting (XST attack)
    if "TRACE" in accepted:
        findings.append({
            "type": "trace_enabled",
            "endpoint": endpoint,
            "status": accepted["TRACE"],
            "description": "TRACE method enabled — Cross-Site Tracing (XST) attack vector",
        })

    # CONNECT method is unusual
    if "CONNECT" in accepted:
        findings.append({
            "type": "connect_enabled",
            "endpoint": endpoint,
            "status": accepted["CONNECT"],
            "description": "CONNECT method enabled — potential proxy misuse",
        })

    # PUT without proper authorization
    if "PUT" in accepted:
        findings.append({
            "type": "put_enabled",
            "endpoint": endpoint,
            "status": accepted["PUT"],
            "description": "PUT method accepted — potential file upload/overwrite vector",
        })

    # DELETE without proper authorization
    if "DELETE" in accepted:
        findings.append({
            "type": "delete_enabled",
            "endpoint": endpoint,
            "status": accepted["DELETE"],
            "description": "DELETE method accepted — potential resource deletion vector",
        })

    # PATCH without proper authorization
    if "PATCH" in accepted:
        findings.append({
            "type": "patch_enabled",
            "endpoint": endpoint,
            "status": accepted["PATCH"],
            "description": "PATCH method accepted — potential data modification vector",
        })

    # HEAD returns different status than GET
    if "HEAD" in accepted and "GET" in accepted:
        if accepted["HEAD"] != accepted["GET"]:
            findings.append({
                "type": "head_get_mismatch",
                "endpoint": endpoint,
                "head_status": accepted["HEAD"],
                "get_status": accepted["GET"],
                "description": "HEAD and GET return different status codes — potential information disclosure",
            })

    # Unexpected methods (not in Allow header but accepted)
    if expected_allow:
        unexpected = set(accepted.keys()) - expected_allow
        for method in sorted(unexpected):
            findings.append({
                "type": "unexpected_method",
                "method": method,
                "endpoint": endpoint,
                "status": accepted[method],
                "allowed": sorted(expected_allow),
                "description": f"{method} is not in the Allow header ({', '.join(sorted(expected_allow))}) but was accepted (HTTP {accepted[method]})",
            })

    return findings


async def _test_method_override(
    url: str, endpoint: str, client: TalismanHTTPClient,
) -> list[dict[str, Any]]:
    """Test method override headers to bypass access controls."""
    findings: list[dict[str, Any]] = []
    test_url = url.rstrip("/") + endpoint

    # Baseline: GET request
    try:
        r_get = await client.get(test_url, timeout=8)
        get_status = r_get.status_code
    except Exception:
        get_status = 0

    # Baseline: POST request
    try:
        r_post = await client.post(test_url, json={}, timeout=8)
        post_status = r_post.status_code
    except Exception:
        post_status = 0

    for header, override_method in METHOD_OVERRIDE_HEADERS:
        try:
            r = await client.get(test_url, headers={header: override_method}, timeout=8)
            if r.status_code not in (405, 403, 401, 400) and r.status_code != get_status:
                findings.append({
                    "type": "method_override_bypass",
                    "endpoint": endpoint,
                    "header": header,
                    "override_method": override_method,
                    "get_status": get_status,
                    "override_status": r.status_code,
                    "description": f"Method override via {header}: {override_method} changed response from {get_status} to {r.status_code}",
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
    console.print(f"\n[module][+] HTTP Verb Tampering Scanner[/module] -> [target]{url}[/target]")
    findings: list[dict[str, Any]] = []

    async with TalismanHTTPClient(proxy=proxy, timeout=10) as client:
        console.print(f"  Testing {len(SENSITIVE_ENDPOINTS)} endpoints across {len(HTTP_METHODS)} methods...")
        for endpoint in SENSITIVE_ENDPOINTS:
            # -- 1. Method testing ----------------------------------------------------
            method_findings = await _test_methods(url, endpoint, client)
            for mf in method_findings:
                mtype = mf["type"]
                ep = mf.get("endpoint", endpoint)

                if mtype == "trace_enabled":
                    title = f"TRACE method enabled at {ep} — Cross-Site Tracing"
                    print_finding(title, "medium", url)
                    findings.append(mf)
                    if session:
                        await session.add_finding(
                            target=url, module="verb_tampering",
                            vuln_type="trace_enabled",
                            severity="medium", confidence="confirmed",
                            title=title,
                            description=f"TRACE method is enabled on {ep}. May be used for Cross-Site Tracing (XST) attacks when combined with XSS.",
                            remediation="Disable TRACE method on production servers. It is not required for normal operation.",
                            cvss_score=5.3, cwe="CWE-16",
                        )

                elif mtype in ("put_enabled", "delete_enabled", "patch_enabled"):
                    severity = "high" if mtype in ("put_enabled", "delete_enabled") else "medium"
                    title = f"{mf.get('method', mtype.split('_')[0].upper())} method accepted at {ep}"
                    print_finding(title, severity, url)
                    findings.append(mf)
                    if session:
                        action = "file upload/overwrite" if "put" in mtype else "resource deletion" if "delete" in mtype else "data modification"
                        await session.add_finding(
                            target=url, module="verb_tampering",
                            vuln_type=mtype,
                            severity=severity, confidence="confirmed",
                            title=title,
                            description=f"{mf.get('method', mtype.split('_')[0].upper())} method accepted on {ep} (HTTP {mf.get('status')}). Potential {action} vector.",
                            remediation=f"Restrict {mf.get('method', mtype.split('_')[0].upper())} method to authenticated and authorized users only, or disable it entirely if not needed.",
                            cvss_score=7.5 if severity == "high" else 6.5, cwe="CWE-16",
                        )

                elif mtype == "unexpected_method":
                    method = mf.get("method", "UNKNOWN")
                    title = f"Unexpected method {method} accepted at {ep}"
                    print_finding(title, "medium", url)
                    findings.append(mf)
                    if session:
                        await session.add_finding(
                            target=url, module="verb_tampering",
                            vuln_type="unexpected_method",
                            severity="medium", confidence="confirmed",
                            title=title,
                            description=f"{method} is accepted on {ep} but is not listed in the Allow header ({', '.join(mf.get('allowed', []))}). May bypass access controls designed for expected methods.",
                            remediation="Ensure the server's Allow header matches the actual accepted methods. Consider disabling unused methods.",
                            cvss_score=5.3, cwe="CWE-16",
                        )

            # -- 2. Method override testing --------------------------------------------
            override_findings = await _test_method_override(url, endpoint, client)
            for of in override_findings:
                if of.get("type") == "method_override_bypass":
                    title = f"Method override bypass at {ep}: {of.get('header')} -> {of.get('override_method')}"
                    print_finding(title, "high", url)
                    findings.append(of)
                    if session:
                        await session.add_finding(
                            target=url, module="verb_tampering",
                            vuln_type="method_override_bypass",
                            severity="high", confidence="confirmed",
                            title=title,
                            description=f"Method override header {of.get('header')}: {of.get('override_method')} bypassed access controls on {ep}. Response changed from {of.get('get_status')} to {of.get('override_status')}.",
                            remediation="1. Disable method override headers unless explicitly required. 2. Validate the overridden method against access controls. 3. Use strict method allowlists.",
                            cvss_score=7.5, cwe="CWE-16",
                        )

    console.print(f"  Verb tampering scan complete -- {len(findings)} issues")
    return {"target": url, "findings": findings, "count": len(findings)}
