"""HTTP Verb Tampering scanner — tests all HTTP methods, method override bypass, OPTIONS verb enumeration."""
from __future__ import annotations
import asyncio
from typing import Any

from talisman.engine.scope import ScopeViolationError
from talisman.utils.http_client import TalismanHTTPClient
from talisman.utils.logger import get_logger, console, print_finding

log = get_logger(__name__)

SAFE_HTTP_METHODS = ["GET", "HEAD", "OPTIONS", "TRACE"]
MUTATING_HTTP_METHODS = ["POST", "PUT", "PATCH", "DELETE"]
HTTP_METHODS = SAFE_HTTP_METHODS

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
    url: str,
    endpoint: str,
    client: TalismanHTTPClient,
    methods: list[str] | None = None,
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

    for method in (methods or HTTP_METHODS):
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
    if scope is None:
        return {
            "target": url,
            "findings": [],
            "observations": [],
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
            "observations": [],
            "candidates": [],
            "count": 0,
            "error": str(exc),
        }

    allow_mutations = False
    try:
        scope.assert_destructive_allowed(url, "POST")
        allow_mutations = True
    except ScopeViolationError:
        pass

    methods = list(SAFE_HTTP_METHODS)
    if allow_mutations:
        methods.extend(MUTATING_HTTP_METHODS)

    observations: list[dict[str, Any]] = []
    candidates: list[dict[str, Any]] = []
    console.print(
        f"\\n[module][+] HTTP Method Surface Assessment[/module] -> [target]{url}[/target]"
    )

    async with TalismanHTTPClient(
        proxy=proxy,
        timeout=10,
        verify_ssl=True,
        follow_redirects=False,
        scope=scope,
    ) as client:
        for endpoint in SENSITIVE_ENDPOINTS:
            method_results = await _test_methods(url, endpoint, client, methods=methods)
            for result in method_results:
                item = {
                    **result,
                    "classification": "http_method_posture_observation",
                    "verification_required": (
                        "An accepted HTTP method does not prove unauthorized access "
                        "or a successful state change. Verify endpoint authorization "
                        "with dedicated disposable resources and compare its Allow "
                        "header with actual application behavior."
                    ),
                }
                if result.get("type") in {
                    "put_enabled",
                    "delete_enabled",
                    "patch_enabled",
                    "unexpected_method",
                }:
                    candidates.append({
                        **item,
                        "confidence": "candidate",
                        "requires_authorization_impact_validation": True,
                    })
                else:
                    observations.append(item)

            if allow_mutations:
                override_results = await _test_method_override(url, endpoint, client)
                for result in override_results:
                    candidates.append({
                        **result,
                        "confidence": "candidate",
                        "requires_authorization_impact_validation": True,
                        "verification_required": (
                            "A status-code difference after an override header does "
                            "not prove the operation succeeded. Verify the resulting "
                            "state change on a disposable resource and check that "
                            "normal authorization controls were bypassed."
                        ),
                    })

    console.print(
        f"  Method assessment complete — {len(candidates)} authorization candidates, "
        f"{len(observations)} protocol observations"
    )
    return {
        "target": url,
        "findings": [],
        "observations": observations,
        "candidates": candidates,
        "count": 0,
        "candidate_count": len(candidates),
        "observation_count": len(observations),
        "mutating_method_probes_enabled": allow_mutations,
        "methods_tested": methods,
    }
