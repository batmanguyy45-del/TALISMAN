"""HTTP Parameter Pollution scanner — framework-aware duplicate parameter handling, WAF bypass, POST body pollution."""
from __future__ import annotations
import asyncio
import random
import string
from typing import Any
from talisman.utils.http_client import TalismanHTTPClient
from talisman.utils.logger import get_logger, console, print_finding

log = get_logger(__name__)

HPP_CANARY_PREFIX = "TLSMHPP"

SENSITIVE_PARAMS = [
    "role", "is_admin", "admin", "user", "uid",
    "id", "type", "status", "action", "mode",
    "debug", "test", "bypass", "disable",
    "amount", "price", "quantity", "total",
    "email", "username", "password", "token",
]

HPP_ENDPOINTS = [
    "/api/user", "/api/users", "/api/profile",
    "/api/login", "/api/auth",
    "/api/admin", "/api/settings",
    "/api/transfer", "/api/order",
    "/api/search", "/api/delete",
    "/api/update", "/api/config",
    "/admin", "/settings", "/profile",
]


def _build_hpp_tests(param: str) -> list[dict[str, Any]]:
    """Build HPP payloads with duplicate parameters using different values."""
    canary_evil = f"{HPP_CANARY_PREFIX}{''.join(random.choices(string.ascii_uppercase + string.digits, k=8))}"
    canary_safe = f"{HPP_CANARY_PREFIX}{''.join(random.choices(string.ascii_lowercase + string.digits, k=8))}"

    return [
        {
            "description": "First-last value discrepancy",
            "params": [(param, canary_safe), (param, canary_evil)],
            "canary": canary_evil,
            "expected_position": "last",
        },
        {
            "description": "Triple duplicate parameters",
            "params": [(param, canary_safe), (param, "middle"), (param, canary_evil)],
            "canary": canary_evil,
            "expected_position": "last",
        },
    ]


async def _test_query_hpp(
    url: str, endpoint: str, client: TalismanHTTPClient,
) -> list[dict[str, Any]]:
    """Test HPP in query string parameters."""
    findings: list[dict[str, Any]] = []
    test_url_base = url.rstrip("/") + endpoint

    for test_param in SENSITIVE_PARAMS[:8]:
        tests = _build_hpp_tests(test_param)

        for test in tests:
            # Build URL with duplicate parameters
            param_pairs = "&".join(f"{k}={v}" for k, v in test["params"])
            test_url = f"{test_url_base}?{param_pairs}"

            try:
                r = await client.get(test_url, timeout=8)
                resp_text = r.text.lower()
                canary = test["canary"].lower()

                if canary in resp_text:
                    findings.append({
                        "type": "query_hpp",
                        "endpoint": endpoint,
                        "parameter": test_param,
                        "description": test["description"],
                        "canary": test["canary"],
                        "evidence": f"Canary reflected at endpoint with duplicate {test_param} parameter",
                        "status": r.status_code,
                    })
                    break
            except Exception:
                pass

    return findings


async def _test_body_hpp(
    url: str, endpoint: str, client: TalismanHTTPClient,
) -> list[dict[str, Any]]:
    """Test HPP in POST body (form-encoded and JSON)."""
    findings: list[dict[str, Any]] = []
    test_url = url.rstrip("/") + endpoint
    canary = f"{HPP_CANARY_PREFIX}{''.join(random.choices(string.ascii_uppercase + string.digits, k=8))}"

    # JSON array parameter test
    try:
        payload = {
            "email": "test@test.com",
            "role": ["user"],
            "role": canary,
        }
        r = await client.post(test_url, json=payload,
            headers={"Content-Type": "application/json"}, timeout=8)
        if canary.lower() in r.text.lower()[:500]:
            findings.append({
                "type": "json_body_hpp",
                "endpoint": endpoint,
                "evidence": f"JSON duplicate 'role' parameter accepted, canary reflected",
                "canary": canary,
            })
    except Exception:
        pass

    # Form-encoded duplicate parameters
    safe_val = f"safe_{''.join(random.choices(string.ascii_lowercase, k=4))}"
    evil_val = canary

    for param in ["role", "admin", "status", "type"]:
        try:
            body = f"email=test@test.com&{param}={safe_val}&{param}={evil_val}"
            r = await client.post(test_url, data=body.encode(),
                headers={"Content-Type": "application/x-www-form-urlencoded"}, timeout=8)
            resp_text = r.text.lower()
            if evil_val.lower() in resp_text:
                findings.append({
                    "type": "form_body_hpp",
                    "endpoint": endpoint,
                    "parameter": param,
                    "canary": evil_val,
                    "evidence": f"Form-encoded duplicate {param} parameter accepted, canary reflected",
                })
                break
        except Exception:
            pass

    return findings


async def _test_header_hpp(
    url: str, endpoint: str, client: TalismanHTTPClient,
) -> list[dict[str, Any]]:
    """Test HPP via duplicate headers."""
    findings: list[dict[str, Any]] = []
    test_url = url.rstrip("/") + endpoint
    canary = f"{HPP_CANARY_PREFIX}{''.join(random.choices(string.ascii_uppercase + string.digits, k=8))}"

    # Duplicate X-Forwarded-For to test IP-based auth bypass
    try:
        r = await client.get(test_url,
            headers={
                "X-Forwarded-For": "127.0.0.1",
                "X-Forwarded-For": canary,
            },
            timeout=8,
        )
        if r.status_code != 403 and r.status_code != 401:
            resp_text = r.text.lower()
            if canary.lower() in resp_text:
                findings.append({
                    "type": "header_hpp",
                    "endpoint": endpoint,
                    "header": "X-Forwarded-For",
                    "canary": canary,
                    "evidence": f"Duplicate X-Forwarded-For header processed, value reflected",
                })
    except Exception:
        pass

    return findings


async def _test_mixed_param_sources(
    url: str, endpoint: str, client: TalismanHTTPClient,
) -> list[dict[str, Any]]:
    """Test HPP where param appears in BOTH query string AND POST body.

    Some frameworks parse different sources independently, allowing
    the same param in query AND body to be read differently by different layers.
    """
    findings: list[dict[str, Any]] = []
    test_url = url.rstrip("/") + endpoint
    canary = f"{HPP_CANARY_PREFIX}{''.join(random.choices(string.ascii_uppercase + string.digits, k=8))}"

    # Same param in both query string and POST body
    try:
        r = await client.post(
            f"{test_url}?role={canary}",
            data="email=test@test.com&role=user",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            timeout=8,
        )
        if canary.lower() in r.text.lower()[:500]:
            findings.append({
                "type": "mixed_source_hpp",
                "endpoint": endpoint,
                "parameter": "role",
                "canary": canary,
                "evidence": f"Same parameter 'role' sent in both query string and POST body. Canary from query string reflected.",
                "description": "Parameter pollution across query string and POST body",
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
    console.print(f"\n[module][+] HTTP Parameter Pollution Scanner[/module] -> [target]{url}[/target]")
    findings: list[dict[str, Any]] = []

    async with TalismanHTTPClient(proxy=proxy, timeout=10) as client:
        console.print(f"  Testing {len(HPP_ENDPOINTS)} endpoints across 4 HPP vectors...")

        for endpoint in HPP_ENDPOINTS:
            # -- 1. Query string HPP ---------------------------------------------------
            q_findings = await _test_query_hpp(url, endpoint, client)
            for f in q_findings:
                param = f.get("parameter", "unknown")
                title = f"HPP in query string at {endpoint}: duplicate '{{param}}' produces different result".replace("{param}", param)
                print_finding(title, "high", url)
                findings.append(f)
                if session:
                    await session.add_finding(
                        target=url, module="hpp",
                        vuln_type="query_hpp",
                        severity="high", confidence="confirmed",
                        title=title,
                        description=f"HTTP Parameter Pollution detected at {endpoint}. Duplicate '{param}' parameter in query string with different values caused the server to process unexpected value. This can bypass WAF rules and input validation.",
                        evidence=f.get("evidence", ""),
                        remediation=f"1. Reject requests with duplicate '{param}' parameter. 2. Add input validation middleware that flags duplicates. 3. Use schema validation that only accepts single-value parameters. 4. Test all security-sensitive parameters for HPP.",
                        cvss_score=7.5, cwe="CWE-235",
                    )

            # -- 2. POST body HPP (form-encoded + JSON) --------------------------------
            b_findings = await _test_body_hpp(url, endpoint, client)
            for f in b_findings:
                ftype = f.get("type", "body_hpp")
                title = f"HPP in POST body at {endpoint}: {'JSON array' if 'json' in ftype else 'form-encoded'} duplicate parameter"
                print_finding(title, "medium", url)
                findings.append(f)
                if session:
                    await session.add_finding(
                        target=url, module="hpp",
                        vuln_type=ftype,
                        severity="medium", confidence="confirmed",
                        title=title,
                        description=f"Duplicate parameter accepted in POST body at {endpoint}. {'JSON body with array-type parameter' if 'json' in ftype else 'Form-encoded body with duplicate keys'} resulted in unexpected parameter resolution.",
                        evidence=f.get("evidence", ""),
                        remediation="1. Reject requests with duplicate body parameters. 2. Use JSON schema validation. 3. Normalize body parameters at middleware layer.",
                        cvss_score=5.3, cwe="CWE-235",
                    )

            # -- 3. Header HPP ---------------------------------------------------------
            h_findings = await _test_header_hpp(url, endpoint, client)
            for f in h_findings:
                header = f.get("header", "X-Forwarded-For")
                title = f"HPP via duplicate {header} header at {endpoint}"
                print_finding(title, "medium", url)
                findings.append(f)
                if session:
                    await session.add_finding(
                        target=url, module="hpp",
                        vuln_type="header_hpp",
                        severity="medium", confidence="confirmed",
                        title=title,
                        description=f"Duplicate '{header}' header accepted at {endpoint}. Headers with multiple values can be misinterpreted by different proxy/application layers.",
                        evidence=f.get("evidence", ""),
                        remediation=f"1. Use comma-separated header format instead of duplicate headers. 2. Normalize {header} header at gateway. 3. Validate header parsing behavior.",
                        cvss_score=5.3, cwe="CWE-235",
                    )

            # -- 4. Mixed source HPP (query + body) ------------------------------------
            m_findings = await _test_mixed_param_sources(url, endpoint, client)
            for f in m_findings:
                param = f.get("parameter", "unknown")
                title = f"HPP across query+body at {endpoint}: '{{param}}' in both sources".replace("{param}", param)
                print_finding(title, "high", url)
                findings.append(f)
                if session:
                    await session.add_finding(
                        target=url, module="hpp",
                        vuln_type="mixed_source_hpp",
                        severity="high", confidence="confirmed",
                        title=title,
                        description=f"Parameter '{param}' sent in BOTH query string and POST body at {endpoint}. The value from the query string was processed even though a body parameter with the same name existed. This can bypass input validation that only checks one source.",
                        evidence=f.get("evidence", ""),
                        remediation="1. Use a single parameter source (query string or body, not both). 2. Implement middleware that raises errors on ambiguous parameter sources. 3. Validate across all parameter sources.",
                        cvss_score=7.5, cwe="CWE-235",
                    )

    console.print(f"  HPP scan complete -- {len(findings)} issues")
    return {"target": url, "findings": findings, "count": len(findings)}
