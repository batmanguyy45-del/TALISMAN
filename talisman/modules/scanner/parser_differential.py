"""Parser differential scanner — detects parsing discrepancies between JSON, XML, URL-encoded, and multipart bodies."""
from __future__ import annotations
import asyncio
import json
import random
import string
from typing import Any
from talisman.utils.http_client import TalismanHTTPClient
from talisman.utils.logger import get_logger, console, print_finding

log = get_logger(__name__)

ENDPOINTS = [
    "/api/user", "/api/users", "/api/profile",
    "/api/v1/user", "/api/v1/users", "/api/v1/profile",
    "/api/data", "/api/submit",
    "/api/update", "/api/process",
    "/api/register", "/api/signup",
    "/api/login", "/api/auth",
    "/api/order", "/api/checkout",
]

# Test cases: each is (payload, content-type, description)
DIFFERENTIAL_TESTS = [
    # Duplicate parameter handling
    ("key=value1&key=value2", "application/x-www-form-urlencoded", "Duplicate URL-encoded params"),
    ("{\"key\":\"value1\",\"key\":\"value2\"}", "application/json", "Duplicate JSON keys"),
    # Array vs string
    ("key[]=admin&key[]=user", "application/x-www-form-urlencoded", "Array parameter submission"),
    ("{\"key\":[\"admin\",\"user\"]}", "application/json", "JSON array parameter"),
    # Nested object confusion
    ("user[role]=admin", "application/x-www-form-urlencoded", "Nested form parameter"),
    ("{\"user\":{\"role\":\"admin\"}}", "application/json", "Nested JSON parameter"),
    # Type coercion
    ("{\"is_admin\":true}", "application/json", "Boolean true"),
    ("{\"is_admin\":1}", "application/json", "Integer 1 as boolean"),
    ("{\"is_admin\":\"true\"}", "application/json", "String 'true' as boolean"),
    # Null handling
    ("{\"role\":null}", "application/json", "Null value"),
    ("role=", "application/x-www-form-urlencoded", "Empty form value"),
    # Integer overflow / negative
    ("{\"balance\":-1}", "application/json", "Negative integer"),
    ("{\"balance\":9999999999999999999}", "application/json", "Integer overflow"),
    # Array of objects
    ("{\"users\":[{\"role\":\"admin\"},{\"role\":\"user\"}]}", "application/json", "Array of objects"),
]

# Signatures that indicate the server parsed our payload differently than intended
PARSER_ERROR_SIGNATURES = [
    "unexpected", "syntax error", "parse error", "malformed",
    "bad request", "invalid", "unprocessable",
    "cannot", "unable to parse",
]


async def _test_parser_differential(
    url: str, endpoint: str, client: TalismanHTTPClient,
) -> list[dict[str, Any]]:
    """Send the same logical payload in different content-types and compare responses."""
    findings: list[dict[str, Any]] = []
    test_url = url.rstrip("/") + endpoint
    prefix = ''.join(random.choices(string.ascii_lowercase, k=4))

    for payload, content_type, description in DIFFERENTIAL_TESTS:
        headers = {"Content-Type": content_type}
        data = payload.encode() if content_type != "application/json" else payload

        try:
            if content_type == "application/json":
                r = await client.post(test_url, data=payload.encode(), headers=headers, timeout=8)
            else:
                r = await client.post(test_url, data=payload.encode(), headers=headers, timeout=8)

            # Check for server errors that suggest parsing confusion
            for sig in PARSER_ERROR_SIGNATURES:
                if sig in r.text.lower():
                    findings.append({
                        "type": "parser_error",
                        "endpoint": endpoint,
                        "content_type": content_type,
                        "payload_preview": payload[:100],
                        "description": description,
                        "status": r.status_code,
                        "evidence": r.text[:300],
                    })
                    break
        except Exception:
            pass

    # Test: same payload different content-types produce different results
    json_payload = '{"email": "test@test.com", "name": "test"}'
    form_payload = "email=test@test.com&name=test"

    try:
        r_json = await client.post(test_url, data=json_payload.encode(), headers={"Content-Type": "application/json"}, timeout=8)
        r_form = await client.post(test_url, data=form_payload.encode(), headers={"Content-Type": "application/x-www-form-urlencoded"}, timeout=8)

        # Compare status codes and response sizes
        status_diff = r_json.status_code != r_form.status_code
        size_diff = abs(len(r_json.text) - len(r_form.text)) > 50

        if status_diff or size_diff:
            findings.append({
                "type": "content_type_differential",
                "endpoint": endpoint,
                "json_status": r_json.status_code,
                "form_status": r_form.status_code,
                "description": "JSON and form-encoded requests produce different results",
                "evidence": f"JSON: {r_json.status_code}, Form: {r_form.status_code}",
            })
    except Exception:
        pass

    return findings


async def _test_uncommon_content_types(
    url: str, endpoint: str, client: TalismanHTTPClient,
) -> list[dict[str, Any]]:
    """Test parsing of uncommon/ambiguous content types."""
    findings: list[dict[str, Any]] = []
    test_url = url.rstrip("/") + endpoint
    test_payload = '{"role": "admin", "email": "test@test.com"}'

    uncommon_types = [
        ("application/xml", f"<user><role>admin</role></user>"),
        ("text/xml", f"<user><role>admin</role></user>"),
        ("text/plain", test_payload),
        ("application/javascript", test_payload),
        ("text/html", test_payload),
        ("application/x-www-form-urlencoded; charset=utf-8", "email=test@test.com"),
        ("multipart/form-data; boundary=BOUNDARY", "--BOUNDARY\r\nContent-Disposition: form-data; name=\"email\"\r\n\r\ntest@test.com\r\n--BOUNDARY--"),
    ]

    for content_type, payload in uncommon_types:
        try:
            r = await client.post(test_url, data=payload.encode(), headers={"Content-Type": content_type}, timeout=8)
            if r.status_code in (200, 201, 204):
                findings.append({
                    "type": "uncommon_content_type_accepted",
                    "endpoint": endpoint,
                    "content_type": content_type,
                    "status": r.status_code,
                    "evidence": r.text[:200],
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
    console.print(f"\n[module][+] Parser Differential Scanner[/module] -> [target]{url}[/target]")
    findings: list[dict[str, Any]] = []

    async with TalismanHTTPClient(proxy=proxy, timeout=10) as client:
        console.print(f"  Testing {len(ENDPOINTS)} endpoints for parser discrepancies...")
        for endpoint in ENDPOINTS:
            # -- 1. Content-type differential tests ----------------------------------
            diff_findings = await _test_parser_differential(url, endpoint, client)
            for df in diff_findings:
                dtype = df.get("type", "")
                endpoint_path = df.get("endpoint", endpoint)

                if dtype == "parser_error":
                    title = f"Parser confusion at {endpoint_path}: {df.get('description', 'parse error')}"
                    print_finding(title, "medium", url)
                    findings.append(df)
                    if session:
                        await session.add_finding(
                            target=url, module="parser_differential",
                            vuln_type="parser_confusion",
                            severity="medium", confidence="confirmed",
                            title=title,
                            description=f"Payload '{df.get('payload_preview', '')}' with content-type '{df.get('content_type')}' caused a parsing error at {endpoint_path}. May indicate different parsers disagree on request boundaries.",
                            evidence=df.get("evidence", ""),
                            remediation="1. Use a single, consistent parser across all layers. 2. Validate and reject malformed requests early. 3. Normalize request bodies to a canonical format.",
                            cvss_score=6.5, cwe="CWE-436",
                        )

                elif dtype == "content_type_differential":
                    title = f"Parser differential at {endpoint_path}: JSON vs form-encoded differ"
                    print_finding(title, "high", url)
                    findings.append(df)
                    if session:
                        await session.add_finding(
                            target=url, module="parser_differential",
                            vuln_type="content_type_differential",
                            severity="high", confidence="confirmed",
                            title=title,
                            description=f"JSON and form-encoded requests to {endpoint_path} produce different results. JSON status: {df.get('json_status')}, form status: {df.get('form_status')}. This discrepancy can be exploited for WAF bypass or mass assignment.",
                            evidence=df.get("evidence", ""),
                            remediation="1. Ensure all parsers treat input identically. 2. Reject ambiguous requests. 3. Use a single content-type for API endpoints.",
                            cvss_score=7.5, cwe="CWE-436",
                        )

            # -- 2. Uncommon content-type acceptance ---------------------------------
            uncommon_findings = await _test_uncommon_content_types(url, endpoint, client)
            for uf in uncommon_findings:
                if uf.get("type") == "uncommon_content_type_accepted":
                    title = f"Uncommon content-type accepted at {uf.get('endpoint', endpoint)}: {uf.get('content_type', 'unknown')}"
                    print_finding(title, "medium", url)
                    findings.append(uf)

    console.print(f"  Parser differential scan complete -- {len(findings)} issues")
    return {"target": url, "findings": findings, "count": len(findings)}
