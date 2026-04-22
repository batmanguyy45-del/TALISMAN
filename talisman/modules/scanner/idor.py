"""IDOR / BOLA scanner — object ID enumeration across authenticated endpoints."""
from __future__ import annotations
import asyncio
import json
import re
import uuid
from typing import Any
from talisman.utils.http_client import TalismanHTTPClient
from talisman.utils.logger import get_logger, console, print_finding

log = get_logger(__name__)

ID_PARAMS = ["id", "user_id", "account_id", "order_id", "invoice_id",
             "document_id", "file_id", "report_id", "profile_id", "uid",
             "record_id", "item_id", "object_id", "ref", "reference"]

async def _test_idor(
    url: str,
    param: str,
    baseline_id: str,
    test_ids: list[str],
    client: TalismanHTTPClient,
    auth_headers: dict[str, str],
) -> dict[str, Any] | None:
    import urllib.parse
    parsed = urllib.parse.urlparse(url)
    base_params = dict(urllib.parse.parse_qsl(parsed.query))

    # Get baseline response
    base_params[param] = baseline_id
    try:
        base_r = await client.get(
            parsed._replace(query=urllib.parse.urlencode(base_params)).geturl(),
            headers=auth_headers,
        )
        if base_r.status_code not in (200, 201):
            return None
        base_len = len(base_r.text)
        base_status = base_r.status_code
    except Exception:
        return None

    for test_id in test_ids:
        test_params = {**base_params, param: test_id}
        test_url = parsed._replace(query=urllib.parse.urlencode(test_params)).geturl()
        try:
            r = await client.get(test_url, headers=auth_headers)
            # IDOR indicators: same status, similar body length, different content
            if r.status_code == base_status and abs(len(r.text) - base_len) < base_len * 0.5:
                if r.text != base_r.text and len(r.text) > 50:
                    return {
                        "param": param,
                        "baseline_id": baseline_id,
                        "accessed_id": test_id,
                        "status": r.status_code,
                        "evidence": r.text[:300],
                        "request": f"GET {test_url} HTTP/1.1",
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
    auth_token: str | None = None,
    **kwargs: Any,
) -> dict[str, Any]:
    url = target if "://" in target else f"https://{target}"
    console.print(f"\n[module]⚡ IDOR Scanner[/module] → [target]{url}[/target]")
    findings: list[dict[str, Any]] = []

    auth_headers: dict[str, str] = {}
    if auth_token:
        auth_headers["Authorization"] = f"Bearer {auth_token}"

    import urllib.parse
    parsed = urllib.parse.urlparse(url)
    existing_params = dict(urllib.parse.parse_qsl(parsed.query))
    params_to_test = {k: v for k, v in existing_params.items()
                      if any(ip in k.lower() for ip in ID_PARAMS)}

    if not params_to_test:
        # Try common ID params with value 1
        params_to_test = {p: "1" for p in ID_PARAMS[:5]}

    async with TalismanHTTPClient(proxy=proxy, timeout=15) as client:
        for param, baseline_id in params_to_test.items():
            # Generate test IDs: sequential, different ranges
            try:
                base_int = int(baseline_id)
                test_ids = [str(i) for i in range(max(1, base_int - 5), base_int + 10)
                            if str(i) != baseline_id][:10]
            except ValueError:
                test_ids = ["1", "2", "3", "100", "999", str(uuid.uuid4())]

            result = await _test_idor(url, param, baseline_id, test_ids, client, auth_headers)
            if result:
                severity = "high"
                title = f"IDOR — parameter '{param}' allows access to ID {result['accessed_id']}"
                print_finding(title, severity, url)
                findings.append(result)
                if session:
                    await session.add_finding(
                        target=url, module="idor",
                        vuln_type="idor",
                        severity=severity, confidence="likely",
                        title=title,
                        description=(
                            f"Insecure Direct Object Reference in parameter '{param}'. "
                            f"Changing ID from '{baseline_id}' to '{result['accessed_id']}' "
                            f"returned a different but valid resource (status {result['status']})."
                        ),
                        request=result["request"],
                        evidence=result["evidence"],
                        reproduction=f"Change {param}={baseline_id} to {param}={result['accessed_id']}",
                        remediation=(
                            "1. Implement object-level authorization checks on every resource access.\n"
                            "2. Use indirect references (UUIDs or opaque tokens) instead of sequential IDs.\n"
                            "3. Validate that the authenticated user owns or has permission for the requested resource."
                        ),
                        cvss_score=8.1, cwe="CWE-639",
                        references=["https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/"],
                    )

    console.print(f"  Found {len(findings)} IDOR vulnerabilities")
    return {"target": url, "findings": findings, "count": len(findings)}
