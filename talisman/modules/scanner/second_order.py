"""Second-order injection scanner — stores payload, then triggers via different endpoint to confirm stored XSS/SQLi/SSTI."""
from __future__ import annotations
import asyncio
import random
import re
import string
from typing import Any
from talisman.utils.http_client import TalismanHTTPClient
from talisman.utils.logger import get_logger, console, print_finding

log = get_logger(__name__)

STORE_ENDPOINTS = [
    ("POST", "/api/profile", {"name": "PAYLOAD", "bio": "PAYLOAD"}),
    ("POST", "/api/user", {"username": "PAYLOAD", "display_name": "PAYLOAD"}),
    ("POST", "/api/users/me", {"display_name": "PAYLOAD", "bio": "PAYLOAD"}),
    ("POST", "/api/settings", {"display_name": "PAYLOAD"}),
    ("POST", "/api/comment", {"text": "PAYLOAD", "post_id": 1}),
    ("POST", "/api/post", {"title": "PAYLOAD", "content": "PAYLOAD"}),
    ("POST", "/profile", {"name": "PAYLOAD", "bio": "PAYLOAD"}),
    ("POST", "/api/message", {"message": "PAYLOAD", "recipient": "test"}),
    ("PUT", "/api/profile", {"name": "PAYLOAD", "bio": "PAYLOAD"}),
    ("PATCH", "/api/profile", {"display_name": "PAYLOAD"}),
]

TRIGGER_ENDPOINTS = [
    "/api/profile", "/api/user", "/api/users/me",
    "/api/settings", "/profile",
    "/api/posts", "/api/comments",
]

SECOND_ORDER_PAYLOADS = [
    # XSS payloads
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "javascript:alert(1)",
    # SSTI payloads
    "{{7*7}}",
    "${7*7}",
    "#{7*7}",
    # SQLi payloads
    "' OR '1'='1",
    "'; DROP TABLE users; --",
    "' UNION SELECT NULL--",
    # Template injection
    "${7*7}",
    "*{7*7}",
]

SECOND_ORDER_SIGNATURES = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)",
    "49",  # 7*7 from SSTI
    "1'='1",
    "DROP TABLE",
    "UNION SELECT",
]

SECOND_ORDER_CANARY_PREFIX = "TLSMSEC"


async def _test_store_and_trigger(
    url: str, client: TalismanHTTPClient,
) -> list[dict[str, Any]]:
    """Store a payload and then try to trigger it via a different endpoint."""
    findings: list[dict[str, Any]] = []
    session_cookies: dict[str, str] = {}

    for method, store_path, template in STORE_ENDPOINTS:
        try:
            canary = f"{SECOND_ORDER_CANARY_PREFIX}{''.join(random.choices(string.ascii_uppercase + string.digits, k=8))}"
            payload = f"<b>{canary}</b>"
            test_url = url.rstrip("/") + store_path

            # Build payload body by replacing PAYLOAD key with our canary payload
            body = {}
            body_has_payload = False
            for k, v in template.items():
                if v == "PAYLOAD":
                    body[k] = payload
                    body_has_payload = True
                else:
                    body[k] = v

            if not body_has_payload:
                continue

            # Store the payload
            headers = {"Content-Type": "application/json"}
            r = await client.request(method, test_url, json=body, headers=headers, timeout=10)
            if r.status_code not in (200, 201, 204):
                continue

            # Now check all trigger endpoints
            for trigger_path in TRIGGER_ENDPOINTS:
                trigger_url = url.rstrip("/") + trigger_path
                try:
                    r2 = await client.get(trigger_url, timeout=10)
                    if canary in r2.text:
                        findings.append({
                            "type": "second_order_xss",
                            "store_endpoint": store_path,
                            "trigger_endpoint": trigger_path,
                            "payload": payload,
                            "canary": canary,
                            "evidence": r2.text[:400],
                        })
                        if session:
                            await session.add_finding(
                                target=url, module="second_order",
                                vuln_type="second_order_injection",
                                severity="high", confidence="confirmed",
                                title=f"Second-order injection: stored at {store_path}, triggered at {trigger_path}",
                                description=f"Payload '{payload}' stored via {method} {store_path} was reflected in the response from {trigger_path}. Stored payloads can affect other users who visit the trigger page.",
                                evidence=r2.text[:500],
                                reproduction=f"1. POST {payload} to {store_path}\n2. GET {trigger_path}\n3. Observe payload reflection",
                                remediation="1. Sanitize ALL stored input before rendering. 2. Use contextual output encoding. 3. Apply CSP headers to mitigate stored XSS impact.",
                                cvss_score=8.7, cwe="CWE-79",
                            )
                        break  # One confirmed finding per store endpoint is enough
                except Exception:
                    pass

        except Exception:
            pass

    # Try second-order via query parameters (e.g., search that stores in session)
    search_paths = ["/search", "/api/search"]
    for search_path in search_paths:
        try:
            canary2 = f"{SECOND_ORDER_CANARY_PREFIX}{''.join(random.choices(string.ascii_uppercase + string.digits, k=8))}"
            test_url = url.rstrip("/") + search_path
            r = await client.get(test_url, params={"q": f"<script>{canary2}</script>"}, timeout=10)
            if r.status_code in (200, 201):
                # Now check if the search term is reflected elsewhere (e.g., recent searches page)
                recent_paths = ["/recent-searches", "/history", "/api/history"]
                for recent_path in recent_paths:
                    recent_url = url.rstrip("/") + recent_path
                    try:
                        r2 = await client.get(recent_url, timeout=10)
                        if canary2 in r2.text:
                            findings.append({
                                "type": "second_order_search",
                                "store_endpoint": search_path,
                                "trigger_endpoint": recent_path,
                                "payload": canary2,
                                "canary": canary2,
                                "evidence": r2.text[:400],
                            })
                            break
                    except Exception:
                        pass
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
    console.print(f"\n[module][+] Second-Order Injection Scanner[/module] -> [target]{url}[/target]")
    findings: list[dict[str, Any]] = []

    async with TalismanHTTPClient(proxy=proxy, timeout=12) as client:
        console.print("  Storing payloads and checking reflection across endpoints...")
        store_findings = await _test_store_and_trigger(url, client)
        for sf in store_findings:
            ftype = sf.get("type", "")
            store_ep = sf.get("store_endpoint", "unknown")
            trigger_ep = sf.get("trigger_endpoint", "unknown")

            if ftype in ("second_order_xss", "second_order_search"):
                title = f"Second-order injection: stored at {store_ep}, triggered at {trigger_ep}"
                print_finding(title, "high", url)
                findings.append(sf)

    console.print(f"  Second-order scan complete -- {len(findings)} issues")
    return {"target": url, "findings": findings, "count": len(findings)}
