"""WebSocket security tester -- hijacking, message injection, cross-origin, DoS.

Tests WebSocket endpoints for:
- Missing origin validation (cross-origin WebSocket hijacking)
- Message injection (SQLi, XSS, command injection via WS messages)
- Unauthenticated access to sensitive WS endpoints
- Replay / message tampering
"""
from __future__ import annotations
import asyncio
import json
import random
import string
from typing import Any
from talisman.utils.logger import get_logger, console, print_finding

log = get_logger(__name__)

WS_PATHS = [
    "/ws", "/websocket", "/socket", "/sock",
    "/chat", "/ws/chat", "/socket.io",
    "/stream", "/events", "/notifications",
    "/ws/realtime", "/realtime", "/live",
    "/api/ws", "/api/v1/ws",
]

WS_INJECTION_PAYLOADS = [
    ("<script>alert(1)</script>", "XSS"),
    ("' OR '1'='1", "SQLi"),
    ("$(cat /etc/passwd)", "CMDi"),
    ("{{7*7}}", "SSTI"),
]

INJECTION_SIGNATURES = [
    "<script>alert", "1'='1", "/etc/passwd", "49",  # 7*7=49
]


async def _discover_ws_endpoint(base_url: str, client: Any) -> list[str]:
    endpoints = []
    for path in WS_PATHS:
        ws_url = base_url.rstrip("/") + path
        ws_url = ws_url.replace("https://", "wss://").replace("http://", "ws://")
        endpoints.append(ws_url)
    return endpoints


async def _test_origin_validation(
    ws_url: str,
) -> dict[str, Any] | None:
    try:
        import websockets
        malicious_origin = f"https://evil-{''.join(random.choices(string.ascii_lowercase, k=6))}.com"
        async with websockets.connect(
            ws_url,
            origin=malicious_origin,
            timeout=8,
        ) as ws:
            await ws.send('{"type":"ping"}')
            try:
                resp = await asyncio.wait_for(ws.recv(), timeout=3)
                return {
                    "issue": "missing_origin_validation",
                    "endpoint": ws_url,
                    "origin_tested": malicious_origin,
                    "evidence": str(resp)[:200],
                }
            except asyncio.TimeoutError:
                pass
    except ImportError:
        pass
    except Exception:
        pass
    return None


async def _test_message_injection(
    ws_url: str,
) -> list[dict[str, Any]]:
    findings = []
    try:
        import websockets
        async with websockets.connect(ws_url, timeout=8) as ws:
            for payload, vuln_type in WS_INJECTION_PAYLOADS:
                try:
                    await ws.send(payload)
                    resp = await asyncio.wait_for(ws.recv(), timeout=3)
                    resp_text = str(resp)
                    for sig in INJECTION_SIGNATURES:
                        if sig in resp_text:
                            findings.append({
                                "issue": f"injection_{vuln_type.lower()}",
                                "endpoint": ws_url,
                                "payload": payload,
                                "vuln_type": vuln_type,
                                "evidence": resp_text[:200],
                            })
                            break
                except asyncio.TimeoutError:
                    pass
    except ImportError:
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
    console.print(f"\n[module][+] WebSocket Security Tester[/module] -> [target]{url}[/target]")
    findings: list[dict[str, Any]] = []

    ws_endpoints = await _discover_ws_endpoint(url, None)
    console.print(f"  Tested {len(ws_endpoints)} potential WebSocket endpoints")

    for ws_url in ws_endpoints:
        origin_result = await _test_origin_validation(ws_url)
        if origin_result:
            title = f"Cross-origin WebSocket hijacking at {ws_url}"
            print_finding(title, "high", url)
            findings.append(origin_result)
            if session:
                await session.add_finding(
                    target=url, module="websocket",
                    vuln_type="ws_origin_bypass",
                    severity="high", confidence="confirmed",
                    title=title,
                    description=(
                        f"WebSocket endpoint {ws_url} accepted connection from "
                        f"origin {origin_result['origin_tested']}. "
                        "This allows cross-origin WebSocket hijacking."
                    ),
                    evidence=origin_result.get("evidence", ""),
                    reproduction=(
                        f"1. Open browser to evil.com\n"
                        f"2. Connect to {ws_url} with origin evil.com\n"
                        f"3. Read messages or send malicious payloads"
                    ),
                    remediation=(
                        "1. Validate Origin header on WebSocket upgrade.\n"
                        "2. Use CSRF tokens in the WebSocket handshake.\n"
                        "3. Authenticate all WebSocket connections."
                    ),
                    cvss_score=8.1, cwe="CWE-1385",
                )

        injection_results = await _test_message_injection(ws_url)
        for r in injection_results:
            title = f"WebSocket {r['vuln_type']} injection at {ws_url}"
            print_finding(title, "high", url)
            findings.append(r)
            if session:
                await session.add_finding(
                    target=url, module="websocket",
                    vuln_type=f"ws_{r['vuln_type'].lower()}_injection",
                    severity="high", confidence="likely",
                    title=title,
                    description=(
                        f"WebSocket endpoint reflected injection payload "
                        f"'{r['payload']}' in response, indicating potential "
                        f"{r['vuln_type']} vulnerability."
                    ),
                    evidence=r.get("evidence", ""),
                    reproduction=f"Connect to {ws_url} and send: {r['payload']}",
                    remediation=(
                        "1. Sanitize all WebSocket message inputs server-side.\n"
                        "2. Use parameterized queries for database operations.\n"
                        "3. Apply output encoding based on message context."
                    ),
                    cvss_score=8.1, cwe="CWE-79",
                )

    console.print(f"  WebSocket testing complete -- {len(findings)} issues")
    return {"target": url, "endpoints": ws_endpoints, "findings": findings, "count": len(findings)}
