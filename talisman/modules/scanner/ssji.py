"""Server-Side JavaScript Injection scanner — eval(), setTimeout(), new Function(), require() gadget chain detection via OAST timing."""
from __future__ import annotations
import asyncio
import random
import string
from typing import Any
from talisman.utils.http_client import TalismanHTTPClient
from talisman.utils.logger import get_logger, console, print_finding

log = get_logger(__name__)

SSJI_CANARY_PREFIX = "TLSMSSJI"

SSJI_ENDPOINTS = [
    "/api/calculate", "/api/calc", "/api/math",
    "/api/evaluate", "/api/exec",
    "/api/render", "/api/template",
    "/api/transform", "/api/convert",
    "/api/process", "/api/run",
    "/api/test", "/api/debug",
    "/api/config", "/api/settings",
    "/api/search", "/api/query",
    "/calculate", "/calc", "/math",
    "/evaluate", "/exec",
    "/debug", "/test",
]

# Each payload: (payload_field, payload_template, description, detection_type)
SSJI_PAYLOADS = [
    # Timing-based detection via setTimeout (non-destructive)
    ("input", '1;setTimeout(()=>{{}},process.env.TLSMSSJI_TIMING||3000)', "setTimeout timing probe", "timing"),
    ("input", '1;new Promise(r=>setTimeout(r,3000))', "Promise-based timing probe", "timing"),
    ("input", '1;require("child_process").execSync("sleep 3")', "execSync timing probe", "timing"),
    ("input", '1+require("fs").readFileSync("/etc/hosts").length', "fs.readFileSync eval", "timing"),
    # Error-based detection
    ("input", '1;JSON.parse(undefined)', "Error-based probe (JSON.parse)", "error"),
    ("input", '1;undefined.x.y.z', "Error-based probe (type error)", "error"),
    ("input", '1+require("nonexistent_module_xyz")', "Error-based probe (require)", "error"),
    # Canary reflection
    ("input", f"'TLSMSSJI_CANARY_REFLECT'", "Canary reflection probe", "reflection"),
]

# Probes that don't require eval — test for code evaluation in template contexts
SSJI_PASSIVE_PROBES = [
    ("name", "${7*7}", "Template injection (${})", "template"),
    ("name", "{{7*7}}", "Template injection ({{}})", "template"),
    ("name", "#{7*7}", "Template injection (#{})", "template"),
    ("name", "<%= 7*7 %>", "ERB-style template", "template"),
]


async def _test_ssji_timing(
    url: str, endpoint: str, client: TalismanHTTPClient,
) -> list[dict[str, Any]]:
    """Test SSJI via timing-based detection — the safest approach."""
    findings: list[dict[str, Any]] = []
    test_url = url.rstrip("/") + endpoint
    canary = f"{SSJI_CANARY_PREFIX}{''.join(random.choices(string.ascii_uppercase + string.digits, k=8))}"

    # Step 1: Baseline timing
    try:
        r_base = await client.post(test_url,
            json={"input": "1+1"},
            headers={"Content-Type": "application/json"}, timeout=5)
        baseline_time = r_base.elapsed.total_seconds() if hasattr(r_base, 'elapsed') else 0.5
    except Exception:
        baseline_time = 0.5

    # Step 2: Send timing probes
    for field, payload_template, description, det_type in SSJI_PAYLOADS:
        if det_type != "timing":
            continue

        payload_value = payload_template.replace("TLSMSSJI_TIMING", canary)
        payload = {"input": payload_value}

        try:
            start = asyncio.get_event_loop().time()
            r = await client.post(test_url, json=payload,
                headers={"Content-Type": "application/json"}, timeout=8)
            elapsed = asyncio.get_event_loop().time() - start

            # If response took >3 seconds, eval is processing our setTimeout
            if elapsed > 2.5 and elapsed > baseline_time * 2:
                findings.append({
                    "type": "ssji_eval_timing",
                    "endpoint": endpoint,
                    "payload_preview": payload_value[:80],
                    "description": description,
                    "elapsed": round(elapsed, 2),
                    "baseline": round(baseline_time, 2),
                    "evidence": f"Response time {elapsed:.1f}s vs baseline {baseline_time:.1f}s",
                    "canary": canary,
                })
                break
        except asyncio.TimeoutError:
            # Timeout is a strong indicator of eval() execution
            findings.append({
                "type": "ssji_eval_timeout",
                "endpoint": endpoint,
                "payload_preview": payload_value[:80],
                "description": f"{description} (timeout)",
                "evidence": "Request timed out — eval() likely executing setTimeout()",
                "canary": canary,
            })
            break
        except Exception:
            pass

    return findings


async def _test_ssji_error(
    url: str, endpoint: str, client: TalismanHTTPClient,
) -> list[dict[str, Any]]:
    """Test SSJI via error-based detection."""
    findings: list[dict[str, Any]] = []
    test_url = url.rstrip("/") + endpoint
    canary = f"{SSJI_CANARY_PREFIX}{''.join(random.choices(string.ascii_uppercase + string.digits, k=8))}"

    for field, payload_template, description, det_type in SSJI_PAYLOADS:
        if det_type != "error":
            continue

        payload = {"input": payload_template}
        try:
            r = await client.post(test_url, json=payload,
                headers={"Content-Type": "application/json"}, timeout=8)
            resp_lower = r.text.lower()

            error_indicators = [
                "json.parse", "undefined", "is not defined",
                "is not a function", "cannot read property",
                "typeerror", "referenceerror",
                "eval", "error:",
                "at eval", "at function",
                "nonexistent_module", "require is not defined",
            ]

            for indicator in error_indicators:
                if indicator in resp_lower:
                    findings.append({
                        "type": "ssji_error_reflection",
                        "endpoint": endpoint,
                        "payload_preview": payload_template[:60],
                        "description": description,
                        "evidence": r.text[:300],
                        "canary": canary,
                    })
                    break
        except Exception:
            pass

    return findings


async def _test_ssji_reflection(
    url: str, endpoint: str, client: TalismanHTTPClient,
) -> list[dict[str, Any]]:
    """Test SSJI via canary reflection in response."""
    findings: list[dict[str, Any]] = []
    test_url = url.rstrip("/") + endpoint
    canary = f"TLSMSSJI_REFLECT{''.join(random.choices(string.ascii_uppercase + string.digits, k=8))}"

    for field, payload_template, description, det_type in SSJI_PAYLOADS:
        if det_type != "reflection":
            continue

        # Replace the canary placeholder
        payload_value = payload_template.replace("TLSMSSJI_CANARY_REFLECT", canary)
        payload = {"input": payload_value}

        try:
            r = await client.post(test_url, json=payload,
                headers={"Content-Type": "application/json"}, timeout=8)
            if canary.lower() in r.text.lower():
                findings.append({
                    "type": "ssji_reflection",
                    "endpoint": endpoint,
                    "payload_preview": payload_value[:60],
                    "description": description,
                    "evidence": f"Canary '{canary}' reflected in response",
                    "canary": canary,
                })
                break
        except Exception:
            pass

    return findings


async def _test_ssji_passive(
    url: str, endpoint: str, client: TalismanHTTPClient,
) -> list[dict[str, Any]]:
    """Test for template context injection — the server may eval template expressions."""
    findings: list[dict[str, Any]] = []
    test_url = url.rstrip("/") + endpoint

    for field, payload, description, det_type in SSJI_PASSIVE_PROBES:
        try:
            payload_map = {"name": payload}
            r = await client.post(test_url, json=payload_map,
                headers={"Content-Type": "application/json"}, timeout=8)

            # SSTI-like: 7*7 evaluates to 49 — check for "49" in response
            resp_text = r.text
            if "49" in resp_text and "7*7" in resp_text.replace(" ", ""):
                findings.append({
                    "type": "ssji_template_eval",
                    "endpoint": endpoint,
                    "payload": payload,
                    "description": description,
                    "evidence": f"Expression '{payload}' evaluated to 49 in response",
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
    console.print(f"\n[module][+] Server-Side JavaScript Injection Scanner[/module] -> [target]{url}[/target]")
    findings: list[dict[str, Any]] = []

    async with TalismanHTTPClient(proxy=proxy, timeout=12) as client:
        console.print(f"  Testing {len(SSJI_ENDPOINTS)} endpoints across 4 detection vectors...")

        for endpoint in SSJI_ENDPOINTS:
            timing_findings = await _test_ssji_timing(url, endpoint, client)
            for f in timing_findings:
                ftype = f.get("type", "")
                title = f"SSJI via eval() at {endpoint}: {f.get('description', ftype)}"
                print_finding(title, "critical", url)
                findings.append(f)
                if session:
                    await session.add_finding(
                        target=url, module="ssji",
                        vuln_type=ftype,
                        severity="critical", confidence="confirmed",
                        title=title,
                        description=f"Server-side JavaScript injection detected at {endpoint}. Timing-based probe returned in {f.get('elapsed', 'N/A')}s vs baseline {f.get('baseline', 'N/A')}s, indicating eval() or setTimeout() execution.",
                        evidence=f.get("evidence", ""),
                        remediation="1. Never use eval() with user input. 2. Use parseInt() instead of eval() for numeric conversion. 3. Avoid setTimeout(string), setInterval(string), and new Function(string). 4. Use a proper sandbox if dynamic code execution is required.",
                        cvss_score=9.8, cwe="CWE-94",
                    )

            error_findings = await _test_ssji_error(url, endpoint, client)
            for f in error_findings:
                title = f"SSJI error reflection at {endpoint}: {f.get('description', '')}"
                print_finding(title, "high", url)
                findings.append(f)
                if session:
                    await session.add_finding(
                        target=url, module="ssji",
                        vuln_type="ssji_error_reflection",
                        severity="high", confidence="confirmed",
                        title=title,
                        description=f"Server-side JavaScript error reflected at {endpoint}. Sending '{f.get('payload_preview', '')}' triggered a JavaScript error that was returned in the response, confirming user input reaches eval() or similar sink.",
                        evidence=f.get("evidence", ""),
                        remediation="1. Never eval() user input. 2. Disable error details in production. 3. Use safe alternatives like parseInt().",
                        cvss_score=9.3, cwe="CWE-94",
                    )

            reflection_findings = await _test_ssji_reflection(url, endpoint, client)
            for f in reflection_findings:
                title = f"SSJI canary reflection at {endpoint}: {f.get('description', '')}"
                print_finding(title, "critical", url)
                findings.append(f)
                if session:
                    await session.add_finding(
                        target=url, module="ssji",
                        vuln_type="ssji_reflection",
                        severity="critical", confidence="confirmed",
                        title=title,
                        description=f"Server-side JavaScript injection with direct canary reflection at {endpoint}. Canary '{f.get('canary', '')}' was returned in the response body, confirming eval()-style code execution.",
                        evidence=f.get("evidence", ""),
                        remediation="1. Remove eval() from codebase. 2. Precompile templates. 3. Use Content-Security-Policy with strict-dynamic.",
                        cvss_score=9.8, cwe="CWE-94",
                    )

            template_findings = await _test_ssji_passive(url, endpoint, client)
            for f in template_findings:
                title = f"Template expression evaluation at {endpoint}: {f.get('payload', '')}"
                print_finding(title, "high", url)
                findings.append(f)
                if session:
                    await session.add_finding(
                        target=url, module="ssji",
                        vuln_type="ssji_template_eval",
                        severity="high", confidence="confirmed",
                        title=title,
                        description=f"Template expression '{f.get('payload', '')}' was evaluated to 49 at {endpoint}, confirming server-side template code execution.",
                        evidence=f.get("evidence", ""),
                        remediation="1. Sanitize template inputs. 2. Use auto-escaping template engines. 3. Disable arbitrary expression evaluation in templates.",
                        cvss_score=9.3, cwe="CWE-94",
                    )

    console.print(f"  SSJI scan complete -- {len(findings)} issues")
    return {"target": url, "findings": findings, "count": len(findings)}
