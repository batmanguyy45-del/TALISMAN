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
    """Fail closed until the operator supplies a dedicated safe SSJI fixture.

    The previous implementation guessed endpoints and sent command execution,
    filesystem-read, error, and timing payloads. Those behaviors are unsuitable
    for unattended testing of an ordinary production target. Reflection, generic
    errors, and a single latency spike cannot establish server-side code execution.
    """
    url = target if "://" in target else f"https://{target}"
    if scope is None:
        return {
            "target": url, "findings": [], "candidates": [], "count": 0,
            "candidate_count": 0, "error": "scope_enforcer_required",
        }
    scope.assert_in_scope(url)

    return {
        "target": url,
        "findings": [],
        "candidates": [],
        "count": 0,
        "candidate_count": 0,
        "skipped": True,
        "reason": (
            "Generic SSJI probing is disabled: prior probes guessed endpoints "
            "and included command-execution and filesystem-read payloads. "
            "A safe implementation requires an operator-supplied disposable "
            "fixture, a harmless deterministic expression oracle, and repeated "
            "baseline/control measurements. No network requests were sent."
        ),
    }
