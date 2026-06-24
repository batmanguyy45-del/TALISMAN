"""
SSTI Scanner — Server-Side Template Injection
Engines: Jinja2, Twig, Freemarker, Velocity, Smarty, Mako, Pebble

FALSE-POSITIVE ELIMINATION STRATEGY
====================================
Naive approach: send {{7*7}} and check if "49" is in the response.
Problem: "49" is a very common string on any webpage (prices, IDs, CSS values, etc.)

Correct approach:
  1. Generate TWO unique large-number multiplication canaries per request.
  2. Both expected values must appear in the response.
  3. Follow-up probe with a DIFFERENT math expression to confirm.
  4. Baseline check: verify the canary values are NOT in the plain response
     without any injection.
"""
from __future__ import annotations
import asyncio
import random
import re
import urllib.parse
from typing import Any

from talisman.utils.http_client import TalismanHTTPClient
from talisman.utils.logger import get_logger, console, print_finding

log = get_logger(__name__)

# ---------------------------------------------------------------------------
# Engine fingerprint table
# Each entry: (probe_template, expected_result_regex, engine_name)
# We use large random numbers so the result is statistically unique.
# ---------------------------------------------------------------------------
def _make_probe(a: int, b: int) -> list[tuple[str, str, str]]:
    """Return engine-specific probes for a * b = expected."""
    expected = a * b
    return [
        # Jinja2 / Twig / Nunjucks  {{expr}}
        (f"{{{{{a}*{b}}}}}", str(expected), "jinja2/twig"),
        # Freemarker / Velocity / Spring EL  ${expr}
        (f"${{{a}*{b}}}", str(expected), "freemarker/velocity/spring"),
        # Smarty  {expr}  (less common)
        (f"{{{a}*{b}}}", str(expected), "smarty"),
        # Ruby ERB / Thymeleaf  <%= expr %>
        (f"<%= {a}*{b} %>", str(expected), "erb"),
        # Mako / Cheetah  ${expr}
        (f"${{str({a}*{b})}}", str(expected), "mako"),
        # OGNL / Spring EL   *{expr}
        (f"*{{{a}*{b}}}", str(expected), "ognl/spring"),
    ]


def _unique_numbers() -> tuple[int, int, int, int]:
    """Generate two pairs of large coprime-ish numbers for canaries."""
    a1 = random.randint(10000, 99999)
    b1 = random.randint(10000, 99999)
    # Second pair for confirmation – completely different
    a2 = random.randint(10000, 99999)
    b2 = random.randint(10000, 99999)
    # Make sure expected values are distinct and look unusual
    while (a1 * b1) == (a2 * b2):
        a2 = random.randint(10000, 99999)
    return a1, b1, a2, b2


async def _baseline_has_value(
    url: str,
    param: str,
    value: str,
    method: str,
    client: TalismanHTTPClient,
) -> bool:
    """Return True if *value* appears in a clean (non-injected) response."""
    parsed = urllib.parse.urlparse(url)
    base_params = dict(urllib.parse.parse_qsl(parsed.query))
    clean_params = {**base_params, param: "hello_world"}
    try:
        if method == "GET":
            test_url = parsed._replace(
                query=urllib.parse.urlencode(clean_params)
            ).geturl()
            r = await client.get(test_url, timeout=10)
        else:
            r = await client.post(url, data={param: "hello_world"}, timeout=10)
        return value in r.text
    except Exception:
        return False


async def _send_probe(
    url: str,
    param: str,
    payload: str,
    method: str,
    client: TalismanHTTPClient,
) -> str:
    """Send a single probe and return response text, or empty string on error."""
    parsed = urllib.parse.urlparse(url)
    base_params = dict(urllib.parse.parse_qsl(parsed.query))
    try:
        if method == "GET":
            test_params = {**base_params, param: payload}
            test_url = parsed._replace(
                query=urllib.parse.urlencode(test_params)
            ).geturl()
            r = await client.get(test_url, timeout=10)
        else:
            r = await client.post(url, data={param: payload}, timeout=10)
        return r.text
    except Exception:
        return ""


async def _verify_ssti(
    url: str,
    param: str,
    method: str,
    engine_name: str,
    probe_template: str,
    a1: int,
    b1: int,
    a2: int,
    b2: int,
    client: TalismanHTTPClient,
) -> dict[str, Any] | None:
    """
    Two-stage verification:
      Stage 1 – first canary (a1*b1) appears in response.
      Stage 2 – second canary (a2*b2) appears in a fresh request with different numbers.
      Both stages must pass before reporting.
    """
    expected1 = str(a1 * b1)
    expected2 = str(a2 * b2)

    # Replace placeholder numbers in the template with actual canary values
    payload1 = probe_template.replace(str(a1), str(a1)).replace(str(b1), str(b1))
    # Build second payload using same template structure
    payload2 = probe_template.replace(str(a1), str(a2)).replace(str(b1), str(b2))

    # ---- Stage 1 ----
    response1 = await _send_probe(url, param, payload1, method, client)
    if not response1 or expected1 not in response1:
        return None

    # ---- Sanity check: is expected1 in a clean response? ----
    if await _baseline_has_value(url, param, expected1, method, client):
        log.debug(
            "ssti_baseline_collision",
            param=param,
            expected=expected1,
            msg="Value present without injection – skipping",
        )
        return None

    # ---- Stage 2 – different numbers, same engine probe ----
    response2 = await _send_probe(url, param, payload2, method, client)
    if not response2 or expected2 not in response2:
        return None

    # ---- Final: confirm expected2 isn't in clean baseline ----
    if await _baseline_has_value(url, param, expected2, method, client):
        return None

    return {
        "param": param,
        "method": method,
        "engine": engine_name,
        "payload1": payload1,
        "payload2": payload2,
        "expected1": expected1,
        "expected2": expected2,
        "evidence": (
            f"Expression '{payload1}' evaluated to '{expected1}'; "
            f"cross-confirmed with '{payload2}' → '{expected2}'"
        ),
        "request": f"{method} {url}?{param}={urllib.parse.quote(payload1)} HTTP/1.1",
    }


async def _test_param(
    url: str,
    param: str,
    method: str,
    client: TalismanHTTPClient,
) -> dict[str, Any] | None:
    a1, b1, a2, b2 = _unique_numbers()
    probes = _make_probe(a1, b1)

    for probe_template, _, engine_name in probes:
        result = await _verify_ssti(
            url, param, method, engine_name,
            probe_template, a1, b1, a2, b2, client,
        )
        if result:
            return result
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
    console.print(
        f"\n[module] SSTI Scanner[/module] → [target]{url}[/target]"
    )
    findings: list[dict[str, Any]] = []

    parsed = urllib.parse.urlparse(url)
    params = list(dict(urllib.parse.parse_qsl(parsed.query)).keys())
    if not params:
        params = [
            "name", "template", "message", "subject", "greeting",
            "text", "content", "body", "page", "title",
            "q", "search", "lang", "view", "render",
        ]

    async with TalismanHTTPClient(proxy=proxy, timeout=15) as client:
        tasks = [
            _test_param(url, p, m, client)
            for p in params
            for m in ["GET", "POST"]
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        seen_params: set[str] = set()
        for result in results:
            if not isinstance(result, dict):
                continue
            key = f"{result['param']}:{result['method']}"
            if key in seen_params:
                continue
            seen_params.add(key)

            severity = "critical"
            title = (
                f"SSTI ({result['engine']}) — "
                f"param '{result['param']}' via {result['method']}"
            )
            print_finding(title, severity, url)
            findings.append(result)

            if session:
                await session.add_finding(
                    target=url,
                    module="ssti",
                    vuln_type="ssti",
                    severity=severity,
                    confidence="confirmed",
                    title=title,
                    description=(
                        f"Server-Side Template Injection confirmed in parameter "
                        f"'{result['param']}' (engine: {result['engine']}). "
                        f"Two independent math canaries both evaluated correctly "
                        f"server-side, ruling out false positives."
                    ),
                    request=result["request"],
                    evidence=result["evidence"],
                    reproduction=(
                        f"Send: {result['method']} with "
                        f"{result['param']}={result['payload1']}"
                        f"\nConfirm: {result['param']}={result['payload2']}"
                    ),
                    remediation=(
                        "1. Never pass user input directly to template engines.\n"
                        "2. Use sandboxed template evaluation with no access to builtins.\n"
                        "3. Escape all user-supplied data before rendering.\n"
                        "4. Consider logic-less templates (Mustache/Handlebars) "
                        "for user content."
                    ),
                    cvss_score=10.0,
                    cwe="CWE-94",
                    references=[
                        "https://portswigger.net/web-security/"
                        "server-side-template-injection"
                    ],
                )

    console.print(f"  Found {len(findings)} confirmed SSTI vulnerabilities")
    return {"target": url, "findings": findings, "count": len(findings)}
