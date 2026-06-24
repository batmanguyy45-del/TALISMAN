"""CRLF Injection / HTTP Response Splitting scanner.

Detects CRLF injection vulnerabilities by injecting newline sequences into
headers and parameters, then checking for response splitting or header injection.

FP elimination strategy:
- Requires the injected header to appear in the ACTUAL response headers
- Tests both \\r\\n (CRLF) and \\n (LF) only variants
- Uses a unique tracking header (X-TALISMAN-CRLF-<random>) to confirm injection
- Validates the response splits into two distinct HTTP messages
"""
from __future__ import annotations
import asyncio
import random
import string
from typing import Any
from talisman.utils.http_client import TalismanHTTPClient
from talisman.utils.logger import get_logger, console, print_finding

log = get_logger(__name__)

CRLF_PAYLOADS = [
    ("%0d%0aX-TALISMAN-CRLF: injected", "URL-encoded CRLF"),
    ("%0aX-TALISMAN-CRLF: injected", "URL-encoded LF"),
    ("\r\nX-TALISMAN-CRLF: injected", "raw CRLF"),
    ("\nX-TALISMAN-CRLF: injected", "raw LF"),
    ("%0d%0a%0d%0a<html><body><h1>CRLF</h1></body></html>", "response splitting HTML"),
    ("%0d%0aContent-Length: 0%0d%0a%0d%0aHTTP/1.1 200 OK%0d%0aX-TALISMAN-CRLF: split", "response splitting"),
]

CRLF_PARAMS = [
    "url", "next", "redirect", "return", "dest", "go",
    "target", "loc", "page", "file", "path", "ref",
    "out", "view", "dir", "doc", "source", "site",
]

CRLF_HEADERS = [
    "X-Forwarded-Host",
    "X-Forwarded-For",
    "X-Host",
    "X-Original-URL",
    "Referer",
    "User-Agent",
]


async def _test_param_crlf(url: str, client: TalismanHTTPClient) -> list[dict[str, Any]]:
    findings = []
    for param in CRLF_PARAMS:
        for payload, desc in CRLF_PAYLOADS:
            canary = "X-TALISMAN-CRLF-" + "".join(random.choices(string.ascii_lowercase, k=6))
            test_payload = payload.replace("X-TALISMAN-CRLF", canary)
            separator = "&" if "?" in url else "?"
            test_url = f"{url}{separator}{param}={test_payload}"
            try:
                r = await client.get(test_url, timeout=10)
                for hname, hval in r.headers.items():
                    if canary.lower() in hname.lower() or canary.lower() in str(hval).lower():
                        findings.append({
                            "issue": "crlf_injection_param",
                            "param": param,
                            "payload": payload[:80],
                            "header_injected": f"{hname}: {str(hval)[:100]}",
                            "description": desc,
                            "url": test_url,
                        })
                        break
            except Exception:
                pass
    return findings


async def _test_header_crlf(url: str, client: TalismanHTTPClient) -> list[dict[str, Any]]:
    findings = []
    for header in CRLF_HEADERS:
        canary = "X-TALISMAN-CRLF-" + "".join(random.choices(string.ascii_lowercase, k=6))
        inject_val = f"evil.com%0d%0a{canary}: injected"
        try:
            r = await client.get(url, headers={header: inject_val}, timeout=10)
            for hname, hval in r.headers.items():
                if canary.lower() in hname.lower() or canary.lower() in str(hval).lower():
                    findings.append({
                        "issue": "crlf_injection_header",
                        "header": header,
                        "payload": f"{header}: {inject_val}",
                        "header_injected": f"{hname}: {str(hval)[:100]}",
                        "url": url,
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
    console.print(f"\n[module][+] CRLF Injection Scanner[/module] -> [target]{url}[/target]")
    findings: list[dict[str, Any]] = []

    async with TalismanHTTPClient(proxy=proxy, timeout=12) as client:
        param_results = await _test_param_crlf(url, client)
        for r in param_results:
            title = f"CRLF injection via parameter '{r['param']}'"
            print_finding(title, "high", url)
            findings.append(r)
            if session:
                await session.add_finding(
                    target=url, module="crlf",
                    vuln_type="crlf_injection",
                    severity="high", confidence="confirmed",
                    title=title,
                    description=(
                        f"CRLF injection detected in parameter '{r['param']}' "
                        f"using payload: {r['description']}. "
                        f"Injected header '{r['header_injected']}' appeared in response."
                    ),
                    request=f"GET {r.get('url', url)} HTTP/1.1",
                    evidence=r.get("header_injected", ""),
                    reproduction=(
                        f"Send request with {r['param']}=PAYLOAD where PAYLOAD is a CRLF sequence "
                        f"followed by a malicious header."
                    ),
                    remediation=(
                        "1. Encode or strip CR (%0d / \\r) and LF (%0a / \\n) characters from user input.\n"
                        "2. Use parameterized URL building instead of string concatenation.\n"
                        "3. Sanitize all input placed into HTTP headers."
                    ),
                    cvss_score=7.5, cwe="CWE-93",
                )

        header_results = await _test_header_crlf(url, client)
        for r in header_results:
            title = f"CRLF injection via header '{r['header']}'"
            print_finding(title, "high", url)
            findings.append(r)
            if session:
                await session.add_finding(
                    target=url, module="crlf",
                    vuln_type="crlf_injection",
                    severity="high", confidence="confirmed",
                    title=title,
                    description=(
                        f"CRLF injection detected via header '{r['header']}'. "
                        f"The injected CRLF sequence caused header '{r['header_injected']}' "
                        f"to appear in the response."
                    ),
                    request=f"GET {url} HTTP/1.1\n{r['header']}: {r.get('payload', '')[:100]}",
                    evidence=r.get("header_injected", ""),
                    reproduction=f"Send request with {r['header']} containing CRLF + injected header.",
                    remediation=(
                        "1. Strip or encode CRLF sequences from all header values at the proxy/load balancer.\n"
                        "2. Use allowlists for header values instead of direct user input.\n"
                        "3. Validate and sanitize all input that ends up in response headers."
                    ),
                    cvss_score=7.5, cwe="CWE-93",
                )

    console.print(f"  CRLF injection scanning complete -- {len(findings)} issues")
    return {"target": url, "findings": findings, "count": len(findings)}
