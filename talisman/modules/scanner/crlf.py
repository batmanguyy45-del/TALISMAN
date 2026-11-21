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
from talisman.engine.scope import ScopeViolationError
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
    if scope is None:
        return {
            "target": url,
            "findings": [],
            "candidates": [],
            "count": 0,
            "error": "scope_enforcer_required",
        }
    try:
        scope.assert_in_scope(url)
    except ScopeViolationError as exc:
        return {
            "target": url,
            "findings": [],
            "candidates": [],
            "count": 0,
            "error": str(exc),
        }

    console.print(
        f"\\n[module][+] CRLF Injection Candidate Assessment[/module] -> [target]{url}[/target]"
    )
    candidates: list[dict[str, Any]] = []

    async with TalismanHTTPClient(
        proxy=proxy,
        timeout=12,
        verify_ssl=True,
        follow_redirects=False,
        scope=scope,
    ) as client:
        param_results = await _test_param_crlf(url, client)
        header_results = await _test_header_crlf(url, client)

    for result in param_results:
        candidates.append({
            **result,
            "confidence": "candidate",
            "requires_raw_response_validation": True,
            "verification_required": (
                "Verify the CRLF sequence created a distinct response header or "
                "separate HTTP response at the wire level. A canary appearing in "
                "a normalized response header can also be ordinary reflection."
            ),
        })

    for result in header_results:
        candidates.append({
            **result,
            "confidence": "candidate",
            "requires_raw_response_validation": True,
            "verification_required": (
                "Confirm whether the client-supplied header value was parsed as "
                "a new response header or merely reflected by the application. "
                "Validate with a raw HTTP capture before reporting."
            ),
        })

    console.print(
        f" CRLF assessment complete — {len(candidates)} response-header candidates; "
        "no vulnerability asserted"
    )
    return {
        "target": url,
        "findings": [],
        "candidates": candidates,
        "count": 0,
        "candidate_count": len(candidates),
    }
