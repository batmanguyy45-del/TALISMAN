"""Open Redirect scanner with chaining advisor."""
from __future__ import annotations
import asyncio
import urllib.parse
from typing import Any
from talisman.utils.http_client import TalismanHTTPClient
from talisman.utils.payload_engine import OPEN_REDIRECT_PAYLOADS
from talisman.utils.logger import get_logger, console, print_finding

log = get_logger(__name__)

REDIRECT_PARAMS = [
    "redirect", "redirect_uri", "redirect_url", "return", "return_to",
    "returnTo", "next", "url", "goto", "target", "link", "dest",
    "destination", "redir", "r", "u", "continue", "forward",
    "success_url", "cancel_url", "callback", "out", "view",
    "go", "path", "ref", "referrer", "jump", "login_url",
]

async def run(
    target: str,
    session: Any = None,
    scope: Any = None,
    rate_limiter: Any = None,
    proxy: str | None = None,
    **kwargs: Any,
) -> dict[str, Any]:
    url = target if "://" in target else f"https://{target}"
    console.print(f"\n[module]⚡ Open Redirect Scanner[/module] → [target]{url}[/target]")
    findings: list[dict[str, Any]] = []

    parsed = urllib.parse.urlparse(url)
    existing_params = list(dict(urllib.parse.parse_qsl(parsed.query)).keys())
    params_to_test = list(set(existing_params + REDIRECT_PARAMS))

    async with TalismanHTTPClient(proxy=proxy, timeout=12, follow_redirects=False) as client:
        for param in params_to_test:
            for payload in OPEN_REDIRECT_PAYLOADS:
                try:
                    test_params = dict(urllib.parse.parse_qsl(parsed.query))
                    test_params[param] = payload
                    test_url = parsed._replace(
                        query=urllib.parse.urlencode(test_params)
                    ).geturl()
                    r = await client.get(test_url)
                    if r.status_code in (301, 302, 303, 307, 308):
                        location = r.headers.get("location", "")
                        if "evil.com" in location or payload in location:
                            severity = "medium"
                            title = f"Open Redirect — param '{param}'"
                            print_finding(title, severity, url)
                            finding = {
                                "param": param,
                                "payload": payload,
                                "redirect_to": location,
                                "status": r.status_code,
                                "request": f"GET {test_url} HTTP/1.1",
                            }
                            findings.append(finding)
                            if session:
                                await session.add_finding(
                                    target=url, module="open_redirect",
                                    vuln_type="open_redirect",
                                    severity=severity, confidence="confirmed",
                                    title=title,
                                    description=(
                                        f"Open redirect via '{param}' parameter. "
                                        f"Redirects to attacker-controlled domain: {location}"
                                    ),
                                    request=finding["request"],
                                    evidence=f"Location: {location}",
                                    reproduction=f"Navigate to: {test_url}",
                                    remediation=(
                                        "1. Validate redirect URLs against an allowlist of trusted domains.\n"
                                        "2. Use relative paths instead of absolute URLs for internal redirects.\n"
                                        "3. Display an interstitial warning page before external redirects."
                                    ),
                                    cvss_score=6.1, cwe="CWE-601",
                                )
                            break  # Found for this param, move on
                except Exception:
                    pass

    console.print(f"  Found {len(findings)} open redirect vulnerabilities")
    return {"target": url, "findings": findings, "count": len(findings)}
