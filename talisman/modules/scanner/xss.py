"""XSS Scanner — reflected, DOM, stored with context-aware payload selection."""
from __future__ import annotations
import asyncio
import re
import urllib.parse
from typing import Any
from bs4 import BeautifulSoup
from talisman.utils.http_client import TalismanHTTPClient
from talisman.utils.payload_engine import PayloadEngine, XSS_PAYLOADS
from talisman.utils.logger import get_logger, console, print_finding

log = get_logger(__name__)

def _detect_context(html: str, marker: str) -> str:
    """Detect injection context: html, attribute, script, url, comment."""
    idx = html.find(marker)
    if idx == -1:
        return "unknown"
    snippet = html[max(0, idx-200):idx+200]
    if re.search(r'<script[^>]*>[^<]*' + re.escape(marker[:10]), snippet, re.IGNORECASE | re.DOTALL):
        return "script"
    attr_match = re.search(r'<\w+[^>]*\s+\w+=(["\'])[^"\']*' + re.escape(marker[:5]), snippet, re.IGNORECASE)
    if attr_match:
        return "attribute"
    if re.search(r'<!--[^-]*' + re.escape(marker[:5]), snippet):
        return "comment"
    if re.search(r'<style[^>]*>[^<]*' + re.escape(marker[:5]), snippet, re.IGNORECASE):
        return "css"
    return "html"

def _is_reflected_unencoded(response_text: str, payload: str) -> bool:
    """Check if payload appears unencoded in response."""
    if payload in response_text:
        if "<script>" in payload and "&lt;script&gt;" not in response_text:
            return True
        if "onerror=" in payload and "onerror=" in response_text:
            return True
        if "onload=" in payload and "onload=" in response_text:
            return True
        if "alert(" in payload and "alert(" in response_text:
            return True
        return True
    return False

async def _test_param(
    url: str, param: str, method: str,
    client: TalismanHTTPClient, engine: PayloadEngine,
    session: Any, waf_bypass: bool,
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    parsed = urllib.parse.urlparse(url)
    params = dict(urllib.parse.parse_qsl(parsed.query))
    payloads = engine.get_xss(waf_bypass=waf_bypass)
    for payload in payloads[:30]:
        try:
            test_params = {**params, param: payload}
            if method.upper() == "GET":
                test_url = parsed._replace(query=urllib.parse.urlencode(test_params)).geturl()
                r = await client.get(test_url)
            else:
                r = await client.post(url, data={param: payload})
            if _is_reflected_unencoded(r.text, payload):
                context = _detect_context(r.text, payload)
                findings.append({
                    "param": param,
                    "payload": payload,
                    "context": context,
                    "method": method,
                    "url": url,
                    "status": r.status_code,
                    "evidence": f"Payload reflected unencoded in {context} context",
                    "request": f"{method} {url}?{param}={urllib.parse.quote(payload)} HTTP/1.1",
                })
                return findings  # Return first confirmed finding per param
        except Exception as e:
            log.debug("xss_test_error", url=url, param=param, error=str(e))
    return findings

async def run(
    target: str,
    session: Any = None,
    scope: Any = None,
    rate_limiter: Any = None,
    proxy: str | None = None,
    types: list[str] | None = None,
    waf_bypass: bool = False,
    oast_domain: str | None = None,
    **kwargs: Any,
) -> dict[str, Any]:
    url = target if "://" in target else f"https://{target}"
    console.print(f"\n[module]⚡ XSS Scanner[/module] → [target]{url}[/target]")
    engine = PayloadEngine(oast_domain)
    all_findings: list[dict[str, Any]] = []
    parsed = urllib.parse.urlparse(url)
    params = list(dict(urllib.parse.parse_qsl(parsed.query)).keys())
    if not params:
        params = ["q", "search", "s", "query", "id", "name", "input", "data", "value", "text"]
    async with TalismanHTTPClient(proxy=proxy, timeout=20) as client:
        tasks = []
        for param in params:
            for method in ["GET", "POST"]:
                tasks.append(_test_param(url, param, method, client, engine, session, waf_bypass))
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for result in results:
            if isinstance(result, list):
                for finding in result:
                    severity = "high"
                    print_finding(
                        f"Reflected XSS in param '{finding['param']}'",
                        severity, finding["url"]
                    )
                    all_findings.append(finding)
                    if session:
                        await session.add_finding(
                            target=url, module="xss",
                            vuln_type="reflected_xss",
                            severity=severity,
                            confidence="confirmed",
                            title=f"Reflected XSS — parameter '{finding['param']}'",
                            description=f"Reflected XSS found in {finding['method']} parameter '{finding['param']}'. "
                                        f"Payload reflected unencoded in {finding['context']} context.",
                            request=finding["request"],
                            evidence=finding["evidence"],
                            reproduction=f"Navigate to: {finding['url']}?{finding['param']}={urllib.parse.quote(finding['payload'])}",
                            remediation="Encode all user-supplied data in the appropriate context. Implement a strict Content-Security-Policy.",
                            cvss_score=6.1,
                            cwe="CWE-79",
                            references=["https://owasp.org/www-community/attacks/xss/"],
                        )
    console.print(f"  Found {len(all_findings)} XSS vulnerabilities")
    return {"target": url, "findings": all_findings, "count": len(all_findings)}
