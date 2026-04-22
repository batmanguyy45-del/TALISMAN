"""CORS misconfiguration scanner — tests all known CORS bypass patterns."""
from __future__ import annotations
import asyncio
from typing import Any
from talisman.utils.http_client import TalismanHTTPClient
from talisman.utils.logger import get_logger, console, print_finding

log = get_logger(__name__)

CORS_TEST_ORIGINS = [
    ("wildcard_reflected", "https://evil.com"),
    ("null_origin", "null"),
    ("subdomain_bypass", "https://evil.{TARGET}"),
    ("prefix_bypass", "https://{TARGET}.evil.com"),
    ("suffix_bypass", "https://evil{TARGET}"),
    ("trusted_subdomain", "https://notreally{TARGET}"),
    ("protocol_downgrade", "http://{TARGET}"),
    ("http_origin_on_https", "http://evil.com"),
    ("arbitrary_trusted_prefix", "https://{TARGET}.evil.com/path"),
]

async def _test_cors(url: str, origin: str, client: TalismanHTTPClient) -> dict[str, Any] | None:
    try:
        r = await client.get(url, headers={"Origin": origin})
        acao = r.headers.get("access-control-allow-origin", "")
        acac = r.headers.get("access-control-allow-credentials", "")
        if acao in ("*", origin) or origin in acao:
            return {
                "origin_sent": origin,
                "acao_received": acao,
                "credentials": acac.lower() == "true",
                "status": r.status_code,
                "critical": acac.lower() == "true" and acao != "*",
            }
    except Exception as e:
        log.debug("cors_test_error", url=url, origin=origin, error=str(e))
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
    domain = url.split("://")[-1].split("/")[0]
    console.print(f"\n[module]⚡ CORS Misconfiguration Scan[/module] → [target]{url}[/target]")
    vulnerabilities: list[dict[str, Any]] = []
    async with TalismanHTTPClient(proxy=proxy, timeout=15) as client:
        tasks = []
        for label, origin_tpl in CORS_TEST_ORIGINS:
            origin = origin_tpl.replace("{TARGET}", domain)
            tasks.append((label, origin, _test_cors(url, origin, client)))
        results = await asyncio.gather(*[t[2] for t in tasks], return_exceptions=True)
        for (label, origin, _), result in zip(tasks, results):
            if isinstance(result, dict) and result:
                severity = "critical" if result["critical"] else "medium"
                title = f"CORS misconfiguration — {label}"
                desc = (
                    f"Origin '{origin}' is reflected in Access-Control-Allow-Origin. "
                    f"With-Credentials: {result['credentials']}. "
                    f"This {'allows cross-origin requests with cookies/auth tokens' if result['critical'] else 'allows cross-origin reads'}."
                )
                vulnerabilities.append({**result, "label": label, "severity": severity})
                print_finding(title, severity, url)
                if session:
                    await session.add_finding(
                        target=url, module="cors", vuln_type="cors_misconfiguration",
                        severity=severity, confidence="confirmed",
                        title=title, description=desc,
                        evidence=f"ACAO: {result['acao_received']}, ACAC: {result['credentials']}",
                        request=f"GET {url} HTTP/1.1\nOrigin: {origin}",
                        remediation="Implement an explicit allowlist of trusted origins. Never reflect the Origin header directly.",
                        cvss_score=8.1 if result["critical"] else 5.3,
                        cwe="CWE-942",
                    )
    console.print(f"  Found {len(vulnerabilities)} CORS issues")
    return {"target": url, "vulnerabilities": vulnerabilities, "count": len(vulnerabilities)}
