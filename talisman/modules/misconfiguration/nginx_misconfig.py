"""Nginx-specific misconfiguration scanner."""
from __future__ import annotations
import asyncio
from typing import Any
from talisman.utils.http_client import TalismanHTTPClient
from talisman.utils.logger import get_logger, console, print_finding

log = get_logger(__name__)

NGINX_ALIAS_PATHS = [
    "/../etc/passwd", "/..%2Fetc%2Fpasswd", "/%2F..%2Fetc%2Fpasswd",
    "/..%252Fetc%252Fpasswd",
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
    console.print(f"\n[module]⚡ Nginx Misconfiguration[/module] → [target]{url}[/target]")
    findings: list[dict[str, Any]] = []

    async with TalismanHTTPClient(proxy=proxy, timeout=10) as client:
        # Test alias traversal
        for path in NGINX_ALIAS_PATHS:
            test_url = url.rstrip("/") + path
            try:
                r = await client.get(test_url, allow_redirects=False, timeout=8)
                if r.status_code == 200 and "root:x:" in r.text:
                    print_finding("Nginx alias path traversal — /etc/passwd read", "critical", url)
                    findings.append({"type": "alias_traversal", "path": path, "status": r.status_code})
                    if session:
                        await session.add_finding(
                            target=url, module="nginx_misconfig",
                            vuln_type="path_traversal",
                            severity="critical", confidence="confirmed",
                            title="Nginx alias traversal — LFI via off-by-slash",
                            description="Nginx alias misconfiguration allows path traversal to read arbitrary files.",
                            evidence=r.text[:200],
                            remediation="Fix Nginx alias: ensure location path and alias path both end with / or neither does.",
                            cwe="CWE-22",
                        )
            except Exception:
                pass

        # Test status page
        for status_path in ["/nginx_status", "/_status", "/stub_status"]:
            try:
                r = await client.get(url.rstrip("/") + status_path, timeout=8)
                if r.status_code == 200 and "Active connections" in r.text:
                    print_finding(f"Nginx status page exposed: {status_path}", "low", url)
                    findings.append({"type": "status_page", "path": status_path})
            except Exception:
                pass

    console.print(f"  Found {len(findings)} Nginx issues")
    return {"target": url, "findings": findings, "count": len(findings)}
