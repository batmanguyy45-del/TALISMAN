"""Web cache poisoning scanner — unkeyed headers, fat GET, parameter cloaking."""
from __future__ import annotations
import asyncio
import random
import string
from typing import Any
from talisman.engine.scope import ScopeViolationError
from talisman.utils.http_client import TalismanHTTPClient
from talisman.utils.logger import get_logger, console, print_finding

log = get_logger(__name__)

UNKEYED_HEADERS = [
 "X-Forwarded-Host",
 "X-Forwarded-Scheme",
 "X-Forwarded-Port",
 "X-Original-URL",
 "X-Rewrite-URL",
 "X-Override-URL",
 "X-Host",
 "X-Forwarded-Server",
 "X-HTTP-Host-Override",
 "Forwarded",
 "X-Real-IP",
 "X-Forwarded-For",
]

CACHE_INDICATORS = [
 "age", "x-cache", "cf-cache-status", "x-varnish",
 "via", "x-cache-hits", "cdn-cache-control",
 "x-served-by", "x-cache-status",
]


def _random_canary() -> str:
 return "talisman-" + "".join(random.choices(string.ascii_lowercase, k=8))


async def _detect_caching(url: str, client: TalismanHTTPClient) -> bool:
 try:
  r1 = await client.get(url, timeout=8)
  r2 = await client.get(url, timeout=8)
  headers1 = {k.lower(): v for k, v in r1.headers.items()}
  headers2 = {k.lower(): v for k, v in r2.headers.items()}
  for ind in CACHE_INDICATORS:
   if ind in headers1 or ind in headers2:
    return True
  # Check Age header increment
  age1 = int(headers1.get("age", 0))
  age2 = int(headers2.get("age", 0))
  if age1 > 0 or age2 > 0:
   return True
 except Exception:
  pass
 return False


async def _test_header_poison(
 url: str, header: str, client: TalismanHTTPClient
) -> dict[str, Any] | None:
 canary = _random_canary()
 poison_value = f"evil-{canary}.attacker.com"
 try:
  # Send poisoning request
  r1 = await client.get(url, headers={header: poison_value}, timeout=8)
  # Fetch without the header to see if poison is cached
  await asyncio.sleep(0.5)
  r2 = await client.get(url, timeout=8)
  if canary in r2.text or poison_value in r2.text:
   return {
    "header": header,
    "poison_value": poison_value,
    "evidence": f"Canary '{canary}' found in cached response",
    "request": f"GET {url} HTTP/1.1\n{header}: {poison_value}",
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
  # A cache-poisoning request can affect responses served to other visitors,
  # even though it uses GET. Require the separate destructive-probe opt-in.
  scope.assert_destructive_allowed(url, "GET")
 except ScopeViolationError as exc:
  return {
   "target": url,
   "findings": [],
   "candidates": [],
   "count": 0,
   "skipped": True,
   "reason": str(exc),
  }

 console.print(
  f"\\n[module][+] Web Cache Poisoning Assessment[/module] -> [target]{url}[/target]"
 )
 candidates: list[dict[str, Any]] = []
 async with TalismanHTTPClient(
  proxy=proxy,
  timeout=12,
  verify_ssl=True,
  follow_redirects=False,
  scope=scope,
 ) as client:
  is_cached = await _detect_caching(url, client)
  if not is_cached:
   return {
    "target": url,
    "cached": False,
    "findings": [],
    "candidates": [],
    "count": 0,
    "reason": "No cache indicators observed in baseline requests.",
   }

  console.print("  Cache indicators observed; testing selected unkeyed headers...")
  for header in UNKEYED_HEADERS[:6]:
   result = await _test_header_poison(url, header, client)
   if not result:
    continue
   candidates.append({
    **result,
    "confidence": "candidate",
    "requires_cache_key_and_cross_client_validation": True,
    "verification_required": (
     "Confirm the canary is absent from the poisoned request's direct response, "
     "then present in an independently issued response without the header. "
     "Repeat from a separate client/session and verify cache status, Age, "
     "cache key variation, and expiry. The test canary alone does not prove "
     "cross-user impact or persistent cache poisoning."
    ),
   })

 console.print(
  f"  Cache assessment complete — {len(candidates)} candidates requiring "
  "independent cache-key validation"
 )
 return {
  "target": url,
  "cached": True,
  "findings": [],
  "candidates": candidates,
  "count": 0,
  "candidate_count": len(candidates),
  "destructive_probe_opt_in_required": True,
 }
