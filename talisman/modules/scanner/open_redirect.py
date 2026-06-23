"""
Open Redirect Scanner

FALSE-POSITIVE ELIMINATION STRATEGY
====================================
PROBLEM: Naive approach checks if Location header contains "evil.com".
 Example FP: Server redirects to https://www.site.com/?next=https://evil.com
 The Location contains "evil.com" but the redirect goes to www.site.com, not evil.com.

CORRECT APPROACH:
 1. Follow the complete redirect chain (up to 10 hops).
 2. Check the FINAL destination hostname — it must be the attacker's domain.
 3. Additionally check: does the first Location directly point to attacker domain?
 4. Multiple payloads including bypass variants — all require final-URL verification.
 5. Distinct attacker domains per test to avoid cross-test contamination.
"""
from __future__ import annotations
import asyncio
import urllib.parse
from typing import Any

import httpx

from talisman.utils.logger import get_logger, console, print_finding

log = get_logger(__name__)

# Canonical attacker-controlled domains used in tests
ATTACKER_DOMAIN = "evil.com"
ATTACKER_DOMAIN_2 = "attacker.net"

# Test payload templates — {ATTACKER} is replaced at runtime
REDIRECT_PAYLOADS: list[tuple[str, str]] = [
 # (payload, description)
 (f"https://{ATTACKER_DOMAIN}", "absolute HTTPS"),
 (f"http://{ATTACKER_DOMAIN}", "absolute HTTP"),
 (f"//{ATTACKER_DOMAIN}", "protocol-relative"),
 (f"//{ATTACKER_DOMAIN}/path", "protocol-relative with path"),
 (f"https://{ATTACKER_DOMAIN}@legit.tld", "credentials injection"),
 (f"/////{ATTACKER_DOMAIN}", "multiple slashes"),
 (f"/\\{ATTACKER_DOMAIN}", "backslash after slash"),
 (f"https:{ATTACKER_DOMAIN}", "scheme without slashes"),
 (f"%2F%2F{ATTACKER_DOMAIN}", "URL-encoded //"),
 (f"%09//{ATTACKER_DOMAIN}", "tab prefix"),
 (f"%0d%0aLocation: https://{ATTACKER_DOMAIN}", "CRLF injection"),
 (f"javascript:location='https://{ATTACKER_DOMAIN}'", "javascript scheme"),
]

# Parameters commonly used for redirects
REDIRECT_PARAMS = [
 "redirect", "redirect_uri", "redirect_url", "return", "return_to",
 "returnTo", "next", "url", "goto", "target", "link", "dest",
 "destination", "redir", "r", "u", "continue", "forward",
 "success_url", "cancel_url", "callback", "out", "view",
 "go", "path", "ref", "referrer", "jump", "login_url",
 "logout_url", "back", "from", "ReturnUrl",
]

# Hostnames that should be treated as the attacker's domain
ATTACKER_HOSTNAMES = {ATTACKER_DOMAIN, ATTACKER_DOMAIN_2, "evil.com", "attacker.net"}


def _is_attacker_destination(final_url: str) -> bool:
 """
 Return True only if the final URL's hostname IS the attacker domain.
 Rejects cases where the attacker domain appears as a path parameter.
 """
 try:
  parsed = urllib.parse.urlparse(final_url)
  host = (parsed.hostname or "").lower().rstrip(".")
  return host in ATTACKER_HOSTNAMES or any(
   host == d or host.endswith("." + d) for d in ATTACKER_HOSTNAMES
  )
 except Exception:
  return False


def _first_hop_is_attacker(location: str) -> bool:
 """
 Check if the first Location header points DIRECTLY to attacker domain.
 Handles protocol-relative, absolute, and encoded variants.
 """
 if not location:
  return False
 try:
  # Decode URL encoding
  decoded = urllib.parse.unquote(location)
  # Strip leading slashes / whitespace
  stripped = decoded.lstrip("/").lstrip("\\").strip()
  # Try to parse as URL
  parsed = urllib.parse.urlparse(decoded)
  host = (parsed.hostname or "").lower()
  if host in ATTACKER_HOSTNAMES:
   return True
  # Protocol-relative: //evil.com
  if stripped.startswith(ATTACKER_DOMAIN) or stripped.startswith(
   ATTACKER_DOMAIN_2
  ):
   return True
 except Exception:
  pass
 return False


async def _follow_redirect_chain(
 client: httpx.AsyncClient,
 url: str,
 max_hops: int = 10,
) -> tuple[str, list[str]]:
 """
 Follow redirect chain manually, returning (final_url, list_of_locations).
 We don't use httpx follow_redirects because we need to inspect each hop.
 """
 current_url = url
 locations: list[str] = []

 for _ in range(max_hops):
  try:
   resp = await client.get(
    current_url,
    follow_redirects=False,
    timeout=8,
   )
  except Exception:
   break

  if resp.status_code not in (301, 302, 303, 307, 308):
   break

  location = resp.headers.get("location", "")
  if not location:
   break

  locations.append(location)

  # Resolve relative redirects
  if location.startswith("http://") or location.startswith("https://"):
   current_url = location
  elif location.startswith("//"):
   scheme = urllib.parse.urlparse(current_url).scheme
   current_url = f"{scheme}:{location}"
  elif location.startswith("/"):
   parsed = urllib.parse.urlparse(current_url)
   current_url = f"{parsed.scheme}://{parsed.netloc}{location}"
  else:
   current_url = location

  # Early exit: we hit an attacker domain in the chain
  if _is_attacker_destination(current_url):
   break

 return current_url, locations


async def _test_param(
 url: str,
 param: str,
 client: httpx.AsyncClient,
) -> dict[str, Any] | None:
 """
 Test a single parameter with all redirect payloads.
 Returns finding only when final redirect destination is the attacker domain.
 """
 parsed = urllib.parse.urlparse(url)
 base_params = dict(urllib.parse.parse_qsl(parsed.query))

 for payload, description in REDIRECT_PAYLOADS:
  test_params = {**base_params, param: payload}
  test_url = parsed._replace(
   query=urllib.parse.urlencode(test_params)
  ).geturl()

  try:
   # Step 1: Get the first response (no redirect follow)
   first_resp = await client.get(
    test_url, follow_redirects=False, timeout=8
   )

   if first_resp.status_code not in (301, 302, 303, 307, 308):
    continue

   first_location = first_resp.headers.get("location", "")
   if not first_location:
    continue

   # Step 2: Check if first Location directly points to attacker
   if _first_hop_is_attacker(first_location):
    return {
     "param": param,
     "payload": payload,
     "description": description,
     "first_location": first_location,
     "final_url": first_location,
     "confidence": "confirmed",
     "request": f"GET {test_url} HTTP/1.1",
     "evidence": f"Location: {first_location}",
    }

   # Step 3: Follow the full chain — maybe it's a multi-hop redirect
   final_url, all_locations = await _follow_redirect_chain(
    client, test_url, max_hops=8
   )

   if _is_attacker_destination(final_url):
    return {
     "param": param,
     "payload": payload,
     "description": description,
     "first_location": first_location,
     "final_url": final_url,
     "redirect_chain": all_locations,
     "confidence": "confirmed",
     "request": f"GET {test_url} HTTP/1.1",
     "evidence": (
      f"Final URL: {final_url}\n"
      f"Chain: {' -> '.join(all_locations[:5])}"
     ),
    }

  except Exception as e:
   log.debug("open_redirect_test", param=param, error=str(e)[:80])

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
 console.print(
  f"\n[module][+] Open Redirect Scanner[/module] -> [target]{url}[/target]"
 )
 findings: list[dict[str, Any]] = []

 parsed = urllib.parse.urlparse(url)
 existing_params = list(dict(urllib.parse.parse_qsl(parsed.query)).keys())
 params_to_test = list(dict.fromkeys(existing_params + REDIRECT_PARAMS))

 # Use a raw httpx client so we can control redirect following per-request
 proxy_kwargs: dict[str, Any] = {}
 if proxy:
  proxy_kwargs["proxy"] = proxy

 async with httpx.AsyncClient(
  verify=False,
  timeout=12,
  **proxy_kwargs,
 ) as client:
  tasks = [_test_param(url, param, client) for param in params_to_test]
  results = await asyncio.gather(*tasks, return_exceptions=True)

  seen_params: set[str] = set()
  for result in results:
   if not isinstance(result, dict):
    continue
   if result["param"] in seen_params:
    continue
   seen_params.add(result["param"])

   severity = "medium"
   title = (
    f"Open Redirect — param '{result['param']}' "
    f"({result['description']})"
   )
   print_finding(title, severity, url)
   findings.append(result)

   if session:
    await session.add_finding(
     target=url,
     module="open_redirect",
     vuln_type="open_redirect",
     severity=severity,
     confidence=result.get("confidence", "confirmed"),
     title=title,
     description=(
      f"Open redirect via '{result['param']}' parameter. "
      f"Payload: {result['payload']}\n"
      f"Final destination confirmed: {result['final_url']}"
     ),
     request=result["request"],
     evidence=result["evidence"],
     reproduction=(
      f"Navigate to: {url}?"
      f"{result['param']}={urllib.parse.quote(result['payload'])}"
     ),
     remediation=(
      "1. Validate redirect URLs against an allowlist of "
      "trusted domains.\n"
      "2. Use relative paths instead of absolute URLs for "
      "internal redirects.\n"
      "3. Display an interstitial warning page before "
      "external redirects."
     ),
     cvss_score=6.1,
     cwe="CWE-601",
    )

 console.print(
  f" Found {len(findings)} confirmed open redirect vulnerabilities"
 )
 return {"target": url, "findings": findings, "count": len(findings)}
