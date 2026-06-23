"""WHOIS and ASN lookup."""
from __future__ import annotations
import asyncio
from typing import Any
from talisman.utils.http_client import TalismanHTTPClient
from talisman.utils.logger import get_logger, console

log = get_logger(__name__)

async def run(
 target: str,
 session: Any = None,
 scope: Any = None,
 rate_limiter: Any = None,
 proxy: str | None = None,
 **kwargs: Any,
) -> dict[str, Any]:
 domain = target.replace("https://", "").replace("http://", "").split("/")[0]
 console.print(f"\n[module][+] WHOIS/ASN[/module] -> [target]{domain}[/target]")
 result: dict[str, Any] = {"domain": domain}

 async with TalismanHTTPClient(proxy=proxy, timeout=15) as client:
  try:
   r = await client.get(f"https://ipinfo.io/{domain}/json", timeout=10)
   if r.status_code == 200:
    data = r.json()
    result.update({
     "ip": data.get("ip"),
     "org": data.get("org"),
     "country": data.get("country"),
     "region": data.get("region"),
     "asn": data.get("org", "").split()[0] if data.get("org") else None,
    })
    console.print(f" IP: {result.get('ip')} | Org: {result.get('org')} | Country: {result.get('country')}")
  except Exception as e:
   log.debug("whois_error", error=str(e))

 return result
