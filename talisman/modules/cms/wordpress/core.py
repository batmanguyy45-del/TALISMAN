"""WordPress core enumeration — version detection, sensitive paths, CVE correlation."""
from __future__ import annotations
import asyncio
import re
from typing import Any
from talisman.utils.http_client import TalismanHTTPClient
from talisman.utils.logger import get_logger, console, print_finding

log = get_logger(__name__)

WP_SENSITIVE_PATHS = [
 ("/wp-config.php", "WordPress config (credentials)"),
 ("/wp-config.php.bak", "WordPress config backup"),
 ("/wp-config.php~", "Vim swap of wp-config"),
 ("/wp-config.php.old", "Old config"),
 ("/wp-config.bak", "Config backup"),
 ("/debug.log", "WordPress debug log"),
 ("/wp-content/debug.log", "WP debug log"),
 ("/wp-content/uploads/debug.log", "Debug log in uploads"),
 ("/.git/config", "Git config exposed"),
 ("/.git/HEAD", "Git HEAD exposed"),
 ("/readme.html", "WordPress readme (version disclosure)"),
 ("/license.txt", "WordPress license (version disclosure)"),
 ("/wp-content/uploads/", "Uploads directory listing"),
 ("/wp-admin/install.php", "WordPress installer"),
 ("/wp-admin/setup-config.php", "Setup config exposed"),
 ("/wp-includes/version.php", "Version file"),
 ("/phpinfo.php", "PHP info page"),
 ("/info.php", "PHP info page"),
 ("/wp-content/phpinfo.php", "PHP info in WP"),
 ("/xmlrpc.php", "XML-RPC endpoint"),
 ("/wp-json/", "WordPress REST API"),
 ("/wp-json/wp/v2/users", "User enumeration via REST API"),
 ("/wp-cron.php", "WP cron (should not be public)"),
]

WP_CRITICAL_CVES: list[dict[str, Any]] = [
 {"version_lt": "6.4.3", "cve": "CVE-2024-6386", "severity": "high", "desc": "Privilege escalation"},
 {"version_lt": "6.2.1", "cve": "CVE-2023-2745", "severity": "high", "desc": "Directory traversal"},
 {"version_lt": "5.9.2", "cve": "CVE-2022-21663", "severity": "critical","desc": "SQL injection"},
 {"version_lt": "5.8.3", "cve": "CVE-2022-21661", "severity": "critical","desc": "SQL injection in WP_Query"},
 {"version_lt": "5.7.2", "cve": "CVE-2021-29447", "severity": "high", "desc": "XXE via media upload"},
 {"version_lt": "5.7", "cve": "CVE-2021-29450", "severity": "medium", "desc": "XXE via pingback"},
 {"version_lt": "5.4.2", "cve": "CVE-2020-28032", "severity": "critical","desc": "Object injection"},
 {"version_lt": "4.9.9", "cve": "CVE-2018-20153", "severity": "medium", "desc": "XSS in user profile"},
]


def _compare_version(ver: str, target: str) -> bool:
 """Return True if ver < target."""
 def parts(v: str) -> tuple[int, ...]:
  try:
   return tuple(int(x) for x in v.split(".")[:3])
  except ValueError:
   return (0, 0, 0)
 return parts(ver) < parts(target)


def _detect_version(html: str, headers: dict[str, str]) -> str | None:
 patterns = [
  r"<meta name=['\"]generator['\"] content=['\"]WordPress ([0-9.]+)['\"]",
  r"<generator>https://wordpress\.org/\?v=([0-9.]+)</generator>",
  r"\?ver=([0-9]+\.[0-9]+(?:\.[0-9]+)?)",
  r"wp-includes/[^?]+\?ver=([0-9]+\.[0-9]+(?:\.[0-9]+)?)",
  r"WordPress ([0-9]+\.[0-9]+(?:\.[0-9]+)?)",
 ]
 for pattern in patterns:
  m = re.search(pattern, html, re.IGNORECASE)
  if m:
   return m.group(1)
 for h, v in headers.items():
  m = re.search(r"WordPress/([0-9.]+)", v, re.IGNORECASE)
  if m:
   return m.group(1)
 return None


async def _check_path(
 base_url: str, path: str, desc: str, client: TalismanHTTPClient
) -> dict[str, Any] | None:
 try:
  r = await client.get(base_url.rstrip("/") + path, allow_redirects=False)
  if r.status_code == 200 and len(r.text) > 50:
   # Avoid false positives — check for relevant content
   if path == "/wp-config.php" and "DB_PASSWORD" not in r.text:
    return None
   if "login" in r.text.lower() and path not in ("/xmlrpc.php", "/wp-json/"):
    return None
   return {
    "path": path,
    "description": desc,
    "status": r.status_code,
    "size": len(r.text),
    "snippet": r.text[:200],
   }
  if r.status_code == 200 and path == "/wp-json/wp/v2/users":
   return {
    "path": path,
    "description": desc,
    "status": r.status_code,
    "size": len(r.text),
    "snippet": r.text[:200],
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
 detect_version: bool = True,
 sensitive_paths: bool = True,
 **kwargs: Any,
) -> dict[str, Any]:
 url = target if "://" in target else f"https://{target}"
 console.print(f"\n[module][+] WordPress Audit[/module] -> [target]{url}[/target]")
 findings: list[dict[str, Any]] = []
 detected_version: str | None = None

 async with TalismanHTTPClient(proxy=proxy, timeout=15) as client:
  # — Version detection ——————————————————————————————————
  if detect_version:
   for path in ["/", "/feed/", "/readme.html", "/?p=1"]:
    try:
     r = await client.get(url.rstrip("/") + path)
     headers = {k.lower(): v for k, v in r.headers.items()}
     ver = _detect_version(r.text, headers)
     if ver:
      detected_version = ver
      console.print(f" WordPress version: [bold]{ver}[/bold]")
      break
    except Exception:
     pass

   if detected_version:
    for cve_info in WP_CRITICAL_CVES:
     if _compare_version(detected_version, cve_info["version_lt"]):
      title = f"WordPress {detected_version} — {cve_info['cve']} ({cve_info['desc']})"
      print_finding(title, cve_info["severity"], url)
      findings.append({"type": "cve", **cve_info, "version": detected_version})
      if session:
       await session.add_finding(
        target=url, module="wordpress",
        vuln_type="outdated_cms",
        severity=cve_info["severity"],
        confidence="confirmed",
        title=title,
        description=f"WordPress {detected_version} is affected by {cve_info['cve']}: {cve_info['desc']}",
        remediation="Update WordPress to the latest stable version immediately.",
        cwe="CWE-1104",
       )

  # — Sensitive paths ——————————————————————————————————————
  if sensitive_paths:
   tasks = [
    _check_path(url, path, desc, client)
    for path, desc in WP_SENSITIVE_PATHS
   ]
   results = await asyncio.gather(*tasks, return_exceptions=True)
   for (path, desc), result in zip(WP_SENSITIVE_PATHS, results):
    if isinstance(result, dict) and result:
     severity = "critical" if "config" in path or "git" in path else "medium"
     title = f"WordPress sensitive path exposed: {path}"
     print_finding(title, severity, url)
     findings.append(result)
     if session:
      await session.add_finding(
       target=url, module="wordpress",
       vuln_type="sensitive_file_exposure",
       severity=severity,
       confidence="confirmed",
       title=title,
       description=f"{desc} is publicly accessible at {url}{path}",
       evidence=result.get("snippet", ""),
       request=f"GET {url}{path} HTTP/1.1",
       remediation="Restrict access to sensitive files via .htaccess or Nginx config.",
       cwe="CWE-200",
      )

 console.print(f" Found {len(findings)} WordPress issues")
 return {
  "target": url,
  "version": detected_version,
  "findings": findings,
  "is_wordpress": detected_version is not None or len(findings) > 0,
 }
