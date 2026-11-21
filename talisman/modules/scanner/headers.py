"""
Security Headers Audit

FALSE-POSITIVE ELIMINATION STRATEGY
====================================
PROBLEM: Reporting X-XSS-Protection as HIGH, or Cache-Control as MEDIUM
 for every single page is noise. Most modern browsers ignore X-XSS-Protection.
 CSP analysis should check for MEANINGFUL weaknesses, not flag every deviation.

CORRECT APPROACH:
 1. Accurate severity calibration based on real-world exploitability.
 2. X-XSS-Protection is DEPRECATED — report as info, not medium.
 3. Only flag CSP issues if the policy actually makes XSS easier.
 4. Information-disclosure headers: flag version numbers, not just presence.
 5. HSTS max-age <1 year is medium, missing entirely is medium (not high).
"""
from __future__ import annotations
import re
from typing import Any

from talisman.utils.http_client import TalismanHTTPClient
from talisman.utils.logger import get_logger, console, print_finding

log = get_logger(__name__)


# ---------------------------------------------------------------------------
# Security header definitions with accurate severity
# ---------------------------------------------------------------------------

SECURITY_HEADERS = [
 {
  "name": "Strict-Transport-Security",
  "required": True,
  "description": "Forces HTTPS connections and prevents SSL stripping",
  "severity_missing": "medium",
  "severity_weak": "low",
  "validate": lambda v: (
   "max-age=" in v
   and (match := re.search(r"max-age=(\d+)", v))
   and int(match.group(1)) >= 31536000
  ),
  "recommendation": (
   "Strict-Transport-Security: max-age=31536000; "
   "includeSubDomains; preload"
  ),
  "cwe": "CWE-319",
 },
 {
  "name": "Content-Security-Policy",
  "required": True,
  "description": "Restricts resource loading to prevent XSS",
  "severity_missing": "medium",
  "severity_weak": "low",
  "validate": lambda v: (
   len(v) > 20
   and "unsafe-inline" not in v
   and "unsafe-eval" not in v
   and "*" not in v.split("default-src")[-1].split(";")[0]
  ),
  "recommendation": (
   "Content-Security-Policy: default-src 'self'; "
   "script-src 'self'; object-src 'none'; base-uri 'self'"
  ),
  "cwe": "CWE-79",
 },
 {
  "name": "X-Frame-Options",
  "required": True,
  "description": "Prevents clickjacking attacks",
  "severity_missing": "medium",
  "severity_weak": "low",
  "validate": lambda v: v.strip().upper() in ("DENY", "SAMEORIGIN"),
  "recommendation": "X-Frame-Options: DENY",
  "cwe": "CWE-1021",
 },
 {
  "name": "X-Content-Type-Options",
  "required": True,
  "description": "Prevents MIME-type sniffing attacks",
  "severity_missing": "low",
  "severity_weak": "info",
  "validate": lambda v: v.strip().lower() == "nosniff",
  "recommendation": "X-Content-Type-Options: nosniff",
  "cwe": "CWE-693",
 },
 {
  "name": "Referrer-Policy",
  "required": True,
  "description": "Controls referrer information leakage",
  "severity_missing": "low",
  "severity_weak": "info",
  "validate": lambda v: v.strip().lower() in (
   "no-referrer",
   "strict-origin",
   "strict-origin-when-cross-origin",
   "same-origin",
   "no-referrer-when-downgrade",
  ),
  "recommendation": "Referrer-Policy: strict-origin-when-cross-origin",
  "cwe": "CWE-200",
 },
 {
  "name": "Permissions-Policy",
  "required": False,
  "description": "Controls browser feature access (camera, mic, geolocation)",
  "severity_missing": "info",
  "severity_weak": "info",
  "validate": lambda v: len(v) > 5,
  "recommendation": (
   "Permissions-Policy: camera=(), microphone=(), "
   "geolocation=(), interest-cohort=()"
  ),
  "cwe": "CWE-693",
 },
]

# ---------------------------------------------------------------------------
# CSP analysis — only flag MEANINGFUL weaknesses
# ---------------------------------------------------------------------------

CSP_ISSUES: list[tuple[re.Pattern, str, str]] = [
 (
  re.compile(r"'unsafe-inline'", re.IGNORECASE),
  "'unsafe-inline' in CSP script-src — XSS mitigation bypassed",
  "high",
 ),
 (
  re.compile(r"'unsafe-eval'", re.IGNORECASE),
  "'unsafe-eval' in CSP — allows eval()-based XSS vectors",
  "medium",
 ),
 (
  re.compile(r"(?:script-src|default-src)\s[^;]*\*", re.IGNORECASE),
  "Wildcard (*) in script-src or default-src — defeats CSP",
  "high",
 ),
 (
  re.compile(r"'unsafe-hashes'", re.IGNORECASE),
  "'unsafe-hashes' weakens event handler restrictions",
  "low",
 ),
 (
  re.compile(r"data:", re.IGNORECASE),
  "data: URI allowed in CSP — can be used for XSS in some contexts",
  "low",
 ),
]

# ---------------------------------------------------------------------------
# Information-disclosure headers
# Only flag if they reveal VERSION numbers or internal paths
# ---------------------------------------------------------------------------

_RE_VERSION = re.compile(r'\d+\.\d+[\.\d]*')
_RE_INTERNAL_PATH = re.compile(r'(?:/(?:var|etc|home|usr|opt)/|C:\\)')

DANGEROUS_HEADERS: dict[str, dict[str, Any]] = {
 "X-Powered-By": {
  "severity": "info",
  "description": "Reveals backend technology",
  "check": lambda v: True, # Always flag this one
 },
 "Server": {
  "severity": "info",
  "description": "Reveals server version",
  # Only flag if it reveals a version number
  "check": lambda v: bool(_RE_VERSION.search(v)),
 },
 "X-AspNet-Version": {
  "severity": "low",
  "description": "Reveals ASP.NET version",
  "check": lambda v: True,
 },
 "X-AspNetMvc-Version": {
  "severity": "low",
  "description": "Reveals ASP.NET MVC version",
  "check": lambda v: True,
 },
 "X-Generator": {
  "severity": "info",
  "description": "Reveals CMS/framework generator",
  "check": lambda v: True,
 },
 "X-Runtime": {
  "severity": "info",
  "description": "Reveals backend runtime",
  "check": lambda v: True,
 },
 "X-Application-Context": {
  "severity": "low",
  "description": "Reveals Spring Boot application context",
  "check": lambda v: True,
 },
 "X-Debug-Token": {
  "severity": "medium",
  "description": "Exposes Symfony debug token",
  "check": lambda v: True,
 },
 "X-Debug-Token-Link": {
  "severity": "medium",
  "description": "Direct link to Symfony profiler — may expose debug data",
  "check": lambda v: True,
 },
}


async def run(
 target: str,
 session: Any = None,
 scope: Any = None,
 rate_limiter: Any = None,
 proxy: str | None = None,
 full_audit: bool = True,
 **kwargs: Any,
) -> dict[str, Any]:
 url = target if "://" in target else f"https://{target}"
 if scope is None:
  return {
   "target": url,
   "findings": [],
   "observations": [],
   "count": 0,
   "error": "scope_enforcer_required",
  }
 try:
  scope.assert_in_scope(url)
 except Exception as exc:
  return {
   "target": url,
   "findings": [],
   "observations": [],
   "count": 0,
   "error": str(exc),
  }

 console.print(
  f"\\n[module][+] Security Header Posture Audit[/module] -> [target]{url}[/target]"
 )
 observations: list[dict[str, Any]] = []
 try:
  async with TalismanHTTPClient(
   proxy=proxy,
   timeout=15,
   verify_ssl=True,
   follow_redirects=False,
   scope=scope,
  ) as client:
   response = await client.get(url)
   headers = {key.lower(): value for key, value in response.headers.items()}
 except Exception as exc:
  log.error("headers_audit_error", url=url, error=type(exc).__name__)
  return {
   "target": url,
   "findings": [],
   "observations": [],
   "count": 0,
   "error": "request_failed",
  }

 for header in SECURITY_HEADERS:
  name = header["name"]
  key = name.lower()
  value = headers.get(key)
  if value is None:
   if header["required"] and header["severity_missing"] != "info":
    observations.append({
     "type": "missing_security_header",
     "header": name,
     "severity_hint": header["severity_missing"],
     "description": header["description"],
     "recommendation": header["recommendation"],
     "cwe": header["cwe"],
     "classification": "security_posture_observation",
     "requires_application_impact_validation": True,
    })
   continue

  try:
   is_valid = bool(header["validate"](value))
  except Exception:
   is_valid = True

  if not is_valid and header["severity_weak"] != "info":
   observations.append({
    "type": "weak_security_header",
    "header": name,
    "value": value[:500],
    "severity_hint": header["severity_weak"],
    "description": header["description"],
    "recommendation": header["recommendation"],
    "cwe": header["cwe"],
    "classification": "security_posture_observation",
    "requires_application_impact_validation": True,
   })

  if name == "Content-Security-Policy":
   for pattern, issue_description, severity_hint in CSP_ISSUES:
    if pattern.search(value):
     observations.append({
      "type": "csp_weakness",
      "header": name,
      "issue": issue_description,
      "severity_hint": severity_hint,
      "value": value[:500],
      "classification": "security_posture_observation",
      "requires_reachable_sink_and_browser_validation": True,
     })

 report_only = headers.get("content-security-policy-report-only")
 if report_only:
  observations.append({
   "type": "csp_report_only_policy",
   "value": report_only[:500],
   "classification": "security_posture_observation",
   "note": (
    "Report-Only policies do not enforce browser restrictions; evaluate any "
    "enforced Content-Security-Policy separately."
   ),
   "severity_hint": "info",
  })

 if full_audit:
  for header_name, metadata in DANGEROUS_HEADERS.items():
   value = headers.get(header_name.lower())
   if value and metadata["check"](value):
    observations.append({
     "type": "information_disclosure_header",
     "header": header_name,
     "value": value[:200],
     "description": metadata["description"],
     "severity_hint": metadata["severity"],
     "classification": "information_disclosure_posture",
     "requires_sensitive_impact_validation": True,
    })

 console.print(
  f" Header audit complete — {len(observations)} posture observations; "
  "no vulnerability asserted"
 )
 return {
  "target": url,
  "findings": [],
  "observations": observations,
  "count": 0,
  "observation_count": len(observations),
 }
