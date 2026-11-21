"""
CORS Misconfiguration Scanner

FALSE-POSITIVE ELIMINATION STRATEGY
====================================
PROBLEM 1: Wildcard (Access-Control-Allow-Origin: *) is NOT exploitable when
 Access-Control-Allow-Credentials is not "true". Reporting it as high/critical
 is a FP for the exploitability level.

PROBLEM 2: Some servers echo the Origin header back in ACAO regardless of any
 access control logic — this is a true vulnerability only if ACAC: true.

PROBLEM 3: Pre-flight responses may differ from actual cross-origin requests.

CORRECT APPROACH:
 1. Test multiple origin bypass patterns.
 2. Only mark CRITICAL if BOTH: origin is reflected AND credentials are allowed.
 3. Wildcard with no credentials = LOW (info disclosure only).
 4. Reflected specific origin without credentials = MEDIUM.
 5. Reflected specific origin WITH credentials = CRITICAL.
 6. Verify the ACAO header actually reflects the SENT origin, not a static value.
"""
from __future__ import annotations
import asyncio
from typing import Any
from urllib.parse import urlsplit

from talisman.engine.scope import ScopeViolationError
from talisman.utils.http_client import TalismanHTTPClient
from talisman.utils.logger import get_logger, console, print_finding

log = get_logger(__name__)


def _build_test_origins(target_domain: str) -> list[tuple[str, str]]:
 """Build a list of (label, origin) pairs to test."""
 d = target_domain.rstrip("/")
 return [
  ("arbitrary_origin",   "https://evil.com"),
  ("null_origin",    "null"),
  ("subdomain_bypass",   f"https://evil.{d}"),
  ("prefix_bypass",    f"https://{d}.evil.com"),
  ("suffix_bypass",    f"https://evil{d}"),
  ("trusted_subdomain",   f"https://notreally{d}"),
  ("http_downgrade",   f"http://{d}"),
  ("http_attacker",    "http://evil.com"),
  ("arbitrary_prefix_path",  f"https://{d}.evil.com/path"),
   ("unicode_confusable",  "https://xn--evl-mya.com"),
 ]


def _assess_severity(
 acao: str,
 acac: str,
 origin_sent: str,
 label: str,
) -> tuple[str, str]:
 """
 Determine severity and rationale.

 Returns (severity, rationale).
 """
 credentials_allowed = acac.strip().lower() == "true"
 is_wildcard = acao.strip() == "*"
 origin_reflected = acao.strip() == origin_sent

 if is_wildcard:
  if credentials_allowed:
   # Spec doesn't allow this combination but some servers do
   return "high", (
    "Wildcard ACAO with Allow-Credentials:true — "
    "some browsers may honour this"
   )
  return "low", "Wildcard ACAO without credentials — cannot send cookies"

 if origin_reflected and credentials_allowed:
  return "critical", (
   f"Origin '{origin_sent}' reflected in ACAO AND "
   f"Access-Control-Allow-Credentials: true — "
   "attacker can make credentialed cross-origin requests and read responses"
  )

 if origin_reflected and not credentials_allowed:
  return "medium", (
   f"Origin '{origin_sent}' reflected in ACAO — "
   "attacker can read responses but cannot send cookies/auth headers "
   "(no Allow-Credentials)"
  )

 return "info", "No meaningful CORS misconfiguration"


async def _test_origin(
 url: str,
 label: str,
 origin: str,
 client: TalismanHTTPClient,
) -> dict[str, Any] | None:
 """
 Test a single origin. Returns a finding dict or None.
 """
 try:
  # Main request with injected Origin
  r = await client.get(url, headers={"Origin": origin}, timeout=10)
  acao = r.headers.get("access-control-allow-origin", "").strip()
  acac = r.headers.get("access-control-allow-credentials", "").strip()

  if not acao:
   return None

  # Wildcard case
  if acao == "*":
   severity, rationale = _assess_severity(acao, acac, origin, label)
   if severity in ("info",):
    return None
   return {
    "label": label,
    "origin_sent": origin,
    "acao": acao,
    "acac": acac,
    "severity": severity,
    "rationale": rationale,
    "credentials": acac.lower() == "true",
    "critical": severity == "critical",
   }

  # Check if our injected origin is actually reflected (not just any value)
  if acao == origin:
   severity, rationale = _assess_severity(acao, acac, origin, label)
   if severity == "info":
    return None

   # Verify with a preflight OPTIONS request
   try:
    preflight = await client.request(
     "OPTIONS",
     url,
     headers={
      "Origin": origin,
      "Access-Control-Request-Method": "GET",
      "Access-Control-Request-Headers": "authorization",
     },
     timeout=8,
    )
    pf_acao = preflight.headers.get(
     "access-control-allow-origin", ""
    ).strip()
    pf_acac = preflight.headers.get(
     "access-control-allow-credentials", ""
    ).strip()

    # Both the main request AND preflight must confirm the misconfiguration
    if pf_acao and (pf_acao == origin or pf_acao == "*"):
     if severity == "critical" and pf_acac.lower() != "true":
      # Preflight doesn't allow credentials -> downgrade
      severity = "medium"
      rationale = (
       f"Origin reflected in ACAO (main request) but "
       f"preflight does not allow credentials"
      )
   except Exception:
    pass # Preflight failed — use main request result

   return {
    "label": label,
    "origin_sent": origin,
    "acao": acao,
    "acac": acac,
    "severity": severity,
    "rationale": rationale,
    "credentials": acac.lower() == "true",
    "critical": severity == "critical",
   }

 except Exception as e:
  log.debug("cors_test", label=label, origin=origin, error=str(e)[:60])

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
   "observations": [],
   "count": 0,
   "error": "scope_enforcer_required",
  }
 try:
  scope.assert_in_scope(url)
 except ScopeViolationError as exc:
  return {
   "target": url,
   "findings": [],
   "candidates": [],
   "observations": [],
   "count": 0,
   "error": str(exc),
  }

 parsed = urlsplit(url)
 domain = parsed.hostname or ""
 if not domain:
  return {
   "target": url,
   "findings": [],
   "candidates": [],
   "observations": [],
   "count": 0,
   "error": "invalid_target",
  }

 console.print(
  f"\\n[module][+] CORS Configuration Assessment[/module] -> [target]{url}[/target]"
 )
 candidates: list[dict[str, Any]] = []
 observations: list[dict[str, Any]] = []
 test_origins = _build_test_origins(domain)

 async with TalismanHTTPClient(
  proxy=proxy,
  timeout=15,
  verify_ssl=True,
  follow_redirects=False,
  scope=scope,
 ) as client:
  results = await asyncio.gather(
   *(
    _test_origin(url, label, origin, client)
    for label, origin in test_origins
   ),
   return_exceptions=True,
  )

 for result in results:
  if not isinstance(result, dict):
   continue
  reflected = result.get("acao") == result.get("origin_sent")
  credentials = result.get("acac", "").strip().lower() == "true"
  if reflected and credentials:
   candidate = {
    **result,
    "confidence": "candidate",
    "requires_authenticated_resource_validation": True,
    "verification_required": (
     "Repeat the request with an authenticated, dedicated test account and "
     "verify that a cross-origin browser context can read a sensitive response. "
     "Header reflection and Access-Control-Allow-Credentials alone do not prove "
     "that protected user data is exposed."
    ),
   }
   candidates.append(candidate)
  else:
   observations.append({
    **result,
    "classification": "cors_posture_observation",
    "note": (
     "This CORS response did not establish credentialed access to a protected "
     "resource. Wildcard or non-credentialed cross-origin access may be intentional "
     "for public resources."
    ),
   })

 console.print(
  f" CORS assessment complete — {len(candidates)} credentialed-origin candidates, "
  f"{len(observations)} posture observations"
 )
 return {
  "target": url,
  "findings": [],
  "candidates": candidates,
  "observations": observations,
  "vulnerabilities": candidates,
  "count": 0,
  "candidate_count": len(candidates),
  "observation_count": len(observations),
 }
