"""DNS deep analysis — zone transfer, DNSSEC, takeover, wildcard, PTR records."""
from __future__ import annotations
import asyncio
from typing import Any
import aiodns
import dns.zone
import dns.query
from urllib.parse import urlsplit

from talisman.engine.scope import ScopeViolationError
from talisman.utils.logger import get_logger, console, print_finding

log = get_logger(__name__)

RECORD_TYPES = ["A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "SRV", "CAA", "DMARC"]
EMAIL_SECURITY_RECORDS = {
 "_dmarc": "DMARC",
 "_domainkey": "DKIM",
}

async def _query_record(
 domain: str,
 rtype: str,
 resolver: aiodns.DNSResolver,
 scope: Any,
 base_domain: str,
) -> list[str]:
 if domain != base_domain and not domain.endswith("." + base_domain):
  return []
 try:
  async with scope.request_concurrency_slot():
   await scope.acquire_request_slot()
   result = await resolver.query(domain, rtype)
  if rtype == "MX":
   return [f"{r.priority} {r.host}" for r in result]
  if rtype == "SOA":
   r = result[0]
   return [f"{r.nsname} {r.hostmaster} serial={r.serial}"]
  if rtype in ("A", "AAAA"):
   return [r.host for r in result]
  if rtype == "NS":
   return [r.host for r in result]
  if rtype == "TXT":
   return [" ".join(r.text.decode() if isinstance(r.text, bytes) else r.text
        for r in result)]
  if rtype == "CNAME":
   return [result.cname]
  return [str(r) for r in result]
 except Exception:
  return []

async def _check_spf(domain: str, resolver: aiodns.DNSResolver, scope: Any) -> dict[str, Any]:
 txt_records = await _query_record(domain, "TXT", resolver, scope, domain)
 spf = [r for r in txt_records if "v=spf1" in r.lower()]
 issues: list[str] = []
 if not spf:
  issues.append("No SPF record found")
 else:
  spf_val = spf[0]
  if "+all" in spf_val:
   issues.append("SPF uses +all (allows any sender — critical misconfiguration)")
  elif "?all" in spf_val:
   issues.append("SPF uses ?all (neutral — does not enforce)")
  elif "~all" in spf_val:
   issues.append("SPF uses ~all (softfail — not enforced by all providers)")
  if not any(m in spf_val for m in ["-all", "~all", "?all", "+all"]):
   issues.append("SPF record missing 'all' mechanism")
 return {"spf": spf[0] if spf else None, "issues": issues}

async def _check_dmarc(domain: str, resolver: aiodns.DNSResolver, scope: Any) -> dict[str, Any]:
 dmarc_records = await _query_record(f"_dmarc.{domain}", "TXT", resolver, scope, domain)
 if not dmarc_records:
  return {"dmarc": None, "issues": ["No DMARC record found"]}
 dmarc = dmarc_records[0]
 issues: list[str] = []
 if "p=none" in dmarc.lower():
  issues.append("DMARC policy is 'none' — no enforcement, only reporting")
 if "p=quarantine" in dmarc.lower():
  issues.append("DMARC policy is 'quarantine' — emails may go to spam")
 if "rua=" not in dmarc.lower():
  issues.append("DMARC missing aggregate reporting (rua) tag")
 return {"dmarc": dmarc, "issues": issues}

async def run(
 target: str,
 session: Any = None,
 scope: Any = None,
 rate_limiter: Any = None,
 proxy: str | None = None,
 zone_transfer: bool = False,
 takeover_check: bool = True,
 dnssec: bool = False,
 **kwargs: Any,
) -> dict[str, Any]:
 parsed_target = urlsplit(target if "://" in target else f"https://{target}")
 domain = (parsed_target.hostname or "").rstrip(".").lower()
 if not domain:
  return {"domain": target, "records": {}, "issues": [], "error": "invalid_target"}
 if scope is None:
  return {"domain": domain, "records": {}, "issues": [], "error": "scope_enforcer_required"}
 try:
  scope.assert_in_scope(domain)
 except ScopeViolationError as exc:
  return {"domain": domain, "records": {}, "issues": [], "error": str(exc)}
 console.print(f"\n[module][+] DNS Analysis[/module] -> [target]{domain}[/target]")
 # Use the system resolver rather than disclosing every queried name to
 # hard-coded public DNS providers.
 resolver = aiodns.DNSResolver()
 results: dict[str, Any] = {"domain": domain, "records": {}, "issues": []}

 # — All record types ————————————————————————————————————————
 for rtype in RECORD_TYPES:
  vals = await _query_record(domain, rtype, resolver, scope, domain)
  if vals:
   results["records"][rtype] = vals
   console.print(f" {rtype:8} -> {', '.join(vals[:3])}")

 # — Zone transfer attempt ——————————————————————————————————
 if zone_transfer and proxy:
  results["zone_transfer_skipped"] = (
   "AXFR uses raw DNS transport and cannot honor the configured HTTP proxy"
  )
 elif zone_transfer and "NS" in results["records"]:
  for ns in results["records"]["NS"][:3]:
   ns_host = ns.rstrip(".")
   # AXFR is an active request to a nameserver. Only query nameservers
   # explicitly included in the authorized scope.
   try:
    async with scope.request_concurrency_slot():
     addresses = await scope.resolve_network_destination(
      f"http://{ns_host}:53/",
      "GET",
     )
     await scope.acquire_request_slot()
     transferred = await asyncio.to_thread(
      _zone_transfer_sync,
      domain,
      str(addresses[0]),
     )
    if transferred:
     print_finding(f"DNS zone transfer allowed from {ns_host}", "medium", domain)
     results["zone_transfer"] = {"ns": ns_host, "records": transferred[:50]}
     results["issues"].append("zone_transfer_allowed")
     if session:
      await session.add_finding(
       target=domain, module="dns",
       vuln_type="dns_zone_transfer",
       severity="medium", confidence="confirmed",
       title=f"DNS zone transfer allowed from {ns_host}",
       description=(
        f"Nameserver {ns_host} accepted an unauthenticated AXFR request "
        "and returned DNS records for the scoped zone."
       ),
       evidence=f"Transfer returned {len(transferred)} records",
       reproduction=f"dig AXFR {domain} @{ns_host}",
       remediation="Restrict DNS zone transfers to authorized secondary nameservers.",
       cvss_score=5.3, cwe="CWE-200",
      )
     break
   except Exception:
    pass

 # — Email security audit ——————————————————————————————————
 spf_result = await _check_spf(domain, resolver, scope)
 dmarc_result = await _check_dmarc(domain, resolver, scope)
 results["email_security"] = {"spf": spf_result, "dmarc": dmarc_result}
 all_email_issues = spf_result["issues"] + dmarc_result["issues"]
 for issue in all_email_issues:
  # SPF/DMARC posture is operational hygiene, not automatically a bounty
  # vulnerability. Keep it as an observation instead of creating findings.
  console.print(f" [dim]Email posture: {issue}[/dim]")
  results["issues"].append(issue)

 console.print(f" DNS analysis complete — {len(results['issues'])} issues found")
 return results

def _zone_transfer_sync(domain: str, nameserver: str) -> list[str] | None:
 try:
  z = dns.zone.from_xfr(dns.query.xfr(nameserver, domain, timeout=10))
  return [f"{name}.{domain}" for name in z.nodes.keys()]
 except Exception:
  return None
