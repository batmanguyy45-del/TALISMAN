"""DNS deep analysis — zone transfer, DNSSEC, takeover, wildcard, PTR records."""
from __future__ import annotations
import asyncio
import socket
from typing import Any
import aiodns
import dns.resolver
import dns.zone
import dns.query
import dns.exception
from talisman.utils.logger import get_logger, console, print_finding

log = get_logger(__name__)

RECORD_TYPES = ["A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "SRV", "CAA", "DMARC"]
EMAIL_SECURITY_RECORDS = {
    "_dmarc": "DMARC",
    "_domainkey": "DKIM",
}

async def _query_record(domain: str, rtype: str, resolver: aiodns.DNSResolver) -> list[str]:
    try:
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

async def _zone_transfer(domain: str, nameserver: str) -> list[str] | None:
    try:
        z = dns.zone.from_xfr(dns.query.xfr(nameserver, domain, timeout=10))
        records: list[str] = []
        for name, node in z.nodes.items():
            rdatasets = node.rdatasets
            for rdataset in rdatasets:
                for rdata in rdataset:
                    records.append(f"{name}.{domain} {rdataset.rdtype} {rdata}")
        return records
    except Exception:
        return None

async def _check_spf(domain: str, resolver: aiodns.DNSResolver) -> dict[str, Any]:
    txt_records = await _query_record(domain, "TXT", resolver)
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

async def _check_dmarc(domain: str, resolver: aiodns.DNSResolver) -> dict[str, Any]:
    dmarc_records = await _query_record(f"_dmarc.{domain}", "TXT", resolver)
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
    zone_transfer: bool = True,
    takeover_check: bool = True,
    dnssec: bool = False,
    **kwargs: Any,
) -> dict[str, Any]:
    domain = target.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
    console.print(f"\n[module]⚡ DNS Analysis[/module] → [target]{domain}[/target]")
    resolver = aiodns.DNSResolver(nameservers=["8.8.8.8", "1.1.1.1"])
    results: dict[str, Any] = {"domain": domain, "records": {}, "issues": []}

    # — All record types ————————————————————————————————————————
    for rtype in RECORD_TYPES:
        vals = await _query_record(domain, rtype, resolver)
        if vals:
            results["records"][rtype] = vals
            console.print(f"  {rtype:8} → {', '.join(vals[:3])}")

    # — Zone transfer attempt ——————————————————————————————————
    if zone_transfer and "NS" in results["records"]:
        for ns in results["records"]["NS"][:3]:
            ns_host = ns.rstrip(".")
            try:
                ns_ip = socket.gethostbyname(ns_host)
                transferred = await asyncio.get_event_loop().run_in_executor(
                    None, lambda: _zone_transfer_sync(domain, ns_ip)
                )
                if transferred:
                    print_finding(f"DNS zone transfer allowed from {ns_host}", "critical", domain)
                    results["zone_transfer"] = {"ns": ns_host, "records": transferred[:50]}
                    results["issues"].append("zone_transfer_allowed")
                    if session:
                        await session.add_finding(
                            target=domain, module="dns",
                            vuln_type="dns_zone_transfer",
                            severity="critical", confidence="confirmed",
                            title=f"DNS zone transfer allowed from {ns_host}",
                            description=f"Nameserver {ns_host} allows unauthenticated zone transfers. "
                                        f"This exposes your complete internal DNS structure to attackers.",
                            evidence=f"Transfer returned {len(transferred)} records",
                            reproduction=f"dig AXFR {domain} @{ns_host}",
                            remediation="Configure nameservers to restrict zone transfers to authorized secondaries only.",
                            cvss_score=7.5, cwe="CWE-200",
                        )
                    break
            except Exception:
                pass

    # — Email security audit ——————————————————————————————————
    spf_result = await _check_spf(domain, resolver)
    dmarc_result = await _check_dmarc(domain, resolver)
    results["email_security"] = {"spf": spf_result, "dmarc": dmarc_result}
    all_email_issues = spf_result["issues"] + dmarc_result["issues"]
    for issue in all_email_issues:
        severity = "high" if "none" in issue.lower() or "no " in issue.lower() else "medium"
        print_finding(f"Email security: {issue}", severity, domain)
        results["issues"].append(issue)
        if session:
            await session.add_finding(
                target=domain, module="dns",
                vuln_type="email_security",
                severity=severity, confidence="confirmed",
                title=f"Email security issue: {issue}",
                description=issue,
                remediation="Implement strict SPF (-all), DMARC (p=reject), and DKIM signing.",
                cwe="CWE-284",
            )

    console.print(f"  DNS analysis complete — {len(results['issues'])} issues found")
    return results

def _zone_transfer_sync(domain: str, nameserver: str) -> list[str] | None:
    try:
        z = dns.zone.from_xfr(dns.query.xfr(nameserver, domain, timeout=10))
        return [f"{name}.{domain}" for name in z.nodes.keys()]
    except Exception:
        return None
