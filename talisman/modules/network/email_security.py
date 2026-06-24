"""Email security posture checker -- SPF, DKIM, DMARC record analysis."""
from __future__ import annotations
import asyncio
import dns.asyncresolver
import dns.exception
from typing import Any
from talisman.utils.logger import get_logger, console, print_finding

log = get_logger(__name__)


async def _query_txt(domain: str) -> list[str]:
    """Query TXT records for a domain."""
    try:
        resolver = dns.asyncresolver.Resolver()
        resolver.timeout = 5
        resolver.lifetime = 5
        answers = await resolver.resolve(domain, "TXT")
        return [str(r).strip('"') for r in answers]
    except dns.exception.DNSException:
        return []
    except Exception:
        return []


async def _check_spf(domain: str) -> dict[str, Any]:
    """Check SPF record."""
    result: dict[str, Any] = {
        "present": False,
        "record": None,
        "strict": False,
        "valid": False,
        "issues": [],
    }
    records = await _query_txt(domain)
    for record in records:
        if record.startswith("v=spf1"):
            result["present"] = True
            result["record"] = record
            result["valid"] = True

            # Check for ~all (softfail) or -all (hardfail)
            if " -all" in record:
                result["strict"] = True
            elif " ~all" in record:
                result["strict"] = False
                result["issues"].append("Softfail (~all) policy allows unauthorized senders")
            elif " ?all" in record or record.endswith("all"):
                result["issues"].append("Neutral (?all or no explicit all mechanism) provides no enforcement")
            else:
                result["issues"].append("Missing 'all' mechanism -- no enforcement of SPF policy")

            # Check include limit
            include_count = record.count("include:")
            if include_count > 10:
                result["issues"].append(f"High DNS lookup count ({include_count} includes) -- may exceed 10-lookup limit")

            break
    else:
        result["issues"].append("No SPF record found")

    return result


async def _check_dkim(domain: str, selector: str = "default") -> dict[str, Any]:
    """Check DKIM record for a given selector."""
    result: dict[str, Any] = {
        "present": False,
        "selector": selector,
        "record": None,
        "valid": False,
        "issues": [],
    }
    dkim_domain = f"{selector}._domainkey.{domain}"
    records = await _query_txt(dkim_domain)
    for record in records:
        if record.startswith("v=DKIM1"):
            result["present"] = True
            result["record"] = record
            result["valid"] = True

            if "p=" not in record:
                result["issues"].append("DKIM record missing public key (p= tag)")
            break
    else:
        result["issues"].append(f"No DKIM record found for selector '{selector}'")

    return result


async def _check_dmarc(domain: str) -> dict[str, Any]:
    """Check DMARC record."""
    result: dict[str, Any] = {
        "present": False,
        "record": None,
        "policy": None,
        "pct": 100,
        "rua": None,
        "strict": False,
        "valid": False,
        "issues": [],
    }
    dmarc_domain = f"_dmarc.{domain}"
    records = await _query_txt(dmarc_domain)
    for record in records:
        if record.startswith("v=DMARC1"):
            result["present"] = True
            result["record"] = record
            result["valid"] = True

            # Extract policy
            for part in record.split(";"):
                part = part.strip()
                if part.startswith("p="):
                    result["policy"] = part[2:]
                    result["strict"] = part[2:] == "reject"
                elif part.startswith("pct="):
                    try:
                        result["pct"] = int(part[4:])
                    except ValueError:
                        pass
                elif part.startswith("rua="):
                    result["rua"] = part[4:]

            # Analyze policy
            if result["policy"] == "none":
                result["issues"].append("DMARC policy is 'none' -- no enforcement of SPF/DKIM alignment")
            elif result["policy"] == "quarantine":
                result["issues"].append("DMARC policy is 'quarantine' -- unauthorized email may be marked as spam")
            elif result["policy"] == "reject":
                pass  # Best policy

            if result["pct"] < 100:
                result["issues"].append(f"DMARC only applies to {result['pct']}% of email")

            if not result["rua"]:
                result["issues"].append("No aggregate reporting (rua) configured -- cannot monitor DMARC failures")

            break
    else:
        result["issues"].append("No DMARC record found")

    return result


async def run(
    target: str,
    session: Any = None,
    scope: Any = None,
    rate_limiter: Any = None,
    proxy: str | None = None,
    dkim_selectors: list[str] | None = None,
    **kwargs: Any,
) -> dict[str, Any]:
    domain = target.split("://")[-1].split("/")[0].split(":")[0]
    console.print(f"\n[module][+] Email Security Checker[/module] -> [target]{domain}[/target]")
    findings: list[dict[str, Any]] = []

    # Remove leading www. for root domain check
    if domain.startswith("www."):
        domain = domain[4:]

    selectors = dkim_selectors or ["default", "google", "protonmail", "selector1", "selector2"]

    spf_result = await _check_spf(domain)
    console.print(f"  SPF: {'[success]Present[/success]' if spf_result['present'] else '[error]Missing[/error]'}")

    if spf_result["present"] and not spf_result["strict"]:
        spf_title = f"SPF record for {domain} uses softfail or no enforcement"
        print_finding(spf_title, "medium", domain)
        findings.append({"issue": "spf_weak_policy", "detail": spf_result})
        if session:
            await session.add_finding(
                target=domain, module="email_security",
                vuln_type="spf_weak_policy",
                severity="medium", confidence="confirmed",
                title=spf_title,
                description=f"SPF record for {domain}: {spf_result['record'][:100]}. Issues: {'; '.join(spf_result['issues'])}",
                remediation="1. Use -all (hardfail) instead of ~all. 2. Avoid excessive DNS lookups. 3. Keep include lists minimal.",
                cwe="CWE-345",
            )

    if not spf_result["present"]:
        print_finding(f"Missing SPF record for {domain}", "high", domain)
        findings.append({"issue": "spf_missing", "detail": spf_result})
        if session:
            await session.add_finding(
                target=domain, module="email_security",
                vuln_type="spf_missing",
                severity="high", confidence="confirmed",
                title="Missing SPF record",
                description=f"No SPF record found for {domain}. Anyone can send email appearing to come from this domain.",
                remediation="Publish an SPF record listing authorized email senders.",
                cvss_score=6.5, cwe="CWE-345",
            )

    # DKIM
    dkim_results = []
    for selector in selectors:
        dkim_result = await _check_dkim(domain, selector)
        dkim_results.append(dkim_result)
        if dkim_result["present"]:
            console.print(f"  DKIM ({selector}): [success]Present[/success]")
            break
    else:
        console.print("  DKIM: [error]No record found (checked selectors: {})[/error]".format(", ".join(selectors)))

    dkim_found = any(r["present"] for r in dkim_results)
    if not dkim_found:
        print_finding(f"Missing DKIM record for {domain}", "high", domain)
        findings.append({"issue": "dkim_missing", "selectors_checked": selectors})
        if session:
            await session.add_finding(
                target=domain, module="email_security",
                vuln_type="dkim_missing",
                severity="high", confidence="confirmed",
                title="Missing DKIM record",
                description=f"No DKIM record found for {domain} (checked selectors: {', '.join(selectors)}). Emails from this domain cannot be cryptographically signed.",
                remediation="Configure DKIM signing for all outgoing email and publish the public key in DNS.",
                cvss_score=6.5, cwe="CWE-345",
            )

    # DMARC
    dmarc_result = await _check_dmarc(domain)
    console.print(f"  DMARC: {'[success]Present[/success]' if dmarc_result['present'] else '[error]Missing[/error]'}")

    if dmarc_result["present"]:
        if dmarc_result["policy"] != "reject":
            print_finding(f"DMARC policy for {domain} is '{dmarc_result['policy']}' -- not enforcing reject", "high", domain)
            findings.append({"issue": "dmarc_weak_policy", "detail": dmarc_result})
            if session:
                await session.add_finding(
                    target=domain, module="email_security",
                    vuln_type="dmarc_weak_policy",
                    severity="high", confidence="confirmed",
                    title=f"DMARC policy for {domain} is '{dmarc_result['policy']}'",
                    description=f"DMARC record: {dmarc_result['record'][:100]}. Policy '{dmarc_result['policy']}' does not reject unauthorized email. Issues: {'; '.join(dmarc_result['issues'])}",
                    remediation="1. Set DMARC policy to 'reject' after monitoring. 2. Configure aggregate reporting (rua). 3. Ensure SPF and DKIM alignment.",
                    cvss_score=6.5, cwe="CWE-345",
                )

        if not dmarc_result["rua"]:
            print_finding(f"No DMARC reporting (rua) configured for {domain}", "low", domain)
            findings.append({"issue": "dmarc_no_reporting"})
    else:
        print_finding(f"Missing DMARC record for {domain}", "high", domain)
        findings.append({"issue": "dmarc_missing", "detail": dmarc_result})
        if session:
            await session.add_finding(
                target=domain, module="email_security",
                vuln_type="dmarc_missing",
                severity="high", confidence="confirmed",
                title="Missing DMARC record",
                description=f"No DMARC record found for {domain}. Receiving mail servers have no policy for handling SPF/DKIM failures.",
                remediation="Publish a DMARC record with policy 'reject' and configure aggregate reporting.",
                cvss_score=6.5, cwe="CWE-345",
            )

    # Overall score
    score = 0
    if spf_result["present"]:
        score += 1
        if spf_result["strict"]:
            score += 1
    if dkim_found:
        score += 1
    if dmarc_result["present"]:
        score += 1
        if dmarc_result["policy"] == "reject":
            score += 1

    console.print(f"  Email security score: {score}/5 (SPF={'Y' if spf_result['present'] else 'N'}, DKIM={'Y' if dkim_found else 'N'}, DMARC={'Y' if dmarc_result['present'] else 'N'})")
    return {
        "target": domain,
        "spf": spf_result,
        "dkim": dkim_results,
        "dmarc": dmarc_result,
        "score": score,
        "max_score": 5,
        "findings": findings,
        "count": len(findings),
    }
