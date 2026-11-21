"""Email DNS posture checker.

SPF, DKIM and DMARC observations are operational hygiene, not automatically
reportable vulnerabilities. This module therefore returns observations only.
"""
from __future__ import annotations

from typing import Any
from urllib.parse import urlsplit

import dns.asyncresolver
import dns.exception

from talisman.engine.scope import ScopeViolationError
from talisman.utils.logger import console, get_logger

log = get_logger(__name__)


async def _query_txt(domain: str, scope: Any, base_domain: str) -> list[str]:
    """Query TXT records only within the DNS zone derived from the scoped host."""
    normalized = domain.rstrip(".").lower()
    base = base_domain.rstrip(".").lower()
    if normalized != base and not normalized.endswith("." + base):
        return []

    try:
        await scope.acquire_request_slot()
        resolver = dns.asyncresolver.Resolver()
        resolver.timeout = 5
        resolver.lifetime = 5
        answers = await resolver.resolve(normalized, "TXT")
        return [str(record).strip('"') for record in answers]
    except (dns.exception.DNSException, OSError):
        return []
    except Exception as exc:
        log.debug("email_dns_query_error", error=type(exc).__name__)
        return []


async def _check_spf(domain: str, scope: Any) -> dict[str, Any]:
    result: dict[str, Any] = {
        "present": False,
        "record": None,
        "strict": False,
        "valid": False,
        "issues": [],
    }
    records = await _query_txt(domain, scope, domain)
    spf_records = [record for record in records if record.lower().startswith("v=spf1")]

    if not spf_records:
        result["issues"].append("No SPF record found at the queried hostname")
        return result
    if len(spf_records) > 1:
        result["issues"].append("Multiple SPF records were returned; verify DNS configuration")

    record = spf_records[0]
    result["present"] = True
    result["record"] = record
    result["valid"] = True

    mechanisms = [part.lower() for part in record.split()]
    if "-all" in mechanisms:
        result["strict"] = True
    elif "~all" in mechanisms:
        result["issues"].append("SPF uses softfail (~all)")
    elif "?all" in mechanisms or "+all" in mechanisms:
        result["issues"].append("SPF uses a non-restrictive all mechanism")

    include_count = record.lower().count("include:")
    if include_count > 10:
        result["issues"].append(
            f"SPF contains {include_count} include mechanisms; evaluate DNS lookup limits"
        )
    return result


async def _check_dkim(
    domain: str,
    selector: str,
    scope: Any,
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "present": False,
        "selector": selector,
        "record": None,
        "valid": False,
        "issues": [],
    }
    if not selector or any(char not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-" for char in selector):
        result["issues"].append("Invalid DKIM selector")
        return result

    dkim_domain = f"{selector}._domainkey.{domain}"
    records = await _query_txt(dkim_domain, scope, domain)
    for record in records:
        if record.lower().startswith("v=dkim1"):
            result["present"] = True
            result["record"] = record
            result["valid"] = "p=" in record.lower()
            if not result["valid"]:
                result["issues"].append("DKIM record has no public-key p= value")
            break

    if not result["present"]:
        result["issues"].append(
            f"No DKIM record found for the supplied selector '{selector}'"
        )
    return result


async def _check_dmarc(domain: str, scope: Any) -> dict[str, Any]:
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
    records = await _query_txt(f"_dmarc.{domain}", scope, domain)
    dmarc_records = [record for record in records if record.lower().startswith("v=dmarc1")]

    if not dmarc_records:
        result["issues"].append("No DMARC record found at the queried hostname")
        return result
    if len(dmarc_records) > 1:
        result["issues"].append("Multiple DMARC records were returned; verify DNS configuration")

    record = dmarc_records[0]
    result["present"] = True
    result["record"] = record
    result["valid"] = True

    for item in record.split(";"):
        part = item.strip()
        if part.lower().startswith("p="):
            result["policy"] = part[2:].lower()
        elif part.lower().startswith("pct="):
            try:
                percentage = int(part[4:])
                if 0 <= percentage <= 100:
                    result["pct"] = percentage
                else:
                    result["issues"].append("DMARC pct value is outside 0-100")
            except ValueError:
                result["issues"].append("DMARC pct value is not an integer")
        elif part.lower().startswith("rua="):
            result["rua"] = part[4:]

    result["strict"] = result["policy"] == "reject" and result["pct"] == 100
    if result["policy"] == "none":
        result["issues"].append("DMARC policy is monitor-only (p=none)")
    elif result["policy"] == "quarantine":
        result["issues"].append("DMARC policy is quarantine (p=quarantine)")
    elif result["policy"] not in {"reject", "quarantine", "none"}:
        result["issues"].append("DMARC policy is missing or unrecognized")
    if result["pct"] < 100:
        result["issues"].append(f"DMARC policy applies to {result['pct']}% of messages")
    if not result["rua"]:
        result["issues"].append("No aggregate reporting (rua) address is configured")
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
    parsed = urlsplit(target if "://" in target else f"https://{target}")
    domain = (parsed.hostname or "").rstrip(".").lower()
    if not domain:
        return {"target": target, "observations": [], "error": "invalid_target"}
    if scope is None:
        return {
            "target": domain,
            "observations": [],
            "error": "scope_enforcer_required",
        }
    try:
        scope.assert_in_scope(domain)
    except ScopeViolationError as exc:
        return {"target": domain, "observations": [], "error": str(exc)}

    console.print(
        f"\n[module][+] Email DNS Posture[/module] -> [target]{domain}[/target]"
    )
    spf_result = await _check_spf(domain, scope)
    dmarc_result = await _check_dmarc(domain, scope)

    # DKIM selectors are not generally discoverable from DNS. Only test
    # selectors supplied by the operator; never claim DKIM is absent based on
    # a small guessed list.
    selectors = list(dict.fromkeys(dkim_selectors or []))[:20]
    dkim_results = [
        await _check_dkim(domain, selector, scope)
        for selector in selectors
    ]

    observations: list[dict[str, Any]] = []
    if spf_result["issues"]:
        observations.append({"type": "spf_posture", "detail": spf_result})
    if dmarc_result["issues"]:
        observations.append({"type": "dmarc_posture", "detail": dmarc_result})
    for item in dkim_results:
        if item["issues"]:
            observations.append({"type": "dkim_selector_check", "detail": item})

    console.print(
        "  SPF: "
        + ("present" if spf_result["present"] else "not found")
        + " | DMARC: "
        + ("present" if dmarc_result["present"] else "not found")
        + f" | DKIM selectors checked: {len(dkim_results)}"
    )
    return {
        "target": domain,
        "spf": spf_result,
        "dkim": dkim_results,
        "dkim_selector_check_performed": bool(selectors),
        "dmarc": dmarc_result,
        "observations": observations,
        "findings": [],
        "count": 0,
    }
