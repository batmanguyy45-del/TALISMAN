"""Security header audit — comprehensive check of all security-relevant HTTP headers."""
from __future__ import annotations
import re
from typing import Any
from talisman.utils.http_client import TalismanHTTPClient
from talisman.utils.logger import get_logger, console, print_finding

log = get_logger(__name__)

SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "required": True,
        "description": "Enforces HTTPS connections",
        "validate": lambda v: "max-age=" in v and int(re.search(r"max-age=(\d+)", v).group(1)) >= 31536000,
        "recommendation": "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
        "cwe": "CWE-319",
        "severity": "medium",
    },
    "X-Content-Type-Options": {
        "required": True,
        "description": "Prevents MIME-type sniffing",
        "validate": lambda v: v.strip().lower() == "nosniff",
        "recommendation": "Add: X-Content-Type-Options: nosniff",
        "cwe": "CWE-693",
        "severity": "low",
    },
    "X-Frame-Options": {
        "required": True,
        "description": "Prevents clickjacking attacks",
        "validate": lambda v: v.strip().upper() in ("DENY", "SAMEORIGIN"),
        "recommendation": "Add: X-Frame-Options: DENY",
        "cwe": "CWE-1021",
        "severity": "medium",
    },
    "Content-Security-Policy": {
        "required": True,
        "description": "Restricts resource loading to prevent XSS",
        "validate": lambda v: len(v) > 20,
        "recommendation": "Implement a strict CSP. Start with: Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'",
        "cwe": "CWE-79",
        "severity": "medium",
    },
    "X-XSS-Protection": {
        "required": False,
        "description": "Legacy XSS filter (deprecated in modern browsers)",
        "validate": lambda v: True,
        "recommendation": "Use CSP instead; if present set to: X-XSS-Protection: 1; mode=block",
        "cwe": "CWE-79",
        "severity": "info",
    },
    "Referrer-Policy": {
        "required": True,
        "description": "Controls referrer information sent with requests",
        "validate": lambda v: v.strip().lower() in ("no-referrer", "strict-origin", "strict-origin-when-cross-origin", "same-origin"),
        "recommendation": "Add: Referrer-Policy: strict-origin-when-cross-origin",
        "cwe": "CWE-200",
        "severity": "low",
    },
    "Permissions-Policy": {
        "required": False,
        "description": "Controls browser feature access",
        "validate": lambda v: len(v) > 5,
        "recommendation": "Add: Permissions-Policy: camera=(), microphone=(), geolocation=()",
        "cwe": "CWE-693",
        "severity": "info",
    },
    "Cache-Control": {
        "required": False,
        "description": "Controls caching behavior for sensitive pages",
        "validate": lambda v: "no-store" in v.lower() or "private" in v.lower(),
        "recommendation": "For sensitive pages: Cache-Control: no-store, no-cache, must-revalidate",
        "cwe": "CWE-524",
        "severity": "low",
    },
}

DANGEROUS_HEADERS = {
    "X-Powered-By": {"severity": "info", "description": "Reveals server technology (information leakage)"},
    "Server": {"severity": "info", "description": "Reveals server version (information leakage)"},
    "X-AspNet-Version": {"severity": "low", "description": "Reveals ASP.NET version"},
    "X-AspNetMvc-Version": {"severity": "low", "description": "Reveals ASP.NET MVC version"},
    "X-Generator": {"severity": "info", "description": "Reveals CMS/generator"},
    "X-Runtime": {"severity": "info", "description": "Reveals backend runtime"},
    "X-Application-Context": {"severity": "low", "description": "Reveals Spring Boot context"},
    "X-Debug-Token": {"severity": "medium", "description": "Exposes Symfony debug information"},
    "X-Debug-Token-Link": {"severity": "medium", "description": "Direct link to Symfony profiler"},
    "X-CF-Debug": {"severity": "medium", "description": "Cloudflare debug information"},
    "X-Amz-Request-Id": {"severity": "info", "description": "Reveals AWS infrastructure"},
    "X-Amz-Id-2": {"severity": "info", "description": "Reveals AWS S3 server identity"},
}

def _analyze_csp(csp: str) -> list[dict[str, str]]:
    issues: list[dict[str, str]] = []
    if "unsafe-inline" in csp:
        issues.append({"issue": "'unsafe-inline' in CSP", "severity": "high",
                       "detail": "Allows inline scripts — negates XSS protection"})
    if "unsafe-eval" in csp:
        issues.append({"issue": "'unsafe-eval' in CSP", "severity": "high",
                       "detail": "Allows eval() — weakens XSS protection significantly"})
    if "default-src *" in csp or "script-src *" in csp:
        issues.append({"issue": "Wildcard in CSP source", "severity": "high",
                       "detail": "Wildcard (*) allows loading resources from any origin"})
    if "http:" in csp and "https:" not in csp:
        issues.append({"issue": "Allows HTTP in CSP", "severity": "medium",
                       "detail": "Mixed content allowed by CSP policy"})
    if "data:" in csp:
        issues.append({"issue": "data: URI scheme allowed in CSP", "severity": "medium",
                       "detail": "data: URIs can be used for XSS in some contexts"})
    cdn_allowlists = ["ajax.googleapis.com", "cdn.jsdelivr.net", "cdnjs.cloudflare.com"]
    for cdn in cdn_allowlists:
        if cdn in csp:
            issues.append({"issue": f"CDN allowlisted: {cdn}", "severity": "low",
                           "detail": "CDN domains may host malicious payloads — prefer SRI hashes"})
    return issues

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
    console.print(f"\n[module]⚡ Security Headers Audit[/module] → [target]{url}[/target]")
    findings: list[dict[str, Any]] = []
    async with TalismanHTTPClient(proxy=proxy, timeout=15) as client:
        try:
            r = await client.get(url)
            headers = {k.lower(): v for k, v in r.headers.items()}
            for header_name, config in SECURITY_HEADERS.items():
                h_lower = header_name.lower()
                if h_lower not in headers:
                    if config["required"]:
                        finding = {
                            "type": "missing_security_header",
                            "header": header_name,
                            "severity": config["severity"],
                            "title": f"Missing {header_name} header",
                            "description": config["description"],
                            "recommendation": config["recommendation"],
                            "cwe": config["cwe"],
                        }
                        findings.append(finding)
                        print_finding(finding["title"], finding["severity"], url)
                        if session:
                            await session.add_finding(
                                target=url, module="headers",
                                vuln_type="missing_security_header",
                                severity=finding["severity"],
                                confidence="confirmed",
                                title=finding["title"],
                                description=finding["description"],
                                remediation=finding["recommendation"],
                                cwe=finding["cwe"],
                                request=f"GET {url} HTTP/1.1",
                                response=f"Response missing header: {header_name}",
                            )
                else:
                    val = headers[h_lower]
                    if not config["validate"](val):
                        finding = {
                            "type": "weak_security_header",
                            "header": header_name,
                            "value": val,
                            "severity": config["severity"],
                            "title": f"Weak {header_name} configuration",
                            "description": f"{config['description']} — current value: {val[:100]}",
                            "recommendation": config["recommendation"],
                        }
                        findings.append(finding)
                        print_finding(finding["title"], "info", url)
                    if header_name == "Content-Security-Policy":
                        csp_issues = _analyze_csp(val)
                        for issue in csp_issues:
                            print_finding(f"CSP Issue: {issue['issue']}", issue["severity"], url)
                            if session:
                                await session.add_finding(
                                    target=url, module="headers",
                                    vuln_type="csp_misconfiguration",
                                    severity=issue["severity"],
                                    confidence="confirmed",
                                    title=f"CSP Issue: {issue['issue']}",
                                    description=issue["detail"],
                                    request=f"GET {url} HTTP/1.1",
                                    response=f"Content-Security-Policy: {val[:200]}",
                                )
            for header_name, config in DANGEROUS_HEADERS.items():
                h_lower = header_name.lower()
                if h_lower in headers:
                    val = headers[h_lower]
                    finding = {
                        "type": "information_disclosure_header",
                        "header": header_name,
                        "value": val,
                        "severity": config["severity"],
                        "title": f"Information disclosure via {header_name}",
                        "description": f"{config['description']}: {val[:100]}",
                    }
                    findings.append(finding)
                    print_finding(finding["title"], config["severity"], url)
                    if session:
                        await session.add_finding(
                            target=url, module="headers",
                            vuln_type="information_disclosure",
                            severity=config["severity"],
                            confidence="confirmed",
                            title=finding["title"],
                            description=finding["description"],
                            evidence=f"{header_name}: {val}",
                        )
            cors_origin = headers.get("access-control-allow-origin", "")
            if cors_origin == "*":
                print_finding("CORS: Wildcard origin allowed", "medium", url)
                if session:
                    await session.add_finding(
                        target=url, module="headers",
                        vuln_type="cors_misconfiguration",
                        severity="medium", confidence="confirmed",
                        title="CORS wildcard origin",
                        description="Access-Control-Allow-Origin: * allows any origin to make cross-origin requests",
                        remediation="Restrict CORS to specific allowed origins",
                        evidence=f"Access-Control-Allow-Origin: {cors_origin}",
                    )
        except Exception as e:
            log.error("headers_audit_error", url=url, error=str(e))
    console.print(f"  Found {len(findings)} header issues")
    return {"target": url, "findings": findings, "count": len(findings)}
