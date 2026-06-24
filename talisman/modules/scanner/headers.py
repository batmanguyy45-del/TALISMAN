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
        "check": lambda v: True,  # Always flag this one
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
    console.print(
        f"\n[module] Security Headers Audit[/module] → [target]{url}[/target]"
    )
    findings: list[dict[str, Any]] = []

    async with TalismanHTTPClient(proxy=proxy, timeout=15) as client:
        try:
            r = await client.get(url)
            headers = {k.lower(): v for k, v in r.headers.items()}
        except Exception as e:
            log.error("headers_audit_error", url=url, error=str(e))
            return {"target": url, "findings": [], "count": 0}

        # --- Security header checks ---
        for hdr in SECURITY_HEADERS:
            h_lower = hdr["name"].lower()

            if h_lower not in headers:
                if not hdr["required"]:
                    continue
                severity = hdr["severity_missing"]
                if severity == "info":
                    continue  # Don't spam info-level missing headers
                title = f"Missing {hdr['name']} header"
                finding = {
                    "type": "missing_security_header",
                    "header": hdr["name"],
                    "severity": severity,
                    "title": title,
                    "description": hdr["description"],
                    "recommendation": hdr["recommendation"],
                    "cwe": hdr["cwe"],
                }
                findings.append(finding)
                print_finding(title, severity, url)
                if session:
                    await session.add_finding(
                        target=url,
                        module="headers",
                        vuln_type="missing_security_header",
                        severity=severity,
                        confidence="confirmed",
                        title=title,
                        description=hdr["description"],
                        remediation=hdr["recommendation"],
                        cwe=hdr["cwe"],
                        request=f"GET {url} HTTP/1.1",
                    )
            else:
                val = headers[h_lower]

                # Weak value check
                try:
                    is_valid = hdr["validate"](val)
                except Exception:
                    is_valid = True

                if not is_valid:
                    severity = hdr["severity_weak"]
                    title = f"Weak {hdr['name']} configuration"
                    finding = {
                        "type": "weak_security_header",
                        "header": hdr["name"],
                        "value": val,
                        "severity": severity,
                        "title": title,
                    }
                    findings.append(finding)
                    if severity not in ("info",):
                        print_finding(title, severity, url)

                # CSP-specific deep analysis
                if hdr["name"] == "Content-Security-Policy":
                    for pattern, issue_desc, issue_sev in CSP_ISSUES:
                        if pattern.search(val):
                            csp_title = f"CSP Issue: {issue_desc}"
                            findings.append({
                                "type": "csp_weakness",
                                "header": "Content-Security-Policy",
                                "value": val,
                                "severity": issue_sev,
                                "title": csp_title,
                                "issue": issue_desc,
                            })
                            print_finding(csp_title, issue_sev, url)
                            if session:
                                await session.add_finding(
                                    target=url,
                                    module="headers",
                                    vuln_type="csp_misconfiguration",
                                    severity=issue_sev,
                                    confidence="confirmed",
                                    title=csp_title,
                                    description=issue_desc,
                                    request=f"GET {url} HTTP/1.1",
                                    evidence=(
                                        f"Content-Security-Policy: {val[:200]}"
                                    ),
                                )

        # --- Dangerous header disclosure ---
        for header_name, config in DANGEROUS_HEADERS.items():
            h_lower = header_name.lower()
            if h_lower in headers:
                val = headers[h_lower]
                # Apply per-header check function
                if config["check"](val):
                    severity = config["severity"]
                    title = f"Information disclosure via {header_name}: {val[:80]}"
                    finding = {
                        "type": "information_disclosure_header",
                        "header": header_name,
                        "value": val,
                        "severity": severity,
                        "title": title,
                        "description": config["description"],
                    }
                    findings.append(finding)
                    # Only print non-info findings to reduce noise
                    if severity not in ("info",):
                        print_finding(title, severity, url)
                    if session:
                        await session.add_finding(
                            target=url,
                            module="headers",
                            vuln_type="information_disclosure",
                            severity=severity,
                            confidence="confirmed",
                            title=title,
                            description=f"{config['description']}: {val}",
                            evidence=f"{header_name}: {val}",
                        )

        # --- CORS wildcard check ---
        cors_origin = headers.get("access-control-allow-origin", "").strip()
        cors_creds = headers.get("access-control-allow-credentials", "").strip()
        if cors_origin == "*" and cors_creds.lower() != "true":
            # Wildcard without credentials = low severity
            title = "CORS: Wildcard origin (Access-Control-Allow-Origin: *)"
            print_finding(title, "low", url)
            findings.append({
                "type": "cors_wildcard",
                "severity": "low",
                "title": title,
                "evidence": "Access-Control-Allow-Origin: *",
            })

    # Summary — only print if findings above info level
    real_findings = [
        f for f in findings if f.get("severity", "info") not in ("info",)
    ]
    console.print(
        f"  Found {len(real_findings)} header issues "
        f"({len(findings)} total including info)"
    )
    return {"target": url, "findings": findings, "count": len(findings)}
