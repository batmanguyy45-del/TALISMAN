"""CSP deep evaluator — bypass technique detection, misconfiguration analysis, nonce quality check."""
from __future__ import annotations
import re
import random
import string
from typing import Any
from talisman.utils.http_client import TalismanHTTPClient
from talisman.utils.logger import get_logger, console, print_finding

log = get_logger(__name__)

CSP_DIRECTIVES = [
    "default-src", "script-src", "style-src", "img-src",
    "connect-src", "font-src", "object-src", "media-src",
    "frame-src", "frame-ancestors", "form-action",
    "base-uri", "manifest-src", "worker-src",
    "report-uri", "report-to", "navigate-to",
    "require-trusted-types-for", "trusted-types",
    "upgrade-insecure-requests", "block-all-mixed-content",
]

DANGEROUS_CDNS = [
    "cdn.jsdelivr.net", "cdnjs.cloudflare.com", "ajax.googleapis.com",
    "ajax.aspnetcdn.com", "code.jquery.com", "cdn.socket.io",
    "maxcdn.bootstrapcdn.com", "stackpath.bootstrapcdn.com",
    "unpkg.com", "cdn.jsdelivr.net",
]

JSONP_ENDPOINTS = [
    "//cdn.jsdelivr.net/npm/jquery@3/dist/jquery.min.js",
    "//cdnjs.cloudflare.com/ajax/libs/angular.js/1.8.3/angular.min.js",
    "//ajax.googleapis.com/ajax/libs/angularjs/1.8.2/angular.min.js",
    "//cdnjs.cloudflare.com/ajax/libs/prototype/1.7.3/prototype.js",
]


def _parse_csp(csp_value: str) -> dict[str, list[str]]:
    """Parse a CSP string into a dict of directives."""
    directives: dict[str, list[str]] = {}
    parts = re.split(r";\s*", csp_value.strip())
    for part in parts:
        part = part.strip()
        if not part:
            continue
        tokens = re.split(r"\s+", part, maxsplit=1)
        directive = tokens[0].lower()
        value = tokens[1] if len(tokens) > 1 else ""
        if directive not in directives:
            directives[directive] = []
        if value:
            directives[directive].append(value)
    return directives


def _analyze_csp(csp_value: str, domain: str) -> list[dict[str, Any]]:
    """Deep CSP analysis — find bypass techniques and misconfigurations."""
    issues: list[dict[str, Any]] = []
    directives = _parse_csp(csp_value)

    # Check for missing CSP
    if not directives:
        return issues

    script_src = directives.get("script-src", directives.get("default-src", []))
    script_src_str = " ".join(script_src)

    # 1. unsafe-inline
    if "'unsafe-inline'" in script_src_str:
        issues.append({
            "issue": "unsafe_inline",
            "severity": "high",
            "directive": "script-src",
            "description": "unsafe-inline allows any inline script to execute, completely defeating CSP's XSS protection",
        })

    # 2. unsafe-eval
    if "'unsafe-eval'" in script_src_str:
        issues.append({
            "issue": "unsafe_eval",
            "severity": "high",
            "directive": "script-src",
            "description": "unsafe-eval allows eval(), setTimeout(), and other code execution vectors",
        })

    # 3. Wildcard or no script-src
    if not script_src:
        issues.append({
            "issue": "no_script_src",
            "severity": "high",
            "directive": "script-src",
            "description": "script-src is not set, falling back to default-src or allowing all scripts",
        })

    for src in script_src:
        # 4. Wildcard sources
        if src == "*" or src.startswith("*.com") or src == "*":
            issues.append({
                "issue": "wildcard_src",
                "severity": "high",
                "directive": "script-src",
                "value": src,
                "description": f"Wildcard source '{src}' allows loading scripts from any domain",
            })

        # 5. HTTP sources (not HTTPS)
        if src.startswith("http://") and domain not in src:
            issues.append({
                "issue": "http_source",
                "severity": "medium",
                "directive": "script-src",
                "value": src,
                "description": f"HTTP source '{src}' allows scripts over unencrypted connection",
            })

        # 6. Dangerous CDNs (potential JSONP abuse)
        for cdn in DANGEROUS_CDNS:
            if cdn in src:
                issues.append({
                    "issue": "cdn_jsonp_bypass",
                    "severity": "medium",
                    "directive": "script-src",
                    "value": src,
                    "description": f"CDN '{cdn}' hosts libraries with JSONP endpoints that can be abused to execute arbitrary JavaScript",
                })
                break

        # 7. data: scheme
        if src == "data:":
            issues.append({
                "issue": "data_scheme",
                "severity": "high",
                "directive": "script-src",
                "value": "data:",
                "description": "data: scheme allows inlining arbitrary JavaScript via data URIs",
            })

        # 8. blob: scheme
        if src == "blob:":
            issues.append({
                "issue": "blob_scheme",
                "severity": "medium",
                "directive": "script-src",
                "value": "blob:",
                "description": "blob: scheme allows creating script from Blob objects, bypassing CSP",
            })

    # 9. Nonce-based CSP check
    has_nonce = any("'nonce-" in s for s in script_src)
    if has_nonce:
        # Extract nonce prefix
        for src in script_src:
            nonce_match = re.search(r"'nonce-([^']+)'", src)
            if nonce_match:
                nonce = nonce_match.group(1)
                # Check for short nonce
                if len(nonce) < 16:
                    issues.append({
                        "issue": "short_nonce",
                        "severity": "medium",
                        "directive": "script-src",
                        "value": f"nonce length: {len(nonce)}",
                        "description": f"Nonce is only {len(nonce)} characters long. Nonces should be at least 128 bits (~27 chars base64) to prevent brute force",
                    })
                break

    # 10. strict-dynamic
    has_strict_dynamic = "'strict-dynamic'" in script_src_str
    if not has_strict_dynamic and has_nonce:
        issues.append({
            "issue": "missing_strict_dynamic",
            "severity": "info",
            "directive": "script-src",
            "description": "nonce-based CSP without strict-dynamic requires maintaining an allowlist of trusted script hosts",
        })

    # 11. base-uri check
    base_uri = directives.get("base-uri", [])
    if not base_uri:
        issues.append({
            "issue": "missing_base_uri",
            "severity": "medium",
            "directive": "base-uri",
            "description": "base-uri not set — attackers can inject <base> tags to hijack relative URLs",
        })
    elif "'none'" not in base_uri and "'self'" not in base_uri and "*" in " ".join(base_uri):
        issues.append({
            "issue": "wildcard_base_uri",
            "severity": "medium",
            "directive": "base-uri",
            "description": "base-uri allows any domain — base tag injection can redirect all relative URLs",
        })

    # 12. frame-ancestors
    frame_ancestors = directives.get("frame-ancestors", [])
    if not frame_ancestors:
        issues.append({
            "issue": "missing_frame_ancestors",
            "severity": "low",
            "directive": "frame-ancestors",
            "description": "frame-ancestors not set — page can be embedded in iframes (clickjacking)",
        })
    elif "*" in " ".join(frame_ancestors):
        issues.append({
            "issue": "wildcard_frame_ancestors",
            "severity": "medium",
            "directive": "frame-ancestors",
            "description": "frame-ancestors allows all domains — any site can embed this page in an iframe",
        })

    # 13. form-action
    form_action = directives.get("form-action", [])
    if not form_action:
        issues.append({
            "issue": "missing_form_action",
            "severity": "low",
            "directive": "form-action",
            "description": "form-action not set — forms can submit to any domain (phishing vector)",
        })

    # 14. Trusted Types
    trusted_types = directives.get("require-trusted-types-for", [])
    if not trusted_types:
        issues.append({
            "issue": "no_trusted_types",
            "severity": "info",
            "directive": "require-trusted-types-for",
            "description": "Trusted Types not enforced — DOM XSS via innerHTML sinks is possible",
        })

    # 15. CSP reporting
    report_uri = directives.get("report-uri", []) or directives.get("report-to", [])
    if not report_uri:
        issues.append({
            "issue": "no_reporting",
            "severity": "info",
            "directive": "report-uri",
            "description": "No CSP reporting configured — violations will not be monitored",
        })

    return issues


async def run(
    target: str,
    session: Any = None,
    scope: Any = None,
    rate_limiter: Any = None,
    proxy: str | None = None,
    **kwargs: Any,
) -> dict[str, Any]:
    url = target if "://" in target else f"https://{target}"
    host = url.split("://")[1].split("/")[0].split(":")[0]
    console.print(f"\n[module][+] CSP Deep Evaluator[/module] -> [target]{url}[/target]")
    findings: list[dict[str, Any]] = []
    csp_value = ""

    async with TalismanHTTPClient(proxy=proxy, timeout=10) as client:
        try:
            r = await client.get(url, timeout=10)
            csp_value = (r.headers.get("Content-Security-Policy") or
                         r.headers.get("Content-Security-Policy-Report-Only") or "")
        except Exception:
            console.print("  Could not retrieve CSP header")
            return {"target": url, "csp_found": False, "findings": []}

        if not csp_value:
            console.print("  No CSP header found")
            findings.append({"issue": "no_csp", "severity": "medium"})
            if session:
                await session.add_finding(
                    target=url, module="csp_evaluator",
                    vuln_type="no_csp",
                    severity="medium", confidence="confirmed",
                    title="No Content Security Policy header",
                    description="The page does not send a Content-Security-Policy header. XSS attacks can execute arbitrary scripts without restriction.",
                    remediation="Implement a strict CSP with nonce-based script-src and 'strict-dynamic'.",
                    cvss_score=6.5, cwe="CWE-1021",
                )
            return {"target": url, "csp": "", "findings": findings}

        console.print(f"  CSP: {csp_value[:120]}...")
        issues = _analyze_csp(csp_value, host)

        for issue in issues:
            severity = issue.get("severity", "medium")
            title = f"CSP misconfiguration: {issue.get('description', issue['issue'])}"
            print_finding(title, severity, url)
            findings.append(issue)
            if session:
                cwe_map = {
                    "unsafe_inline": "CWE-79",
                    "unsafe_eval": "CWE-79",
                    "wildcard_src": "CWE-79",
                    "data_scheme": "CWE-79",
                    "blob_scheme": "CWE-79",
                    "cdn_jsonp_bypass": "CWE-79",
                    "missing_base_uri": "CWE-444",
                    "short_nonce": "CWE-330",
                    "wildcard_frame_ancestors": "CWE-1021",
                }
                cvss_map = {
                    "high": 8.3, "medium": 6.1, "low": 3.7, "info": 0.0,
                }
                await session.add_finding(
                    target=url, module="csp_evaluator",
                    vuln_type=f"csp_{issue['issue']}",
                    severity=severity, confidence="confirmed",
                    title=title,
                    description=issue.get("description", ""),
                    evidence=f"Directive: {issue.get('directive', 'N/A')}, Value: {issue.get('value', 'N/A')}",
                    remediation=_get_remediation(issue["issue"]),
                    cvss_score=cvss_map.get(severity, 5.0),
                    cwe=cwe_map.get(issue["issue"], "CWE-693"),
                )

    console.print(f"  CSP evaluation complete -- {len(findings)} issues")
    return {"target": url, "csp": csp_value, "findings": findings, "count": len(findings)}


def _get_remediation(issue_type: str) -> str:
    remediations = {
        "unsafe_inline": "Remove 'unsafe-inline'. Use nonce-based or hash-based script allowlisting with 'strict-dynamic'.",
        "unsafe_eval": "Remove 'unsafe-eval'. Refactor code to avoid eval(), setTimeout(string), and new Function().",
        "wildcard_src": "Replace wildcard sources with specific, trusted domains. Prefer nonce+strict-dynamic over URL allowlisting.",
        "data_scheme": "Remove data: from script-src. If needed for images, restrict to img-src only.",
        "blob_scheme": "Remove blob: from script-src. Use worker-src for Web Workers if needed.",
        "cdn_jsonp_bypass": "Remove CDN allowlisting and use nonce+strict-dynamic instead. JSONP endpoints can execute arbitrary code.",
        "missing_base_uri": "Set base-uri 'self' or 'none' to prevent base tag injection attacks.",
        "short_nonce": "Use cryptographically random nonces of at least 128 bits (~27 chars in base64).",
        "missing_frame_ancestors": "Set frame-ancestors 'none' or 'self' to prevent clickjacking.",
        "wildcard_frame_ancestors": "Restrict frame-ancestors to 'none' or specific trusted origins.",
        "missing_form_action": "Set form-action 'self' to prevent phishing via form submission to attacker domains.",
        "no_trusted_types": "Implement Trusted Types policy to prevent DOM XSS via innerHTML and similar sinks.",
        "no_reporting": "Configure report-uri or report-to to monitor CSP violations for debugging and attack detection.",
    }
    return remediations.get(issue_type, "Review and tighten CSP directives according to application requirements.")
