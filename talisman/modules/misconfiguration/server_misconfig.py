"""Server misconfiguration scanner — Nginx, Apache, IIS, general checks."""
from __future__ import annotations
import asyncio
import re
from typing import Any
from talisman.utils.http_client import TalismanHTTPClient
from talisman.utils.logger import get_logger, console, print_finding

log = get_logger(__name__)

SENSITIVE_DISCLOSURES = [
    ("/.htaccess",              "Apache .htaccess configuration"),
    ("/.htpasswd",              "Apache .htpasswd credentials"),
    ("/server-status",          "Apache mod_status"),
    ("/server-status?auto",     "Apache mod_status auto"),
    ("/server-info",            "Apache mod_info"),
    ("/nginx_status",           "Nginx stub_status"),
    ("/_status",                "Status page"),
    ("/status",                 "Generic status"),
    ("/cgi-bin/test-cgi",       "CGI test script"),
    ("/cgi-bin/printenv",       "CGI printenv"),
    ("/.DS_Store",              "macOS directory metadata"),
    ("/Thumbs.db",              "Windows thumbnail DB"),
    ("/.git/config",            "Git repository config"),
    ("/.git/HEAD",              "Git HEAD reference"),
    ("/.svn/entries",           "SVN entries"),
    ("/.env",                   "Environment variables file"),
    ("/web.config",             "IIS web.config"),
    ("/WEB-INF/web.xml",        "Java web.xml"),
    ("/META-INF/MANIFEST.MF",   "Java manifest"),
    ("/composer.json",          "PHP Composer config"),
    ("/package.json",           "Node.js package config"),
    ("/Makefile",               "Makefile"),
    ("/Dockerfile",             "Dockerfile"),
    ("/docker-compose.yml",     "Docker Compose config"),
    ("/.dockerignore",          "Docker ignore file"),
    ("/requirements.txt",       "Python requirements"),
    ("/Gemfile",                "Ruby Gemfile"),
]

NGINX_MISCONFIG_CHECKS = [
    # Off-by-slash / alias traversal
    ("/{ALIAS}../etc/passwd",   "Nginx alias traversal"),
    ("/{ALIAS}../",             "Nginx off-by-slash"),
    ("//{PATH}",                "Nginx merge_slash bypass"),
]

HTTP_METHODS_TO_TEST = ["OPTIONS", "TRACE", "PUT", "DELETE", "PATCH", "CONNECT", "DEBUG", "PROPFIND"]


async def _check_http_methods(url: str, client: TalismanHTTPClient) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for method in HTTP_METHODS_TO_TEST:
        try:
            r = await client.request(method, url, timeout=8)
            if r.status_code not in (405, 501, 400, 404):
                if method == "TRACE" and ("TRACE" in r.text or r.status_code == 200):
                    findings.append({
                        "method": method,
                        "status": r.status_code,
                        "issue": "TRACE method enabled (XST vector)",
                        "severity": "medium",
                    })
                elif method in ("PUT", "DELETE") and r.status_code in (200, 201, 204):
                    findings.append({
                        "method": method,
                        "status": r.status_code,
                        "issue": f"Dangerous HTTP method {method} accepted",
                        "severity": "high",
                    })
                elif method == "OPTIONS":
                    allow_header = r.headers.get("allow", r.headers.get("public", ""))
                    if allow_header:
                        findings.append({
                            "method": method,
                            "status": r.status_code,
                            "issue": f"OPTIONS reveals allowed methods: {allow_header}",
                            "severity": "info",
                        })
        except Exception:
            pass
    return findings


async def _check_crlf(url: str, client: TalismanHTTPClient) -> bool:
    payloads = [
        url + "/%0d%0aSet-Cookie:crlf=injected",
        url + "/?x=%0d%0aContent-Length:0%0d%0a%0d%0aHTTP/1.1 200 OK",
        url + "/%0aSet-Cookie:crlftest=1",
    ]
    for p in payloads:
        try:
            r = await client.get(p, allow_redirects=False, timeout=8)
            if "crlftest" in str(r.headers).lower() or "crlf=injected" in str(r.headers).lower():
                return True
            if r.status_code in (301, 302):
                loc = r.headers.get("location", "")
                if "crlftest" in loc or "crlf" in loc:
                    return True
        except Exception:
            pass
    return False


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
    console.print(f"\n[module]⚡ Server Misconfiguration Scanner[/module] → [target]{url}[/target]")
    findings: list[dict[str, Any]] = []

    async with TalismanHTTPClient(proxy=proxy, timeout=12) as client:
        # Sensitive file disclosure
        console.print(f"  Checking {len(SENSITIVE_DISCLOSURES)} sensitive paths...")
        tasks = []
        for path, desc in SENSITIVE_DISCLOSURES:
            full_url = url.rstrip("/") + path
            tasks.append((path, desc, client.get(full_url, allow_redirects=False, timeout=8)))

        for path, desc, coro in tasks:
            try:
                r = await coro
                if r.status_code == 200 and len(r.content) > 10:
                    severity = "critical" if any(kw in path for kw in [".git", ".env", "htpasswd", "web.config", "web.xml"]) else "high"
                    title = f"Sensitive file exposed: {path}"
                    print_finding(title, severity, url)
                    finding = {"path": path, "desc": desc, "status": r.status_code, "size": len(r.content)}
                    findings.append(finding)
                    if session:
                        await session.add_finding(
                            target=url, module="server_misconfig",
                            vuln_type="sensitive_file_exposure",
                            severity=severity, confidence="confirmed",
                            title=title,
                            description=f"{desc} is publicly accessible",
                            evidence=r.text[:300],
                            request=f"GET {url}{path} HTTP/1.1",
                            remediation=f"Restrict access to {path} in your web server configuration.",
                            cwe="CWE-200",
                        )
            except Exception:
                pass

        # HTTP method testing
        method_findings = await _check_http_methods(url, client)
        for mf in method_findings:
            if mf["severity"] in ("high", "medium"):
                print_finding(mf["issue"], mf["severity"], url)
                findings.append(mf)
                if session and mf["severity"] != "info":
                    await session.add_finding(
                        target=url, module="server_misconfig",
                        vuln_type="dangerous_http_method",
                        severity=mf["severity"], confidence="confirmed",
                        title=mf["issue"],
                        remediation=f"Disable {mf['method']} method in server configuration.",
                        cwe="CWE-650",
                    )

        # CRLF injection
        crlf_vuln = await _check_crlf(url, client)
        if crlf_vuln:
            print_finding("CRLF injection vulnerability", "high", url)
            findings.append({"issue": "crlf_injection", "severity": "high"})
            if session:
                await session.add_finding(
                    target=url, module="server_misconfig",
                    vuln_type="crlf_injection",
                    severity="high", confidence="confirmed",
                    title="CRLF injection — HTTP response splitting",
                    description="URL parameters or headers allow injection of CRLF sequences, enabling response splitting, header injection, and potentially XSS.",
                    remediation="Validate and sanitize all user input. Encode CRLF characters before including in HTTP headers.",
                    cvss_score=6.1, cwe="CWE-93",
                )

    console.print(f"  Found {len(findings)} misconfiguration issues")
    return {"target": url, "findings": findings, "count": len(findings)}
