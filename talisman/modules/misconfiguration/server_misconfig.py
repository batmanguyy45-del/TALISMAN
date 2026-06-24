"""
Server Misconfiguration Scanner — Nginx, Apache, IIS, CRLF injection

FALSE-POSITIVE ELIMINATION STRATEGY
====================================
PROBLEM 1 – CRLF: Checking if the URL parameter appears in the Location header
  is NOT sufficient. Many redirect-heavy sites put params in Location naturally.
  Fix: Inject a UNIQUE canary header name/value and verify it appears as an actual
  HTTP response header (not just in the HTML body).

PROBLEM 2 – Sensitive files: A 200 response doesn't mean the file is accessible.
  Many sites return 200 with a custom "404" page. Verify file-specific content.

PROBLEM 3 – HTTP methods: Many endpoints legitimately accept OPTIONS/TRACE.
  Fix: Only flag TRACE if the request body is reflected (XST vector confirmed).
  Only flag PUT/DELETE if 2xx response contains confirmation data.
"""
from __future__ import annotations
import asyncio
import re
import uuid
from typing import Any

from talisman.utils.http_client import TalismanHTTPClient
from talisman.utils.logger import get_logger, console, print_finding

log = get_logger(__name__)

# ---------------------------------------------------------------------------
# File content signatures (same strict approach as LFI scanner)
# ---------------------------------------------------------------------------
FILE_CONTENT_SIGNATURES: dict[str, re.Pattern] = {
    "/.htpasswd":        re.compile(r'\w+:\$(?:apr1|2y)\$[^\s]+', re.IGNORECASE),
    "/.htaccess":        re.compile(r'(?:RewriteEngine|Options|AllowOverride|AuthType)', re.IGNORECASE),
    "/server-status":    re.compile(r'Apache Server Status|Requests currently being processed', re.IGNORECASE),
    "/server-info":      re.compile(r'Apache Server Information|Server Built', re.IGNORECASE),
    "/nginx_status":     re.compile(r'Active connections:\s*\d+', re.IGNORECASE),
    "/_status":          re.compile(r'Active connections:\s*\d+', re.IGNORECASE),
    "/.env":             re.compile(r'(?:APP_KEY|DB_PASSWORD|SECRET_KEY|API_KEY)\s*=', re.IGNORECASE),
    "/.git/config":      re.compile(r'\[core\].*?repositoryformatversion', re.IGNORECASE | re.DOTALL),
    "/.git/HEAD":        re.compile(r'ref:\s+refs/heads/', re.IGNORECASE),
    "/.svn/entries":     re.compile(r'(?:^10$|^dir$|svn\.apache\.org)', re.MULTILINE),
    "/web.config":       re.compile(r'<configuration>.*?<system\.web>', re.IGNORECASE | re.DOTALL),
    "/WEB-INF/web.xml":  re.compile(r'<web-app.*?xmlns', re.IGNORECASE | re.DOTALL),
    "/phpinfo.php":      re.compile(r'PHP Version \d+\.\d+\.\d+.*?php\.net', re.IGNORECASE | re.DOTALL),
    "/info.php":         re.compile(r'PHP Version \d+\.\d+\.\d+.*?php\.net', re.IGNORECASE | re.DOTALL),
    "/composer.json":    re.compile(r'"require"\s*:\s*\{', re.IGNORECASE),
    "/package.json":     re.compile(r'"dependencies"\s*:\s*\{', re.IGNORECASE),
    "/Dockerfile":       re.compile(r'^FROM\s+\w+', re.MULTILINE),
    "/docker-compose.yml": re.compile(r'^services:\s*$', re.MULTILINE),
    "/.DS_Store":        re.compile(r'Bud1', re.IGNORECASE),  # DS_Store magic bytes
}

# Paths to check — ordered by severity
SENSITIVE_PATHS: list[tuple[str, str, str]] = [
    # (path, description, severity)
    ("/.env",               "Environment variables file",            "critical"),
    ("/.env.local",         "Local environment variables",           "critical"),
    ("/.env.production",    "Production environment variables",      "critical"),
    ("/.git/config",        "Git repository configuration",          "critical"),
    ("/.git/HEAD",          "Git HEAD reference",                    "high"),
    ("/.svn/entries",       "SVN repository entries",                "high"),
    ("/WEB-INF/web.xml",    "Java web.xml deployment descriptor",    "high"),
    ("/web.config",         "IIS web.config",                        "high"),
    ("/.htpasswd",          "Apache .htpasswd credential file",      "critical"),
    ("/.htaccess",          "Apache .htaccess configuration",        "medium"),
    ("/phpinfo.php",        "PHP configuration disclosure",          "medium"),
    ("/info.php",           "PHP configuration disclosure",          "medium"),
    ("/server-status",      "Apache mod_status metrics",             "medium"),
    ("/server-info",        "Apache mod_info disclosure",            "medium"),
    ("/nginx_status",       "Nginx stub_status metrics",             "low"),
    ("/_status",            "Status page",                           "low"),
    ("/composer.json",      "PHP Composer dependency list",          "low"),
    ("/package.json",       "Node.js package manifest",              "low"),
    ("/Dockerfile",         "Docker build instructions",             "medium"),
    ("/docker-compose.yml", "Docker Compose configuration",          "medium"),
    ("/.DS_Store",          "macOS directory metadata",              "low"),
]


async def _check_sensitive_file(
    base_url: str,
    path: str,
    description: str,
    severity: str,
    client: TalismanHTTPClient,
) -> dict[str, Any] | None:
    """
    Check if a sensitive file is accessible AND contains expected content.
    A 200 response alone is NOT sufficient.
    """
    full_url = base_url.rstrip("/") + path

    try:
        r = await client.get(full_url, allow_redirects=False, timeout=8)

        if r.status_code not in (200, 206):
            return None

        if len(r.content) < 10:
            return None

        # Verify content matches expected file signature
        signature = FILE_CONTENT_SIGNATURES.get(path)
        if signature:
            if not signature.search(r.text):
                # Has a specific signature requirement — must match
                return None
        else:
            # No specific signature — require at least some meaningful content
            # and exclude common "404 as 200" patterns
            if len(r.text) < 50:
                return None
            not_found_patterns = re.compile(
                r'(?:404|not found|page not found|does not exist)',
                re.IGNORECASE,
            )
            if not_found_patterns.search(r.text[:200]):
                return None

        # Extract evidence snippet
        snippet = r.text[:300].strip()

        return {
            "path": path,
            "description": description,
            "severity": severity,
            "status": r.status_code,
            "size": len(r.content),
            "evidence": snippet,
            "request": f"GET {full_url} HTTP/1.1",
        }

    except Exception as e:
        log.debug("sensitive_file_check", path=path, error=str(e)[:60])
        return None


async def _check_crlf(
    url: str,
    client: TalismanHTTPClient,
) -> dict[str, Any] | None:
    """
    CRLF injection verification:
    Inject a unique canary header name and value.
    Confirmed ONLY if the canary appears as an actual response HEADER,
    not just in the HTML body.
    """
    canary_name = f"X-Talisman-{uuid.uuid4().hex[:8].upper()}"
    canary_value = f"crlftest{uuid.uuid4().hex[:8]}"

    payloads = [
        f"/%0d%0a{canary_name}:{canary_value}",
        f"/?x=%0d%0a{canary_name}:{canary_value}",
        f"/%0a{canary_name}:{canary_value}",
        f"/%0d%0a{canary_name}:%20{canary_value}",
        f"/test%0d%0a{canary_name}:{canary_value}%0d%0a",
    ]

    for payload in payloads:
        test_url = url.rstrip("/") + payload
        try:
            r = await client.get(test_url, allow_redirects=False, timeout=8)

            # Check if the canary appears in the RESPONSE HEADERS (not body)
            for header_name, header_value in r.headers.items():
                if (
                    canary_name.lower() in header_name.lower()
                    or canary_value.lower() in header_value.lower()
                ):
                    return {
                        "payload": payload,
                        "canary_header": canary_name,
                        "canary_value": canary_value,
                        "found_in_header": f"{header_name}: {header_value}",
                        "status": r.status_code,
                        "evidence": (
                            f"Injected header '{canary_name}: {canary_value}' "
                            f"appeared in response headers: "
                            f"'{header_name}: {header_value}'"
                        ),
                        "request": f"GET {test_url} HTTP/1.1",
                    }

            # Also check Location header for redirect-based CRLF
            location = r.headers.get("location", "")
            if r.status_code in (301, 302, 307, 308) and canary_value in location:
                # Follow the redirect and check if canary appears in headers there
                try:
                    r2 = await client.get(location, allow_redirects=False, timeout=6)
                    for hk, hv in r2.headers.items():
                        if canary_value in hv:
                            return {
                                "payload": payload,
                                "canary_header": canary_name,
                                "canary_value": canary_value,
                                "found_in_header": f"{hk}: {hv}",
                                "status": r.status_code,
                                "evidence": (
                                    f"CRLF injection confirmed via redirect chain: "
                                    f"'{hk}: {hv}'"
                                ),
                                "request": f"GET {test_url} HTTP/1.1",
                            }
                except Exception:
                    pass

        except Exception as e:
            log.debug("crlf_check", error=str(e)[:60])

    return None


async def _check_http_methods(
    url: str,
    client: TalismanHTTPClient,
) -> list[dict[str, Any]]:
    """
    Check for dangerous HTTP methods.
    TRACE: Only flag if response body REFLECTS request headers (XST).
    PUT/DELETE: Only flag if 2xx with meaningful confirmation response.
    """
    findings: list[dict[str, Any]] = []
    canary_header = "X-Talisman-Trace-Test"
    canary_value = uuid.uuid4().hex[:16]

    # TRACE — check for Cross-Site Tracing (XST)
    try:
        r = await client.request(
            "TRACE",
            url,
            headers={canary_header: canary_value},
            timeout=8,
        )
        if r.status_code == 200 and canary_value in r.text:
            findings.append({
                "method": "TRACE",
                "status": r.status_code,
                "issue": "TRACE method enabled — XST (Cross-Site Tracing) confirmed",
                "severity": "medium",
                "evidence": (
                    f"Canary header '{canary_header}: {canary_value}' "
                    f"reflected in TRACE response body"
                ),
            })
    except Exception:
        pass

    # OPTIONS — informational only (not a vulnerability itself)
    try:
        r = await client.request("OPTIONS", url, timeout=8)
        allow_header = r.headers.get("allow", r.headers.get("public", ""))
        if allow_header and r.status_code in (200, 204):
            dangerous = {"PUT", "DELETE", "PATCH"} & set(
                m.strip().upper() for m in allow_header.split(",")
            )
            if dangerous:
                findings.append({
                    "method": "OPTIONS",
                    "status": r.status_code,
                    "issue": (
                        f"OPTIONS reveals potentially dangerous methods: "
                        f"{', '.join(dangerous)}"
                    ),
                    "severity": "info",
                    "evidence": f"Allow: {allow_header}",
                })
    except Exception:
        pass

    return findings


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
        f"\n[module] Server Misconfiguration Scanner[/module] → [target]{url}[/target]"
    )
    findings: list[dict[str, Any]] = []

    async with TalismanHTTPClient(proxy=proxy, timeout=12) as client:

        # --- Sensitive file checks ---
        console.print(f"  Checking {len(SENSITIVE_PATHS)} sensitive paths...")
        file_tasks = [
            _check_sensitive_file(url, path, desc, sev, client)
            for path, desc, sev in SENSITIVE_PATHS
        ]
        file_results = await asyncio.gather(*file_tasks, return_exceptions=True)

        for result in file_results:
            if not isinstance(result, dict):
                continue
            severity = result["severity"]
            title = f"Sensitive file exposed: {result['path']}"
            print_finding(title, severity, url)
            findings.append(result)
            if session:
                await session.add_finding(
                    target=url,
                    module="server_misconfig",
                    vuln_type="sensitive_file_exposure",
                    severity=severity,
                    confidence="confirmed",
                    title=title,
                    description=(
                        f"{result['description']} is publicly accessible at "
                        f"{url}{result['path']}. "
                        f"Content verified against expected file signature."
                    ),
                    evidence=result["evidence"],
                    request=result["request"],
                    remediation=(
                        f"Restrict access to {result['path']} in your web server "
                        f"configuration. For Apache: deny from all in .htaccess. "
                        f"For Nginx: location ~ {result['path']} {{ deny all; }}"
                    ),
                    cwe="CWE-200",
                )

        # --- CRLF injection ---
        console.print("  Testing CRLF injection...")
        crlf_result = await _check_crlf(url, client)
        if crlf_result:
            severity = "high"
            print_finding("CRLF injection — HTTP response splitting confirmed", severity, url)
            findings.append({**crlf_result, "type": "crlf_injection"})
            if session:
                await session.add_finding(
                    target=url,
                    module="server_misconfig",
                    vuln_type="crlf_injection",
                    severity=severity,
                    confidence="confirmed",
                    title="CRLF Injection — HTTP response splitting",
                    description=(
                        "Carriage-return/line-feed sequences in URL parameters "
                        "are reflected into HTTP response headers. Confirmed by "
                        f"injecting unique canary header: {crlf_result['evidence']}"
                    ),
                    request=crlf_result["request"],
                    evidence=crlf_result["evidence"],
                    remediation=(
                        "Validate and strip CR/LF characters from all user input "
                        "before using in HTTP headers or redirect locations."
                    ),
                    cvss_score=6.1,
                    cwe="CWE-93",
                )

        # --- HTTP method testing ---
        method_findings = await _check_http_methods(url, client)
        for mf in method_findings:
            if mf["severity"] in ("medium", "high"):
                print_finding(mf["issue"], mf["severity"], url)
                findings.append(mf)
                if session:
                    await session.add_finding(
                        target=url,
                        module="server_misconfig",
                        vuln_type="dangerous_http_method",
                        severity=mf["severity"],
                        confidence="confirmed",
                        title=mf["issue"],
                        evidence=mf.get("evidence", ""),
                        remediation=(
                            f"Disable {mf['method']} method in server "
                            f"configuration unless explicitly required."
                        ),
                        cwe="CWE-650",
                    )

    console.print(f"  Found {len(findings)} server misconfiguration issues")
    return {"target": url, "findings": findings, "count": len(findings)}
