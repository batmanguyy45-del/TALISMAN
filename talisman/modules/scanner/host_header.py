"""Host header injection scanner — password reset poisoning, cache poisoning, redirect hijacking."""
from __future__ import annotations
import asyncio
import random
import string
from typing import Any
from talisman.utils.http_client import TalismanHTTPClient
from talisman.utils.logger import get_logger, console, print_finding

log = get_logger(__name__)

HOST_HEADER_VARIANTS = [
    "evil.com",
    "attackerevil.com",
    "127.0.0.1",
    "localhost",
    "0.0.0.0",
    "10.0.0.1",
    "192.168.1.1",
]

X_FORWARDED_HOST_VARIANTS = [
    "evil.com",
    "127.0.0.1",
    "localhost",
]

PASSWORD_RESET_PATHS = [
    "/forgot-password", "/api/forgot-password",
    "/reset-password", "/api/reset-password",
    "/forgot", "/api/forgot",
    "/password-reset", "/api/password-reset",
]


async def _test_host_injection(
    url: str, client: TalismanHTTPClient,
) -> list[dict[str, Any]]:
    """Test Host header injection variants."""
    findings: list[dict[str, Any]] = []
    original_host = url.split("://")[1].split("/")[0].split(":")[0]

    for evil_host in HOST_HEADER_VARIANTS:
        try:
            r = await client.get(
                url,
                headers={"Host": evil_host},
                allow_redirects=False,
                timeout=8,
            )
            body_lower = r.text.lower()
            location = (r.headers.get("location", "") or "").lower()

            # Check if the evil host is reflected in the response
            if evil_host in body_lower:
                findings.append({
                    "type": "host_reflection",
                    "header": "Host",
                    "value": evil_host,
                    "location": evil_host in location,
                    "status": r.status_code,
                    "evidence": r.text[:300],
                })
                break  # One confirmed variant is enough

            # Check for redirect to evil host
            if evil_host in location:
                findings.append({
                    "type": "redirect_to_evil",
                    "header": "Host",
                    "value": evil_host,
                    "location": location,
                    "status": r.status_code,
                    "evidence": f"Redirect to: {location}",
                })
                break
        except Exception:
            pass

    return findings


async def _test_xfh_injection(
    url: str, client: TalismanHTTPClient,
) -> list[dict[str, Any]]:
    """Test X-Forwarded-Host injection."""
    findings: list[dict[str, Any]] = []
    for evil_host in X_FORWARDED_HOST_VARIANTS:
        try:
            r = await client.get(
                url,
                headers={"X-Forwarded-Host": evil_host},
                allow_redirects=False,
                timeout=8,
            )
            body_lower = r.text.lower()
            location = (r.headers.get("location", "") or "").lower()

            if evil_host in body_lower or evil_host in location:
                findings.append({
                    "type": "xfh_injection",
                    "header": "X-Forwarded-Host",
                    "value": evil_host,
                    "status": r.status_code,
                    "evidence": r.text[:300] if evil_host in body_lower else f"Redirect to: {location}",
                })
                break
        except Exception:
            pass

    return findings


async def _test_password_reset_poisoning(
    url: str, client: TalismanHTTPClient,
) -> list[dict[str, Any]]:
    """Test password reset poisoning via Host header injection."""
    findings: list[dict[str, Any]] = []
    reset_email = f"test_{''.join(random.choices(string.ascii_lowercase, k=6))}@example.com"
    evil_host = "evil.com"

    for reset_path in PASSWORD_RESET_PATHS:
        test_url = url.rstrip("/") + reset_path
        try:
            r = await client.post(
                test_url,
                json={"email": reset_email},
                headers={
                    "Host": evil_host,
                    "Content-Type": "application/json",
                },
                timeout=8,
            )
            body_lower = r.text.lower()
            # Check if the response includes a link with the evil host
            if evil_host in body_lower:
                injection_type = "password_reset_host"
                # Extract the reset link
                start = body_lower.find(evil_host)
                context = body_lower[max(0, start - 50):start + 100]
                findings.append({
                    "type": injection_type,
                    "host_header": evil_host,
                    "endpoint": reset_path,
                    "email": reset_email,
                    "evidence": f"Response contains evil host in context: ...{context}...",
                })
                break

            # Check for email link in response body
            if "reset" in body_lower and ("http://" in body_lower or "https://" in body_lower):
                findings.append({
                    "type": "password_reset_link_in_response",
                    "endpoint": reset_path,
                    "evidence": r.text[:500],
                })
        except Exception:
            pass

    return findings


async def _test_absolute_url_redirect(
    url: str, client: TalismanHTTPClient,
) -> list[dict[str, Any]]:
    """Test if server constructs absolute URLs based on Host header."""
    findings: list[dict[str, Any]] = []
    evil_host = f"evil-{''.join(random.choices(string.ascii_lowercase, k=6))}.com"

    try:
        r = await client.get(
            url,
            headers={"Host": evil_host},
            allow_redirects=False,
            timeout=8,
        )
        body = r.text.lower()
        location = (r.headers.get("location", "") or "").lower()

        # Check for absolute URL construction
        if evil_host in body or evil_host in location:
            findings.append({
                "type": "absolute_url_construction",
                "value": evil_host,
                "evidence": r.text[:400] if evil_host in body else f"Location: {location}",
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
    **kwargs: Any,
) -> dict[str, Any]:
    url = target if "://" in target else f"https://{target}"
    console.print(f"\n[module][+] Host Header Injection Scanner[/module] -> [target]{url}[/target]")
    findings: list[dict[str, Any]] = []

    async with TalismanHTTPClient(proxy=proxy, timeout=10) as client:
        # -- 1. Host header reflection / redirect ------------------------------------
        host_findings = await _test_host_injection(url, client)
        for f in host_findings:
            ftype = f["type"]
            title = f"Host header injection: {f['header']} = {f['value']} ({ftype})"
            print_finding(title, "high", url)
            findings.append(f)
            if session:
                await session.add_finding(
                    target=url, module="host_header",
                    vuln_type="host_header_injection",
                    severity="high", confidence="confirmed",
                    title=title,
                    description=f"Host header '{f['header']}: {f['value']}' was reflected in the response or caused a redirect. This can be used for cache poisoning, password reset poisoning, and SSRF.",
                    evidence=f.get("evidence", "")[:500],
                    remediation="1. Do not trust the Host header for URL generation. 2. Use a server name whitelist. 3. Configure virtual hosts explicitly.",
                    cvss_score=7.5, cwe="CWE-644",
                )

        # -- 2. X-Forwarded-Host injection ------------------------------------------
        xfh_findings = await _test_xfh_injection(url, client)
        for f in xfh_findings:
            title = f"X-Forwarded-Host injection: {f['value']}"
            print_finding(title, "medium", url)
            findings.append(f)
            if session:
                await session.add_finding(
                    target=url, module="host_header",
                    vuln_type="xfh_injection",
                    severity="medium", confidence="confirmed",
                    title=title,
                    description=f"X-Forwarded-Host header injection confirmed. Value '{f['value']}' was reflected in the response. Can be used to manipulate URL generation.",
                    evidence=f.get("evidence", "")[:500],
                    remediation="1. Only trust X-Forwarded-Host from known proxies. 2. Validate and sanitize forward-proxy headers.",
                    cvss_score=6.5, cwe="CWE-644",
                )

        # -- 3. Password reset poisoning ---------------------------------------------
        reset_findings = await _test_password_reset_poisoning(url, client)
        for f in reset_findings:
            title = f"Password reset poisoning via Host header at {f.get('endpoint', 'unknown')}"
            print_finding(title, "critical", url)
            findings.append(f)
            if session:
                await session.add_finding(
                    target=url, module="host_header",
                    vuln_type="password_reset_poisoning",
                    severity="critical", confidence="confirmed",
                    title=title,
                    description=f"Password reset endpoint {f.get('endpoint', '')} reflects attacker-controlled Host header in the reset link. Attackers can hijack account reset flows.",
                    evidence=f.get("evidence", "")[:500],
                    remediation="1. Use a fixed hostname for password reset links. 2. Never trust the Host header for link generation. 3. Use absolute URLs from configuration.",
                    cvss_score=9.6, cwe="CWE-644",
                )

        # -- 4. Absolute URL construction via Host -----------------------------------
        abs_findings = await _test_absolute_url_redirect(url, client)
        for f in abs_findings:
            title = f"Absolute URL construction via Host header (cache poisoning vector)"
            print_finding(title, "medium", url)
            findings.append(f)
            if session:
                await session.add_finding(
                    target=url, module="host_header",
                    vuln_type="absolute_url_construction",
                    severity="medium", confidence="confirmed",
                    title=title,
                    description=f"The server constructs absolute URLs using the Host header. This can be combined with cache poisoning (e.g., web cache poisoning via Host header).",
                    evidence=f.get("evidence", "")[:500],
                    remediation="1. Use relative URLs where possible. 2. Validate Host header against a whitelist. 3. Use canonical URLs from configuration.",
                    cvss_score=6.5, cwe="CWE-644",
                )

    console.print(f"  Host header scan complete -- {len(findings)} issues")
    return {"target": url, "findings": findings, "count": len(findings)}
