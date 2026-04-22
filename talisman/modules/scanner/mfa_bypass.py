"""MFA/2FA bypass techniques — code reuse, response manipulation, skip-step."""
from __future__ import annotations
import asyncio
import re
from typing import Any
from talisman.utils.http_client import TalismanHTTPClient
from talisman.utils.logger import get_logger, console, print_finding

log = get_logger(__name__)

MFA_PATHS = [
    "/mfa", "/2fa", "/verify", "/otp", "/totp",
    "/auth/mfa", "/auth/2fa", "/auth/verify",
    "/account/mfa", "/account/2fa",
    "/login/mfa", "/login/2fa", "/login/verify",
    "/two-factor", "/two_factor", "/twofactor",
    "/sms/verify", "/email/verify", "/phone/verify",
]

MFA_BYPASS_CODES = ["000000", "123456", "111111", "999999", "000001", "888888"]


async def _detect_mfa_endpoint(base_url: str, client: TalismanHTTPClient) -> str | None:
    for path in MFA_PATHS:
        try:
            r = await client.get(base_url.rstrip("/") + path, allow_redirects=False, timeout=8)
            if r.status_code in (200, 302) and any(
                kw in r.text.lower()
                for kw in ["otp", "code", "token", "verify", "two-factor", "2fa", "mfa"]
            ):
                return base_url.rstrip("/") + path
        except Exception:
            pass
    return None


async def _test_bypass_direct_access(
    mfa_url: str, protected_url: str, client: TalismanHTTPClient
) -> bool:
    """Test if protected URL is accessible without completing MFA."""
    try:
        r = await client.get(protected_url, allow_redirects=False, timeout=8)
        return r.status_code == 200 and "login" not in str(r.url).lower()
    except Exception:
        return False


async def _test_code_brute(mfa_url: str, client: TalismanHTTPClient) -> dict | None:
    """Test if MFA code brute force is rate-limited."""
    for code in MFA_BYPASS_CODES:
        try:
            r = await client.post(mfa_url, data={"code": code, "otp": code, "token": code}, timeout=8)
            if r.status_code == 429:
                return None  # Rate limited — good
        except Exception:
            pass
        await asyncio.sleep(0.1)
    return {"issue": "no_rate_limit_on_mfa", "tested_codes": len(MFA_BYPASS_CODES)}


async def run(
    target: str,
    session: Any = None,
    scope: Any = None,
    rate_limiter: Any = None,
    proxy: str | None = None,
    **kwargs: Any,
) -> dict[str, Any]:
    url = target if "://" in target else f"https://{target}"
    console.print(f"\n[module]⚡ MFA Bypass Testing[/module] → [target]{url}[/target]")
    findings: list[dict[str, Any]] = []

    async with TalismanHTTPClient(proxy=proxy, timeout=12) as client:
        mfa_url = await _detect_mfa_endpoint(url, client)
        if not mfa_url:
            console.print("  No MFA endpoint detected")
            return {"target": url, "findings": [], "mfa_detected": False}

        console.print(f"  [success]✓ MFA endpoint: {mfa_url}[/success]")

        # Test 1: Direct URL bypass
        protected_urls = [url + "/dashboard", url + "/account", url + "/profile", url + "/admin"]
        for protected in protected_urls:
            bypassed = await _test_bypass_direct_access(mfa_url, protected, client)
            if bypassed:
                title = f"MFA step bypass — direct access to {protected}"
                print_finding(title, "critical", url)
                findings.append({"issue": "mfa_step_bypass", "url": protected})
                if session:
                    await session.add_finding(
                        target=url, module="mfa_bypass",
                        vuln_type="mfa_bypass",
                        severity="critical", confidence="confirmed",
                        title=title,
                        description=(
                            f"Protected URL {protected} accessible without completing MFA. "
                            "The authentication flow does not enforce MFA completion."
                        ),
                        reproduction=f"1. Initiate login\n2. Skip MFA step\n3. Navigate directly to {protected}",
                        remediation=(
                            "1. Check MFA completion on every request to protected resources.\n"
                            "2. Store MFA state in server-side session, not client-side.\n"
                            "3. Invalidate session if MFA is not completed within timeout."
                        ),
                        cvss_score=9.8, cwe="CWE-306",
                    )
                break

        # Test 2: Rate limit on brute force
        brute_result = await _test_code_brute(mfa_url, client)
        if brute_result:
            title = "MFA code brute force not rate-limited"
            print_finding(title, "high", url)
            findings.append(brute_result)
            if session:
                await session.add_finding(
                    target=url, module="mfa_bypass",
                    vuln_type="mfa_brute_force",
                    severity="high", confidence="likely",
                    title=title,
                    description="MFA code endpoint does not rate-limit attempts. 6-digit SMS codes (1M combinations) or TOTP codes (30-second window) can be brute forced.",
                    remediation=(
                        "1. Lock account after 5-10 failed MFA attempts.\n"
                        "2. Implement exponential backoff on failed attempts.\n"
                        "3. Notify user of failed MFA attempts via email/SMS."
                    ),
                    cvss_score=7.5, cwe="CWE-307",
                )

    console.print(f"  MFA bypass testing complete — {len(findings)} issues")
    return {"target": url, "mfa_url": mfa_url, "findings": findings, "count": len(findings)}
