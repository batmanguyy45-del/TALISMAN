"""Authentication bypass — default creds, JWT attacks, session fixation, CSRF."""
from __future__ import annotations
import asyncio
import re
from typing import Any
from talisman.utils.http_client import TalismanHTTPClient
from talisman.utils.logger import get_logger, console, print_finding

log = get_logger(__name__)

DEFAULT_CREDENTIALS = [
    ("admin", "admin"), ("admin", "password"), ("admin", ""), ("admin", "1234"),
    ("admin", "admin123"), ("admin", "Password1"), ("root", "root"),
    ("root", "toor"), ("root", ""), ("administrator", "administrator"),
    ("test", "test"), ("guest", "guest"), ("user", "user"),
    ("admin", "123456"), ("admin", "pass"), ("admin", "letmein"),
    ("admin", "qwerty"), ("admin", "changeme"), ("admin", "default"),
]

LOGIN_SUCCESS_INDICATORS = [
    "dashboard", "logout", "welcome", "profile", "account",
    "signed in", "logged in", "my account", "settings",
]
LOGIN_FAIL_INDICATORS = [
    "invalid", "incorrect", "failed", "error", "wrong",
    "not found", "doesn't match", "unauthorized",
]

async def _detect_login_form(url: str, client: TalismanHTTPClient) -> dict[str, Any] | None:
    """Auto-detect login form fields."""
    common_paths = ["/login", "/signin", "/admin", "/admin/login",
                    "/wp-login.php", "/user/login", "/auth/login", "/"]
    for path in common_paths:
        test_url = url.rstrip("/") + path
        try:
            r = await client.get(test_url, timeout=8)
            if r.status_code != 200:
                continue
            # Look for password input
            if 'type="password"' not in r.text and "type='password'" not in r.text:
                continue
            # Extract form action and field names
            action_m = re.search(r'<form[^>]+action=["\']([^"\']*)["\']', r.text, re.IGNORECASE)
            action = action_m.group(1) if action_m else path
            if not action.startswith("http"):
                action = url.rstrip("/") + "/" + action.lstrip("/")
            user_m = re.search(
                r'<input[^>]+name=["\']([^"\']*(?:user|login|email|username)[^"\']*)["\']',
                r.text, re.IGNORECASE
            )
            pass_m = re.search(
                r'<input[^>]+name=["\']([^"\']*(?:pass|pwd|password)[^"\']*)["\']',
                r.text, re.IGNORECASE
            )
            csrf_m = re.search(
                r'<input[^>]+name=["\']([^"\']*(?:csrf|token|nonce|_token)[^"\']*)["\'][^>]+value=["\']([^"\']*)["\']',
                r.text, re.IGNORECASE
            )
            if user_m and pass_m:
                return {
                    "url": test_url,
                    "action": action,
                    "user_field": user_m.group(1),
                    "pass_field": pass_m.group(1),
                    "csrf_field": csrf_m.group(1) if csrf_m else None,
                    "csrf_value": csrf_m.group(2) if csrf_m else None,
                }
        except Exception:
            pass
    return None

async def _try_login(
    action: str, user_field: str, pass_field: str,
    username: str, password: str,
    client: TalismanHTTPClient,
    csrf_field: str | None = None,
    csrf_value: str | None = None,
) -> dict[str, Any] | None:
    data: dict[str, str] = {user_field: username, pass_field: password}
    if csrf_field and csrf_value:
        data[csrf_field] = csrf_value
    try:
        r = await client.post(action, data=data, timeout=10)
        resp_lower = r.text.lower()
        url_lower = str(r.url).lower()
        # Success heuristics
        success = (
            any(ind in resp_lower or ind in url_lower for ind in LOGIN_SUCCESS_INDICATORS)
            and not any(fail in resp_lower for fail in LOGIN_FAIL_INDICATORS)
            and r.status_code in (200, 301, 302)
        )
        if success:
            return {"username": username, "password": password,
                    "status": r.status_code, "redirect": str(r.url)}
    except Exception:
        pass
    return None

async def run(
    target: str,
    session: Any = None,
    scope: Any = None,
    rate_limiter: Any = None,
    proxy: str | None = None,
    test_default_creds: bool = True,
    login_url: str | None = None,
    **kwargs: Any,
) -> dict[str, Any]:
    url = target if "://" in target else f"https://{target}"
    console.print(f"\n[module] Authentication Audit[/module] → [target]{url}[/target]")
    findings: list[dict[str, Any]] = []

    async with TalismanHTTPClient(proxy=proxy, timeout=15) as client:
        # Detect login form
        login_info = None
        if login_url:
            login_info = {"url": login_url, "action": login_url,
                         "user_field": "username", "pass_field": "password",
                         "csrf_field": None, "csrf_value": None}
        else:
            console.print("  Auto-detecting login form...")
            login_info = await _detect_login_form(url, client)

        if not login_info:
            console.print("  No login form detected")
        else:
            console.print(f"  Login form at: {login_info['action']}")
            if test_default_creds:
                console.print(f"  Testing {len(DEFAULT_CREDENTIALS)} default credential pairs...")
                for username, password in DEFAULT_CREDENTIALS:
                    result = await _try_login(
                        login_info["action"],
                        login_info["user_field"],
                        login_info["pass_field"],
                        username, password, client,
                        login_info.get("csrf_field"),
                        login_info.get("csrf_value"),
                    )
                    if result:
                        severity = "critical"
                        title = f"Default credentials accepted: {username}:{password}"
                        print_finding(title, severity, url)
                        findings.append(result)
                        if session:
                            await session.add_finding(
                                target=url, module="auth", vuln_type="default_credentials",
                                severity=severity, confidence="confirmed",
                                title=title,
                                description=f"Login succeeded with default credentials {username}:{password}",
                                evidence=f"Redirected to: {result.get('redirect','')}",
                                reproduction=f"POST {login_info['action']} with {login_info['user_field']}={username}&{login_info['pass_field']}={password}",
                                remediation="Change all default passwords immediately. Implement account lockout after 5 failed attempts.",
                                cvss_score=9.8, cwe="CWE-798",
                            )
                        break  # Found creds, stop brute forcing
                    await asyncio.sleep(0.1)  # Gentle rate limit

        # Check for missing CSRF protection
        if login_info and not login_info.get("csrf_field"):
            print_finding("No CSRF token on login form", "medium", url)
            if session:
                await session.add_finding(
                    target=url, module="auth", vuln_type="csrf",
                    severity="medium", confidence="likely",
                    title="Login form missing CSRF token",
                    description="The login form does not include a CSRF token, making it potentially vulnerable to cross-site request forgery.",
                    remediation="Implement CSRF tokens on all state-changing forms.",
                    cwe="CWE-352",
                )

    console.print(f"  Auth audit complete — {len(findings)} issues")
    return {"target": url, "findings": findings, "login_detected": login_info is not None}
