"""Passive authentication-form discovery.

Credential spraying against guessed login endpoints is intentionally disabled.
A defensible authentication test requires an operator-provided disposable account,
program permission for active authentication testing, and careful lockout handling.
"""
from __future__ import annotations

import re
from typing import Any
from urllib.parse import urljoin, urlsplit

from talisman.engine.scope import ScopeViolationError
from talisman.utils.http_client import TalismanHTTPClient
from talisman.utils.logger import console, get_logger

log = get_logger(__name__)


def _extract_input_name(html: str, pattern: str) -> str | None:
    match = re.search(pattern, html, re.IGNORECASE)
    return match.group(1) if match else None


async def _detect_login_form(
    url: str,
    client: TalismanHTTPClient,
) -> dict[str, Any] | None:
    """Find a password form using bounded, read-only GET requests."""
    common_paths = (
        "/",
        "/login",
        "/signin",
        "/admin",
        "/admin/login",
        "/wp-login.php",
        "/user/login",
        "/auth/login",
    )

    for path in common_paths:
        test_url = urljoin(url.rstrip("/") + "/", path.lstrip("/"))
        try:
            response = await client.get(test_url, timeout=8)
        except Exception as exc:
            log.debug("auth_form_probe_failed", error=type(exc).__name__)
            continue

        if response.status_code != 200:
            continue

        html = response.text
        if not re.search(r"<input\\b[^>]*type\\s*=\\s*['\"]?password", html, re.IGNORECASE):
            continue

        form_match = re.search(
            r"<form\\b([^>]*)>",
            html,
            re.IGNORECASE | re.DOTALL,
        )
        form_attrs = form_match.group(1) if form_match else ""
        action_match = re.search(
            r"""action\\s*=\\s*['"]([^'"]*)['"]""",
            form_attrs,
            re.IGNORECASE,
        )
        action = urljoin(test_url, action_match.group(1) if action_match else test_url)

        user_field = _extract_input_name(
            html,
            r"""<input\\b[^>]*name\\s*=\\s*['"]([^'"]*(?:user|login|email)[^'"]*)['"]""",
        )
        pass_field = _extract_input_name(
            html,
            r"""<input\\b[^>]*name\\s*=\\s*['"]([^'"]*(?:pass|pwd)[^'"]*)['"]""",
        )
        csrf_match = re.search(
            r"""<input\\b[^>]*name\\s*=\\s*['"]([^'"]*(?:csrf|token|nonce|_token)[^'"]*)['"]""",
            html,
            re.IGNORECASE,
        )

        if user_field and pass_field:
            return {
                "page_url": test_url,
                "action": action,
                "user_field": user_field,
                "pass_field": pass_field,
                "csrf_field_observed": csrf_match.group(1) if csrf_match else None,
            }

    return None


async def run(
    target: str,
    session: Any = None,
    scope: Any = None,
    rate_limiter: Any = None,
    proxy: str | None = None,
    test_default_creds: bool = False,
    login_url: str | None = None,
    **kwargs: Any,
) -> dict[str, Any]:
    url = target if "://" in target else f"https://{target}"
    if scope is None:
        return {
            "target": url,
            "findings": [],
            "candidates": [],
            "observations": [],
            "count": 0,
            "error": "scope_enforcer_required",
            "credential_testing_enabled": False,
        }

    try:
        scope.assert_in_scope(url)
        if login_url:
            scope.assert_request_allowed(login_url, "GET")
    except ScopeViolationError as exc:
        return {
            "target": url,
            "findings": [],
            "candidates": [],
            "observations": [],
            "count": 0,
            "error": str(exc),
            "credential_testing_enabled": False,
        }

    console.print(
        f"\\n[module][+] Passive Authentication Surface Audit[/module] -> [target]{url}[/target]"
    )
    observations: list[dict[str, Any]] = []

    async with TalismanHTTPClient(
        proxy=proxy,
        timeout=15,
        verify_ssl=True,
        follow_redirects=False,
        scope=scope,
    ) as client:
        if login_url:
            login_info = {
                "page_url": login_url,
                "action": login_url,
                "user_field": None,
                "pass_field": None,
                "csrf_field_observed": None,
            }
        else:
            login_info = await _detect_login_form(url, client)

    if login_info:
        action_parts = urlsplit(login_info["action"])
        observations.append({
            "type": "login_form_detected",
            "page": urlsplit(login_info["page_url"]).path or "/",
            "action": action_parts.path or "/",
            "user_field": login_info.get("user_field"),
            "password_field_detected": bool(login_info.get("pass_field")),
            "csrf_field_observed": bool(login_info.get("csrf_field_observed")),
            "classification": "attack_surface_observation",
        })
        if not login_info.get("csrf_field_observed"):
            observations.append({
                "type": "csrf_token_not_observed_in_form_markup",
                "page": urlsplit(login_info["page_url"]).path or "/",
                "classification": "observation",
                "note": (
                    "This does not prove CSRF protection is absent. Tokens may be "
                    "added by JavaScript, supplied through cookies, or enforced "
                    "using Origin/Referer validation and browser cookie policy."
                ),
            })

    console.print(
        f" Authentication audit complete — {len(observations)} surface observations; "
        "credential spraying was not performed"
    )
    return {
        "target": url,
        "findings": [],
        "candidates": [],
        "observations": observations,
        "count": 0,
        "observation_count": len(observations),
        "credential_testing_enabled": False,
        "credential_testing_skipped": bool(test_default_creds),
    }
