"""Passive CSRF-related cookie posture assessment.

Generic CSRF mutation probes against guessed account-management endpoints are
intentionally not performed. A real CSRF test needs an application-specific
state-changing action, a disposable victim account, and a verified postcondition.
"""
from __future__ import annotations

import re
from typing import Any

from talisman.engine.scope import ScopeViolationError
from talisman.utils.http_client import TalismanHTTPClient
from talisman.utils.logger import console, get_logger

log = get_logger(__name__)

SESSION_COOKIE_NAME = re.compile(
    r"(?:session|sid|auth|token|jwt)",
    re.IGNORECASE,
)


def _analyze_cookies(set_cookie_headers: list[str]) -> list[dict[str, Any]]:
    """Return cookie-attribute observations, never standalone CSRF findings."""
    observations: list[dict[str, Any]] = []

    for cookie_header in set_cookie_headers:
        if not cookie_header or "=" not in cookie_header:
            continue

        name = cookie_header.split("=", 1)[0].strip()
        segments = [segment.strip() for segment in cookie_header.split(";")[1:]]
        attributes: dict[str, str | None] = {}
        for segment in segments:
            key, separator, value = segment.partition("=")
            if key.strip():
                attributes[key.strip().lower()] = value.strip() if separator else None

        is_session_cookie = bool(SESSION_COOKIE_NAME.search(name))
        same_site = str(attributes.get("samesite") or "").lower()
        is_secure = "secure" in attributes
        is_http_only = "httponly" in attributes

        if is_session_cookie and not same_site:
            observations.append({
                "type": "session_cookie_missing_samesite",
                "cookie": name,
                "detail": (
                    "The session-like cookie omits SameSite. Browser defaults vary; "
                    "this does not establish a CSRF vulnerability without an "
                    "application-specific cross-site request test."
                ),
            })

        if is_session_cookie and not is_secure:
            observations.append({
                "type": "session_cookie_missing_secure",
                "cookie": name,
                "detail": (
                    "The session-like cookie omits Secure, so it may be sent over "
                    "unencrypted HTTP when the application is reachable that way."
                ),
            })

        if is_session_cookie and not is_http_only:
            observations.append({
                "type": "session_cookie_missing_httponly",
                "cookie": name,
                "detail": (
                    "The session-like cookie is script-readable, increasing the "
                    "impact of a separate XSS flaw. This is not CSRF evidence."
                ),
            })

        if same_site == "none" and not is_secure:
            observations.append({
                "type": "samesite_none_without_secure",
                "cookie": name,
                "detail": (
                    "SameSite=None is set without Secure. Modern browsers reject "
                    "such cookies; verify actual browser behavior."
                ),
            })

    return observations


async def run(
    target: str,
    session: Any = None,
    scope: Any = None,
    rate_limiter: Any = None,
    proxy: str | None = None,
    **kwargs: Any,
) -> dict[str, Any]:
    url = target if "://" in target else f"https://{target}"
    if scope is None:
        return {
            "target": url,
            "findings": [],
            "observations": [],
            "count": 0,
            "error": "scope_enforcer_required",
        }

    try:
        scope.assert_in_scope(url)
    except ScopeViolationError as exc:
        return {
            "target": url,
            "findings": [],
            "observations": [],
            "count": 0,
            "error": str(exc),
        }

    console.print(
        f"\\n[module][+] Passive CSRF Cookie Assessment[/module] -> [target]{url}[/target]"
    )
    try:
        async with TalismanHTTPClient(
            proxy=proxy,
            timeout=10,
            verify_ssl=True,
            follow_redirects=False,
            scope=scope,
        ) as client:
            response = await client.get(url, timeout=10)
            cookie_headers = response.headers.get_list("set-cookie")
    except Exception as exc:
        log.warning("csrf_posture_request_failed", error=type(exc).__name__)
        return {
            "target": url,
            "findings": [],
            "observations": [],
            "count": 0,
            "error": "request_failed",
        }

    observations = [
        {
            **item,
            "classification": "security_posture_observation",
            "requires_csrf_impact_validation": True,
        }
        for item in _analyze_cookies(cookie_headers)
    ]

    console.print(
        f"  CSRF posture assessment complete — {len(observations)} cookie observations; "
        "no state-changing probes were sent"
    )
    return {
        "target": url,
        "findings": [],
        "observations": observations,
        "count": 0,
        "observation_count": len(observations),
        "state_changing_probes_sent": 0,
    }
