"""Passive MFA endpoint discovery.

Guessed OTPs and repeated invalid MFA submissions are not sent. They can lock
real accounts, trigger alerts and create noisy results without establishing
a vulnerability. This module inventories likely MFA routes and leaves all
state-changing authentication verification to a dedicated disposable account.
"""
from __future__ import annotations

from typing import Any
from urllib.parse import urljoin, urlsplit

from talisman.engine.scope import ScopeViolationError
from talisman.utils.http_client import TalismanHTTPClient
from talisman.utils.logger import console, get_logger

log = get_logger(__name__)

MFA_PATHS = [
    "/mfa", "/2fa", "/verify", "/otp", "/totp",
    "/auth/mfa", "/auth/2fa", "/auth/verify",
    "/account/mfa", "/account/2fa",
    "/login/mfa", "/login/2fa", "/login/verify",
    "/two-factor", "/two_factor", "/twofactor",
    "/sms/verify", "/email/verify", "/phone/verify",
]


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

    observations: list[dict[str, Any]] = []
    console.print(
        f"\\n[module][+] Passive MFA Surface Discovery[/module] -> [target]{url}[/target]"
    )

    async with TalismanHTTPClient(
        proxy=proxy,
        timeout=12,
        verify_ssl=True,
        follow_redirects=False,
        scope=scope,
    ) as client:
        for path in MFA_PATHS:
            test_url = urljoin(url.rstrip("/") + "/", path.lstrip("/"))
            try:
                response = await client.get(test_url, timeout=8)
            except Exception as exc:
                log.debug("mfa_route_probe_failed", error=type(exc).__name__)
                continue

            if response.status_code not in (200, 301, 302, 401, 403):
                continue

            body = response.text[:10000].lower()
            if not any(
                marker in body
                for marker in ("otp", "one-time", "verification code", "two-factor", "2fa", "mfa")
            ):
                # A status code alone does not identify an MFA endpoint.
                continue

            observations.append({
                "type": "possible_mfa_endpoint",
                "path": urlsplit(test_url).path,
                "status": response.status_code,
                "classification": "attack_surface_observation",
                "verification_required": (
                    "Confirm the route belongs to the MFA flow for an authorized "
                    "disposable account. No OTP was submitted and no bypass or "
                    "rate-limit property was tested."
                ),
            })

    console.print(
        f" MFA surface discovery complete — {len(observations)} route observations; "
        "no codes or state-changing requests were sent"
    )
    return {
        "target": url,
        "findings": [],
        "observations": observations,
        "count": 0,
        "observation_count": len(observations),
        "otp_attempts_sent": 0,
    }
